// template.go 实现 AdminService 模板管理族五方法（ListTemplates / CreateTemplate /
// GetTemplate / UpdateTemplate / DeleteTemplate，接口文档 §5.7）的业务层，
// 并提供 Resolve 供页面壳渲染按 key 取模板内容（§8.1）。
//
// 内置模板由 pages 包启动扫描全集常驻内存、只读、不进库与缓存（§3.13）；
// 本层只管理 DB template 表行，Create / Update 拒绝与任一内置 key 同名，
// 保留字集合即 pages 扫描全集（不止单个 key）。content 缓存 al:tpl:v:{key}
// （§5.1）归 cache 包，写路径成功后单步 DEL、改 key 时旧 + 新双失效；
// 解析顺序缓存 → 内置 → DB → 回落，内置命中不回填缓存、DB 回填失败不阻断。
//
// 错误沿用包内哨兵（同 provider.go 包注释）：ErrInvalidRequest 参数 / 校验
// 类（含 Resolve 全 miss、内置 key 冲突）；repo.ErrTemplateDuplicate →
// ErrDuplicateKey；gorm.ErrRecordNotFound 资源不存在；其余原样上抛。
package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"

	"authloft/internal/cache"
	"authloft/internal/pages"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// templateKeyMaxRunes 模板 key 列宽上限（§4.9 VARCHAR(64)）。
const templateKeyMaxRunes = 64

// templateStore template 表读写窄接口（§20 依赖注入）：*repo.TemplateRepo
// 天然满足，测试可传内存 fake。Resolve 用 FindByKey，其余方法经 List 取行后
// 按主键定位（repo 只暴露 List 的查询口径，分页 / 筛选归本层）。
type templateStore interface {
	FindByKey(ctx context.Context, templateKey string) (*model.Template, error)
	List(ctx context.Context) ([]model.Template, error)
	Create(ctx context.Context, t *model.Template) error
	Update(ctx context.Context, t *model.Template) error
	Delete(ctx context.Context, id int64) error
}

// TemplateService 模板管理族业务层 + 页面壳解析入口。
type TemplateService struct {
	store templateStore
	cache *cache.TemplateCache
}

// NewTemplateService 构造；store 为 nil 属程序错误（fail-fast，口径同
// NewClientService）。cache 为 content 缓存封装，由装配层注入同一实例。
func NewTemplateService(store templateStore, tplCache *cache.TemplateCache) *TemplateService {
	if store == nil {
		panic("admin service: NewTemplateService: nil templateStore")
	}
	return &TemplateService{store: store, cache: tplCache}
}

// List 只返回 DB 自定义模板行、不含内置模板（§5.7）；按 id ASC 稳定排序，
// q 按 name 模糊筛选，page / pageSize 由 handler 归一（§1.7）。
func (s *TemplateService) List(ctx context.Context, page, pageSize int, q string) ([]model.Template, int64, error) {
	rows, err := s.store.List(ctx)
	if err != nil {
		return nil, 0, err
	}
	if q != "" {
		needle := strings.ToLower(q)
		filtered := make([]model.Template, 0, len(rows))
		for _, row := range rows {
			if strings.Contains(strings.ToLower(row.Name), needle) {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	total := int64(len(rows))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	// 先做除法判界，避免超大 page 做乘法溢出成负数。
	if page-1 > len(rows)/pageSize {
		return []model.Template{}, total, nil
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	if end > len(rows) {
		end = len(rows)
	}
	return rows[start:end], total, nil
}

// Create 新建自定义模板（§5.7）：template_key 非空且列宽内、不与内置 key
// 同名；唯一键冲突转译 ErrDuplicateKey；成功后失效该 key 缓存。
func (s *TemplateService) Create(ctx context.Context, key, name, content string) error {
	if err := validateTemplateKey(key); err != nil {
		return err
	}
	now := time.Now()
	row := &model.Template{
		TemplateKey: key,
		Name:        name,
		Content:     content,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.store.Create(ctx, row); err != nil {
		if errors.Is(err, repo.ErrTemplateDuplicate) {
			return ErrDuplicateKey
		}
		return err
	}
	return s.invalidate(ctx, key)
}

// Get 按自增 id 取详情（§5.7）；id 非正属参数错误，查无此行由 List 命中
// 不到按 gorm.ErrRecordNotFound 上抛（handler 映射 not_found）。
func (s *TemplateService) Get(ctx context.Context, id int64) (*model.Template, error) {
	if id <= 0 {
		return nil, ErrInvalidRequest
	}
	row := s.findByID(ctx, id)
	if row == nil {
		return nil, gorm.ErrRecordNotFound
	}
	return row, nil
}

// Update 部分更新（§5.7）：key / name / content 三个指针缺省保留原值，
// 允许改 key；改 key 时旧、新两 key 双失效（§8.1）。唯一键冲突转译
// ErrDuplicateKey。
func (s *TemplateService) Update(ctx context.Context, id int64, key, name, content *string) error {
	if id <= 0 {
		return ErrInvalidRequest
	}
	row := s.findByID(ctx, id)
	if row == nil {
		return gorm.ErrRecordNotFound
	}
	oldKey := row.TemplateKey
	if key != nil {
		if err := validateTemplateKey(*key); err != nil {
			return err
		}
		row.TemplateKey = *key
	}
	if name != nil {
		row.Name = *name
	}
	if content != nil {
		row.Content = *content
	}
	if err := s.store.Update(ctx, row); err != nil {
		if errors.Is(err, repo.ErrTemplateDuplicate) {
			return ErrDuplicateKey
		}
		return err
	}
	if row.TemplateKey != oldKey {
		return s.invalidate(ctx, oldKey, row.TemplateKey)
	}
	return s.invalidate(ctx, row.TemplateKey)
}

// Delete 硬删（§5.7）：先取回行以拿到 template_key，删成功后失效该 key
// 缓存；查无此行按 gorm.ErrRecordNotFound 上抛。
func (s *TemplateService) Delete(ctx context.Context, id int64) error {
	if id <= 0 {
		return ErrInvalidRequest
	}
	row := s.findByID(ctx, id)
	if row == nil {
		return gorm.ErrRecordNotFound
	}
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	return s.invalidate(ctx, row.TemplateKey)
}

// Resolve 按 key 解析模板内容（§8.1）：① 缓存命中返回；② 内置模板命中返回
// 且不回填缓存；③ DB 命中回填缓存（回填失败不阻断）并返回；④ 全 miss
// → ErrInvalidRequest（调用方据此回落默认文件壳）。缓存读故障按未命中处理，
// 继续回落内置与 DB，不因缓存抖动中断渲染。
func (s *TemplateService) Resolve(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", ErrInvalidRequest
	}
	if s.cache != nil {
		if content, ok, err := s.cache.Get(ctx, key); err == nil && ok {
			return content, nil
		}
	}
	if content, ok := pages.GetBuiltinTemplate(key); ok {
		return content, nil
	}
	row, err := s.store.FindByKey(ctx, key)
	if err == nil {
		if s.cache != nil {
			if setErr := s.cache.SetRow(ctx, key, row.Content); setErr != nil {
				_ = setErr // 回填失败不阻断本次返回
			}
		}
		return row.Content, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("admin service: resolve template %q: %w", key, err)
	}
	return "", ErrInvalidRequest
}

// findByID 经 List 按主键定位；返回副本指针避免改到切片的临时元素。
func (s *TemplateService) findByID(ctx context.Context, id int64) *model.Template {
	rows, err := s.store.List(ctx)
	if err != nil {
		return nil
	}
	for i := range rows {
		if rows[i].ID == id {
			cp := rows[i]
			return &cp
		}
	}
	return nil
}

// invalidate 写路径成功后逐 key 单步 DEL（§5.1）；首个失败即上抛，避免
// 静默留下旧值达到 TTL 600s。cache 为 nil 时按无缓存处理（防御）。
func (s *TemplateService) invalidate(ctx context.Context, keys ...string) error {
	if s.cache == nil {
		return nil
	}
	for _, key := range keys {
		if err := s.cache.Invalidate(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

// validateTemplateKey 校验 template_key（§5.7 / §4.9）：非空、列宽内，
// 且不与任一内置模板 key 同名（pages 扫描全集为保留字集合）。
func validateTemplateKey(key string) error {
	if key == "" || utf8.RuneCountInString(key) > templateKeyMaxRunes {
		return ErrInvalidRequest
	}
	if pages.IsBuiltinTemplate(key) {
		return ErrInvalidRequest
	}
	return nil
}

// 编译期断言 *repo.TemplateRepo 满足 templateStore（签名漂移在编译期暴露）。
var _ templateStore = (*repo.TemplateRepo)(nil)
