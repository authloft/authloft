// template 表读写（后端架构 §4.9 / §3.13）。DDL 归 migrations/（§3.16），
// 本文件只做行级读写与文档明确的查询最小集。模板内容缓存 al:tpl:v:{key}
// （§5.1）的读写与失效归 internal/cache，由上层写路径负责，本 repo 不做
// 缓存。1062 唯一键冲突判别复用同包 isClientDuplicateKey。
package repo

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"authloft/internal/repo/model"
)

// ErrTemplateDuplicate Create / Update 命中唯一键 uk_template_key 时的
// 可判别错误（errors.Is 可判）；冲突键与值在底层 *mysql.MySQLError 中。
var ErrTemplateDuplicate = errors.New("template repo: duplicate unique key")

// TemplateRepo template 表数据访问。
type TemplateRepo struct {
	db *gorm.DB
}

// NewTemplateRepo 按 GORM 连接构造。
func NewTemplateRepo(db *gorm.DB) *TemplateRepo {
	return &TemplateRepo{db: db}
}

// FindByKey 按唯一键 uk_template_key 取 Template；未命中返回包装的
// gorm.ErrRecordNotFound。
func (r *TemplateRepo) FindByKey(ctx context.Context, templateKey string) (*model.Template, error) {
	var t model.Template
	if err := r.db.WithContext(ctx).Take(&t, "template_key = ?", templateKey).Error; err != nil {
		return nil, fmt.Errorf("template repo: find by key: %w", err)
	}
	return &t, nil
}

// List 全量列出自定义模板（§4.9：template 表只存自定义行）；按 id ASC
// 保证稳定顺序，不分页——分页与筛选口径归上层接口卡。
func (r *TemplateRepo) List(ctx context.Context) ([]model.Template, error) {
	var rows []model.Template
	if err := r.db.WithContext(ctx).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("template repo: list: %w", err)
	}
	return rows, nil
}

// Create 插入 Template；命中 uk_template_key 返回 ErrTemplateDuplicate，
// 其余错误原样包装。
func (r *TemplateRepo) Create(ctx context.Context, t *model.Template) error {
	err := r.db.WithContext(ctx).Create(t).Error
	if err != nil {
		if isClientDuplicateKey(err) {
			return fmt.Errorf("template repo: create: %w: %w", ErrTemplateDuplicate, err)
		}
		return fmt.Errorf("template repo: create: %w", err)
	}
	return nil
}

// Update 按主键整行 UPDATE（Select("*") 强制含零值列；允许改 template_key，
// 旧 key 缓存失效由上层写路径负责）。不用 Save：其 RowsAffected==0 时
// 自动回落 Create 的 upsert 语义会把「行不存在」静默变成插入。MySQL 驱动
// 默认 changed-rows 语义：同值 UPDATE RowsAffected=0 与行不存在不可区分，
// rows=0 时补 SELECT 存在性判定（行在则幂等成功，查无此行才报
// ErrRecordNotFound，与 provider_repo.Update 同口径）。
func (r *TemplateRepo) Update(ctx context.Context, t *model.Template) error {
	res := r.db.WithContext(ctx).
		Model(&model.Template{}).
		Select("*").
		Where("id = ?", t.ID).
		Updates(t)
	if res.Error != nil {
		if isClientDuplicateKey(res.Error) {
			return fmt.Errorf("template repo: update: %w: %w", ErrTemplateDuplicate, res.Error)
		}
		return fmt.Errorf("template repo: update: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		var exists int64
		if err := r.db.WithContext(ctx).
			Model(&model.Template{}).
			Select("COUNT(*)").
			Where("id = ?", t.ID).
			Scan(&exists).Error; err != nil {
			return fmt.Errorf("template repo: update: %w", err)
		}
		if exists == 0 {
			return fmt.Errorf("template repo: update: %w", gorm.ErrRecordNotFound)
		}
	}
	return nil
}

// Delete 按主键删除；行不存在返回包装的 gorm.ErrRecordNotFound
// （DELETE 的 rows=0 无同值歧义，直接判 not found，无需补查）。
func (r *TemplateRepo) Delete(ctx context.Context, id int64) error {
	res := r.db.WithContext(ctx).
		Where("id = ?", id).
		Delete(&model.Template{})
	if res.Error != nil {
		return fmt.Errorf("template repo: delete: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("template repo: delete: %w", gorm.ErrRecordNotFound)
	}
	return nil
}
