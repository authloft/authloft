// template 表读写（后端架构 §4.9 / §3.13）。DDL 归 migrations/（§3.16），
// 本文件只做行级读写与文档明确的查询最小集。模板内容缓存 al:tpl:v:{key}
// （§5.1）的读写与失效归 internal/cache，由上层写路径负责，本 repo 不做
// 缓存。1062 唯一键冲突判别复用同包 isClientDuplicateKey。
package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"authloft/internal/repo/model"
)

// ErrTemplateDuplicate Create / Update 命中唯一键 uk_template_key 时的
// 可判别错误（errors.Is 可判）；冲突键与值在底层 *mysql.MySQLError 中。
var ErrTemplateDuplicate = errors.New("template repo: duplicate unique key")

// TemplateRepo template 表数据访问。
type TemplateRepo struct {
	db *bun.DB
}

// NewTemplateRepo 按 bun 连接构造。
func NewTemplateRepo(db *bun.DB) *TemplateRepo {
	return &TemplateRepo{db: db}
}

// FindByKey 按唯一键 uk_template_key 取 Template；未命中返回包装的
// sql.ErrNoRows。
func (r *TemplateRepo) FindByKey(ctx context.Context, templateKey string) (*model.Template, error) {
	var t model.Template
	if err := r.db.NewSelect().Model(&t).
		Where("template_key = ?", templateKey).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("template repo: find by key: %w", err)
	}
	return &t, nil
}

// List 全量列出自定义模板（§4.9：template 表只存自定义行）；按 id ASC
// 保证稳定顺序，不分页——分页与筛选口径归上层接口卡。
func (r *TemplateRepo) List(ctx context.Context) ([]model.Template, error) {
	var rows []model.Template
	if err := r.db.NewSelect().Model(&rows).
		OrderExpr("id ASC").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("template repo: list: %w", err)
	}
	return rows, nil
}

// Create 插入 Template；命中 uk_template_key 返回 ErrTemplateDuplicate，
// 其余错误原样包装。created_at / updated_at 零值时由本方法补齐（bun 无
// 时间列自动填充）。
func (r *TemplateRepo) Create(ctx context.Context, t *model.Template) error {
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	if t.UpdatedAt.IsZero() {
		t.UpdatedAt = now
	}
	if _, err := r.db.NewInsert().Model(t).Exec(ctx); err != nil {
		if isClientDuplicateKey(err) {
			return fmt.Errorf("template repo: create: %w: %w", ErrTemplateDuplicate, err)
		}
		return fmt.Errorf("template repo: create: %w", err)
	}
	return nil
}

// Update 按主键整行 UPDATE（全列覆盖，含零值列；允许改 template_key，旧 key
// 缓存失效由上层写路径负责）。不用 upsert 语义：行不存在静默变插入会把
// 「行不存在」错误口径吞掉。MySQL 驱动默认 changed-rows 语义：同值 UPDATE
// RowsAffected=0 与行不存在不可区分，rows=0 时补 SELECT 存在性判定（行在
// 则幂等成功，查无此行才报 sql.ErrNoRows，与 provider_repo.Update 同口径）。
// updated_at 随更新刷新（与旧 ORM struct 更新自动刷新 updated_at 同语义）。
func (r *TemplateRepo) Update(ctx context.Context, t *model.Template) error {
	res, err := r.db.NewUpdate().Model((*model.Template)(nil)).
		Where("id = ?", t.ID).
		Set("template_key = ?", t.TemplateKey).
		Set("name = ?", t.Name).
		Set("content = ?", t.Content).
		Set("created_at = ?", t.CreatedAt).
		Set("updated_at = ?", time.Now()).
		Exec(ctx)
	if err != nil {
		if isClientDuplicateKey(err) {
			return fmt.Errorf("template repo: update: %w: %w", ErrTemplateDuplicate, err)
		}
		return fmt.Errorf("template repo: update: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.Template)(nil),
		"template repo: update", "id = ?", t.ID); err != nil {
		return err
	}
	return nil
}

// Delete 按主键删除；行不存在返回包装的 sql.ErrNoRows（DELETE 的 rows=0
// 无同值歧义，直接判 not found，无需补查）。
func (r *TemplateRepo) Delete(ctx context.Context, id int64) error {
	res, err := r.db.NewDelete().Model((*model.Template)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("template repo: delete: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.Template)(nil),
		"template repo: delete", "id = ?", id); err != nil {
		return err
	}
	return nil
}
