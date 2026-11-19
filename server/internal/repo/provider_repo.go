// provider 表读写（后端架构 §3.9 / §4.1）。DDL 归 migrations/（§3.16），
// 本文件只做行级读写与文档明确的查询最小集；事务边界在 service（§3.9）。
// ext 列的 provider.Ext proto 编解码唯一出口在本文件 MarshalProviderExt /
// ParseProviderExt（消费 gen/go/provider，接口文档 §12.1）；本地 LRU 缓存与
// 失效发布归 internal/provider + cache（§3.9、后续实现），repo 不做缓存。
// ext 内凭证字段的视图裁剪（前台公开接口与 __AUTHLOFT_INIT__.methods 永不
// 返回，仅 /api/admin/providers/** 可透出，接口文档 §12.1）归 dto / view 层
// ——repo 拿到什么存什么，不裁剪视图。
package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"
	"google.golang.org/protobuf/proto"

	"authloft/gen/go/provider"
	"authloft/internal/repo/model"
)

// ErrProviderDuplicate Create 命中唯一键 uk_provider_key（§4.1）时的可判别
// 错误；冲突键与值在底层 *mysql.MySQLError 中。
var ErrProviderDuplicate = errors.New("provider repo: duplicate unique key")

// providerExtMaxBytes ext 列业务上限 1 MiB（§4.1：物理列 MEDIUMBLOB 容
// 16 MiB，业务卡 1 MiB，超限直接拒绝——admin 走统一 bad_request）。
const providerExtMaxBytes = 1 << 20

// ProviderRepo provider 表数据访问（§3.9：表与文件对应 provider →
// provider_repo.go）。
type ProviderRepo struct {
	db *bun.DB
}

// NewProviderRepo 按 bun 连接构造。
func NewProviderRepo(db *bun.DB) *ProviderRepo {
	return &ProviderRepo{db: db}
}

// FindByKey 按唯一键 uk_provider_key 取 Provider（provider_key 是唯一对外
// 契约，接口文档 §12.1）；未命中返回包装的 sql.ErrNoRows。
func (r *ProviderRepo) FindByKey(ctx context.Context, providerKey string) (*model.Provider, error) {
	var p model.Provider
	if err := r.db.NewSelect().Model(&p).
		Where("provider_key = ?", providerKey).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("provider repo: find by key: %w", err)
	}
	return &p, nil
}

// ProviderListQuery 列表入参：Category / Type / IsEnabled 为 nil 时不过滤
// （admin §5.2 ListProviders 与登录页可用 Provider 列表的筛选口径归 service
// 拼装）；分页按 §1.7（page 从 1 开始、pageSize 默认 20、上限 100）。排序
// 固定 sort_order ASC, id ASC（§4.1 sort_order 即列表展示序），保证分页全序
// 稳定，任意列排序归 service / handler 卡（与 user_repo ListUsers 同约束）。
type ProviderListQuery struct {
	Category  *string
	Type      *string
	IsEnabled *int8
	Page      int
	PageSize  int
}

// ListProviders 分页列表：返回当页行与过滤后总数（§1.7 响应
// {items, total, page, pageSize} 的数据来源）。
func (r *ProviderRepo) ListProviders(ctx context.Context, q ProviderListQuery) ([]model.Provider, int64, error) {
	page, size := q.normalize()
	filter := func() *bun.SelectQuery {
		sq := r.db.NewSelect().Model((*model.Provider)(nil))
		if q.Category != nil {
			sq = sq.Where("category = ?", *q.Category)
		}
		if q.Type != nil {
			sq = sq.Where("type = ?", *q.Type)
		}
		if q.IsEnabled != nil {
			sq = sq.Where("is_enabled = ?", *q.IsEnabled)
		}
		return sq
	}
	total, err := filter().Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("provider repo: list count: %w", err)
	}
	var rows []model.Provider
	err = filter().
		OrderExpr("sort_order ASC").
		OrderExpr("id ASC").
		Limit(int64(size)).
		Offset(int64((page-1)*size)).
		Scan(ctx, &rows)
	if err != nil {
		return nil, 0, fmt.Errorf("provider repo: list: %w", err)
	}
	return rows, total, nil
}

// normalize 分页参数归一（§1.7：page 1 起、pageSize 默认 20 上限 100）。
func (q ProviderListQuery) normalize() (page, size int) {
	page, size = q.Page, q.PageSize
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return page, size
}

// Create 插入 Provider；命中 uk_provider_key 返回 ErrProviderDuplicate
// （errors.Is 可判别），其余错误原样包装。default tag 列（enable_signin 等）
// 零值经 DEFAULT 占位由 DB 默认值填充（与 user.go 同口径，CODE_GUIDE
// §3.5）——显式写 0 走列级 UPDATE。created_at / updated_at 零值时由本方法
// 补齐（bun 无时间列自动填充）。
func (r *ProviderRepo) Create(ctx context.Context, p *model.Provider) error {
	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = now
	}
	if _, err := r.db.NewInsert().Model(p).Exec(ctx); err != nil {
		if isProviderDuplicateKey(err) {
			return fmt.Errorf("provider repo: create: %w: %w", ErrProviderDuplicate, err)
		}
		return fmt.Errorf("provider repo: create: %w", err)
	}
	return nil
}

// Update 按主键整行 UPDATE（全列覆盖，含零值列——is_enabled=0 等禁用零值
// 必须可落库；调用方应传入 FindByKey 取回的完整行，全列忠实覆盖含
// created_at；provider_key 创建后不可改由 service 保证，repo 不做二次校验，
// 改键需求属上游契约违背）。不用 upsert 语义：行不存在静默变插入会把
// 「行不存在」错误口径吞掉。MySQL 驱动默认 changed-rows 语义：同值 UPDATE
// RowsAffected=0 与行不存在不可区分，故 rows=0 时补 SELECT 存在性判定——
// 行仍在则视为幂等成功，查无此行才报 sql.ErrNoRows（与
// user_repo.UpdateLastLogin 同款口径）。updated_at 随更新刷新（与旧
// ORM struct 更新自动刷新 updated_at 同语义）。
func (r *ProviderRepo) Update(ctx context.Context, p *model.Provider) error {
	res, err := r.db.NewUpdate().Model((*model.Provider)(nil)).
		Where("id = ?", p.ID).
		Set("provider_key = ?", p.ProviderKey).
		Set("union_provider = ?", p.UnionProvider).
		Set("display_name = ?", p.DisplayName).
		Set("category = ?", p.Category).
		Set("type = ?", p.Type).
		Set("enable_signin = ?", p.EnableSignin).
		Set("enable_signup = ?", p.EnableSignup).
		Set("auto_bind = ?", p.AutoBind).
		Set("auto_bind_fields = ?", p.AutoBindFields).
		Set("is_enabled = ?", p.IsEnabled).
		Set("ui_group = ?", p.UiGroup).
		Set("sort_order = ?", p.SortOrder).
		Set("icon_url = ?", p.IconURL).
		Set("ext = ?", p.Ext).
		Set("remark = ?", p.Remark).
		Set("created_at = ?", p.CreatedAt).
		Set("updated_at = ?", time.Now()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("provider repo: update: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.Provider)(nil),
		"provider repo: update", "id = ?", p.ID); err != nil {
		return err
	}
	return nil
}

// ProviderSortUpdate SortProviders 的单行排序更新（provider_key 定位 +
// 目标 sort_order；admin §5.2 拖拽排序）。
type ProviderSortUpdate struct {
	ProviderKey string
	SortOrder   int32
}

// SetEnabled 按主键列级最小 UPDATE is_enabled（列级收编 repo，service 不自
// 写 SQL；default tag 只影响 Create，禁用零值必须走列级 UPDATE 才可落库，
// 见 Create 注释），updated_at 一并刷新（与旧 ORM Update 自动刷新同语义）。
// changed-rows 语义下同值 UPDATE RowsAffected=0 与行不存在不可区分，rows=0
// 时补 SELECT 存在性判定（行在则幂等成功，查无此行才报 sql.ErrNoRows，与
// Update 同口径）。
func (r *ProviderRepo) SetEnabled(ctx context.Context, id int64, enabled int8) error {
	res, err := r.db.NewUpdate().Model((*model.Provider)(nil)).
		Where("id = ?", id).
		Set("is_enabled = ?", enabled).
		Set("updated_at = ?", time.Now()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("provider repo: set enabled: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.Provider)(nil),
		"provider repo: set enabled", "id = ?", id); err != nil {
		return err
	}
	return nil
}

// UpdateSortOrders 批量列级最小 UPDATE sort_order（admin §5.2：
// {items:[{providerKey, sortOrder}]} 拖拽排序）：事务内逐行按 provider_key
// 更新，任一行失败全批回滚（批量语义要么全成、要么全败）。updated_at 随
// 行刷新。rows=0 同 changed-rows 歧义：补查存在性——行在则同值幂等，查无
// 此行（provider_key 不存在）报 sql.ErrNoRows，调用方映射 404。
func (r *ProviderRepo) UpdateSortOrders(ctx context.Context, updates []ProviderSortUpdate) error {
	return r.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for _, u := range updates {
			res, err := tx.NewUpdate().Model((*model.Provider)(nil)).
				Where("provider_key = ?", u.ProviderKey).
				Set("sort_order = ?", u.SortOrder).
				Set("updated_at = ?", time.Now()).
				Exec(ctx)
			if err != nil {
				return fmt.Errorf("provider repo: update sort orders: %w", err)
			}
			if err := requireChangedRow(ctx, tx, res, (*model.Provider)(nil),
				fmt.Sprintf("provider repo: update sort orders: key %q", u.ProviderKey),
				"provider_key = ?", u.ProviderKey); err != nil {
				return err
			}
		}
		return nil
	})
}

// Delete 按主键删除；行不存在返回包装的 sql.ErrNoRows（DELETE 的 rows=0
// 无同值歧义，直接判 not found，无需补查）。
func (r *ProviderRepo) Delete(ctx context.Context, id int64) error {
	res, err := r.db.NewDelete().Model((*model.Provider)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("provider repo: delete: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.Provider)(nil),
		"provider repo: delete", "id = ?", id); err != nil {
		return err
	}
	return nil
}

// MarshalProviderExt 将 provider.Ext 序列化为 ext 列字节（接口文档 §12.1：
// 结构固定走 Protobuf），并做 1 MiB 业务上限校验（§4.1，超限直接拒绝）——
// 校验放在唯一序列化出口，Create / Update 只透传字节不再重复校验。nil 输入
// 返回 nil（ext 列 NULL）。
func MarshalProviderExt(ext *provider.Ext) ([]byte, error) {
	if ext == nil {
		return nil, nil
	}
	data, err := proto.Marshal(ext)
	if err != nil {
		return nil, fmt.Errorf("provider repo: marshal ext: %w", err)
	}
	if len(data) > providerExtMaxBytes {
		return nil, fmt.Errorf("provider repo: marshal ext: %d bytes exceeds 1 MiB limit (§4.1)", len(data))
	}
	return data, nil
}

// ParseProviderExt 将 ext 列字节反序列化为 provider.Ext。空 / NULL 列返回
// 空消息（非 nil），调用方无需判空。
func ParseProviderExt(data []byte) (*provider.Ext, error) {
	ext := &provider.Ext{}
	if len(data) == 0 {
		return ext, nil
	}
	if err := proto.Unmarshal(data, ext); err != nil {
		return nil, fmt.Errorf("provider repo: parse ext: %w", err)
	}
	return ext, nil
}

// isProviderDuplicateKey 判唯一键冲突（MariaDB 1062 / PG 23505），判定归
// 同包语义化 helper IsDuplicateKey，命中后归一为 ErrProviderDuplicate。
func isProviderDuplicateKey(err error) bool {
	return IsDuplicateKey(err)
}
