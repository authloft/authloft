// provider 表读写（后端架构 §3.9 行 415 / §4.1）。DDL 归 migrations/
// （§3.16），本文件只做行级读写与文档明确的查询最小集；事务边界在
// service（§3.9）。ext 列的 provider.Ext proto 编解码唯一出口在本文件
// MarshalProviderExt / ParseProviderExt（消费 gen/go/provider，接口文档
// §12.1）；本地 LRU 缓存与失效发布归 internal/provider + cache（§3.9、
// 后续实现），repo 不做缓存。ext 内凭证字段的视图裁剪（前台公开接口与
// __AUTHLOFT_INIT__.methods 永不返回，仅 /api/admin/providers/** 可透出，
// 接口文档 §12.1 行 1696）归 dto / view 层——repo 拿到什么存什么，不裁
// 剪视图。
package repo

import (
	"context"
	"errors"
	"fmt"

	mysqldriver "github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
	"google.golang.org/protobuf/proto"

	"authloft/gen/go/provider"
	"authloft/internal/repo/model"
)

// ErrProviderDuplicate Create 命中唯一键 uk_provider_key（§4.1 行 607）
// 时的可判别错误；冲突键与值在底层 *mysql.MySQLError 中。
var ErrProviderDuplicate = errors.New("provider repo: duplicate unique key")

// providerExtMaxBytes ext 列业务上限 1 MiB（§4.1 行 615：物理列
// MEDIUMBLOB 容 16 MiB，业务卡 1 MiB，超限直接拒绝——admin 走统一
// bad_request）。
const providerExtMaxBytes = 1 << 20

// ProviderRepo provider 表数据访问（§3.9：表与文件对应 provider →
// provider_repo.go）。
type ProviderRepo struct {
	db *gorm.DB
}

// NewProviderRepo 按 GORM 连接构造。
func NewProviderRepo(db *gorm.DB) *ProviderRepo {
	return &ProviderRepo{db: db}
}

// FindByKey 按唯一键 uk_provider_key 取 Provider（provider_key 是唯一
// 对外契约，接口文档 §12.1）；未命中返回包装的 gorm.ErrRecordNotFound。
func (r *ProviderRepo) FindByKey(ctx context.Context, providerKey string) (*model.Provider, error) {
	var p model.Provider
	if err := r.db.WithContext(ctx).Take(&p, "provider_key = ?", providerKey).Error; err != nil {
		return nil, fmt.Errorf("provider repo: find by key: %w", err)
	}
	return &p, nil
}

// ProviderListQuery 列表入参：Category / Type / IsEnabled 为 nil 时不过滤
//（admin §5.2 ListProviders 与登录页可用 Provider 列表的筛选口径归
// service 拼装）；分页按 §1.7（page 从 1 开始、pageSize 默认 20、上限
// 100）。排序固定 sort_order ASC, id ASC（§4.1 sort_order 即列表展示
// 序），保证分页全序稳定，任意列排序归 service / handler 卡（与
// user_repo ListUsers 同约束）。
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
	filter := func() *gorm.DB {
		tx := r.db.WithContext(ctx).Model(&model.Provider{})
		if q.Category != nil {
			tx = tx.Where("category = ?", *q.Category)
		}
		if q.Type != nil {
			tx = tx.Where("type = ?", *q.Type)
		}
		if q.IsEnabled != nil {
			tx = tx.Where("is_enabled = ?", *q.IsEnabled)
		}
		return tx
	}
	var total int64
	if err := filter().Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("provider repo: list count: %w", err)
	}
	var rows []model.Provider
	err := filter().
		Order("sort_order ASC").
		Order("id ASC").
		Limit(size).
		Offset((page - 1) * size).
		Find(&rows).Error
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
//（errors.Is 可判别），其余错误原样包装。default tag 列（enable_signin
// 等）的零值被 tag 值显式写入 INSERT 并回填 struct（gorm@v1.31.2
// callbacks/create.go:340-343，与 user.go 同口径）——显式写 0 走列级
// UPDATE（Update）。
func (r *ProviderRepo) Create(ctx context.Context, p *model.Provider) error {
	err := r.db.WithContext(ctx).Create(p).Error
	if err != nil {
		if isProviderDuplicateKey(err) {
			return fmt.Errorf("provider repo: create: %w: %w", ErrProviderDuplicate, err)
		}
		return fmt.Errorf("provider repo: create: %w", err)
	}
	return nil
}

// Update 按主键整行 UPDATE（Select("*") 强制含零值列——is_enabled=0
// 等禁用零值必须可落库；调用方应传入 FindByKey 取回的完整行，全列
// 忠实覆盖含 created_at；provider_key 创建后不可改由 service 保证，
// repo 不做二次校验，改键需求属上游契约违背）。不用 Save：其
// RowsAffected==0 时自动回落 Create 的 upsert 语义会把「行不存在」
// 静默变成插入（gorm@v1.31.2 FinisherMethod Save 分支）。MySQL 驱动
// 默认 changed-rows 语义：同值 UPDATE RowsAffected=0 与行不存在不可
// 区分，故 rows=0 时补 SELECT 存在性判定——行仍在则视为幂等成功，
// 查无此行才报 ErrRecordNotFound（与 user_repo.UpdateLastLogin 同款口径）。
func (r *ProviderRepo) Update(ctx context.Context, p *model.Provider) error {
	res := r.db.WithContext(ctx).
		Model(&model.Provider{}).
		Select("*").
		Where("id = ?", p.ID).
		Updates(p)
	if res.Error != nil {
		return fmt.Errorf("provider repo: update: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		var exists int64
		if err := r.db.WithContext(ctx).
			Model(&model.Provider{}).
			Select("COUNT(*)").
			Where("id = ?", p.ID).
			Scan(&exists).Error; err != nil {
			return fmt.Errorf("provider repo: update: %w", err)
		}
		if exists == 0 {
			return fmt.Errorf("provider repo: update: %w", gorm.ErrRecordNotFound)
		}
	}
	return nil
}

// ProviderSortUpdate SortProviders 的单行排序更新（provider_key 定位 +
// 目标 sort_order；admin §5.2 行 1174 拖拽排序）。
type ProviderSortUpdate struct {
	ProviderKey string
	SortOrder   int32
}

// SetEnabled 按主键列级最小 UPDATE is_enabled（列级收编
// repo，service 不自写 SQL；default tag 只影响 Create，禁用零值必须走列级
// UPDATE 才可落库，见 Create 注释）。changed-rows 语义下同值 UPDATE
// RowsAffected=0 与行不存在不可区分，rows=0 时补 SELECT 存在性判定
//（行在则幂等成功，查无此行才报 ErrRecordNotFound，与 Update 同口径）。
func (r *ProviderRepo) SetEnabled(ctx context.Context, id int64, enabled int8) error {
	res := r.db.WithContext(ctx).
		Model(&model.Provider{}).
		Where("id = ?", id).
		Update("is_enabled", enabled)
	if res.Error != nil {
		return fmt.Errorf("provider repo: set enabled: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return r.ensureProviderExists(ctx, id, "set enabled")
	}
	return nil
}

// UpdateSortOrders 批量列级最小 UPDATE sort_order（admin §5.2 行 1174：
// {items:[{providerKey, sortOrder}]} 拖拽排序）：事务内逐行按 provider_key
// 更新，任一行失败全批回滚（批量语义要么全成、要么全败）。rows=0 同
// changed-rows 歧义：补查存在性——行在则同值幂等，查无此行（provider_key
// 不存在）报 ErrRecordNotFound，调用方映射 404。
func (r *ProviderRepo) UpdateSortOrders(ctx context.Context, updates []ProviderSortUpdate) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, u := range updates {
			res := tx.Model(&model.Provider{}).
				Where("provider_key = ?", u.ProviderKey).
				Update("sort_order", u.SortOrder)
			if res.Error != nil {
				return fmt.Errorf("provider repo: update sort orders: %w", res.Error)
			}
			if res.RowsAffected == 0 {
				var exists int64
				if err := tx.Model(&model.Provider{}).
					Select("COUNT(*)").
					Where("provider_key = ?", u.ProviderKey).
					Scan(&exists).Error; err != nil {
					return fmt.Errorf("provider repo: update sort orders: %w", err)
				}
				if exists == 0 {
					return fmt.Errorf("provider repo: update sort orders: key %q: %w", u.ProviderKey, gorm.ErrRecordNotFound)
				}
			}
		}
		return nil
	})
}

// ensureProviderExists 列级 UPDATE rows=0 时的存在性补查（changed-rows 语义，
// 与 Update 的补查同口径）。
func (r *ProviderRepo) ensureProviderExists(ctx context.Context, id int64, op string) error {
	var exists int64
	if err := r.db.WithContext(ctx).
		Model(&model.Provider{}).
		Select("COUNT(*)").
		Where("id = ?", id).
		Scan(&exists).Error; err != nil {
		return fmt.Errorf("provider repo: %s: %w", op, err)
	}
	if exists == 0 {
		return fmt.Errorf("provider repo: %s: %w", op, gorm.ErrRecordNotFound)
	}
	return nil
}

// Delete 按主键删除；行不存在返回包装的 gorm.ErrRecordNotFound
//（DELETE 的 rows=0 无同值歧义，直接判 not found，无需补查）。
func (r *ProviderRepo) Delete(ctx context.Context, id int64) error {
	res := r.db.WithContext(ctx).
		Where("id = ?", id).
		Delete(&model.Provider{})
	if res.Error != nil {
		return fmt.Errorf("provider repo: delete: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("provider repo: delete: %w", gorm.ErrRecordNotFound)
	}
	return nil
}

// MarshalProviderExt 将 provider.Ext 序列化为 ext 列字节（接口文档
// §12.1：结构固定走 Protobuf），并做 1 MiB 业务上限校验（§4.1 行 615，
// 超限直接拒绝）——校验放在唯一序列化出口，Create / Update 只透传字节
// 不再重复校验。nil 输入返回 nil（ext 列 NULL）。
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

// ParseProviderExt 将 ext 列字节反序列化为 provider.Ext。空 / NULL 列
// 返回空消息（非 nil），调用方无需判空。
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

// isProviderDuplicateKey 判 MySQL/MariaDB 1062（duplicate entry）唯一键冲突。
func isProviderDuplicateKey(err error) bool {
	var me *mysqldriver.MySQLError
	return errors.As(err, &me) && me.Number == 1062
}
