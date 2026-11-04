// sso_client / oidc_client 表读写（后端架构 §3.10 行 415：client →
// client_repo.go；§4.4 行 713-724 / §4.5 行 729-742 DDL）。DDL 归
// migrations/（§3.16），本文件只做行级读写、分页与唯一键冲突判别；事务
// 边界在 service（§3.10）。redirect_uris 列的 client.RedirectUris proto
// 编解码唯一出口在本文件 MarshalClientRedirectUris /
// ParseClientRedirectUris（接口文档 §12.3 行 1723-1730），service 不直接
// 拼 proto.Marshal。client_secret 生成策略、scopes[] ↔ 逗号串转换、
// redirect_uris 通配匹配规则均归上层，repo 拿到什么存什么。
package repo

import (
	"context"
	"errors"
	"fmt"

	mysqldriver "github.com/go-sql-driver/mysql"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	"authloft/gen/go/client"
	"authloft/internal/repo/model"
)

// ErrClientDuplicate Create / Update 命中唯一键 uk_client_id（§4.4 行 722、
// §4.5 行 741）时的可判别错误；具体冲突键与值在底层 *mysql.MySQLError 中。
var ErrClientDuplicate = errors.New("client repo: duplicate unique key")

// ClientRepo sso_client / oidc_client 表数据访问（§3.10：表与文件对应
// client(sso_client + oidc_client) → client_repo.go）。
type ClientRepo struct {
	db *gorm.DB
}

// NewClientRepo 按 GORM 连接构造。
func NewClientRepo(db *gorm.DB) *ClientRepo {
	return &ClientRepo{db: db}
}

// FindSsoClientByClientID 按唯一键 uk_client_id 取 SSO 客户端；未命中
// 返回包装的 gorm.ErrRecordNotFound。
func (r *ClientRepo) FindSsoClientByClientID(ctx context.Context, clientID string) (*model.SsoClient, error) {
	var c model.SsoClient
	if err := r.db.WithContext(ctx).Take(&c, "client_id = ?", clientID).Error; err != nil {
		return nil, fmt.Errorf("client repo: find sso client by client id: %w", err)
	}
	return &c, nil
}

// FindOidcClientByClientID 按唯一键 uk_client_id 取 OIDC 客户端；未命中
// 返回包装的 gorm.ErrRecordNotFound。
func (r *ClientRepo) FindOidcClientByClientID(ctx context.Context, clientID string) (*model.OidcClient, error) {
	var c model.OidcClient
	if err := r.db.WithContext(ctx).Take(&c, "client_id = ?", clientID).Error; err != nil {
		return nil, fmt.Errorf("client repo: find oidc client by client id: %w", err)
	}
	return &c, nil
}

// ClientListQuery 客户端列表分页入参；分页按 §1.7（page 从 1 开始、
// pageSize 默认 20、上限 100）。文档未定义客户端列表筛选与排序字段，
// repo 固定 ORDER BY id ASC（创建序）保证分页全序稳定。
type ClientListQuery struct {
	Page     int
	PageSize int
}

// normalize 分页参数归一（§1.7：page 1 起、pageSize 默认 20 上限 100）。
func (q ClientListQuery) normalize() (page, size int) {
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

// ListSsoClients 分页列表：返回当页行与总数（§1.7 响应
// {items, total, page, pageSize} 的数据来源）。
func (r *ClientRepo) ListSsoClients(ctx context.Context, q ClientListQuery) ([]model.SsoClient, int64, error) {
	page, size := q.normalize()
	var total int64
	if err := r.db.WithContext(ctx).Model(&model.SsoClient{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("client repo: list sso clients count: %w", err)
	}
	var rows []model.SsoClient
	err := r.db.WithContext(ctx).
		Order("id ASC").
		Limit(size).
		Offset((page - 1) * size).
		Find(&rows).Error
	if err != nil {
		return nil, 0, fmt.Errorf("client repo: list sso clients: %w", err)
	}
	return rows, total, nil
}

// ListOidcClients 分页列表：返回当页行与总数（§1.7 响应
// {items, total, page, pageSize} 的数据来源）。
func (r *ClientRepo) ListOidcClients(ctx context.Context, q ClientListQuery) ([]model.OidcClient, int64, error) {
	page, size := q.normalize()
	var total int64
	if err := r.db.WithContext(ctx).Model(&model.OidcClient{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("client repo: list oidc clients count: %w", err)
	}
	var rows []model.OidcClient
	err := r.db.WithContext(ctx).
		Order("id ASC").
		Limit(size).
		Offset((page - 1) * size).
		Find(&rows).Error
	if err != nil {
		return nil, 0, fmt.Errorf("client repo: list oidc clients: %w", err)
	}
	return rows, total, nil
}

// CreateSsoClient 插入 SSO 客户端；命中 uk_client_id 返回
// ErrClientDuplicate（errors.Is 可判别），其余错误原样包装。default tag
// 列（is_enabled）的零值被 tag 值显式写入 INSERT 并回填 struct（口径同
// provider_repo.Create）——显式写 0 走列级 UPDATE。
func (r *ClientRepo) CreateSsoClient(ctx context.Context, c *model.SsoClient) error {
	if err := r.db.WithContext(ctx).Create(c).Error; err != nil {
		if isClientDuplicateKey(err) {
			return fmt.Errorf("client repo: create sso client: %w: %w", ErrClientDuplicate, err)
		}
		return fmt.Errorf("client repo: create sso client: %w", err)
	}
	return nil
}

// CreateOidcClient 插入 OIDC 客户端；命中 uk_client_id 返回
// ErrClientDuplicate（errors.Is 可判别），其余错误原样包装。default tag
// 列（scopes / access_token_ttl / refresh_token_ttl / is_enabled）的零值
// 被 tag 值显式写入 INSERT 并回填 struct（口径同 provider_repo.Create）。
func (r *ClientRepo) CreateOidcClient(ctx context.Context, c *model.OidcClient) error {
	if err := r.db.WithContext(ctx).Create(c).Error; err != nil {
		if isClientDuplicateKey(err) {
			return fmt.Errorf("client repo: create oidc client: %w: %w", ErrClientDuplicate, err)
		}
		return fmt.Errorf("client repo: create oidc client: %w", err)
	}
	return nil
}

// UpdateSsoClient 按主键整行 UPDATE（Select("*") 强制含零值列——
// is_enabled=0 等禁用零值必须可落库；调用方应传入 FindSsoClientByClientID
// 取回的完整行，全列忠实覆盖含 created_at；client_id 创建后不可改由
// service 保证）。若改了 client_id 命中 uk_client_id，返回
// ErrClientDuplicate。不用 Save：其 RowsAffected==0 时自动回落 Create 的
// upsert 语义（gorm@v1.31.2 FinisherMethod Save 分支）。MySQL 驱动默认
// changed-rows 语义：同值 UPDATE RowsAffected=0 与行不存在不可区分，故
// rows=0 时补 SELECT 存在性判定——行仍在则视为幂等成功，查无此行才报
// ErrRecordNotFound（口径同 provider_repo.Update）。
func (r *ClientRepo) UpdateSsoClient(ctx context.Context, c *model.SsoClient) error {
	res := r.db.WithContext(ctx).
		Model(&model.SsoClient{}).
		Select("*").
		Where("id = ?", c.ID).
		Updates(c)
	if res.Error != nil {
		if isClientDuplicateKey(res.Error) {
			return fmt.Errorf("client repo: update sso client: %w: %w", ErrClientDuplicate, res.Error)
		}
		return fmt.Errorf("client repo: update sso client: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		var exists int64
		if err := r.db.WithContext(ctx).
			Model(&model.SsoClient{}).
			Select("COUNT(*)").
			Where("id = ?", c.ID).
			Scan(&exists).Error; err != nil {
			return fmt.Errorf("client repo: update sso client: %w", err)
		}
		if exists == 0 {
			return fmt.Errorf("client repo: update sso client: %w", gorm.ErrRecordNotFound)
		}
	}
	return nil
}

// UpdateOidcClient 按主键整行 UPDATE，口径同 UpdateSsoClient（整行覆盖、
// 零值可落库、同值幂等、client_id 冲突返回 ErrClientDuplicate）。
func (r *ClientRepo) UpdateOidcClient(ctx context.Context, c *model.OidcClient) error {
	res := r.db.WithContext(ctx).
		Model(&model.OidcClient{}).
		Select("*").
		Where("id = ?", c.ID).
		Updates(c)
	if res.Error != nil {
		if isClientDuplicateKey(res.Error) {
			return fmt.Errorf("client repo: update oidc client: %w: %w", ErrClientDuplicate, res.Error)
		}
		return fmt.Errorf("client repo: update oidc client: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		var exists int64
		if err := r.db.WithContext(ctx).
			Model(&model.OidcClient{}).
			Select("COUNT(*)").
			Where("id = ?", c.ID).
			Scan(&exists).Error; err != nil {
			return fmt.Errorf("client repo: update oidc client: %w", err)
		}
		if exists == 0 {
			return fmt.Errorf("client repo: update oidc client: %w", gorm.ErrRecordNotFound)
		}
	}
	return nil
}

// DeleteSsoClient 按主键删除；行不存在返回包装的 gorm.ErrRecordNotFound
// （DELETE 的 rows=0 无同值歧义，直接判 not found）。
func (r *ClientRepo) DeleteSsoClient(ctx context.Context, id int64) error {
	res := r.db.WithContext(ctx).
		Where("id = ?", id).
		Delete(&model.SsoClient{})
	if res.Error != nil {
		return fmt.Errorf("client repo: delete sso client: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("client repo: delete sso client: %w", gorm.ErrRecordNotFound)
	}
	return nil
}

// DeleteOidcClient 按主键删除；行不存在返回包装的 gorm.ErrRecordNotFound。
func (r *ClientRepo) DeleteOidcClient(ctx context.Context, id int64) error {
	res := r.db.WithContext(ctx).
		Where("id = ?", id).
		Delete(&model.OidcClient{})
	if res.Error != nil {
		return fmt.Errorf("client repo: delete oidc client: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("client repo: delete oidc client: %w", gorm.ErrRecordNotFound)
	}
	return nil
}

// MarshalClientRedirectUris 将 client.RedirectUris（接口文档 §12.3 行
// 1723-1730）序列化为 redirect_uris 列字节（§12.0 行 1627：结构固定走
// Protobuf）。nil 输入按空消息编码，返回非 nil 的零长字节——列定义为
// VARBINARY NOT NULL（§4.4 行 718 / §4.5 行 734），返回 nil 会被 GORM 写成
// NULL 触发 MySQL 1048。protocol 编码错误原样包装。校验（通配符合法性、
// 条目上限）归 service，repo 只做唯一编解码出口。
func MarshalClientRedirectUris(uris *client.ClientRedirectUris) ([]byte, error) {
	if uris == nil {
		uris = &client.ClientRedirectUris{}
	}
	data, err := proto.Marshal(uris)
	if err != nil {
		return nil, fmt.Errorf("client repo: marshal redirect uris: %w", err)
	}
	if data == nil {
		data = []byte{}
	}
	return data, nil
}

// ParseClientRedirectUris 将 redirect_uris 列字节反序列化为
// client.RedirectUris。空 / NULL 列返回空消息（非 nil），调用方无需判空；
// 解码错误原样包装。与 MarshalClientRedirectUris 互为逆运算。
func ParseClientRedirectUris(data []byte) (*client.ClientRedirectUris, error) {
	uris := &client.ClientRedirectUris{}
	if len(data) == 0 {
		return uris, nil
	}
	if err := proto.Unmarshal(data, uris); err != nil {
		return nil, fmt.Errorf("client repo: parse redirect uris: %w", err)
	}
	return uris, nil
}

// isClientDuplicateKey 判 MySQL/MariaDB 1062（duplicate entry）唯一键冲突。
func isClientDuplicateKey(err error) bool {
	var me *mysqldriver.MySQLError
	return errors.As(err, &me) && me.Number == 1062
}
