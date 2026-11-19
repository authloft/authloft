// sso_client / oidc_client 表读写（后端架构 §3.10：client →
// client_repo.go；§4.4 / §4.5 DDL）。DDL 归 migrations/（§3.16），本文件只
// 做行级读写、分页与唯一键冲突判别；事务边界在 service（§3.10）。
// redirect_uris / login_methods / oauth_providers 列的结构化 proto 编解码
// 唯一出口在本文件（接口文档 §12.3），service 不直接拼 proto.Marshal。
// client_secret 生成策略、scopes[] ↔ 逗号串转换、redirect_uris 通配匹配
// 规则均归上层，repo 拿到什么存什么。
package repo

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"google.golang.org/protobuf/proto"

	"authloft/gen/go/client"
	"authloft/internal/repo/model"
)

// ErrClientDuplicate Create / Update 命中唯一键 uk_client_id（§4.4、§4.5）
// 时的可判别错误；具体冲突键与值在底层 *mysql.MySQLError 中。
var ErrClientDuplicate = errors.New("client repo: duplicate unique key")

// ClientRepo sso_client / oidc_client 表数据访问（§3.10：表与文件对应
// client(sso_client + oidc_client) → client_repo.go）。
type ClientRepo struct {
	db *bun.DB
}

// NewClientRepo 按 bun 连接构造。
func NewClientRepo(db *bun.DB) *ClientRepo {
	return &ClientRepo{db: db}
}

// FindSsoClientByClientID 按唯一键 uk_client_id 取 SSO 客户端；未命中
// 返回包装的 sql.ErrNoRows。
func (r *ClientRepo) FindSsoClientByClientID(ctx context.Context, clientID string) (*model.SsoClient, error) {
	var c model.SsoClient
	if err := r.db.NewSelect().Model(&c).
		Where("client_id = ?", clientID).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("client repo: find sso client by client id: %w", err)
	}
	return &c, nil
}

// FindOidcClientByClientID 按唯一键 uk_client_id 取 OIDC 客户端；未命中
// 返回包装的 sql.ErrNoRows。
func (r *ClientRepo) FindOidcClientByClientID(ctx context.Context, clientID string) (*model.OidcClient, error) {
	var c model.OidcClient
	if err := r.db.NewSelect().Model(&c).
		Where("client_id = ?", clientID).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("client repo: find oidc client by client id: %w", err)
	}
	return &c, nil
}

// FindSsoClientByID 按主键 id 取 SSO 客户端；未命中返回包装的
// sql.ErrNoRows（GetSsoClient / UpdateSsoClient 按 §5.5 的 int64 id 定位，
// Find 操作的主键形态，口径同 UserRepo.FindByID）。
func (r *ClientRepo) FindSsoClientByID(ctx context.Context, id int64) (*model.SsoClient, error) {
	var c model.SsoClient
	if err := r.db.NewSelect().Model(&c).
		Where("id = ?", id).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("client repo: find sso client by id: %w", err)
	}
	return &c, nil
}

// FindOidcClientByID 按主键 id 取 OIDC 客户端；未命中返回包装的
// sql.ErrNoRows（口径同 FindSsoClientByID）。
func (r *ClientRepo) FindOidcClientByID(ctx context.Context, id int64) (*model.OidcClient, error) {
	var c model.OidcClient
	if err := r.db.NewSelect().Model(&c).
		Where("id = ?", id).
		Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("client repo: find oidc client by id: %w", err)
	}
	return &c, nil
}

// ClientListQuery 客户端列表分页入参；分页按 §1.7（page 从 1 开始、
// pageSize 默认 20、上限 100）。Sort / Order 取值由前端限定（§1.7 后端不做
// 白名单强制校验）——repo 只做字符集防注入（非 [a-z0-9_] 列名静默回落 id，
// order 非 asc 一律 desc），不拒绝请求；口径同 user_repo.UserListQuery。
type ClientListQuery struct {
	Sort     string
	Order    string
	Page     int
	PageSize int
}

// clientSortColumnPattern 排序列名字符集（小写字母 / 数字 / 下划线——
// sso_client / oidc_client 表列名均在该集合内；字符集校验是防 ORDER BY
// 注入的格式约束，不是取值白名单：§1.7 后端不做白名单强制校验）。
var clientSortColumnPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// clientDefaultSortColumn 默认排序列（缺省 / 非法 sort 的回落值）。
const clientDefaultSortColumn = "id"

// orderClause 排序子句：sort 缺省 / 字符集外回落 id，order 仅 asc / desc
// （大小写不敏感，其余含缺省一律 desc）；非 id 主序恒追加 id 次序保证分页
// 全序稳定（同值行跨页不漂移，口径同 user_repo.orderClause /
// webauthn_repo.ListByUser）。列名经 bun.Ident 随方言引用（MySQL 反引号 /
// PG 双引号），白名单仍是防注入前置，Ident 只负责引用形态。
func (q ClientListQuery) orderClause() (string, []any) {
	col := q.Sort
	if col == "" || !clientSortColumnPattern.MatchString(col) {
		col = clientDefaultSortColumn
	}
	dir := "DESC"
	if strings.EqualFold(q.Order, "asc") {
		dir = "ASC"
	}
	if col == clientDefaultSortColumn {
		return col + " " + dir, nil
	}
	return "? " + dir + ", id DESC", []any{bun.Ident(col)}
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
	total, err := r.db.NewSelect().Model((*model.SsoClient)(nil)).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("client repo: list sso clients count: %w", err)
	}
	var rows []model.SsoClient
	clause, orderArgs := q.orderClause()
	err = r.db.NewSelect().Model(&rows).
		OrderExpr(clause, orderArgs...).
		Limit(int64(size)).
		Offset(int64((page - 1) * size)).
		Scan(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("client repo: list sso clients: %w", err)
	}
	return rows, total, nil
}

// ListOidcClients 分页列表：返回当页行与总数（§1.7 响应
// {items, total, page, pageSize} 的数据来源）。
func (r *ClientRepo) ListOidcClients(ctx context.Context, q ClientListQuery) ([]model.OidcClient, int64, error) {
	page, size := q.normalize()
	total, err := r.db.NewSelect().Model((*model.OidcClient)(nil)).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("client repo: list oidc clients count: %w", err)
	}
	var rows []model.OidcClient
	clause, orderArgs := q.orderClause()
	err = r.db.NewSelect().Model(&rows).
		OrderExpr(clause, orderArgs...).
		Limit(int64(size)).
		Offset(int64((page - 1) * size)).
		Scan(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("client repo: list oidc clients: %w", err)
	}
	return rows, total, nil
}

// CreateSsoClient 插入 SSO 客户端；命中 uk_client_id 返回 ErrClientDuplicate
// （errors.Is 可判别），其余错误原样包装。default tag 列（is_enabled）零值
// 经 DEFAULT 占位由 DB 默认值填充（口径同 provider_repo.Create）——显式写
// 0 走列级 UPDATE。created_at / updated_at 零值时由本方法补齐（bun 无
// 时间列自动填充）。
func (r *ClientRepo) CreateSsoClient(ctx context.Context, c *model.SsoClient) error {
	now := time.Now()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}
	if _, err := r.db.NewInsert().Model(c).Exec(ctx); err != nil {
		if isClientDuplicateKey(err) {
			return fmt.Errorf("client repo: create sso client: %w: %w", ErrClientDuplicate, err)
		}
		return fmt.Errorf("client repo: create sso client: %w", err)
	}
	return nil
}

// CreateOidcClient 插入 OIDC 客户端；命中 uk_client_id 返回
// ErrClientDuplicate（errors.Is 可判别），其余错误原样包装。default tag 列
// （scopes / access_token_ttl / refresh_token_ttl / is_enabled）零值经
// DEFAULT 占位由 DB 默认值填充（口径同 provider_repo.Create）。
// created_at / updated_at 零值时由本方法补齐。
func (r *ClientRepo) CreateOidcClient(ctx context.Context, c *model.OidcClient) error {
	now := time.Now()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}
	if _, err := r.db.NewInsert().Model(c).Exec(ctx); err != nil {
		if isClientDuplicateKey(err) {
			return fmt.Errorf("client repo: create oidc client: %w: %w", ErrClientDuplicate, err)
		}
		return fmt.Errorf("client repo: create oidc client: %w", err)
	}
	return nil
}

// UpdateSsoClient 按主键整行 UPDATE（全列覆盖，含零值列——is_enabled=0 等
// 禁用零值必须可落库；调用方应传入 FindSsoClientByClientID 取回的完整行，
// 全列忠实覆盖含 created_at；client_id 创建后不可改由 service 保证）。若改
// 了 client_id 命中 uk_client_id，返回 ErrClientDuplicate。不用 upsert 语义：
// 行不存在静默变插入会把「行不存在」错误口径吞掉。MySQL 驱动默认
// changed-rows 语义：同值 UPDATE RowsAffected=0 与行不存在不可区分，故
// rows=0 时补 SELECT 存在性判定——行仍在则视为幂等成功，查无此行才报
// sql.ErrNoRows（口径同 provider_repo.Update）。updated_at 随更新刷新
// （与旧 ORM struct 更新自动刷新 updated_at 同语义）。
func (r *ClientRepo) UpdateSsoClient(ctx context.Context, c *model.SsoClient) error {
	res, err := r.db.NewUpdate().Model((*model.SsoClient)(nil)).
		Where("id = ?", c.ID).
		Set("client_id = ?", c.ClientID).
		Set("client_secret = ?", c.ClientSecret).
		Set("name = ?", c.Name).
		Set("redirect_uris = ?", c.RedirectURIs).
		Set("login_methods = ?", c.LoginMethods).
		Set("oauth_providers = ?", c.OauthProviders).
		Set("default_redirect_uri = ?", c.DefaultRedirectURI).
		Set("is_enabled = ?", c.IsEnabled).
		Set("template_key = ?", c.TemplateKey).
		Set("template_vars = ?", c.TemplateVars).
		Set("created_at = ?", c.CreatedAt).
		Set("updated_at = ?", time.Now()).
		Exec(ctx)
	if err != nil {
		if isClientDuplicateKey(err) {
			return fmt.Errorf("client repo: update sso client: %w: %w", ErrClientDuplicate, err)
		}
		return fmt.Errorf("client repo: update sso client: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.SsoClient)(nil),
		"client repo: update sso client", "id = ?", c.ID); err != nil {
		return err
	}
	return nil
}

// UpdateOidcClient 按主键整行 UPDATE，口径同 UpdateSsoClient（整行覆盖、
// 零值可落库、同值幂等、client_id 冲突返回 ErrClientDuplicate）。
func (r *ClientRepo) UpdateOidcClient(ctx context.Context, c *model.OidcClient) error {
	res, err := r.db.NewUpdate().Model((*model.OidcClient)(nil)).
		Where("id = ?", c.ID).
		Set("client_id = ?", c.ClientID).
		Set("client_secret = ?", c.ClientSecret).
		Set("name = ?", c.Name).
		Set("redirect_uris = ?", c.RedirectURIs).
		Set("scopes = ?", c.Scopes).
		Set("access_token_ttl = ?", c.AccessTokenTTL).
		Set("refresh_token_ttl = ?", c.RefreshTokenTTL).
		Set("is_enabled = ?", c.IsEnabled).
		Set("template_key = ?", c.TemplateKey).
		Set("template_vars = ?", c.TemplateVars).
		Set("created_at = ?", c.CreatedAt).
		Set("updated_at = ?", time.Now()).
		Exec(ctx)
	if err != nil {
		if isClientDuplicateKey(err) {
			return fmt.Errorf("client repo: update oidc client: %w: %w", ErrClientDuplicate, err)
		}
		return fmt.Errorf("client repo: update oidc client: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.OidcClient)(nil),
		"client repo: update oidc client", "id = ?", c.ID); err != nil {
		return err
	}
	return nil
}

// DeleteSsoClient 按主键删除；行不存在返回包装的 sql.ErrNoRows（DELETE 的
// rows=0 无同值歧义，直接判 not found）。
func (r *ClientRepo) DeleteSsoClient(ctx context.Context, id int64) error {
	res, err := r.db.NewDelete().Model((*model.SsoClient)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("client repo: delete sso client: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.SsoClient)(nil),
		"client repo: delete sso client", "id = ?", id); err != nil {
		return err
	}
	return nil
}

// DeleteOidcClient 按主键删除；行不存在返回包装的 sql.ErrNoRows。
func (r *ClientRepo) DeleteOidcClient(ctx context.Context, id int64) error {
	res, err := r.db.NewDelete().Model((*model.OidcClient)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("client repo: delete oidc client: %w", err)
	}
	if err := requireChangedRow(ctx, r.db, res, (*model.OidcClient)(nil),
		"client repo: delete oidc client", "id = ?", id); err != nil {
		return err
	}
	return nil
}

// MarshalClientRedirectUris 将 client.RedirectUris（接口文档 §12.3）序列化
// 为 redirect_uris 列字节（§12.0：结构固定走 Protobuf）。nil 输入按空消息
// 编码，返回非 nil 的零长字节——列定义为 VARBINARY NOT NULL（§4.4 / §4.5），
// 返回 nil 会被写成 NULL 触发 MySQL 1048。protocol 编码错误原样包装。校验
// （通配符合法性、条目上限）归 service，repo 只做唯一编解码出口。
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

// MarshalClientLoginMethods 将 client.ClientLoginMethods（接口文档 §12.3、
// §5.5）序列化为 sso_client.login_methods 列字节（§12.0：结构固定走
// Protobuf）。nil 输入按空消息编码，返回非 nil 的零长字节——列定义为
// VARBINARY NOT NULL（《后端架构》§4.4），返回 nil 会被写成 NULL 触发
// MySQL 1048。空消息 = 未配置 = 跟随全局（§2.1）。登录方式封闭集校验归
// service，repo 只做编解码。
func MarshalClientLoginMethods(methods *client.ClientLoginMethods) ([]byte, error) {
	if methods == nil {
		methods = &client.ClientLoginMethods{}
	}
	data, err := proto.Marshal(methods)
	if err != nil {
		return nil, fmt.Errorf("client repo: marshal login methods: %w", err)
	}
	if data == nil {
		data = []byte{}
	}
	return data, nil
}

// ParseClientLoginMethods 将 login_methods 列字节反序列化为
// client.ClientLoginMethods。空 / NULL 列返回空消息（非 nil），调用方无需
// 判空；解码错误原样包装。与 MarshalClientLoginMethods 互为逆运算。
func ParseClientLoginMethods(data []byte) (*client.ClientLoginMethods, error) {
	methods := &client.ClientLoginMethods{}
	if len(data) == 0 {
		return methods, nil
	}
	if err := proto.Unmarshal(data, methods); err != nil {
		return nil, fmt.Errorf("client repo: parse login methods: %w", err)
	}
	return methods, nil
}

// MarshalClientOauthProviders 将 client.ClientOauthProviders（接口文档
// §12.3、§5.5）序列化为 sso_client.oauth_providers 列字节（§12.0：结构固定
// 走 Protobuf）。nil 输入按空消息编码，返回非 nil 的零长字节——列定义为
// VARBINARY NOT NULL（《后端架构》§4.4），返回 nil 会被写成 NULL 触发
// MySQL 1048。空消息 = 未配置 = 跟随全局（§2.1）。provider key 存在性校验
// 归 service，repo 只做编解码。
func MarshalClientOauthProviders(providers *client.ClientOauthProviders) ([]byte, error) {
	if providers == nil {
		providers = &client.ClientOauthProviders{}
	}
	data, err := proto.Marshal(providers)
	if err != nil {
		return nil, fmt.Errorf("client repo: marshal oauth providers: %w", err)
	}
	if data == nil {
		data = []byte{}
	}
	return data, nil
}

// ParseClientOauthProviders 将 oauth_providers 列字节反序列化为
// client.ClientOauthProviders。空 / NULL 列返回空消息（非 nil），调用方
// 无需判空；解码错误原样包装。与 MarshalClientOauthProviders 互为逆运算。
func ParseClientOauthProviders(data []byte) (*client.ClientOauthProviders, error) {
	providers := &client.ClientOauthProviders{}
	if len(data) == 0 {
		return providers, nil
	}
	if err := proto.Unmarshal(data, providers); err != nil {
		return nil, fmt.Errorf("client repo: parse oauth providers: %w", err)
	}
	return providers, nil
}

// isClientDuplicateKey 判唯一键冲突（MariaDB 1062 / PG 23505），判定归同包
// 语义化 helper IsDuplicateKey；template 侧判别复用本函数。
func isClientDuplicateKey(err error) bool {
	return IsDuplicateKey(err)
}
