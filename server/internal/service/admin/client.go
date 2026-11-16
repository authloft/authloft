// client.go 实现 AdminService 客户端管理族 10 方法（ListSsoClients /
// CreateSsoClient / GetSsoClient / UpdateSsoClient / DeleteSsoClient +
// ListOidcClients / CreateOidcClient / GetOidcClient / UpdateOidcClient /
// DeleteOidcClient，接口文档 §5.5 行 1258-1268）的业务层（
// docs/后端架构.md §3.9 行 390、§18 行 1792 分层 handler →
// service/admin/client.go → repo/client_repo.go）。
//
// 职责边界：client_secret 服务端生成（security.RandomString，crypto/rand；
// 管理员经 Get 明文查看——§5.2 行 1170 Provider 凭证明文同口径，仅 admin
// 会话可达，本层不落日志、错误信息不含 secret 值）；client_id 创建时提交
// 非空用提交值、空则服务端生成（proto 普通 string 空串即未指定；docs 未
// 明说，默认口径，待定）；uk_client_id 冲突转译 ErrDuplicateKey；
// redirect_uris 条目校验（字面 * 或 ^https?:// 前缀，默认）+
// VARBINARY(2048) 列宽防御；应用级登录配置（§5.5）三校验——login_methods
// 封闭集、oauth_providers key 经 ProviderKeyFinder 存在性、
// default_redirect_uri 命中 §12.3 回调白名单——与 has 位 PATCH 语义；OIDC
// scopes[] ↔ 逗号串转换（model 注释归
// service）与 TTL 值域 [1, 86400] / [1, 2592000]（docs 未定义上限，默认
// 即默认值量级，待定）；Update 按缺省键保留原值（PATCH，沿
// provider.go UpdateProvider 先例）；client_id 创建后不可改（改 →
// invalid_request，同值放行）。OIDC 客户端不设授权类型字段（§5.5 行 1268
// 固定 authorization_code + refresh_token，不建模）。审计：eventlog 无
// client 系常量，本实现不写审计（默认）。Connect 错误形态映射归 handler
// （复用 mapWriteError 口径）；本层返回可判别哨兵错误（同 provider.go 包注释）：
//   - ErrInvalidRequest 参数 / 校验类（映射 invalid_argument + code=invalid_request）；
//   - ErrDuplicateKey Create 命中 uk_client_id（映射 already_exists）；
//   - gorm.ErrRecordNotFound 资源不存在（映射 not_found）；
//   - 其余错误原样上抛，由错误包装拦截器消毒为 internal。
package admin

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"gorm.io/gorm"

	clientpb "authloft/gen/go/client"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
)

// 默认口径常量（docs 未细化，待定）：client_secret 长度对齐
// §4.4/§4.5 DDL CHAR(64)；client_id 生成长度与列宽 VARCHAR(64) 防御上限；
// redirect_uris 序列化字节上限对齐 VARBINARY(2048)；scopes 逗号串长度对齐
// VARCHAR(512)；OIDC TTL 上限即默认值量级（3600 → 86400、2592000 → 2592000）。
const (
	clientSecretLen     = 64
	clientIDGenLen      = 32
	clientIDMaxRunes    = 64
	clientNameMaxRunes  = 128
	redirectURIsMaxByte = 2048
	oidcScopesMaxRunes  = 512
	oidcAccessTTLMax    = 86400
	oidcRefreshTTLMax   = 2592000
	// 应用级登录配置两列 VARBINARY(1024) 与 default_redirect_uri
	// VARCHAR(1024) 的列宽防御（§4.4 DDL 硬约束，口径同 redirectURIsMaxByte）。
	loginMethodsMaxByte   = 1024
	oauthProvidersMaxByte = 1024
	defaultRedirectURIMax = 1024
)

// clientLoginMethodSet 应用级登录方式封闭集（§5.5）：password / otp_sms /
// otp_email / webauthn / thirdparty。thirdparty 是 OAuth Provider 的整体
// 开关；totp / recovery_code 只随全局 MFA 配置，不在集合域。
var clientLoginMethodSet = map[string]struct{}{
	"password":   {},
	"otp_sms":    {},
	"otp_email":  {},
	"webauthn":   {},
	"thirdparty": {},
}

// redirectURISchemePattern redirect_uris[] 条目格式（§5.5 行 1262「支持 *」
// + 默认 ^https?:// 前缀校验，待定）。
var redirectURISchemePattern = regexp.MustCompile(`^https?://`)

// ClientStore sso_client / oidc_client 表读写窄接口（§20 依赖注入）：
// *repo.ClientRepo 天然满足（FindByClientID / List / Create / Update /
// Delete 既有；FindSsoClientByID / FindOidcClientByID 为本实现补齐 Find 操作
// 的主键形态——§5.5 行 1259/1261 按自增 id 定位，口径同 UserRepo.FindByID），
// 测试可传 fake。
type ClientStore interface {
	FindSsoClientByID(ctx context.Context, id int64) (*model.SsoClient, error)
	FindOidcClientByID(ctx context.Context, id int64) (*model.OidcClient, error)
	ListSsoClients(ctx context.Context, q repo.ClientListQuery) ([]model.SsoClient, int64, error)
	ListOidcClients(ctx context.Context, q repo.ClientListQuery) ([]model.OidcClient, int64, error)
	CreateSsoClient(ctx context.Context, c *model.SsoClient) error
	CreateOidcClient(ctx context.Context, c *model.OidcClient) error
	UpdateSsoClient(ctx context.Context, c *model.SsoClient) error
	UpdateOidcClient(ctx context.Context, c *model.OidcClient) error
	DeleteSsoClient(ctx context.Context, id int64) error
	DeleteOidcClient(ctx context.Context, id int64) error
}

// SsoClientInput CreateSsoClient 入参（proto CreateSsoClientRequest 拆解）。
// 无 ClientSecret 字段：client_secret 服务端生成，请求中的同名字段被
// 明确忽略（类型系统挡住误用，口径同 Provider 列表无 ext）。
type SsoClientInput struct {
	ClientID           string // 空 → 服务端生成（默认）
	Name               string
	RedirectURIs       []string
	LoginMethods       []string // 应用级登录方式（§5.5）：Create 全量提交，空 = 未配置 = 跟随全局
	OauthProviders     []string // OAuth Provider key 白名单（§5.5）：key 必须存在于 provider 表
	DefaultRedirectURI string   // 默认回跳地址（§5.5）：非空须命中提交的 redirect_uris 白名单
	TemplateKey        string   // 空 / 未设置 → 回落默认文件壳（§5.5 / §8.1）
	TemplateVars       string   // 模板变量 JSON 原文，空按 {} 注入（§5.5）
}

// OidcClientInput CreateOidcClient 入参（proto CreateOidcClientRequest 拆解）：
// SSO 字段基线 + OIDC 专属（§5.5 行 1264「额外」）。TTL 为 0 表示未提交，
// INSERT 落 DDL 默认（3600 / 2592000，gorm default tag 由 DB 填充）。
type OidcClientInput struct {
	ClientID        string
	Name            string
	RedirectURIs    []string
	Scopes          []string
	AccessTokenTTL  int64
	RefreshTokenTTL int64
	TemplateKey     string
	TemplateVars    string
}

// SsoClientPatch UpdateSsoClient 入参（proto UpdateSsoClientRequest 拆解）：
// 缺省键保留原值（PATCH，沿 UpdateProvider 先例）——string 空串 / 切片
// len==0 即未提交（proto3 可空性），覆盖语义见各字段。应用级登录配置三
// 字段（§5.5 PATCH 语义，先例同 §5.6 settings 的 has_* 写入口径）：两个
// repeated 无 has 位、各配伴生 bool——true = 整组替换（空数组 = 清空为
// 跟随全局），缺省 / false = 不动；default_redirect_uri 为 proto3 optional
// string——指针非 nil 且空串 = 清空，非空 = 覆盖，nil = 不动。
type SsoClientPatch struct {
	ClientID           string   // 非空且与行现值不同 → invalid_request（创建后不可改）；相同放行
	ClientSecret       string   // 非空 → 覆盖为提交值（PATCH；服务端生成仅约束 Create）
	Name               string   // 非空 → 覆盖
	RedirectURIs       []string // len>0 → 校验后整组覆盖；==0 → 保留原值（既有口径不动）
	LoginMethods       []string // HasLoginMethods=true → 校验后整组替换（空数组 = 清空为跟随全局）；false → 不动
	HasLoginMethods    bool
	OauthProviders     []string // HasOauthProviders=true → key 存在性校验后整组替换（空数组 = 清空为跟随全局）；false → 不动
	HasOauthProviders  bool
	DefaultRedirectURI *string // nil=不动；非 nil 空串=清空为未配置；非空=覆盖（须命中合并后的回调白名单）
	TemplateKey        string  // 非空 → 覆盖；空 → 保留原值
	TemplateVars       string  // 非空 → 覆盖；空 → 保留原值
}

// OidcClientPatch UpdateOidcClient 入参：SSO 基线 + OIDC 专属，缺省保留。
type OidcClientPatch struct {
	ClientID        string
	ClientSecret    string
	Name            string
	RedirectURIs    []string
	Scopes          []string // len>0 → 校验后覆盖；==0 → 保留
	AccessTokenTTL  int64    // 0 保留原值；非 0 须在 [1, 86400]
	RefreshTokenTTL int64    // 0 保留原值；非 0 须在 [1, 2592000]
	TemplateKey     string   // 非空 → 覆盖；空 → 保留原值
	TemplateVars    string   // 非空 → 覆盖；空 → 保留原值
}

// SsoClientDetail GetSsoClient 的聚合结果：行 + 解析后的回调白名单与应用级
// 登录配置（repo.ParseClientRedirectUris / ParseClientLoginMethods /
// ParseClientOauthProviders 是 §12.3 编解码唯一出口，由本层调用，dto 只收
// []string）。
type SsoClientDetail struct {
	Row            *model.SsoClient
	RedirectURIs   []string
	LoginMethods   []string
	OauthProviders []string
}

// ProviderKeyFinder oauth_providers key 存在性校验（§5.5）依赖的窄接口
// （消费方定义，*repo.ProviderRepo 天然满足）：FindByKey 未命中返回包装的
// gorm.ErrRecordNotFound。
type ProviderKeyFinder interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
}

// ClientService admin 域客户端管理族业务层。
type ClientService struct {
	store     ClientStore
	providers ProviderKeyFinder
}

// NewClientService 构造；任一依赖为 nil 属程序错误（fail-fast，口径同
// NewService / NewUserService）。
func NewClientService(store ClientStore, providers ProviderKeyFinder) *ClientService {
	if store == nil {
		panic("admin service: NewClientService: nil ClientStore")
	}
	if providers == nil {
		panic("admin service: NewClientService: nil ProviderKeyFinder")
	}
	return &ClientService{store: store, providers: providers}
}

// OidcClientDetail GetOidcClient 的聚合结果：行 + 白名单 + 拆分后的 scopes
// （scopes[] ↔ 逗号串转换归本层，model 注释）。
type OidcClientDetail struct {
	Row          *model.OidcClient
	RedirectURIs []string
	Scopes       []string
}

// ListSsoClients（§5.5 行 1258）：§1.7 分页列表，逐行经
// repo.ParseClientRedirectUris（§12.3 编解码唯一出口）解析回调白名单后以
// detail 承载（投影在 dto，handler 不做编解码）。归一（page 从 1、pageSize
// 默认 20 上限 100）在 handler normalizeListPage 与 repo
// ClientListQuery.normalize 双层各自成立，sort / order 亦由 handler 原样
// 透传（§1.7 行 277 后端不做白名单强制校验，防注入字符集约束在
// repo.orderClause，口径同 ListUsers）。
func (s *ClientService) ListSsoClients(ctx context.Context, page, pageSize int, sort, order string) ([]SsoClientDetail, int64, error) {
	rows, total, err := s.store.ListSsoClients(ctx, repo.ClientListQuery{Page: page, PageSize: pageSize, Sort: sort, Order: order})
	if err != nil {
		return nil, 0, err
	}
	items := make([]SsoClientDetail, len(rows))
	for i := range rows {
		uris, methods, providers, err := parseSsoClientLoginConfig(&rows[i])
		if err != nil {
			return nil, 0, err
		}
		items[i] = SsoClientDetail{Row: &rows[i], RedirectURIs: uris, LoginMethods: methods, OauthProviders: providers}
	}
	return items, total, nil
}

// ListOidcClients（§5.5 行 1260）：口径同 ListSsoClients，另逐行
// 拆 scopes 逗号串。
func (s *ClientService) ListOidcClients(ctx context.Context, page, pageSize int, sort, order string) ([]OidcClientDetail, int64, error) {
	rows, total, err := s.store.ListOidcClients(ctx, repo.ClientListQuery{Page: page, PageSize: pageSize, Sort: sort, Order: order})
	if err != nil {
		return nil, 0, err
	}
	items := make([]OidcClientDetail, len(rows))
	for i := range rows {
		uris, err := repo.ParseClientRedirectUris(rows[i].RedirectURIs)
		if err != nil {
			return nil, 0, fmt.Errorf("admin service: parse oidc client %d redirect uris: %w", rows[i].ID, err)
		}
		items[i] = OidcClientDetail{Row: &rows[i], RedirectURIs: uris.Uris, Scopes: splitScopes(rows[i].Scopes)}
	}
	return items, total, nil
}

// CreateSsoClient（§5.5 行 1258/1266）：仅后台手动创建；secret
// 服务端生成；client_id 提交非空用提交值、空则生成；redirect_uris 条目
// 校验 + 列宽防御；uk 冲突转译 ErrDuplicateKey。name/uris 允许空
// （DDL default ” / 空消息字节，先建后补）。
func (s *ClientService) CreateSsoClient(ctx context.Context, in SsoClientInput) error {
	clientID, err := resolveClientID(in.ClientID)
	if err != nil {
		return err
	}
	secret, err := security.RandomString(clientSecretLen)
	if err != nil {
		return err
	}
	uris, err := marshalRedirectURIs(in.RedirectURIs)
	if err != nil {
		return err
	}
	// 应用级登录配置（§5.5，Create / Update 同口径）：三校验 + 编解码出口
	// 落字节（空消息 = 未配置 = 跟随全局）。
	if err := validateLoginMethods(in.LoginMethods); err != nil {
		return err
	}
	if err := s.validateOauthProviderKeys(ctx, in.OauthProviders); err != nil {
		return err
	}
	methods, err := marshalLoginMethods(in.LoginMethods)
	if err != nil {
		return err
	}
	providerKeys, err := marshalOauthProviders(in.OauthProviders)
	if err != nil {
		return err
	}
	defaultURI, err := validateDefaultRedirectURI(in.DefaultRedirectURI, in.RedirectURIs)
	if err != nil {
		return err
	}
	row := &model.SsoClient{
		ClientID:           clientID,
		ClientSecret:       secret,
		Name:               in.Name,
		RedirectURIs:       uris,
		LoginMethods:       methods,
		OauthProviders:     providerKeys,
		DefaultRedirectURI: defaultURI,
		TemplateKey:        in.TemplateKey,
		TemplateVars:       in.TemplateVars,
	}
	if err := s.store.CreateSsoClient(ctx, row); err != nil {
		if errors.Is(err, repo.ErrClientDuplicate) {
			return ErrDuplicateKey
		}
		return err
	}
	return nil
}

// CreateOidcClient（§5.5 行 1260）：SSO 基线 + OIDC 专属——
// scopes 逗号串落库（空组落 DDL default 'openid,profile,email'，gorm
// default tag 零值列由 DB 填充）；TTL 0 落 DDL 默认（3600 / 2592000）、
// 非 0 须在值域内。授权类型不建模（§5.5 行 1268）。
func (s *ClientService) CreateOidcClient(ctx context.Context, in OidcClientInput) error {
	clientID, err := resolveClientID(in.ClientID)
	if err != nil {
		return err
	}
	secret, err := security.RandomString(clientSecretLen)
	if err != nil {
		return err
	}
	uris, err := marshalRedirectURIs(in.RedirectURIs)
	if err != nil {
		return err
	}
	scopes, err := joinScopes(in.Scopes)
	if err != nil {
		return err
	}
	if err := validateTTL(in.AccessTokenTTL, oidcAccessTTLMax); err != nil {
		return err
	}
	if err := validateTTL(in.RefreshTokenTTL, oidcRefreshTTLMax); err != nil {
		return err
	}
	row := &model.OidcClient{
		ClientID:        clientID,
		ClientSecret:    secret,
		Name:            in.Name,
		RedirectURIs:    uris,
		Scopes:          scopes,
		AccessTokenTTL:  int32(in.AccessTokenTTL),
		RefreshTokenTTL: int32(in.RefreshTokenTTL),
		TemplateKey:     in.TemplateKey,
		TemplateVars:    in.TemplateVars,
	}
	if err := s.store.CreateOidcClient(ctx, row); err != nil {
		if errors.Is(err, repo.ErrClientDuplicate) {
			return ErrDuplicateKey
		}
		return err
	}
	return nil
}

// GetSsoClient（§5.5 行 1259）：按自增 id 定位（proto
// GetSsoClientRequest 唯一定位字段）→ 行 + 解析后回调白名单；详情含明文
// secret（§5.2 行 1170 凭证口径，投影在 dto）。
func (s *ClientService) GetSsoClient(ctx context.Context, id int64) (*SsoClientDetail, error) {
	if id <= 0 {
		return nil, ErrInvalidRequest
	}
	row, err := s.store.FindSsoClientByID(ctx, id)
	if err != nil {
		return nil, err // 含 gorm.ErrRecordNotFound → 404
	}
	uris, methods, providers, err := parseSsoClientLoginConfig(row)
	if err != nil {
		return nil, err
	}
	return &SsoClientDetail{Row: row, RedirectURIs: uris, LoginMethods: methods, OauthProviders: providers}, nil
}

// GetOidcClient（§5.5 行 1261）：口径同 GetSsoClient，另拆
// scopes 逗号串。
func (s *ClientService) GetOidcClient(ctx context.Context, id int64) (*OidcClientDetail, error) {
	if id <= 0 {
		return nil, ErrInvalidRequest
	}
	row, err := s.store.FindOidcClientByID(ctx, id)
	if err != nil {
		return nil, err
	}
	uris, err := repo.ParseClientRedirectUris(row.RedirectURIs)
	if err != nil {
		return nil, fmt.Errorf("admin service: parse oidc client %d redirect uris: %w", id, err)
	}
	return &OidcClientDetail{Row: row, RedirectURIs: uris.Uris, Scopes: splitScopes(row.Scopes)}, nil
}

// UpdateSsoClient（§5.5 行 1259）：FindByID 取回完整行 → 缺省
// 键保留原值（PATCH）→ repo 整行 UPDATE。client_id 提交非空且与行现值
// 不同 → invalid_request（创建后不可改）；相同值放行（幂等重放）。应用级
// 登录配置走 has 位语义（§5.5：has_* true = 整组替换、空数组 = 清空为跟随
// 全局，false / 缺省 = 不动；default_redirect_uri optional：nil = 不动、空串
// = 清空、非空 = 覆盖），default_redirect_uri 非空时对本 PATCH 合并后的
// 回调白名单校验。uk 冲突分支在生产 client_id 不可改语义下不可达，保留给
// 脏数据场景（防御同 UpdateProvider 的 provider_key 分支）。
func (s *ClientService) UpdateSsoClient(ctx context.Context, id int64, p SsoClientPatch) error {
	if id <= 0 {
		return ErrInvalidRequest
	}
	row, err := s.store.FindSsoClientByID(ctx, id)
	if err != nil {
		return err
	}
	if p.ClientID != "" && p.ClientID != row.ClientID {
		return ErrInvalidRequest
	}
	if p.ClientSecret != "" {
		row.ClientSecret = p.ClientSecret
	}
	if p.Name != "" {
		row.Name = p.Name
	}
	if len(p.RedirectURIs) > 0 {
		data, err := marshalRedirectURIs(p.RedirectURIs)
		if err != nil {
			return err
		}
		row.RedirectURIs = data
	}
	if p.HasLoginMethods {
		if err := validateLoginMethods(p.LoginMethods); err != nil {
			return err
		}
		data, err := marshalLoginMethods(p.LoginMethods)
		if err != nil {
			return err
		}
		row.LoginMethods = data
	}
	if p.HasOauthProviders {
		if err := s.validateOauthProviderKeys(ctx, p.OauthProviders); err != nil {
			return err
		}
		data, err := marshalOauthProviders(p.OauthProviders)
		if err != nil {
			return err
		}
		row.OauthProviders = data
	}
	if p.DefaultRedirectURI != nil {
		v := *p.DefaultRedirectURI
		if v != "" {
			uris, err := repo.ParseClientRedirectUris(row.RedirectURIs)
			if err != nil {
				return fmt.Errorf("admin service: parse sso client %d redirect uris: %w", id, err)
			}
			if _, err := validateDefaultRedirectURI(v, uris.Uris); err != nil {
				return err
			}
		}
		row.DefaultRedirectURI = v
	}
	if p.TemplateKey != "" {
		row.TemplateKey = p.TemplateKey
	}
	if p.TemplateVars != "" {
		row.TemplateVars = p.TemplateVars
	}
	if err := s.store.UpdateSsoClient(ctx, row); err != nil {
		if errors.Is(err, repo.ErrClientDuplicate) {
			return ErrDuplicateKey
		}
		return err
	}
	return nil
}

// UpdateOidcClient（§5.5 行 1261）：口径同 UpdateSsoClient，
// 另 scopes（len>0 覆盖）与 TTL（0 保留原值，非 0 须在值域内）。
func (s *ClientService) UpdateOidcClient(ctx context.Context, id int64, p OidcClientPatch) error {
	if id <= 0 {
		return ErrInvalidRequest
	}
	row, err := s.store.FindOidcClientByID(ctx, id)
	if err != nil {
		return err
	}
	if p.ClientID != "" && p.ClientID != row.ClientID {
		return ErrInvalidRequest
	}
	if p.ClientSecret != "" {
		row.ClientSecret = p.ClientSecret
	}
	if p.Name != "" {
		row.Name = p.Name
	}
	if len(p.RedirectURIs) > 0 {
		data, err := marshalRedirectURIs(p.RedirectURIs)
		if err != nil {
			return err
		}
		row.RedirectURIs = data
	}
	if len(p.Scopes) > 0 {
		joined, err := joinScopes(p.Scopes)
		if err != nil {
			return err
		}
		row.Scopes = joined
	}
	if p.AccessTokenTTL != 0 {
		if err := validateTTL(p.AccessTokenTTL, oidcAccessTTLMax); err != nil {
			return err
		}
		row.AccessTokenTTL = int32(p.AccessTokenTTL)
	}
	if p.RefreshTokenTTL != 0 {
		if err := validateTTL(p.RefreshTokenTTL, oidcRefreshTTLMax); err != nil {
			return err
		}
		row.RefreshTokenTTL = int32(p.RefreshTokenTTL)
	}
	if p.TemplateKey != "" {
		row.TemplateKey = p.TemplateKey
	}
	if p.TemplateVars != "" {
		row.TemplateVars = p.TemplateVars
	}
	if err := s.store.UpdateOidcClient(ctx, row); err != nil {
		if errors.Is(err, repo.ErrClientDuplicate) {
			return ErrDuplicateKey
		}
		return err
	}
	return nil
}

// DeleteSsoClient（§5.5 行 1259）：硬删（repo.Delete 按主键，
// 行不存在 → gorm.ErrRecordNotFound → 404）。不触发会话失效——docs 未
// 定义客户端删除的联动行为，默认（待定）。
func (s *ClientService) DeleteSsoClient(ctx context.Context, id int64) error {
	if id <= 0 {
		return ErrInvalidRequest
	}
	return s.store.DeleteSsoClient(ctx, id)
}

// DeleteOidcClient（§5.5 行 1261）：口径同 DeleteSsoClient。
func (s *ClientService) DeleteOidcClient(ctx context.Context, id int64) error {
	if id <= 0 {
		return ErrInvalidRequest
	}
	return s.store.DeleteOidcClient(ctx, id)
}

// resolveClientID client_id 生成 / 指定口径（默认，待定）：
// proto 普通 string 空串即未指定 → 服务端生成；非空用提交值（VARCHAR(64)
// 列宽按字符数防御）。
func resolveClientID(submitted string) (string, error) {
	if submitted == "" {
		return security.RandomString(clientIDGenLen)
	}
	if utf8.RuneCountInString(submitted) > clientIDMaxRunes {
		return "", ErrInvalidRequest
	}
	return submitted, nil
}

// marshalRedirectURIs 校验并序列化回调白名单：条目字面 * 或 ^https?:// 前缀
// （§5.5 行 1262「支持 *」，默认，待定）；经 repo 唯一编解码
// 出口 MarshalClientRedirectUris 落字节，超 §4.4/§4.5 VARBINARY(2048)
// 列宽 → invalid_request（列宽为 DDL 硬约束的防御转译，非自造规则）。
func marshalRedirectURIs(uris []string) ([]byte, error) {
	for _, u := range uris {
		if u == "" || (u != "*" && !redirectURISchemePattern.MatchString(u)) {
			return nil, ErrInvalidRequest
		}
	}
	data, err := repo.MarshalClientRedirectUris(&clientpb.ClientRedirectUris{Uris: uris})
	if err != nil {
		return nil, err
	}
	if len(data) > redirectURIsMaxByte {
		return nil, ErrInvalidRequest
	}
	return data, nil
}

// joinScopes scopes[] → 逗号串（§4.5 VARCHAR(512)，model 注释归 service）：
// 条目空串或含逗号（会破坏逗号串表示）→ invalid_request；空组返回空串，
// INSERT 落 DDL default 'openid,profile,email'（gorm default tag）。
func joinScopes(scopes []string) (string, error) {
	for _, sc := range scopes {
		if sc == "" || strings.Contains(sc, ",") {
			return "", ErrInvalidRequest
		}
	}
	joined := strings.Join(scopes, ",")
	if utf8.RuneCountInString(joined) > oidcScopesMaxRunes {
		return "", ErrInvalidRequest
	}
	return joined, nil
}

// splitScopes 逗号串 → scopes[]（GetOidcClient 投影）：空串返回 nil
// （strings.Split 会产出 [""]，防御）；proto3 空 repeated 序列化省略。
func splitScopes(joined string) []string {
	if joined == "" {
		return nil
	}
	return strings.Split(joined, ",")
}

// validateTTL OIDC TTL 值域（默认，待定）：0 = 未提交
// （Create 落 DDL 默认 / Update 保留原值，调用方分支处理）；非 0 须在
// [1, max]，越界 / 负数 → invalid_request。上限即默认值量级
// （access 86400 / refresh 2592000，§4.5 行 736-737）。
func validateTTL(ttl, max int64) error {
	if ttl < 0 || ttl > max {
		return ErrInvalidRequest
	}
	return nil
}

// parseSsoClientLoginConfig 行三列 → 视图切片：redirect_uris 与应用级登录
// 配置两列均经 repo 唯一编解码出口（§12.3），空 / NULL 列返回空切片非 nil。
// 行内字节损坏属脏数据，包装后上抛（消毒为 internal，fail-closed）。
func parseSsoClientLoginConfig(row *model.SsoClient) (uris, methods, providers []string, err error) {
	pu, err := repo.ParseClientRedirectUris(row.RedirectURIs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("admin service: parse sso client %d redirect uris: %w", row.ID, err)
	}
	pm, err := repo.ParseClientLoginMethods(row.LoginMethods)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("admin service: parse sso client %d login methods: %w", row.ID, err)
	}
	pp, err := repo.ParseClientOauthProviders(row.OauthProviders)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("admin service: parse sso client %d oauth providers: %w", row.ID, err)
	}
	return pu.Uris, pm.Methods, pp.Providers, nil
}

// validateLoginMethods 应用级登录方式封闭集校验（§5.5，Create / Update 同
// 口径）：每个取值 ∈ clientLoginMethodSet；空数组 = 未配置 = 跟随全局，
// 合法。越界取值 → invalid_request。
func validateLoginMethods(methods []string) error {
	for _, m := range methods {
		if _, ok := clientLoginMethodSet[m]; !ok {
			return ErrInvalidRequest
		}
	}
	return nil
}

// validateOauthProviderKeys oauth_providers key 存在性校验（§5.5）：每个 key
// 必须存在于 provider 表——复用 ProviderKeyFinder.FindByKey 既有查询逐 key
// 确认（管理端提交量小，逐条查询可接受），未命中 → invalid_request；其余
// 查询错误原样包装上抛。
func (s *ClientService) validateOauthProviderKeys(ctx context.Context, keys []string) error {
	for _, k := range keys {
		_, err := s.providers.FindByKey(ctx, k)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrInvalidRequest
			}
			return fmt.Errorf("admin service: check oauth provider key %q: %w", k, err)
		}
	}
	return nil
}

// validateDefaultRedirectURI 默认回跳地址校验（§5.5）：空 = 未配置 = 维持
// 默认落点，原样放行；非空须命中回调白名单（§12.3 整段匹配 / * 通配）且不
// 超 VARCHAR(1024) 列宽，越界 → invalid_request。
func validateDefaultRedirectURI(uri string, whitelist []string) (string, error) {
	if uri == "" {
		return uri, nil
	}
	if utf8.RuneCountInString(uri) > defaultRedirectURIMax {
		return "", ErrInvalidRequest
	}
	if !redirectURIHit(whitelist, uri) {
		return "", ErrInvalidRequest
	}
	return uri, nil
}

// marshalLoginMethods / marshalOauthProviders 经 repo 唯一编解码出口落字节，
// 超 VARBINARY(1024) 列宽 → invalid_request（DDL 硬约束的防御转译，口径同
// marshalRedirectURIs）。
func marshalLoginMethods(methods []string) ([]byte, error) {
	data, err := repo.MarshalClientLoginMethods(&clientpb.ClientLoginMethods{Methods: methods})
	if err != nil {
		return nil, err
	}
	if len(data) > loginMethodsMaxByte {
		return nil, ErrInvalidRequest
	}
	return data, nil
}

func marshalOauthProviders(providers []string) ([]byte, error) {
	data, err := repo.MarshalClientOauthProviders(&clientpb.ClientOauthProviders{Providers: providers})
	if err != nil {
		return nil, err
	}
	if len(data) > oauthProvidersMaxByte {
		return nil, ErrInvalidRequest
	}
	return data, nil
}

// matchRedirectURI 回调白名单条目整段匹配（§12.3：支持 * 通配、整段匹配防
// 子域名陷阱）：字面相等，或按 * 切段后前缀 / 中段 / 后缀依序匹配。与登出
// 页白名单（internal/pages）是同一规则的两处实现，改规则须两处同步。
func matchRedirectURI(pattern, target string) bool {
	if pattern == target {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(target, parts[0]) {
		return false
	}
	rest := target[len(parts[0]):]
	for i := 1; i < len(parts); i++ {
		if i == len(parts)-1 {
			if len(rest) < len(parts[i]) || !strings.HasSuffix(rest, parts[i]) {
				return false
			}
		} else {
			idx := strings.Index(rest, parts[i])
			if idx < 0 {
				return false
			}
			rest = rest[idx+len(parts[i]):]
		}
	}
	return true
}

// redirectURIHit target 是否命中白名单任一条目。
func redirectURIHit(patterns []string, target string) bool {
	for _, p := range patterns {
		if matchRedirectURI(p, target) {
			return true
		}
	}
	return false
}

// compile 时断言 *repo.ClientRepo 满足 ClientStore、*repo.ProviderRepo 满足
// ProviderKeyFinder（签名漂移在编译期暴露）。
var (
	_ ClientStore       = (*repo.ClientRepo)(nil)
	_ ProviderKeyFinder = (*repo.ProviderRepo)(nil)
)
