// Package pages 页面壳路由族（接口文档 §8 行 1486-1543）：/sso/login、
// /sso/register、/sso/reset、/sso/oauth/callback/{provider_key}（login
// entry）、/account、/admin（仅根映射，account / admin entry；子路径走
// 前端 hash 路由，未注册子路径 echo 错误体 404，通配收窄）的 SPA 空壳渲染，
// 外加 /sso/logout（§2.9）与 /sso/sync_cookie 中转（§11.2 接收端）。
//
// 壳层 HTML 不由后端手写：读前端构建产物模板（render.go //go:embed
// templates）+ 五占位符纯字符串全量替换，注入 window.__AUTHLOFT_INIT__
// （注入键白名单 + JSON 编码 <>& 与 \u2028/\u2029 转义）、Cache-Control:
// no-store、CSP nonce、不注入任何凭证（CSP 终稿：基线 =
// middleware/csp.go + cdnOrigin 追加，setup 壳同基线）。注入键白名单（§8）：
// al_root / static_base 三端，methods（login 必填，缺失即服务端故障）、
// oidc（login 可选，/auth/authorize 渲染空壳时注入）、sso（login 可选，
// 登录端入口命中 sso_client 行时注入，§2.1）、passwordPolicy（三端，§2.1：
// settings pwd_* 三键快照，长度 / 类数按 §1.12 十进制字符串）。
package pages

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v5"

	"authloft/gen/go/token"
	"authloft/internal/captcha"
	"authloft/internal/factor"
	"authloft/internal/oidc"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
	"authloft/internal/settings"
)

// SettingsReader settings 快照读取窄接口（§20 依赖注入）：*settings.Store
// 天然满足，测试可传 fake。
type SettingsReader interface {
	GetString(key string) (string, bool)
	GetInt64(key string) (int64, bool)
	GetBool(key string) (bool, bool)
	GetStringSlice(key string) ([]string, bool)
}

// ProviderLister provider Loader 窄接口：thirdparty.providers 经 Loader /
// 缓存读取（后端架构 §12.3 行 1462-1466）。
type ProviderLister interface {
	ListByType(ctx context.Context, providerType string) ([]*provider.Provider, error)
}

// ChannelProber 消息渠道可用性判定窄接口（*provider.CodeBridge 天然满足）：
// otp_sms / otp_email 注入快照前的渠道维度过滤出口（§2.1），判定实现归
// provider 包公共函数，与发送期 provider_disabled 同源。
type ChannelProber interface {
	Available(ctx context.Context) (bool, error)
}

// FactorSource 因子注册表窄接口：*factor.Registry 天然满足；methods 快照
// 按 settings.login_methods 过滤读取（§2.1）。
type FactorSource interface {
	Get(kind factor.FactorKind) (factor.Factor, error)
}

// CaptchaConfiger 首屏 captcha 配置来源（§2.5 三处同结构出口之一）：
// *captcha.Gate 天然满足（Config 每次现算，无可用项降级 builtin_image）。
type CaptchaConfiger interface {
	Config(ctx context.Context) captcha.Config
}

// SyncBuilder 多域名同步首跳 URL 构造（§11.2 发起端）：
// session 子包的同步跳转链构造器天然满足（与 orchestrator 同一签名）。
type SyncBuilder interface {
	Build(ctx context.Context, cookieName, cookieValue, cookieTTL string, domains []string, finalURL string) (string, error)
}

// JWTVerifier OIDC RS256 验签（§14.3）：*oidc.JWT 天然满足；登出
// id_token_hint 解析 aud=client_id 用（§2.9）。
type JWTVerifier interface {
	Verify(raw string) (jwt.MapClaims, error)
}

// OidcClientReader oidc_client 行读取窄接口：*repo.ClientRepo 天然满足。
type OidcClientReader interface {
	FindOidcClientByClientID(ctx context.Context, clientID string) (*model.OidcClient, error)
}

// SessionVerifier al_session 会话校验窄接口（后端架构 §11.1 四步）：
// *session.Verifier 天然满足；/auth/authorize 有无有效会话判定用。
type SessionVerifier interface {
	Verify(ctx context.Context, sessionToken string) (*token.SessionTokenPayload, error)
}

// CodeIssuer OIDC 授权码签发窄接口（后端架构 §14.2 行 1642：与 Terminal
// 共用同一注入实例，不得各写一份）：*oidc.CodeIssuer 天然满足（签名即
// orchestrator.OIDCCodeIssuer）；/auth/authorize 有会话路径消费。
type CodeIssuer interface {
	Issue(ctx context.Context, in orchestrator.OIDCIssue) (string, error)
}

// AuditSink 审计事件投递窄接口：*eventlog.Writer 天然满足（非阻塞，队列
// 满静默降级）；/auth/authorize 记 oidc_authorize_no_state。
type AuditSink interface {
	PushEvent(ev model.EventLog)
}

// Consents 授权同意判定窄接口（§4.2 三态 / §14.2 步骤 3）：
// *oidc.ConsentService 天然满足；有会话分支据 Decide 结果分派形态 B / C，
// Decide 内部按「有效 scope ⊆ 已授权」判定并合并 prompt=consent。
type Consents interface {
	Decide(ctx context.Context, userID int64, clientID, reqScope, prompt string) (oidc.Decision, error)
}

// AuthzValidator 授权参数校验窄接口（§14.2「不得各写一份」）：
// *oidc.AuthzValidator 天然满足，与 Terminal / 同意 RPC 共用同一实例；形态 C
// 直签前复用 Validate（必含 openid + ⊆ 注册 scopes），不在 pages 重写规则。
type AuthzValidator interface {
	Validate(ctx context.Context, clientID, redirectURI, scope string) (*model.OidcClient, error)
}

// ProfileReader 形态 B 账号摘要读取窄接口（§4.2 账号卡片 / §5.1 account）：
// *repo.UserRepo 天然满足（FindByID）；取 nickname / avatar_url / 账号标识，
// 掩码在页面层按 §3.1 口径生成，不注入凭证或完整手机号邮箱。
type ProfileReader interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
}

// Deps 页面壳装配依赖（bootstrap 构造注入，§20）。
type Deps struct {
	// Root al_root（cfg.Authloft.Root 完整 URL，§1.1 行 76）。
	Root string
	// RootDomain 根域（Cookie Domain 属性，rootHost(root)；空 = 主机限定）。
	RootDomain string
	// Settings settings 快照（static_base / login_methods / flags /
	// sso_domains / cookie_name 等）。nil 时全部回落默认值。
	Settings SettingsReader
	// Loader provider 加载链（thirdparty.providers 数据源）。
	Loader ProviderLister
	// SmsChannel / EmailChannel otp 渠道可用性判定（settings 键 → provider 行
	// → Enabled，§2.1）：*provider.CodeBridge 天然满足；nil = 渠道维度不判定，
	// 方式照常注入（既有口径），生产装配恒注入两桥实例。
	SmsChannel   ChannelProber
	EmailChannel ChannelProber
	// Factors 因子注册表（login_methods 过滤读取）。
	Factors FactorSource
	// Gate captcha 首屏配置；nil 降级 builtin_image（§2.5）。
	Gate CaptchaConfiger
	// Sync 登出多域同步首跳构造（§11.2 发起端）；nil 跳过同步直接 302。
	Sync SyncBuilder
	// Codec sync_payload 编解码器（/sso/sync_cookie 接收端解密 / 重封）。
	Codec *security.Codec
	// JWT id_token_hint 验签；nil 时 hint 一律按非法处理（回退默认页）。
	JWT JWTVerifier
	// Clients OIDC 客户端行源（logout 白名单 + authorize 校验）。
	Clients OidcClientReader
	// Sessions al_session 会话校验（§11.1 四步）；nil 时 /auth/authorize
	// 一律按无有效会话处理（§4.2）。
	Sessions SessionVerifier
	// Codes OIDC 授权码签发（与 Terminal 共用同一 CodeIssuer 实例，
	// §14.2）；/auth/authorize 有会话路径消费，nil 时该路径按服务端故障
	// 500（正常装配恒注入）。
	Codes CodeIssuer
	// Audit 审计事件投递（oidc_authorize_no_state，§4.2 行 1074）；nil
	// 静默跳过（不阻断授权主链路）。
	Audit AuditSink
	// Consents 授权同意判定（三态形态 B/C）；nil 时有会话分支按全部需同意
	// 处理（fail-closed，形态 B），不静默直签。
	Consents Consents
	// Authz 授权参数校验（§14.2 两条签发路径共用同一校验工具）：形态 C 直签
	// 前消费；nil 时同 Consents 口径 fail-closed（全部需同意），绝不静默直签。
	Authz AuthzValidator
	// ProfileReader 形态 B 账号摘要数据源；nil 时 account 注入空摘要。
	Profiles ProfileReader
	// Templates 自定义模板解析源（§8.1）：admin 侧 TemplateService 天然满足。
	// nil（setup 模式 / 未装配）时一律回落默认文件壳，本包零 DB / Redis 依赖。
	Templates TemplateResolver
	// SsoClients sso_client 行源（§8.1 登录端入口选模板用；行命中同时是
	// __AUTHLOFT_INIT__.sso 注入与 methods 应用级过滤的依据，§2.1）；nil 时
	// 登录端回落默认文件壳且不注入 sso。OIDC 入口沿用 Clients
	// （OidcClientReader），两族分列。
	SsoClients SsoClientReader
	// Metas provider 渠道注册表枚举（type → category/channel）；nil 用
	// provider 全局注册表（Types + Lookup）。测试注入用。
	Metas func() []provider.Meta
	// Now 时钟注入（sync 载荷 exp 判定）；nil 用 time.Now。
	Now func() time.Time
}

// initPayload window.__AUTHLOFT_INIT__ 注入体：字段即 §8 注入白名单
// （al_root / static_base 三端，methods login 必填，oidc / sso login 可选，
// passwordPolicy 三端）。oidc 为 json.RawMessage 注入位——/auth/authorize
// 渲染登录空壳时填充（authorize.go，§4.2），其余路由不注入（nil 时
// omitted）。sso 为 SSO 应用上下文（§2.1）——登录端入口命中 sso_client 行时
// 填充（loginPage），authorize 入口不注入（nil 时 omitted）。passwordPolicy
// 为密码策略快照（§2.1）——三端渲染空壳时统一装配（h.passwordPolicy）。
type initPayload struct {
	ALRoot         string              `json:"al_root"`
	StaticBase     string              `json:"static_base"`
	Methods        *MethodsSnapshot    `json:"methods,omitempty"`
	OIDC           json.RawMessage     `json:"oidc,omitempty"`
	SSO            *ssoContext         `json:"sso,omitempty"`
	PasswordPolicy *passwordPolicyInit `json:"passwordPolicy,omitempty"`
}

// passwordPolicyInit __AUTHLOFT_INIT__.passwordPolicy 注入体（§2.1）：
// 注册 / 重置 / 改密 / admin 重置四入口前端预校验与强度提示的三项参数，
// 与 settings pwd_* 三键（§5.6）同源同值。长度 / 类数为计数类数值，按
// §1.12 以十进制字符串下发；服务端校验权威在 security/policy.go，本层
// 只装配下发值（前端为体验层同值预判，password_weak 由服务端权威判定）。
type passwordPolicyInit struct {
	MinLength      string `json:"minLength"`
	MaxLength      string `json:"maxLength"`
	RequireClasses string `json:"requireClasses"`
}

// ssoContext __AUTHLOFT_INIT__.sso 注入体（§2.1 注入结构）：clientId 供前端
// 首签请求回传（§2.2 / §2.7.2 / §2.8），name 仅供前端展示、不参与任何判定。
// 不含过滤结果——应用级过滤直接体现在 methods 快照，避免双份快照（§2.1）。
// 值随 INIT_JSON 走 json.Marshal 既有转义（<>& 与 \u2028/\u2029，§8），无
// 新增转义面。
type ssoContext struct {
	ClientID string `json:"clientId"`
	Name     string `json:"name"`
}

// Handler 页面壳处理器。
type Handler struct {
	root         string
	rootDomain   string
	settings     SettingsReader
	loader       ProviderLister
	smsChannel   ChannelProber
	emailChannel ChannelProber
	factors      FactorSource
	gate         CaptchaConfiger
	sync         SyncBuilder
	codec        *security.Codec
	jwt          JWTVerifier
	clients      OidcClientReader
	sessions     SessionVerifier
	codes        CodeIssuer
	audit        AuditSink
	consents     Consents
	authz        AuthzValidator
	profiles     ProfileReader
	metas        func() []provider.Meta
	now          func() time.Time
	// deps 保存装配期窄接口集合，供 resolveClientTpl 复用（§8.1）。
	deps Deps
}

// Register 挂全部页面路由（§8 路由表 + §2.9 logout / sync_cookie + §4.2
// /auth/authorize 授权入口）。页面路由归 echo 链（Connect 域走 mux 前缀，
// 互不相交）。
func Register(r *echo.Group, d Deps) *Handler {
	h := &Handler{
		root:         d.Root,
		rootDomain:   d.RootDomain,
		settings:     d.Settings,
		loader:       d.Loader,
		smsChannel:   d.SmsChannel,
		emailChannel: d.EmailChannel,
		factors:      d.Factors,
		gate:         d.Gate,
		sync:         d.Sync,
		codec:        d.Codec,
		jwt:          d.JWT,
		clients:      d.Clients,
		sessions:     d.Sessions,
		codes:        d.Codes,
		audit:        d.Audit,
		consents:     d.Consents,
		authz:        d.Authz,
		profiles:     d.Profiles,
		metas:        d.Metas,
		now:          d.Now,
		deps:         d,
	}
	if h.now == nil {
		h.now = time.Now
	}
	// /sso/login 渲染空壳前先做已登录直达检测（§8 专段）；callback 维持现状
	// 恒渲染空壳（§2.1，仅本路由检测）。register / reset 拆独立 entry 壳
	// （整页跳转，注入快照按页注入，§1.3），不参与客户端模板选壳。
	r.GET("/sso/login", h.loginEntry)
	r.GET("/sso/register", h.flowEntryShell(flowRegister, "register"))
	r.GET("/sso/reset", h.flowEntryShell(flowReset, "reset"))
	// callback 零业务逻辑（§2.7.3 行 604）：只渲染 login entry 空壳，
	// provider_key 路径参数不做任何业务校验（分派归前端）。
	r.GET("/sso/oauth/callback/:provider_key", h.loginPage(flowLogin))
	// 收窄：仅根映射——子路径走前端 hash 路由（/account#/…），
	// 不发往服务端；未注册子路径由 echo 错误体 404 兜底（接口文档 §8）。
	r.GET("/account", h.entryPage("account"))
	r.GET("/admin", h.entryPage("admin"))
	r.GET("/sso/logout", h.logout)
	r.GET("/sso/sync_cookie", h.syncCookie)
	// OIDC 授权入口（§4.2）：discovery 已广告 authorization_endpoint。
	r.GET("/auth/authorize", h.authorize)
	return h
}

// entryPage account / admin entry 空壳：注入 al_root / static_base /
// passwordPolicy（§8 白名单，methods 是 login 必填项、account 无）。account
// / admin 不参与客户端模板选壳（§8.1 仅 SSO 登录入口 / OIDC 授权入口），
// 恒走文件壳。
func (h *Handler) entryPage(entry string) echo.HandlerFunc {
	return func(c *echo.Context) error {
		return h.renderShell(c, entry, &initPayload{
			ALRoot:         h.root,
			StaticBase:     h.staticBase(),
			PasswordPolicy: h.passwordPolicy(),
		}, nil)
	}
}

// loginPage login entry 空壳（/sso/oauth/callback/*；/sso/login 走
// loginEntry 先做已登录直达检测；register / reset 已拆独立 entry 壳
// flowEntryShell）：渲染细节见 serveLoginShell。
func (h *Handler) loginPage(defaultFlow string) echo.HandlerFunc {
	return func(c *echo.Context) error {
		return h.serveLoginShell(c, defaultFlow)
	}
}

// flowEntryShell /sso/register、/sso/reset 独立 entry 空壳（整页跳转拆分，
// §1.3）：methods 按 flow 过滤（应用级交集不消费，register / reset 镜像
// 全局口径，§2.1）；client_id 命中行时仍注入 __AUTHLOFT_INIT__.sso（注册
// 首签回传 ssoClientId 依赖此键，§1.5），但不参与客户端模板选壳（§8.1 仅
// SSO 登录入口 / OIDC 授权入口）。模板取各自 entry（register.html /
// reset.html）——每页整页加载即拿到自己的快照，不串用首开页注入；flow 取
// 页面 URL query（login 默认，§2.1 行 363-368），路径缺省已按页带对。
func (h *Handler) flowEntryShell(defaultFlow, entry string) echo.HandlerFunc {
	return func(c *echo.Context) error {
		flow := defaultFlow
		if q := c.QueryParam("flow"); q == flowLogin || q == flowRegister || q == flowReset {
			flow = q
		}
		// 行查询只取 sso 注入与 scope（buildMethods 对非 login 流不消费交集）；
		// tpl 丢弃——本壳不走客户端模板。
		_, ssoRow := h.resolveLoginClientTpl(c.Request().Context(), c.QueryParam("client_id"))
		scope, err := ssoScopeFromRow(ssoRow)
		if err != nil {
			slog.Error("pages: parse sso client config", "err", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		var ssoCtx *ssoContext
		if ssoRow != nil {
			ssoCtx = &ssoContext{ClientID: ssoRow.ClientID, Name: ssoRow.Name}
		}
		snapshot, err := h.buildMethods(c.Request().Context(), flow, scope)
		if err != nil {
			slog.Error("pages: build methods snapshot", "flow", flow, "err", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		return h.renderShell(c, entry, &initPayload{
			ALRoot:         h.root,
			StaticBase:     h.staticBase(),
			Methods:        snapshot,
			SSO:            ssoCtx,
			PasswordPolicy: h.passwordPolicy(),
		}, nil)
	}
}

// loginDefaultLanding 已登录直达终点③ 的默认落点（§8 专段，同 §1.3 终点 3）：
// hash 路由形态、本域相对路径，与前端 DEFAULT_ACCOUNT_HOME 同一值。
const loginDefaultLanding = "/account#/"

// loginEntry /sso/login 入口（§8「/sso/login 已登录直达」专段）：渲染空壳前
// 先校验 al_session——判定口径与 /auth/authorize 直达一致，复用同一
// SessionVerifier 注入与四步语义（含 epoch）。有效会话不渲染页面、不经过
// 前端、不注入快照，按终点顺序直接 302（三种情形互斥完备，与 §1.3 终点
// 2 / 3 同序）；校验故障（校验异常、epoch 失效等一切「非有效」情形）一律按
// 无会话处理：照常渲染空壳并按 §2.1 注入（安全向 fail-closed，不 302、不
// 渲染错误页）。直达 302 不插入 /sso/sync_cookie 中转——§2.9 同步链只覆盖
// 登录成功与登出的会话传播，直达本域会话已有效、无传播需求。
func (h *Handler) loginEntry(c *echo.Context) error {
	if h.authorizeSession(c) != nil {
		return c.Redirect(http.StatusFound, h.loginDirectTarget(c))
	}
	return h.serveLoginShell(c, flowLogin)
}

// loginDirectTarget 已登录直达终点解析（§8 专段三步，互斥完备）：① URL 携带
// returnTo 且白名单校验通过 → 原值回跳；② 页面 client_id 命中已启用的
// sso_client 行（禁用应用不命中，同 §2.2 首签对禁用应用的保守口径，禁用应用
// 永不获得默认回跳）且该应用 default_redirect_uri 非空并命中本应用
// redirectUris 白名单 → 该默认回跳地址；③ 否则默认落点。未携带 / 白名单外 /
// 未命中 / 禁用不是错误，向后回落；SsoClients 未装配 / 行查询异常同按未命中
// 处理。
func (h *Handler) loginDirectTarget(c *echo.Context) string {
	if rt := c.QueryParam("returnTo"); isReturnToAllowed(rt) {
		return rt
	}
	if h.deps.SsoClients != nil {
		if id := c.QueryParam("client_id"); id != "" {
			if row, err := h.deps.SsoClients.FindSsoClientByClientID(c.Request().Context(), id); err == nil && row != nil &&
				row.IsEnabled == 1 && row.DefaultRedirectURI != "" &&
				ssoRedirectAllowed(row, row.DefaultRedirectURI) {
				return row.DefaultRedirectURI
			}
		}
	}
	return loginDefaultLanding
}

// isReturnToAllowed returnTo 白名单（§8 专段①）：仅放行 /account# / /admin#
// 站内 hash 前缀值，与前端 shared/urls.ts 的前缀白名单同一集合（防开放
// 重定向；前缀含 #，/accounts#… 等近似路径不误放）。
func isReturnToAllowed(v string) bool {
	return strings.HasPrefix(v, "/account#") || strings.HasPrefix(v, "/admin#")
}

// ssoRedirectAllowed default_redirect_uri 对本应用 redirectUris 白名单的
// 既有匹配（§12.3 整段匹配 / * 通配，与 authorize redirect_uri 白名单同一套
// uriMatches 匹配语义）：解码失败 / 未命中一律不放行——配置期强制命中（
// §5.5）之外的运行期防线，配置漂移时向后回落默认落点，不开放重定向。
func ssoRedirectAllowed(row *model.SsoClient, target string) bool {
	uris, err := repo.ParseClientRedirectUris(row.RedirectURIs)
	if err != nil {
		return false
	}
	for _, pattern := range uris.GetUris() {
		if uriMatches(pattern, target) {
			return true
		}
	}
	return false
}

// serveLoginShell 渲染登录 entry 空壳（loginPage 的 callback 路径与
// loginEntry 无会话路径共用；register / reset 走 flowEntryShell 独立壳）：
// 注入 al_root / static_base / methods（必填）。
// flow 按 §2.1 行 363-368 取页面 URL query（login 默认）；路径缺省即 login
// （前端入口链接不带 query，依赖按页过滤的快照）。
// client_id 按 §8.1 选客户端自定义模板（SSO 登录入口查 sso_client），行
// 命中状态传入 methods 组装——命中 sso_client 行时应用级交集即 flow=login
// 的方式过滤，并同时注入
// __AUTHLOFT_INIT__.sso（§2.1 注入结构：clientId / name，转义走 INIT_JSON
// 既有口径）；行命中与模板解析正交——模板回落（含无自定义模板的常态）仍
// 注入 sso，查无行回落壳才不注入。应用配置列解码失败 → 空体 500（§8 行
// 1436「缺失即服务端故障」，§1.5 行 225 豁免端点按 HTTP 语义）。
func (h *Handler) serveLoginShell(c *echo.Context, defaultFlow string) error {
	flow := defaultFlow
	if q := c.QueryParam("flow"); q == flowLogin || q == flowRegister || q == flowReset {
		flow = q
	}
	tpl, ssoRow := h.resolveLoginClientTpl(c.Request().Context(), c.QueryParam("client_id"))
	scope, err := ssoScopeFromRow(ssoRow)
	if err != nil {
		slog.Error("pages: parse sso client config", "err", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	var ssoCtx *ssoContext
	if ssoRow != nil {
		ssoCtx = &ssoContext{ClientID: ssoRow.ClientID, Name: ssoRow.Name}
	}
	snapshot, err := h.buildMethods(c.Request().Context(), flow, scope)
	if err != nil {
		slog.Error("pages: build methods snapshot", "flow", flow, "err", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	return h.renderShell(c, "login", &initPayload{
		ALRoot:         h.root,
		StaticBase:     h.staticBase(),
		Methods:        snapshot,
		SSO:            ssoCtx,
		PasswordPolicy: h.passwordPolicy(),
	}, tpl)
}

// renderShell 渲染 SPA 空壳：tpl 非 nil（客户端模板解析成功）走
// RenderClientShell 用自定义内容渲染，否则回落 RenderShell 读默认文件壳
// （§8.1 第 6 步）。两条路径共用 nonce 消费 / CSP 头 / no-store / 500 语义；
// static_base 取 settings 快照（nil 回落默认 /assets），site_name 同理（nil /
// 缺失 / 空回落默认 Authloft）。
func (h *Handler) renderShell(c *echo.Context, entry string, init *initPayload, tpl *clientTemplate) error {
	staticBase := h.staticBase()
	siteName := h.siteName()
	if tpl != nil {
		return RenderClientShell(c, tpl.html, init, staticBase, tpl.varsJSON, siteName)
	}
	return RenderShell(c, entry, init, staticBase, siteName)
}

// staticBase settings 键 static_base（§5.6 默认 /assets，可为 CDN 绝对
// 地址）；缺失 / 空 / 无 settings 时回落默认。
func (h *Handler) staticBase() string {
	if h.settings != nil {
		if v, ok := h.settings.GetString(settings.KeyStaticBase); ok && v != "" {
			return v
		}
	}
	return "/assets"
}

// siteName settings 键 site_name（§5.6 默认 Authloft，页面标题）；缺失 / 空 /
// 无 settings 时回落默认。值为管理员配置（不可信），HTML 文本上下文转义在
// renderHTML 构造注入值时完成（§8.1），本层只取原值。
func (h *Handler) siteName() string {
	if h.settings != nil {
		if v, ok := h.settings.GetString(settings.KeySiteName); ok && v != "" {
			return v
		}
	}
	return settings.DefaultSiteName
}

// passwordPolicy settings pwd_* 三键（§5.6）→ 注入快照 passwordPolicy（§2.1）：
// 越界 / 缺失键回落默认 8 / 64 / 3（与三处 service 的 settings 读取同口径；
// 校验权威在 security/policy.go，本层只装配下发值、不改各 service 校验）。
// 恒注入——未配置 settings 时下发默认档，前端未拿到注入时回落同一组默认值，
// 两层兜底口径一致。
func (h *Handler) passwordPolicy() *passwordPolicyInit {
	minLength, maxLength, classes := 8, 64, 3
	if h.settings != nil {
		if v, ok := h.settings.GetInt64(settings.KeyPwdMinLength); ok && v > 0 {
			minLength = int(v)
		}
		if v, ok := h.settings.GetInt64(settings.KeyPwdMaxLength); ok && v > 0 {
			maxLength = int(v)
		}
		if v, ok := h.settings.GetInt64(settings.KeyPwdRequireClasses); ok && v >= 1 && v <= 3 {
			classes = int(v)
		}
	}
	return &passwordPolicyInit{
		MinLength:      strconv.Itoa(minLength),
		MaxLength:      strconv.Itoa(maxLength),
		RequireClasses: strconv.Itoa(classes),
	}
}

// genNonce 生成 CSP nonce（crypto/rand 16 字节 base64url，22 字符）：
// RenderShell 未经中间件路径的兜底（中间件路径用 middleware.CSP 的
// security.RandomString）。
func genNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
