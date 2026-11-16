// Package pages 页面壳路由族（接口文档 §8 行 1486-1543）：/sso/login、
// /sso/register、/sso/reset、/sso/oauth/callback/{provider_key}（login
// entry）、/account、/admin（仅根映射，account / admin entry；子路径走
// 前端 hash 路由，未注册子路径 gin 原生 404，通配收窄）的 SPA 空壳渲染，
// 外加 /sso/logout（§2.9）与 /sso/sync_cookie 中转（§11.2 接收端）。
//
// 壳层 HTML 不由后端手写：读前端构建产物模板（render.go //go:embed
// templates）+ 五占位符纯字符串全量替换，注入 window.__AUTHLOFT_INIT__
// （五键白名单 + JSON 编码 <>& 与 \u2028/\u2029 转义）、Cache-Control:
// no-store、CSP nonce、不注入任何凭证（CSP 终稿：基线 =
// middleware/csp.go + cdnOrigin 追加，setup 壳同基线）。注入键白名单
// （§8 行 1534-1541）：al_root / static_base 三端，methods（login 必填，
// 缺失即服务端故障）、oidc（login 可选，/auth/authorize 渲染空壳时注入）、
// sso（login 可选，登录端入口命中 sso_client 行时注入，§2.1）。
package pages

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"authloft/gen/go/token"
	"authloft/internal/captcha"
	"authloft/internal/factor"
	"authloft/internal/provider"
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
// （al_root / static_base 三端，methods login 必填，oidc / sso login 可选）。
// oidc 为 json.RawMessage 注入位——/auth/authorize 渲染登录空壳时填充
// （authorize.go，§4.2 行 1081），其余路由不注入（nil 时 omitted）。sso 为
// SSO 应用上下文（§2.1）——登录端入口命中 sso_client 行时填充（loginPage），
// authorize 入口不注入（nil 时 omitted）。
type initPayload struct {
	ALRoot     string           `json:"al_root"`
	StaticBase string           `json:"static_base"`
	Methods    *MethodsSnapshot `json:"methods,omitempty"`
	OIDC       json.RawMessage  `json:"oidc,omitempty"`
	SSO        *ssoContext      `json:"sso,omitempty"`
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
	root       string
	rootDomain string
	settings   SettingsReader
	loader     ProviderLister
	factors    FactorSource
	gate       CaptchaConfiger
	sync       SyncBuilder
	codec      *security.Codec
	jwt        JWTVerifier
	clients    OidcClientReader
	sessions   SessionVerifier
	codes      CodeIssuer
	audit      AuditSink
	metas      func() []provider.Meta
	now        func() time.Time
	// deps 保存装配期窄接口集合，供 resolveClientTpl 复用（§8.1）。
	deps Deps
}

// Register 挂全部页面路由（§8 路由表 + §2.9 logout / sync_cookie + §4.2
// /auth/authorize 授权入口）。页面路由归 gin 链（Connect 域走 mux 前缀，
// 互不相交）。
func Register(r gin.IRouter, d Deps) *Handler {
	h := &Handler{
		root:       d.Root,
		rootDomain: d.RootDomain,
		settings:   d.Settings,
		loader:     d.Loader,
		factors:    d.Factors,
		gate:       d.Gate,
		sync:       d.Sync,
		codec:      d.Codec,
		jwt:        d.JWT,
		clients:    d.Clients,
		sessions:   d.Sessions,
		codes:      d.Codes,
		audit:      d.Audit,
		metas:      d.Metas,
		now:        d.Now,
		deps:       d,
	}
	if h.now == nil {
		h.now = time.Now
	}
	r.GET("/sso/login", h.loginPage(flowLogin))
	r.GET("/sso/register", h.loginPage(flowRegister))
	r.GET("/sso/reset", h.loginPage(flowReset))
	// callback 零业务逻辑（§2.7.3 行 604）：只渲染 login entry 空壳，
	// provider_key 路径参数不做任何业务校验（分派归前端）。
	r.GET("/sso/oauth/callback/:provider_key", h.loginPage(flowLogin))
	// 收窄：仅根映射——子路径走前端 hash 路由（/account#/…），
	// 不发往服务端；未注册子路径由 gin 原生 404 兜底（接口文档 §8）。
	r.GET("/account", h.entryPage("account"))
	r.GET("/admin", h.entryPage("admin"))
	r.GET("/sso/logout", h.logout)
	r.GET("/sso/sync_cookie", h.syncCookie)
	// OIDC 授权入口（§4.2）：discovery 已广告 authorization_endpoint。
	r.GET("/auth/authorize", h.authorize)
	return h
}

// entryPage account / admin entry 空壳：仅注入 al_root / static_base
// （§8 白名单，methods 是 login 必填项、account 无）。account / admin 不参与
// 客户端模板选壳（§8.1 仅 SSO 登录入口 / OIDC 授权入口），恒走文件壳。
func (h *Handler) entryPage(entry string) gin.HandlerFunc {
	return func(c *gin.Context) {
		h.renderShell(c, entry, &initPayload{
			ALRoot:     h.root,
			StaticBase: h.staticBase(),
		}, nil)
	}
}

// loginPage login entry 空壳（/sso/login、/sso/register、/sso/reset、
// /sso/oauth/callback/*）：注入 al_root / static_base / methods（必填）。
// flow 按 §2.1 行 363-368 取页面 URL query（login 默认）；三页各自带路径
// 缺省（前端入口链接不带 query，routes.tsx 行 67 依赖按页过滤的快照）。
// client_id 按 §8.1 选客户端自定义模板（SSO 登录入口查 sso_client），行
// 命中状态传入 methods 组装——命中 sso_client 行时应用级交集仅 flow=login
// 消费（register / reset 镜像全局口径，§2.1），并同时注入
// __AUTHLOFT_INIT__.sso（§2.1 注入结构：clientId / name，转义走 INIT_JSON
// 既有口径）；行命中与模板解析正交——模板回落（含无自定义模板的常态）仍
// 注入 sso，查无行回落壳才不注入。应用配置列解码失败 → 空体 500（§8 行
// 1436「缺失即服务端故障」，§1.5 行 225 豁免端点按 HTTP 语义）。
func (h *Handler) loginPage(defaultFlow string) gin.HandlerFunc {
	return func(c *gin.Context) {
		flow := defaultFlow
		if q := c.Query("flow"); q == flowLogin || q == flowRegister || q == flowReset {
			flow = q
		}
		tpl, ssoRow := h.resolveLoginClientTpl(c.Request.Context(), c.Query("client_id"))
		scope, err := ssoScopeFromRow(ssoRow)
		if err != nil {
			slog.Error("pages: parse sso client config", "err", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		var ssoCtx *ssoContext
		if ssoRow != nil {
			ssoCtx = &ssoContext{ClientID: ssoRow.ClientID, Name: ssoRow.Name}
		}
		snapshot, err := h.buildMethods(c.Request.Context(), flow, scope)
		if err != nil {
			slog.Error("pages: build methods snapshot", "flow", flow, "err", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		h.renderShell(c, "login", &initPayload{
			ALRoot:     h.root,
			StaticBase: h.staticBase(),
			Methods:    snapshot,
			SSO:        ssoCtx,
		}, tpl)
	}
}

// renderShell 渲染 SPA 空壳：tpl 非 nil（客户端模板解析成功）走
// RenderClientShell 用自定义内容渲染，否则回落 RenderGinShell 读默认文件壳
// （§8.1 第 6 步）。两条路径共用 nonce 消费 / CSP 头 / no-store / 500 语义；
// static_base 取 settings 快照（nil 回落默认 /assets），site_name 同理（nil /
// 缺失 / 空回落默认 Authloft）。
func (h *Handler) renderShell(c *gin.Context, entry string, init *initPayload, tpl *clientTemplate) {
	staticBase := h.staticBase()
	siteName := h.siteName()
	if tpl != nil {
		RenderClientShell(c, tpl.html, init, staticBase, tpl.varsJSON, siteName)
		return
	}
	RenderGinShell(c, entry, init, staticBase, siteName)
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

// genNonce 生成 CSP nonce（crypto/rand 16 字节 base64url，22 字符）：
// RenderGinShell 未经中间件路径的兜底（中间件路径用 middleware.CSP 的
// security.RandomString）。
func genNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
