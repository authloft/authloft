// authorize.go GET /auth/authorize（接口文档 §4.2 行 1059-1089 / §8 行 1461、
// 后端架构 §14.2 授权流程）：OIDC 授权入口，discovery 已广告
// authorization_endpoint（handler/oidc）。校验矩阵与两条路径：
//
//   - client_id 非法（缺失 / 不存在 / 未启用）或 redirect_uri 未命中该客户端
//     redirect_uris 白名单（整段匹配支持 * 通配，复用 logout.go
//     matchClientRedirectURI / uriMatches）→ 不跳转，HTTP 400 简短错误页
//     （防开放重定向，无注入内容）；
//   - redirect_uri 校验通过后 scope 含未支持值（支持值 = discovery
//     scopes_supported 同一清单，internal/oidc 导出口径）→ 302
//     redirect_uri?error=invalid_scope&state=…（state 缺失省略）；
//   - state 缺失不属参数错误：不拒绝、正常签发与跳转、URL 不带 state、不做
//     CSRF 比对，改记审计事件 oidc_authorize_no_state（actor_type=system，
//     §4.2 行 1074）——orchestrator Terminal 侧无该审计写点，本端点记一次
//     即覆盖「authorize 直签」与「登录后 Terminal 签发」两条路径，不双记；
//   - prompt=none 且无有效会话 → 不渲染空壳，302
//     redirect_uri?error=login_required&state=…（同上省略规则）；prompt=login
//     忽略（不支持强制重认证）；
//   - 有有效会话（Cookie al_session 经 SessionVerifier 四步校验含 epoch）→
//     用注入的 CodeIssuer（与 Terminal 共用同一实例，§14.2 行 1642「两条
//     路径共用同一注入的 OIDCCodeIssuer，不得各写一份」）生成一次性授权码
//     → 302 redirect_uri?code=…&state=…（amr / auth_time 取会话载荷，同
//     请求上下文）；PKCE 两参数透传（method 非 S256 由 token 端点消费侧
//     ValidatePKCE 兜底校验）；
//   - 无会话 → 渲染登录空壳（login entry，URL 保持 /auth/authorize 不重写），
//     methods 必填（§8 行 1478）+ OIDC 七原始参数原样注入
//     __AUTHLOFT_INIT__.oidc（snake_case，§4.2 行 1081）→ 前端首次请求以
//     body 顶层 oidc 回传。
package pages

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"authloft/gen/go/token"
	"authloft/internal/eventlog"
	"authloft/internal/oidc"
	"authloft/internal/repo/model"
	"authloft/internal/service/orchestrator"
	"authloft/internal/session"
	"authloft/internal/settings"
)

// 编译期断言：装配层注入的具体类型满足窄接口（shell.go 定义）。
var (
	_ SessionVerifier = (*session.Verifier)(nil)
	_ CodeIssuer      = (*oidc.CodeIssuer)(nil)
	_ AuditSink       = (*eventlog.Writer)(nil)
)

// oidcAuthorizeInit __AUTHLOFT_INIT__.oidc 注入体（§4.2 行 1081「OIDC 原始
// 参数由 Go 原样注入」/ §8 行 1479 白名单）：七键恒定存在（snake_case 原样，
// 值为解码后的原始 query 值），缺失参数以空串注入——键集稳定，前端读取不漂移。
type oidcAuthorizeInit struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// authorize GET /auth/authorize：分支与顺序见文件注释（校验矩阵 §4.2 行
// 1071-1076 全覆盖）。
func (h *Handler) authorize(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")

	// 1. client_id / redirect_uri 校验（§4.2 行 1073）：任一不通过都不跳转
	//    （400 简短错误页，防开放重定向）。白名单整段匹配复用 logout.go。
	if clientID == "" || redirectURI == "" ||
		!h.matchClientRedirectURI(c.Request.Context(), clientID, redirectURI) {
		authorizeError(c)
		return
	}

	// 2. scope 校验（§4.2 行 1075）：缺省补 DefaultScope；含未支持值 →
	//    302 error=invalid_scope（redirect_uri 已验证可信，不签发）。
	scope := c.Query("scope")
	if scope == "" {
		scope = oidc.DefaultScope
	}
	state := c.Query("state")
	if !oidc.ScopeSupported(scope) {
		redirectAuthorizeError(c, redirectURI, "invalid_scope", state)
		return
	}

	// 3. 会话校验（§11.1 四步）。
	sess := h.authorizeSession(c)

	// 4. prompt=none 且无有效会话 → login_required（不渲染空壳，
	//    §4.2 行 1076）；prompt=login 忽略。
	if sess == nil && promptHasNone(c.Query("prompt")) {
		redirectAuthorizeError(c, redirectURI, "login_required", state)
		return
	}

	// 5. state 缺失：改记审计（§4.2 行 1074）。审计点在全部错误分支之后，
	//    只对正常路径（直签 / 空壳登录）记账，错误跳转不记。
	if state == "" {
		h.auditAuthorizeNoState(c, clientID)
	}

	// 6. 有有效会话 → 同一 CodeIssuer 签发一次性授权码 → 302 code（§14.2
	//    行 1636：不渲染页面、不经过前端）。
	if sess != nil {
		if h.codes == nil {
			slog.Error("pages: authorize code issuer not configured")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		code, err := h.codes.Issue(c.Request.Context(), orchestrator.OIDCIssue{
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			Scope:               scope,
			Nonce:               c.Query("nonce"),
			CodeChallenge:       c.Query("code_challenge"),
			CodeChallengeMethod: c.Query("code_challenge_method"),
			UID:                 sess.GetId(),
			AMR:                 sess.GetAmr(),
			AuthTime:            sess.GetIat(),
		})
		if err != nil {
			slog.Error("pages: authorize issue code", "err", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.Redirect(http.StatusFound, appendQuery(redirectURI, url.Values{
			"code":  {code},
			"state": {state}, // 空串由 appendQuery 剔除（缺失省略）
		}))
		return
	}

	// 7. 无会话 → 渲染登录空壳（login entry，URL 保持 /auth/authorize）：
	//    methods 必填（缺失即服务端故障 500，§8 行 1478）+ OIDC 七原始参数
	//    原样注入（scope 注入原始 query 值而非缺省补值——「原样」，§4.2
	//    行 1081；缺省逻辑由登录流程收编后统一应用）。
	snapshot, err := h.buildMethods(c.Request.Context(), flowLogin)
	if err != nil {
		slog.Error("pages: authorize build methods", "err", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	oidcInit, err := json.Marshal(oidcAuthorizeInit{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               c.Query("scope"),
		State:               state,
		Nonce:               c.Query("nonce"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
	})
	if err != nil {
		slog.Error("pages: authorize marshal oidc init", "err", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	h.renderShell(c, "login", &initPayload{
		ALRoot:     h.root,
		StaticBase: h.staticBase(),
		Methods:    snapshot,
		OIDC:       oidcInit,
	})
}

// authorizeSession al_session 校验（§11.1 四步）：无 Cookie / 未登录 / 会话
// 失效 / 校验链故障一律按「无有效会话」处理（安全向：绝不把校验故障误判为
// 已登录；prompt=none 语境发 login_required 亦符合 OIDC 保守语义）。
// Sessions 未装配（nil）同按无会话。
func (h *Handler) authorizeSession(c *gin.Context) *token.SessionTokenPayload {
	if h.sessions == nil {
		return nil
	}
	name := h.stringSetting(settings.KeyCookieName, defaultCookieName)
	ck, err := c.Request.Cookie(name)
	if err != nil {
		return nil // 无 Cookie = 无会话
	}
	p, err := h.sessions.Verify(c.Request.Context(), ck.Value)
	if err != nil {
		return nil
	}
	return p
}

// auditAuthorizeNoState 投递 oidc_authorize_no_state 审计事件（§4.2 行 1074、
// 后端架构 §4.6：actor_type=system、actor_id=0）：detail 无文档定义不自行
// 构造（nil 落 NULL）；ClientID / IP / UA 供排障。Audit 未装配静默跳过
// （审计缺失不阻断授权主链路）。
func (h *Handler) auditAuthorizeNoState(c *gin.Context, clientID string) {
	if h.audit == nil {
		return
	}
	ua := c.Request.UserAgent()
	if len(ua) > 512 { // model.EventLog.UA 列上限；截断尾部无效 UTF-8 字节
		ua = strings.ToValidUTF8(ua[:512], "")
	}
	h.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventOIDCAuthorizeNoState,
		ActorType: eventlog.ActorTypeSystem,
		ClientID:  clientID,
		IP:        c.ClientIP(),
		UA:        ua,
	})
}

// redirectAuthorizeError 302 回 redirect_uri 携带 error（+state，缺失省略，
// §4.2 行 1075 / 1076 两分支同构：invalid_scope / login_required）。
func redirectAuthorizeError(c *gin.Context, redirectURI, errorCode, state string) {
	c.Redirect(http.StatusFound, appendQuery(redirectURI, url.Values{
		"error": {errorCode},
		"state": {state},
	}))
}

// authorizeError 简短 400 错误页（§4.2 行 1073：不跳转、防开放重定向）：
// 纯静态 HTML——不渲染 SPA 空壳、不注入 __AUTHLOFT_INIT__、不回显任何请求
// 参数（错误参数不可信，回显即引入注入面）；no-store 防中间层缓存。
func authorizeError(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusBadRequest, "text/html; charset=utf-8", []byte(`<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Authloft</title></head>
<body><p>invalid_request: client_id or redirect_uri is not allowed.</p></body></html>
`))
}

// appendQuery 往 base 追加 query 参数（302 Location 构造）：已带 query 用
// &、否则 ?；含 fragment 时参数插在 # 之前（防御——注册面不应带 fragment）。
// 值为空串的键剔除（state 缺失即省略该参数，§4.2 行 1066）。
func appendQuery(base string, kv url.Values) string {
	for k, v := range kv {
		if len(v) == 1 && v[0] == "" {
			delete(kv, k)
		}
	}
	suffix := kv.Encode()
	if suffix == "" {
		return base
	}
	head, frag := base, ""
	if i := strings.Index(base, "#"); i >= 0 {
		head, frag = base[:i], base[i:]
	}
	sep := "?"
	if strings.Contains(head, "?") {
		sep = "&"
	}
	return head + sep + suffix + frag
}

// promptHasNone OIDC prompt 为空格分隔列表：任一取值为 none 即按 none
// 处理；login / 其他取值忽略（§4.2 行 1069：login 本期不支持强制重认证）。
func promptHasNone(prompt string) bool {
	for _, v := range strings.Fields(prompt) {
		if v == "none" {
			return true
		}
	}
	return false
}
