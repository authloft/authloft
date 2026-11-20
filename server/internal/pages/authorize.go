// authorize.go GET /auth/authorize（接口文档 §4.2 行 1059-1089 / §8 行 1461、
// 后端架构 §14.2 授权流程）：OIDC 授权入口，discovery 已广告
// authorization_endpoint（handler/oidc）。校验矩阵与两条路径：
//
//   - client_id 非法（缺失 / 不存在 / 未启用）或 redirect_uri 未命中该客户端
//     redirect_uris 白名单（整段匹配支持 * 通配，复用 logout.go
//     matchClientRedirectURI / uriMatches）→ 不跳转，HTTP 400 简短错误页
//     （防开放重定向，无注入内容）；
//   - redirect_uri 校验通过后 scope 含未支持值或不含 openid（支持值 =
//     discovery scopes_supported 同一清单 + openid 必含，internal/oidc
//     导出口径 EntryScopeValid）→ 302
//     redirect_uri?error=invalid_scope&state=…（state 缺失省略）；
//   - state 缺失不属参数错误：不拒绝、正常签发与跳转、URL 不带 state、不做
//     CSRF 比对，改记审计事件 oidc_authorize_no_state（actor_type=system，
//     §4.2 行 1074）——orchestrator Terminal 侧无该审计写点，本端点记一次
//     即覆盖「authorize 直签」与「登录后 Terminal 签发」两条路径，不双记；
//   - prompt=none 且无有效会话 → 不渲染空壳，302
//     redirect_uri?error=login_required&state=…（同上省略规则）；prompt=login
//     忽略（不支持强制重认证）；
//   - 有有效会话（Cookie al_session 经 SessionVerifier 四步校验含 epoch）→
//     免同意直签前经注入的 AuthzValidator（与 Terminal 共用同一实例，
//     §14.2「不得各写一份」）复核 scope（必含 openid + ⊆ 注册 scopes），
//     再用注入的 CodeIssuer（与 Terminal 共用同一实例，两条路径共用同一
//     注入的 OIDCCodeIssuer，不得各写一份）生成一次性授权码
//     → 302 redirect_uri?code=…&state=…（amr / auth_time 取会话载荷，同
//     请求上下文）；PKCE 两参数透传（method 非 S256 由 token 端点消费侧
//     ValidatePKCE 兜底校验）；
//   - 无会话 → 渲染登录空壳（login entry，URL 保持 /auth/authorize 不重写），
//     methods 必填（§8 行 1478）+ OIDC 七原始参数原样注入
//     __AUTHLOFT_INIT__.oidc（snake_case，§4.2 行 1081）→ 前端首次请求以
//     body 顶层 oidc 回传。
package pages

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v5"

	"authloft/gen/go/token"
	"authloft/internal/eventlog"
	"authloft/internal/oidc"
	"authloft/internal/repo"
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
	_ Consents        = (*oidc.ConsentService)(nil)
	_ AuthzValidator  = (*oidc.AuthzValidator)(nil)
	_ ProfileReader   = (*repo.UserRepo)(nil)
)

// oidcAuthorizeInit __AUTHLOFT_INIT__.oidc 注入体（§4.2「OIDC 参数由 Go
// 注入」/ §8 白名单 / §5.1 注入契约扩展）：七授权参数恒定存在（snake_case
// 原样，值为解码后的原始 query 值，缺失以空串注入，键集稳定）；形态 A/B 另
// 注入 mode（login / consent，前端据此分派左栏）+ client_name（oidc_client.name，
// 右栏应用名）；形态 B 再注入 granted_scopes（该用户对该客户端的已授权 scope
// 集，Decision.GrantedScopes 已授权并集透传，规范化空格分隔、空集为空串恒
// 注入——前端据此锁定已授权项不可取消）+ account（当前账号摘要，§3.1 掩码
// 口径；两键形态 A 均省略——omitempty，键集按形态稳定）。scope 为缺省补值
// 后的有效 scope（§4.2 补充口径 / 评审裁决④：堵住「用户没见过就授权」的
// 静默扩权窗口）。
type oidcAuthorizeInit struct {
	ClientID            string           `json:"client_id"`
	RedirectURI         string           `json:"redirect_uri"`
	Scope               string           `json:"scope"`
	State               string           `json:"state"`
	Nonce               string           `json:"nonce"`
	CodeChallenge       string           `json:"code_challenge"`
	CodeChallengeMethod string           `json:"code_challenge_method"`
	Mode                string           `json:"mode"`
	ClientName          string           `json:"client_name"`
	GrantedScopes       *string          `json:"granted_scopes,omitempty"`
	Account             *oidcAccountInit `json:"account,omitempty"`
}

// oidcAccountInit 形态 B 左栏账号摘要（§5.1 account / §3.1 掩码矩阵）：昵称 /
// 头像 + 掩码账号标识（手机号 / 邮箱二选一，均掩码；无则用户名），不注入任何
// 凭证或完整手机号邮箱明文。随 INIT_JSON 走 json.Marshal 既有转义，无新增面。
type oidcAccountInit struct {
	Nickname   string `json:"nickname"`
	AvatarURL  string `json:"avatar_url"`
	Identifier string `json:"identifier"`
}

// authorize GET /auth/authorize：分支与顺序见文件注释（校验矩阵 §4.2 行
// 1071-1076 全覆盖）。
func (h *Handler) authorize(c *echo.Context) error {
	clientID := c.QueryParam("client_id")
	redirectURI := c.QueryParam("redirect_uri")

	// 1. client_id / redirect_uri 校验（§4.2 行 1073）：任一不通过都不跳转
	//    （400 简短错误页，防开放重定向）。白名单整段匹配复用 logout.go。
	if clientID == "" || redirectURI == "" ||
		!h.matchClientRedirectURI(c.Request().Context(), clientID, redirectURI) {
		return authorizeError(c)
	}

	// 2. scope 校验（§4.2 参数错误档）：缺省补 DefaultScope；含未支持值或
	//    不含 openid → 302 error=invalid_scope（redirect_uri 已验证可信）。
	//    空 scope 补值后恒含 openid 不命中此分支；注册 scopes 子集校验不在
	//    入口档——形态 A/B 由 Terminal / 同意 RPC 经 Validate 收口，形态 C
	//    由直签前 Validate 收口。
	scope := c.QueryParam("scope")
	if scope == "" {
		scope = oidc.DefaultScope
	}
	state := c.QueryParam("state")
	if !oidc.EntryScopeValid(scope) {
		return redirectAuthorizeError(c, redirectURI, "invalid_scope", state)
	}

	// 3. 会话校验（§11.1 四步）。
	sess := h.authorizeSession(c)

	// 4. prompt=none 且无有效会话 → login_required（不渲染空壳，
	//    §4.2 行 1076）；prompt=login 忽略。
	if sess == nil && promptHasNone(c.QueryParam("prompt")) {
		return redirectAuthorizeError(c, redirectURI, "login_required", state)
	}

	// 5. state 缺失：改记审计（§4.2 行 1074）。审计点在全部错误分支之后，
	//    只对正常路径（直签 / 空壳登录）记账，错误跳转不记。
	if state == "" {
		h.auditAuthorizeNoState(c, clientID)
	}

	// 6. 有有效会话 → 三态判定（§4.2 / §14.2 步骤 3）：Consents.Decide 以
	//    有效 scope 比对已授权并集，并合并 prompt=consent 强制。
	//    - 免同意（子集且 prompt≠consent）→ 形态 C：同一 CodeIssuer 直签
	//      一次性授权码 → 302 code（不渲染页面、不经过前端）；
	//    - 需同意且 prompt=none → 302 consent_required（零交互，不渲染）；
	//    - 需同意其余 → 形态 B：注入 mode=consent + client_name + granted_scopes
	//      （已授权并集，空集合法）+ 账号摘要渲染同意页，无登录表单、
	//      不 buildMethods（§8 methods 收窄）。
	if sess != nil {
		prompt := c.QueryParam("prompt")
		decision, err := h.decide(c.Request().Context(), sess.GetId(), clientID, scope, prompt)
		if err != nil {
			slog.Error("pages: authorize consent decide", "err", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		if decision.NeedsConsent && promptHasNone(prompt) {
			return redirectAuthorizeError(c, redirectURI, "consent_required", state)
		}
		if !decision.NeedsConsent {
			if h.codes == nil {
				slog.Error("pages: authorize code issuer not configured")
				return c.NoContent(http.StatusInternalServerError)
			}
			// 形态 C 签码前重跑授权参数校验（§14.2 与 Terminal 同一
			// AuthzValidator 实例，复用 internal/oidc 规则不在 pages 重写）：
			// scope 必含 openid 且 ⊆ 客户端注册 scopes（防授权记录漂移出注册
			// 集，如管理员收窄客户端 scopes 后的存量记录）；client / redirect
			// 已过入口档，此处再校验属同档复核。
			if _, err := h.authz.Validate(c.Request().Context(), clientID, redirectURI, scope); err != nil {
				switch {
				case errors.Is(err, oidc.ErrAuthzScope):
					return redirectAuthorizeError(c, redirectURI, "invalid_scope", state)
				case errors.Is(err, oidc.ErrAuthzClient), errors.Is(err, oidc.ErrAuthzRedirect):
					return authorizeError(c) // §4.2：client / redirect 档不跳转（防开放重定向）
				default:
					slog.Error("pages: authorize pre-issue authz validate", "err", err)
					return c.NoContent(http.StatusInternalServerError)
				}
			}
			code, err := h.codes.Issue(c.Request().Context(), orchestrator.OIDCIssue{
				ClientID:            clientID,
				RedirectURI:         redirectURI,
				Scope:               scope,
				Nonce:               c.QueryParam("nonce"),
				CodeChallenge:       c.QueryParam("code_challenge"),
				CodeChallengeMethod: c.QueryParam("code_challenge_method"),
				UID:                 sess.GetId(),
				AMR:                 sess.GetAmr(),
				AuthTime:            sess.GetIat(),
			})
			if err != nil {
				slog.Error("pages: authorize issue code", "err", err)
				return c.NoContent(http.StatusInternalServerError)
			}
			return c.Redirect(http.StatusFound, appendQuery(redirectURI, url.Values{
				"code":  {code},
				"state": {state}, // 空串由 appendQuery 剔除（缺失省略）
			}))
		}
		return h.renderConsent(c, clientID, scope, decision.GrantedScopes, state, h.accountSummary(c.Request().Context(), sess.GetId()))
	}

	// 7. 无会话 → 形态 A 登录双栏：渲染登录空壳（login entry，URL 保持
	//    /auth/authorize），methods 必填（缺失即服务端故障 500，§8）+ 注入
	//    mode=login / client_name / 有效 scope（缺省补值，§4.2 补充口径）。
	snapshot, err := h.buildMethods(c.Request().Context(), flowLogin)
	if err != nil {
		slog.Error("pages: authorize build methods", "err", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	oidcInit, err := json.Marshal(oidcAuthorizeInit{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		Nonce:               c.QueryParam("nonce"),
		CodeChallenge:       c.QueryParam("code_challenge"),
		CodeChallengeMethod: c.QueryParam("code_challenge_method"),
		Mode:                "login",
		ClientName:          h.clientName(c.Request().Context(), clientID),
	})
	if err != nil {
		slog.Error("pages: authorize marshal oidc init", "err", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	// client_id 已由上方 OIDC 校验层确认（§8.1 第 1 步）：复用同一解析入口
	// 按 oidc_client 选模板；未指定 / 解析失败回落默认文件壳，有会话 302
	// 路径不受影响。
	tpl := h.resolveClientTpl(c.Request().Context(), clientID, true)
	return h.renderShell(c, "login", &initPayload{
		ALRoot:         h.root,
		StaticBase:     h.staticBase(),
		Methods:        snapshot,
		OIDC:           oidcInit,
		PasswordPolicy: h.passwordPolicy(),
	}, tpl)
}

// decide 三态判定入口（§14.2 步骤 3）：Consents 已装配时委托 Decide；未装配
// （misassembly）按「全部需同意」fail-closed——绝不静默直签，最坏落到形态 B
// 由用户显式同意，不绕过授权记录。Authz 未装配同口径 fail-closed：形态 C
// 直签前须经同一校验工具复核 scope，缺校验器就不存在免同意直签。
func (h *Handler) decide(ctx context.Context, uid int64, clientID, scope, prompt string) (oidc.Decision, error) {
	if h.consents == nil || h.authz == nil {
		return oidc.Decision{NeedsConsent: true}, nil
	}
	return h.consents.Decide(ctx, uid, clientID, scope, prompt)
}

// renderConsent 形态 B 同意双栏（§4.2 / §5.1）：注入 mode=consent +
// client_name + granted_scopes + account 渲染 login entry（同一页壳按 mode
// 分派左栏），无登录表单故不 buildMethods（§8 methods 收窄为 mode=login
// 必填）。七个授权参数中的 scope 为缺省补值后的有效值（§4.2 补充口径）；
// granted 取 Decision.GrantedScopes 已授权并集原样透传（空集合法，键恒在）。
func (h *Handler) renderConsent(c *echo.Context, clientID, scope, granted, state string, account *oidcAccountInit) error {
	oidcInit, err := json.Marshal(oidcAuthorizeInit{
		ClientID:            clientID,
		RedirectURI:         c.QueryParam("redirect_uri"),
		Scope:               scope,
		State:               state,
		Nonce:               c.QueryParam("nonce"),
		CodeChallenge:       c.QueryParam("code_challenge"),
		CodeChallengeMethod: c.QueryParam("code_challenge_method"),
		Mode:                "consent",
		ClientName:          h.clientName(c.Request().Context(), clientID),
		GrantedScopes:       &granted,
		Account:             account,
	})
	if err != nil {
		slog.Error("pages: render consent marshal oidc init", "err", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	tpl := h.resolveClientTpl(c.Request().Context(), clientID, true)
	return h.renderShell(c, "login", &initPayload{
		ALRoot:     h.root,
		StaticBase: h.staticBase(),
		OIDC:       oidcInit,
	}, tpl)
}

// clientName 取 oidc_client.name 注入右栏应用名（§5.1 client_name）：client_id
// 已由参数校验确认存在启用，查询故障 / 未注入源按空串回落（展示字段，不阻断
// 授权主链路）。
func (h *Handler) clientName(ctx context.Context, clientID string) string {
	if h.clients == nil {
		return ""
	}
	row, err := h.clients.FindOidcClientByClientID(ctx, clientID)
	if err != nil || row == nil {
		return ""
	}
	return row.Name
}

// accountSummary 形态 B 左栏账号摘要（§3.1 掩码矩阵 / §5.1 account）：昵称 /
// 头像取 user 行，账号标识按手机号 → 邮箱 → 用户名取值，前两者按 §3.1 掩码，
// 不注入完整手机号邮箱明文与任何凭证。ProfileReader 未注入 / 查询故障按空
// 摘要回落（展示字段，不阻断同意主链路）。
func (h *Handler) accountSummary(ctx context.Context, uid int64) *oidcAccountInit {
	sum := &oidcAccountInit{}
	if h.profiles == nil {
		return sum
	}
	u, err := h.profiles.FindByID(ctx, uid)
	if err != nil || u == nil {
		return sum
	}
	sum.Nickname = u.Nickname
	sum.AvatarURL = u.AvatarURL
	if u.Phone != nil && *u.Phone != "" {
		sum.Identifier = maskAccountPhone(*u.Phone)
	} else if u.Email != nil && *u.Email != "" {
		sum.Identifier = maskAccountEmail(*u.Email)
	} else {
		sum.Identifier = u.Username
	}
	return sum
}

// maskAccountPhone / maskAccountEmail 账号标识掩码（§3.1 矩阵）：与 dto 同
// 口径——手机号前 3 + **** + 后 4（不足 8 位整体 ****），邮箱本地首字符 +
// *** + 域名（无 @ 仅 ***）。本页注入不复用 dto 私有函数，避免跨层依赖。
func maskAccountPhone(phone string) string {
	if len(phone) <= 7 {
		return "****"
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}

func maskAccountEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		return "***"
	}
	local := []rune(email[:at])
	if len(local) == 0 {
		return "***" + email[at:]
	}
	return string(local[0]) + "***" + email[at:]
}

// authorizeSession al_session 校验（§11.1 四步）：无 Cookie / 未登录 / 会话
// 失效 / 校验链故障一律按「无有效会话」处理（安全向：绝不把校验故障误判为
// 已登录；prompt=none 语境发 login_required 亦符合 OIDC 保守语义）。
// Sessions 未装配（nil）同按无会话。
func (h *Handler) authorizeSession(c *echo.Context) *token.SessionTokenPayload {
	if h.sessions == nil {
		return nil
	}
	name := h.stringSetting(settings.KeyCookieName, defaultCookieName)
	ck, err := c.Request().Cookie(name)
	if err != nil {
		return nil // 无 Cookie = 无会话
	}
	p, err := h.sessions.Verify(c.Request().Context(), ck.Value)
	if err != nil {
		return nil
	}
	return p
}

// auditAuthorizeNoState 投递 oidc_authorize_no_state 审计事件（接口文档 §4.2、
// 后端架构 §4.6：actor_type=system、actor_id=0）：detail 无文档定义不自行
// 构造（nil 落 NULL）；ClientID / IP / UA 供排障。Audit 未装配静默跳过
// （审计缺失不阻断授权主链路）。IP 取挂载层注入口径（echo IPExtractor 与
// connect 前缀链共用 orchestrator.ClientIPFromRequest：采信头由 settings 键
// client_ip_header 配置、未配置仅取直连，§13.0 / 采信边界接口文档 §1.1）。
func (h *Handler) auditAuthorizeNoState(c *echo.Context, clientID string) {
	if h.audit == nil {
		return
	}
	ua := c.Request().UserAgent()
	if len(ua) > 512 { // model.EventLog.UA 列上限；截断尾部无效 UTF-8 字节
		ua = strings.ToValidUTF8(ua[:512], "")
	}
	h.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventOIDCAuthorizeNoState,
		ActorType: eventlog.ActorTypeSystem,
		ClientID:  clientID,
		IP:        c.RealIP(),
		UA:        ua,
	})
}

// redirectAuthorizeError 302 回 redirect_uri 携带 error（+state，缺失省略，
// §4.2 行 1075 / 1076 两分支同构：invalid_scope / login_required）。
func redirectAuthorizeError(c *echo.Context, redirectURI, errorCode, state string) error {
	return c.Redirect(http.StatusFound, appendQuery(redirectURI, url.Values{
		"error": {errorCode},
		"state": {state},
	}))
}

// authorizeError 简短 400 错误页（§4.2 行 1073：不跳转、防开放重定向）：
// 纯静态 HTML——不渲染 SPA 空壳、不注入 __AUTHLOFT_INIT__、不回显任何请求
// 参数（错误参数不可信，回显即引入注入面）；no-store 防中间层缓存。
func authorizeError(c *echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.Blob(http.StatusBadRequest, "text/html; charset=utf-8", []byte(`<!DOCTYPE html>
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
