// Package gateway 实现网关域唯一端点 `ANY /api/gateway/decode`（接口文档
// §6 行 1346-1361、后端架构 §17 行 1768）：解 session_token 并以
// X-Session-* 响应头返回 SessionTokenPayload 全部字段，状态码恒 200、
// 纯响应头、无响应体（§1.0 行 66 豁免清单）。X-Gateway-Token 校验归
// Gateway 中间件（§3.3 行 314，无效 403 空体，§1.5 行 188），本 handler
// 绝不 401/403。
//
// 解码 / 校验复用 session.Tokens.Parse + Verifier.Verify（§11.1 四步，
// 不新造第二套）；令牌取值优先级 X-Authloft-Token Header → Cookie 与来源
// 判定经 connect.PickSessionToken 与 Connect 会话拦截器共用同一实现（取值
// 顺序而非失败回退，口径同 §1.2）；失效分支的清理头按令牌来源分流
// 且互斥（§6 / §1.9）。
package gateway

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"

	"authloft/internal/connect"
	"authloft/internal/logx"
	"authloft/internal/session"
)

// sessionTokenHeader 会话令牌请求头（§6 行 1352、§1.2 行 120、SDK-init
// §3 HeaderKey 同值）。connect 拦截器同名常量为包私有，此处按文档值
// 重复定义（先例：internal/connect/interceptors.go 行 42）。
const sessionTokenHeader = "X-Authloft-Token"

// X-Session-* 响应头（§6 行 1354-1359「部分字段例，详见
// SessionTokenPayload」；头名 = X-Session- + payload 字段名大写，SDK-init
// §4.1 行 62：id = 用户 ID、sid = 会话 ID）。HTTP 字段名大小写不敏感
// （RFC 9110 §5.1），net/http 写出时按 canonical MIME 形式呈现（如
// X-Session-AMR → X-Session-Amr），消费方按大小写不敏感读取（SDK 即如此）。
const (
	headerStatus = "X-Session-Status" // valid / invalid（§6 行 1356）
	headerID     = "X-Session-ID"     // payload.id（用户 ID）
	headerEpoch  = "X-Session-Epoch"  // payload.epoch（用户安全版本号）
	headerAMR    = "X-Session-AMR"    // payload.amr（逗号分隔，§6 行 1359）
	headerSID    = "X-Session-SID"    // payload.sid（会话 ID）
	headerIat    = "X-Session-Iat"    // payload.iat（签发时间 Unix 秒）
	headerExp    = "X-Session-Exp"    // payload.exp（过期时间 Unix 秒）
)

// statusValid / statusInvalid X-Session-Status 取值（§6 行 1356 封闭二值）。
const (
	statusValid   = "valid"
	statusInvalid = "invalid"
)

// invalidationTokenNone 失效指令字面量（§1.2 / §6）：经 X-Authloft-Token
// 响应头下发，不是令牌——客户端收到即清空本地令牌，不得解析或回传。
const invalidationTokenNone = "none"

// Deps 端点依赖（全部由装配层构造注入，叶子件不读 settings / config）：
// Verify 复用 assemble 共享单例（sessionTokens / epochStore）；Cookie 为
// 会话 Cookie 属性构造器（与登录 / 续期下发同一实例），Cookie 来源令牌的
// 失效清理头经其 Clear 构造（nil 时跳过清理头——装配缺省防御，生产恒注入）；
// CookieName 为 Cookie 名动态源（settings 键 cookie_name 每请求读取，空值
// 回落 al_session），nil 时直接用默认名。
type Deps struct {
	Verify     *session.Verifier
	Cookie     *session.Cookie
	CookieName func() string
}

// Register 注册网关域唯一端点到 /api/gateway 路由组（ANY，§6 行 1350）。
// Gateway 中间件（X-Gateway-Token 校验）由装配层在组上先挂（bootstrap
// registerGateway），本包不挂中间件（口径同 handler/oidc）。X-Request-Id
// 由 echo 全局链 requestid 统一回写（§1.1），本包不重复写。
func Register(r *echo.Group, deps Deps) {
	h := &handler{deps: deps}
	r.Any("/decode", h.decode)
}

type handler struct {
	deps Deps
}

// decode `ANY /api/gateway/decode`（§6 行 1350-1361）：恒 200、纯响应头、
// 无响应体。无 / 篡改 / 过期 / epoch 不一致 / 已逐出的令牌一律
// X-Session-Status: invalid，不携带其余字段头；失效分支按令牌来源追加
// 清理头且互斥（§6 / §1.9）：Header 来源 → X-Authloft-Token: none、Cookie
// 来源 → Set-Cookie 清除，无令牌不下发任何清理头；唯一非 200 出口是失效
// 检查读取链基础设施故障（verify.go 口径：不得与未登录混同）→ 500 空体。
func (h *handler) decode(c *echo.Context) error {
	tok, fromHeader := h.pickToken(c)
	if tok == "" {
		return writeStatus(c, statusInvalid)
	}
	p, err := h.deps.Verify.Verify(c.Request().Context(), tok)
	switch {
	case err == nil:
	case errors.Is(err, session.ErrNotAuthenticated), errors.Is(err, session.ErrSessionStale),
		errors.Is(err, session.ErrSessionRevoked):
		// 解不开（kid 未知 / 篡改 / 跨 purpose）/ 过期 / epoch 不一致 /
		// 已逐出：会话无效，恒 200 + invalid（403 归 Gateway 中间件管，
		// §6）+ 按令牌来源的清理头（互斥）。
		h.writeInvalidation(c, fromHeader)
		return writeStatus(c, statusInvalid)
	default:
		// 失效检查读取链故障（fail-open 回源也失败，verify.go）：
		// 基础设施错误不得误判为登出态，按豁免端点原生最小形态 500 空体
		// 拒绝（口径同 connect 会话拦截器 internal 错误分支）。本域是 echo
		// REST 端点、不在 Connect 错误日志拦截链内，且响应无错误体，必须
		// 就地留痕；只记错误文本，不记令牌串。
		logx.Error(c.Request().Context(), "gateway: session verify infra failure",
			"step", "verify", "error", logx.RedactText(err.Error()))
		return c.NoContent(http.StatusInternalServerError)
	}
	// 有效：payload 全字段逐项映射（proto/token/session.proto 行 14-27；
	// 字段输出顺序 = proto 编号顺序）。amr 逗号分隔、空数组输出空值头
	//（§6 行 1361——nil 与空切片经 strings.Join 同为空值）。
	setHeader(c, headerStatus, statusValid)
	setHeader(c, headerID, strconv.FormatInt(p.GetId(), 10))
	setHeader(c, headerEpoch, strconv.FormatInt(p.GetEpoch(), 10))
	setHeader(c, headerAMR, strings.Join(p.GetAmr(), ","))
	setHeader(c, headerSID, p.GetSid())
	setHeader(c, headerIat, strconv.FormatInt(p.GetIat(), 10))
	setHeader(c, headerExp, strconv.FormatInt(p.GetExp(), 10))
	return c.NoContent(http.StatusOK)
}

// writeStatus 写最小状态响应（恒 200、仅 X-Session-Status、空体）。
func writeStatus(c *echo.Context, status string) error {
	setHeader(c, headerStatus, status)
	return c.NoContent(http.StatusOK)
}

// setHeader 写响应头（http.Header.Set 原样保留空值）：§6 行 1361 要求空
// 数组「输出空值」——amr 为空（nil / 空切片）时头仍在、值为空；proto
// string 字段 sid 空串同理（全字段恒输出）。
func setHeader(c *echo.Context, key, value string) {
	c.Response().Header().Set(key, value)
}

// writeInvalidation 失效分支的清理头（§6 / §1.9，按令牌来源分流且互斥）：
// Header 来源 → X-Authloft-Token: none；Cookie 来源 → Set-Cookie 清除同名
// 会话 Cookie（MaxAge=-1，属性经同一构造器按当前请求判定——echo 链拿得到
// 真实 *http.Request，Header 与 TLS 双信号齐供）。Cookie 构造器未注入时
// 跳过（装配缺省防御，生产恒注入）。
func (h *handler) writeInvalidation(c *echo.Context, fromHeader bool) {
	if fromHeader {
		setHeader(c, sessionTokenHeader, invalidationTokenNone)
		return
	}
	if h.deps.Cookie == nil {
		return
	}
	sig := session.RequestSignal{Header: c.Request().Header, TLS: c.Request().TLS != nil}
	http.SetCookie(c.Response(), h.deps.Cookie.Clear(sig))
}

// pickToken 取 session_token 及其来源（§6：X-Authloft-Token Header
// → Cookie）。优先级是取值顺序而非失败回退——Header 有值即用、无效不回落
// Cookie（口径同 connect 会话拦截器）；实现经 connect.PickSessionToken 共用，
// 防两处判定漂移。
func (h *handler) pickToken(c *echo.Context) (string, bool) {
	return connect.PickSessionToken(c.Request().Header, h.deps.CookieName)
}
