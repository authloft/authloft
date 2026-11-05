// 会话 Cookie 属性构造与清除（接口文档 §1.9 行 286-310、后端架构
// §11.1 行 1175）：名默认 al_session（键 cookie_name）、有效期默认
// 7 天（键 session_ttl）、Domain 取根域——三者均由构造注入，不读
// settings（热更由装配方重构造注入）；HttpOnly 恒定。Secure / SameSite
// 受 settings 键 https_deployment 驱动（§1.9 行 299-310）：
// 判定为 HTTPS → Secure; SameSite=None；判定为明文 → 省略 Secure 且
// SameSite 联动降为 Lax（行 292：无 Secure 的 None 被浏览器拒收）。
// auto 推断与《SDK-init》§4.4 逐字对齐：X-Forwarded-Proto 逗号首值
// （忽略大小写，https → HTTPS；http 及其他任意值 → 明文）→ 头不存在
// 看请求自身 TLS → 无头无 TLS 兜底明文；头优先于 TLS（行 306-309）。
// 三态源经 WithHTTPSMode 注入（每请求读取，沿 cookie_name 热更口径，
// 不进程内缓存死值）；未注入的构造点沿旧默认恒按 HTTPS——既有调用方
// 零破坏。只构造 *http.Cookie，下发（http.SetCookie / Set-Cookie 头）归
// middleware / connect.AddSessionCookie。
package session

import (
	"context"
	"net/http"
	"strings"
	"time"

	"authloft/internal/settings"
)

// defaultCookieName Cookie 名默认值（接口文档 §1.9：al_session）。
const defaultCookieName = "al_session"

// xForwardedProtoHeader auto 推断首选信号头（§1.9 行 307 / SDK-init
// §4.4 规则 1：反代 TLS 终止在反代、服务端收到明文 + 头，头是该场景
// 唯一可靠来源）。
const xForwardedProtoHeader = "X-Forwarded-Proto"

// RequestSignal 请求侧 HTTPS 信号（auto 推断依据，§1.9 行 306-309）：
// Header 携带 X-Forwarded-Proto；TLS 为请求自身是否 TLS 直连。connect
// 链 AnyRequest 只暴露 Header（TLS 不可得，TLS 恒 false），由 session
// 拦截器入口采集并注入 ctx（WithRequestSignal）；gin 链在调用点从
// c.Request 显式构造（双信号齐供）。零值 = 无信号，auto 分支按明文
// 兜底（无头且无 TLS 即明文直连，SDK-init §4.4：写 Secure 会被浏览器
// 拒收、续期断链）。
type RequestSignal struct {
	Header http.Header
	TLS    bool
}

// requestSignalKey ctx 注入键（私有类型，包外无法伪造同型键）。
type requestSignalKey struct{}

// WithRequestSignal 把请求信号注入 ctx：connect 链装配层（session
// 拦截器）入口采集后注入，下游 handler / service 经
// RequestSignalFromContext 读取（sso 登录终点写点、thirdparty
// al_login_state 构造共用同一信号源）。
func WithRequestSignal(ctx context.Context, sig RequestSignal) context.Context {
	return context.WithValue(ctx, requestSignalKey{}, sig)
}

// RequestSignalFromContext 从 ctx 读请求信号；未注入返回零值（无信号）。
func RequestSignalFromContext(ctx context.Context) RequestSignal {
	if ctx == nil {
		return RequestSignal{}
	}
	sig, _ := ctx.Value(requestSignalKey{}).(RequestSignal)
	return sig
}

// CookieOption NewCookie 构造选项（Go 无可选参，variadic 承载：既有
// 3 参调用零改动，默认「签名不变或加可选参」）。
type CookieOption func(*Cookie)

// WithHTTPSMode 注入 https_deployment 三态源（每请求读取：装配层传
// settings.Store 读取闭包，沿 cookie_name 热更口径；键缺失返回空串，
// 判定侧按 auto 缺省）。未注入 → 恒按 HTTPS（旧默认，调用方零破坏）。
func WithHTTPSMode(mode func() string) CookieOption {
	return func(c *Cookie) { c.mode = mode }
}

// Cookie 会话 Cookie 属性构造器。
type Cookie struct {
	name   string
	domain string
	ttl    time.Duration
	// mode https_deployment 三态源（nil = 构造点未接入本键，恒 HTTPS）。
	mode func() string
}

// NewCookie 构造。name 传空串回落默认 al_session；domain 为根域
// （跨子域共享会话所需）；ttl 为有效期（settings 键 session_ttl，
// 默认 7 天，由装配方注入）；opts 注入 https_deployment 三态源等选项。
func NewCookie(name, domain string, ttl time.Duration, opts ...CookieOption) *Cookie {
	if name == "" {
		name = defaultCookieName
	}
	c := &Cookie{name: name, domain: domain, ttl: ttl}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ResolveHTTPS https_deployment 三态判定（§1.9 行 299-310 唯一判定点，
// al_session 与 al_login_state 共用本判定——全部下发点 Secure 属性
// 同源联动，行 301-305「同一个 Cookie 属性构造器」的判定半边）：
//
//	true → 恒按 HTTPS；false → 恒按明文；auto（含缺省 / 未知值防御）
//	→ 按请求信号推断（deriveAutoHTTPS）。mode nil（构造点未接入本键）
//	→ 沿旧默认恒 HTTPS。
func ResolveHTTPS(mode func() string, sig RequestSignal) bool {
	if mode == nil {
		return true
	}
	switch mode() {
	case settings.HTTPSDeploymentTrue:
		return true
	case settings.HTTPSDeploymentFalse:
		return false
	default:
		return deriveAutoHTTPS(sig)
	}
}

// deriveAutoHTTPS auto 推断（§1.9 行 306-309，与《SDK-init》§4.4
// DeriveCookieSecure 逐字同构）：
//
//  1. X-Forwarded-Proto 头存在 → 取逗号分隔首个值、忽略大小写判定：
//     https → 按 HTTPS；http 及其他任意值 → 按明文；
//  2. 头不存在 → 看请求自身 TLS：直连 → 按 HTTPS；无 TLS → 明文（兜底）；
//  3. 头优先于 TLS 判定：头与直连 TLS 并存且矛盾时，以显式头声明为准。
func deriveAutoHTTPS(sig RequestSignal) bool {
	if sig.Header != nil {
		if v := sig.Header.Get(xForwardedProtoHeader); v != "" {
			first := v
			if i := strings.IndexByte(first, ','); i >= 0 {
				first = first[:i]
			}
			return strings.EqualFold(strings.TrimSpace(first), "https")
		}
	}
	return sig.TLS
}

// Set 构造写值 Cookie（登录建会话 / 每次请求续期下发）。可选 sig 供
// auto 推断（§1.9 行 306：服务端在 Cookie 下发点按当前请求逐请求判定；
// 未传按无信号 → auto 兜底明文）。判定为 HTTPS → Secure; SameSite=None
//（§1.9 行 288）；明文 → 省略 Secure、SameSite=Lax（行 292 联动降级）。
func (c *Cookie) Set(value string, sig ...RequestSignal) *http.Cookie {
	secure := ResolveHTTPS(c.mode, firstSignal(sig))
	ck := &http.Cookie{
		Name:     c.name,
		Value:    value,
		Path:     "/",
		Domain:   c.domain,
		MaxAge:   int(c.ttl / time.Second),
		HttpOnly: true,
	}
	if secure {
		ck.Secure = true
		ck.SameSite = http.SameSiteNoneMode
	} else {
		ck.SameSite = http.SameSiteLaxMode
	}
	return ck
}

// Clear 构造清除 Cookie（登出 / 校验失败清 Cookie）。同名同 Path /
// Domain、MaxAge=-1 浏览器立即删除；其余属性与 Set 同判定保持一致，
// 确保覆盖到要删的那枚 Cookie（RFC 6265 删除匹配只看 name/domain/
// path，Secure 不参与匹配，属性对齐仅为一致性）。
func (c *Cookie) Clear(sig ...RequestSignal) *http.Cookie {
	ck := c.Set("", sig...)
	ck.MaxAge = -1
	return ck
}

// firstSignal variadic 首参；未传 = 零值（无信号）。
func firstSignal(sig []RequestSignal) RequestSignal {
	if len(sig) > 0 {
		return sig[0]
	}
	return RequestSignal{}
}
