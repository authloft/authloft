package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"authloft/internal/codec"
	"authloft/internal/session"
)

// Session 会话中间件（docs/后端架构.md §3.3 行 311、§11.1 / §11.5；
// docs/接口文档.md §1.2 行 120、§1.9 行 286-292）：
//
//   - 取值优先级 X-Authloft-Token Header → Cookie（名取注入值，默认
//     al_session）；Header 有值（哪怕无效）不回落 Cookie——优先级是取值
//     顺序而非失败回退；
//   - 校验（§11.1 四步，实现全部在 session.Verifier，本文件只装配调用）
//     通过 → uid/amr/sid 注入请求 ctx + 每请求重签（§11.5：iat/exp 刷新、
//     epoch/sid 不变、纯计算无存储写入），按令牌来源下发：Cookie 来源 →
//     Set-Cookie；Header 来源 → X-Authloft-Token 响应头（§1.9 行 290-291）；
//   - 失败（无令牌 / 校验失败 / epoch 不一致）→ 未登录：清 Cookie 并放行，
//     不 401——需要登录的路径由 admin 等下游中间件判 401（§5 行 1145）；
//   - epoch 读取链故障（Redis 与回源均失败）属基础设施错误，不得与未登录
//     混同（session/verify.go 口径），按 500 internal_error 拒绝。
//
// 装配口径（叶子件，不 import settings，同 origin.go 的 config 注入口径）：
// Verifier / Renewer / Cookie 构造注入；cookie 名经 cookieName 函数每请求
// 读取（settings 键 cookie_name 快照，热更新由装配方换函数实现；nil 或
// 空串回落默认 al_session）。Cookie 名与 *session.Cookie 内部名由装配方
// 保证同源一致（均出自同一快照值）。
func Session(verifier *session.Verifier, renewer *session.Renewer, cookie *session.Cookie, cookieName func() string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tok, fromHeader := pickSessionToken(c, cookieName)
		if tok == "" {
			// 无令牌：未登录。清 Cookie（防御性清除残留同名 Cookie）并放行。
			setSessionCookie(c, cookie.Clear())
			c.Next()
			return
		}
		p, err := verifier.Verify(c.Request.Context(), tok)
		switch {
		case err == nil:
		case errors.Is(err, session.ErrNotAuthenticated), errors.Is(err, session.ErrSessionStale):
			// 解不开 / 过期 / epoch 不一致：未登录（§3.3 行 311「失败即视为
			// 未登录，清 Cookie」），放行；401 归 admin 等下游中间件。
			setSessionCookie(c, cookie.Clear())
			c.Next()
			return
		default:
			codec.WriteError(c, http.StatusInternalServerError, codec.CodeInternalError, "internal error")
			c.Abort()
			return
		}
		// 校验通过：uid/amr/sid 注入请求 ctx（§11.1 步骤 4；下游经
		// session.UIDFromContext 等读取，注入载荷值本身、不含令牌串）。
		c.Request = c.Request.WithContext(session.WithSessionContext(c.Request.Context(), p))
		// 每请求重签（§11.5 行 1243「在 middleware 内完成」）。重签失败
		// （Seal 属内存操作，实际不可达）不拒绝已验证的请求，仅不下发新令牌。
		if _, renewed, err := renewer.Renew(p); err == nil {
			if fromHeader {
				c.Header(sessionTokenHeader, renewed)
			} else {
				setSessionCookie(c, cookie.Set(renewed))
			}
		}
		c.Next()
	}
}

// sessionTokenHeader 小程序 / 宿主环境回传 session_token 的 Header 名
// （docs/接口文档.md §1.2 行 120）；校验通过后新令牌亦经同名响应头下发
// （§1.9 行 291）。
const sessionTokenHeader = "X-Authloft-Token"

// defaultSessionCookieName 会话 Cookie 名默认值（docs/接口文档.md §1.9 行 288，
// settings 键 cookie_name）。session 包的 defaultCookieName 为私有常量，
// 此处按文档口径同值另设，不为此扩大 session 包导出面。
const defaultSessionCookieName = "al_session"

// pickSessionToken 按取值优先级取 session_token（§1.2 行 120）：
// X-Authloft-Token Header → Cookie。Cookie 名每请求经 cookieName 读取
// （热更新生效）；nil 或空串回落默认 al_session。
func pickSessionToken(c *gin.Context, cookieName func() string) (tok string, fromHeader bool) {
	if h := strings.TrimSpace(c.GetHeader(sessionTokenHeader)); h != "" {
		return h, true
	}
	name := defaultSessionCookieName
	if cookieName != nil {
		if n := strings.TrimSpace(cookieName()); n != "" {
			name = n
		}
	}
	if ck, err := c.Request.Cookie(name); err == nil {
		return ck.Value, false
	}
	return "", false
}

// setSessionCookie 下发完整属性的会话 Cookie（Set / Clear 构造结果）。
// 不用 gin 的 c.SetCookie：其 API 不支持 SameSite，而 §1.9 要求
// HttpOnly; Secure; SameSite=None，session.Cookie 构造的属性必须原样落地。
func setSessionCookie(c *gin.Context, ck *http.Cookie) {
	http.SetCookie(c.Writer, ck)
}
