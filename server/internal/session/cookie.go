// 会话 Cookie 属性构造与清除（接口文档 §1.9 行 286-292、后端架构
// §11.1 行 1175）：名默认 al_session（键 cookie_name）、有效期默认
// 7 天（键 session_ttl）、Domain 取根域——三者均由构造注入，不读
// settings（热更由装配方重构造注入）；属性固定
// HttpOnly; Secure; SameSite=None; Path=/。只构造 *http.Cookie，
// 下发（http.SetCookie / Set-Cookie 头）归 middleware。
package session

import (
	"net/http"
	"time"
)

// defaultCookieName Cookie 名默认值（接口文档 §1.9：al_session）。
const defaultCookieName = "al_session"

// Cookie 会话 Cookie 属性构造器。
type Cookie struct {
	name   string
	domain string
	ttl    time.Duration
}

// NewCookie 构造。name 传空串回落默认 al_session；domain 为根域
// （跨子域共享会话所需）；ttl 为有效期（settings 键 session_ttl，
// 默认 7 天，由装配方注入）。
func NewCookie(name, domain string, ttl time.Duration) *Cookie {
	if name == "" {
		name = defaultCookieName
	}
	return &Cookie{name: name, domain: domain, ttl: ttl}
}

// Set 构造写值 Cookie（登录建会话 / 每次请求续期下发）。
func (c *Cookie) Set(value string) *http.Cookie {
	return &http.Cookie{
		Name:     c.name,
		Value:    value,
		Path:     "/",
		Domain:   c.domain,
		MaxAge:   int(c.ttl / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}
}

// Clear 构造清除 Cookie（登出 / 校验失败清 Cookie）。同名同 Path /
// Domain、MaxAge=-1 浏览器立即删除；其余属性与 Set 一致，确保覆盖到
// 要删的那枚 Cookie。
func (c *Cookie) Clear() *http.Cookie {
	ck := c.Set("")
	ck.MaxAge = -1
	return ck
}
