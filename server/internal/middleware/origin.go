package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"authloft/internal/codec"
)

// refererHost 是微信小程序 / 宿主环境 Referer 的固定 host（docs/接口文档.md §1.1 行 58）。
const refererHost = "servicewechat.com"

// Origin 校验写请求的 Origin 与当前站点同源，跨站 403；无 Origin 时校验 Referer
// （https://servicewechat.com/{appid}/… 白名单）；免检组 /api/oidc/**、/api/rpc/**、
// /api/gateway/** 恒过（docs/后端架构.md §3.3 行 302、docs/接口文档.md §1.1 行 57-58）。
//
// 校验范围是写方法（非 GET/HEAD/OPTIONS，见 isWriteMethod）：CSRF 只针对状态变更请求，
// 接口文档 §1.1 行 57 的「写接口 + 登录相关接口」均为写方法；GET 一律 query string
// （§1.1 行 56），跨站读由浏览器同源策略阻挡，不靠 Origin 校验。
//
// 站点根 origin 与 appid 白名单经构造函数注入（中间件不 import config，同 codec 叶子口径）：
//   - rootOrigin：{al_root}（接口文档 §1.1 行 54，如 https://authloft.example.com，可含端口）；
//   - refererAllowlist：已启用 provider 的 app_id 白名单。
//
// 未配置（rootOrigin 空串 / 白名单 nil）时保守拒绝而非放行：缺配置下「默认放行」
// 会让 CSRF 防护整体失效，「默认拒绝」只是可用性缺口，等 config 系统接入后注入真实值恢复。
func Origin(rootOrigin string, refererAllowlist []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isWriteMethod(c.Request.Method) || isOriginExemptPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		if requestOriginAllowed(c.Request, rootOrigin, refererAllowlist) {
			c.Next()
			return
		}
		codec.WriteError(c, http.StatusForbidden, codec.CodeForbidden, "cross-origin request rejected")
		c.Abort()
	}
}

// requestOriginAllowed 判定写请求的跨站防护：带 Origin 走同源判断，无 Origin 走 Referer 白名单。
func requestOriginAllowed(r *http.Request, rootOrigin string, refererAllowlist []string) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		return sameOrigin(origin, rootOrigin)
	}
	return refererAllowed(r.Header.Get("Referer"), refererAllowlist)
}

// isWriteMethod 判定是否写方法：GET/HEAD/OPTIONS 属安全方法，不做 Origin / Content-Type 校验
//（docs/接口文档.md §1.1 行 56-57 的校验对象是写接口；登录相关接口亦均为写方法）。
func isWriteMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// isOriginExemptPath 覆盖 Origin 免检组（docs/接口文档.md §1.1 行 57、后端架构 §3.3 行 302：
// /api/oidc/**、/api/rpc/**、/api/gateway/** 为服务间签名鉴权，无 Origin）。
func isOriginExemptPath(path string) bool {
	for _, prefix := range []string{"/api/oidc", "/api/rpc", "/api/gateway"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// sameOrigin 判断 Origin 头与站点根 origin 是否同源：比较 scheme + host（均大小写不敏感、
// 端口敏感）；Origin 规范上不含 path，若客户端携带仅忽略。rootOrigin 空串（未配置）恒 false。
func sameOrigin(origin, rootOrigin string) bool {
	if rootOrigin == "" {
		return false
	}
	o, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || o.Host == "" {
		return false
	}
	root, err := url.Parse(strings.TrimSpace(rootOrigin))
	if err != nil || root.Host == "" {
		return false
	}
	return strings.EqualFold(o.Scheme, root.Scheme) && strings.EqualFold(o.Host, root.Host)
}

// refererAllowed 判断无 Origin 请求的 Referer 是否命中小程序白名单（接口文档 §1.1 行 58）：
// host 必须恰为 servicewechat.com（不接受子域等其他 host），path 首段为 appid 且在白名单内；
// 白名单为空（未配置）时恒 false。
func refererAllowed(referer string, refererAllowlist []string) bool {
	u, err := url.Parse(strings.TrimSpace(referer))
	if err != nil || !strings.EqualFold(u.Host, refererHost) {
		return false
	}
	appid, _, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
	if appid == "" {
		return false
	}
	for _, allowed := range refererAllowlist {
		if allowed == appid {
			return true
		}
	}
	return false
}
