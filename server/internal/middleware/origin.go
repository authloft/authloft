package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// refererHost 是微信小程序 / 宿主环境 Referer 的固定 host（docs/接口文档.md §1.1 行 80）。
const refererHost = "servicewechat.com"

// originRejectedBody 跨站拒绝的 403 错误体：Connect 错误 JSON 形态
// permission_denied（docs/接口文档.md §1.5 行 188：Origin 跨站归 Connect
// 标准码映射；无 ErrorInfo detail，标准码语义）。
const originRejectedBody = `{"code":"permission_denied","message":"cross-origin request rejected"}`

// Origin 校验写请求的 Origin 与当前站点同源，跨站 403；无 Origin 时校验 Referer
// （https://servicewechat.com/{appid}/… 白名单）；免检组恒过（docs/后端架构.md
// §3.3 行 289、docs/接口文档.md §1.1 行 79 例外）。
//
// 挂全局链、位于 connect handler 之前（§3.3 行 296）：Connect 域请求（POST
// /api.<域>.v1.*/）与 REST 豁免写端点（如 multipart 头像直传）均在本层完成
// Origin/CSRF 校验。免检组 = 服务间签名鉴权等无 Origin 场景：
//   - OIDC /api/oidc/**（REST 原路径不变）；
//   - rpc 域 Connect 路径 /api.rpc.v1.**（HMAC 拦截器鉴权，接口文档 §1.1 行 79）；
//   - /api/gateway/**（X-Gateway-Token，接口文档 §6）。
//
// 校验范围是写方法（非 GET/HEAD/OPTIONS，见 isWriteMethod）：CSRF 只针对状态变更请求，
// 接口文档 §1.1 行 79 的「写 RPC + 登录相关 RPC」均为写方法；GET 一律 query string
// （§1.1 行 77），跨站读由浏览器同源策略阻挡，不靠 Origin 校验。
//
// 站点根 origin 与 appid 白名单经构造函数注入（中间件不 import config，叶子口径）：
//   - rootOrigin：{al_root}（接口文档 §1.1 行 76，如 https://authloft.example.com，可含端口）；
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
		// 403 出口取 Connect 错误 JSON（§1.5 行 188 permission_denied）：被本层
		// 拦截的主要是 Connect 域请求；豁免端点（OIDC / gateway）在免检组，
		// 不经此出口。X-Request-Id 头由 requestid 中间件已写入头表。
		c.Data(http.StatusForbidden, "application/json", []byte(originRejectedBody))
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

// isWriteMethod 判定是否写方法：GET/HEAD/OPTIONS 属安全方法，不做 Origin 校验
//（docs/接口文档.md §1.1 行 79 的校验对象是写接口；登录相关接口亦均为写方法）。
func isWriteMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// isOriginExemptPath 覆盖 Origin 免检组（docs/接口文档.md §1.1 行 79 例外、
// 后端架构 §3.3 行 289）：/api/oidc/**（REST 原路径）、rpc 域 Connect 路径
// /api.rpc.v1.**、/api/gateway/**（服务间签名鉴权，无 Origin）。
func isOriginExemptPath(path string) bool {
	if strings.HasPrefix(path, "/api.rpc.v1.") {
		return true
	}
	for _, prefix := range []string{"/api/oidc", "/api/gateway"} {
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

// refererAllowed 判断无 Origin 请求的 Referer 是否命中小程序白名单（接口文档 §1.1 行 80）：
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
