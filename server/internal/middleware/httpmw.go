package middleware

import (
	"context"
	"net/http"
)

// 本文件提供 Connect 域（顶层 http.ServeMux 分流链，docs/后端架构.md
// §3.1 行 241-246）的 net/http 版中间件：ServeMux 分流后 Connect 请求不再
// 经 gin 全局链，requestid 与 origin 防护由本文件对 Connect 域等效生效。
// 与 gin 版（requestid.go / origin.go）
// 共用同一实现——生成与校验逻辑均为同包纯函数，禁止复制（§3.14 同口径）。

// requestIDCtxKey 链路 ID 在 http 请求 ctx 中的键（HTTPRequestID 写入，
// RequestIDFromContext 读取）。gin 版写入 gin.Context 的 RequestIDKey，
// connect 域经本键读取（connect 错误包装 / 未来 http 版 logger 消费）。
type requestIDCtxKey struct{}

// RequestIDFromContext 从 http 请求 ctx 读取链路 ID（HTTPRequestID 写入；
// 未写入返回空串）。
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDCtxKey{}).(string)
	return id
}

// HTTPRequestID http 版链路 ID 中间件（§3.3 行 302 requestid 职责的
// net/http 形态，Connect 域等效）：生成口径与 gin 版共用 newRequestID
// （crypto/rand 16 字节 hex，不读不透传入站头，失败留空不伪造）；
// X-Request-Id 在入口即写响应头（所有响应统一回写——
// origin 403 / connect 错误响应均携带）；id 非空时注入 r.Context()
// 供 connect 错误包装 / 日志读取（§3.3 行 302）。
func HTTPRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		if id != "" {
			r = r.WithContext(context.WithValue(r.Context(), requestIDCtxKey{}, id))
		}
		w.Header().Set(XRequestIDHeader, id)
		next.ServeHTTP(w, r)
	})
}

// HTTPOrigin http 版 Origin/CSRF 中间件（§3.3 行 299 origin 职责的
// net/http 形态，Connect 域等效）：校验逻辑与 gin 版 Origin 共用同包
// 纯函数（requestOriginAllowed / isWriteMethod / isOriginExemptPath），
// 免检组与写方法口径一致；跨站 403 出口写 Connect 错误 JSON
// permission_denied（§1.5 行 188），X-Request-Id 头由 HTTPRequestID
// 先写入。
func HTTPOrigin(rootOrigin string, refererAllowlist []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWriteMethod(r.Method) || isOriginExemptPath(r.URL.Path) || requestOriginAllowed(r, rootOrigin, refererAllowlist) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(originRejectedBody))
	})
}
