// requestinfo.go 请求侧 IP / UA 注入 connect 前缀链（docs/后端架构.md §4.6
// 行 776-777）：http 挂载层是唯一能同时拿到 RemoteAddr 与头信息的层。
package orchestrator

import (
	"net"
	"net/http"
	"strings"
)

// WithRequestInfoHandler 给 connect 前缀链注入请求侧信息：http 挂载层
// 是唯一能同时拿到 RemoteAddr 与头信息的层（connect 链 AnyRequest 只暴露
// Header——session.RequestSignal 只采头、拿不到来源 IP 的先例），登录成功
// 事件经 ctx 带到 orchestrator.Terminal.Complete，落 event_log.ip / ua
// （§4.6 行 776-777）。所有 connect 域统一注入，消费点只有登录终点。
func WithRequestInfoHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithRequestInfo(r.Context(), RequestInfo{
			IP: clientIPFromRequest(r),
			UA: r.UserAgent(),
		})))
	})
}

// clientIPFromRequest 来源 IP（审计用途 event_log.ip，非安全判定依据）：
// 反代链优先 X-Forwarded-For 首段，次选 X-Real-IP，直连回落 RemoteAddr
// host 段。直连场景客户端可伪造 XFF / X-Real-IP，如实记录——部署方负责
// 在反代清洗入站头（§1.1 明文部署风险自负的同款口径）。
func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		return strings.TrimSpace(xff)
	}
	if rip := strings.TrimSpace(r.Header.Get("X-Real-IP")); rip != "" {
		return rip
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
