// requestinfo.go 请求侧 IP / UA 注入 connect 前缀链（docs/后端架构.md §3.6 /
// §4.6）：http 挂载层是唯一能同时拿到 RemoteAddr 与头信息的层。
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
// （§4.6）。所有 connect 域统一注入，消费点只有登录终点。
//
// clientIPHeader 由装配层注入来源 IP 采信头名动态源（每请求读 settings 键
// client_ip_header，热更新不固化）；nil 或返回空串 = 未配置，取值仅直连。
// 取值实现与 echo 链 IPExtractor 共用 ClientIPFromRequest（单一实现）：
// 同一请求在审计与限流键里必须是同一个 IP。
func WithRequestInfoHandler(h http.Handler, clientIPHeader func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := ""
		if clientIPHeader != nil {
			header = clientIPHeader()
		}
		h.ServeHTTP(w, r.WithContext(WithRequestInfo(r.Context(), RequestInfo{
			IP: ClientIPFromRequest(r, header),
			UA: r.UserAgent(),
		})))
	})
}

// ClientIPFromRequest 来源 IP（仅供审计 event_log.ip 与限流键，不作鉴权
// 依据）。headerName 非空 = 配置了采信头：取该头首个逗号前段并 TrimSpace，
// 头缺失 / 空值 / 首段空白回落直连；未配置（空串）仅取 RemoteAddr host 段、
// 不采信任何转发头。RemoteAddr 无 host:port 时回落原串。
// 采信边界（接口文档 §1.1）：配置的可信头由部署方在反代清洗入站头，直连
// 客户端可伪造、如实记录；不提供可信代理白名单。
func ClientIPFromRequest(r *http.Request, headerName string) string {
	if headerName != "" {
		if v := r.Header.Get(headerName); v != "" {
			if i := strings.IndexByte(v, ','); i >= 0 {
				v = v[:i]
			}
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
