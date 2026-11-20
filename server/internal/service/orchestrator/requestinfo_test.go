// requestinfo_test.go 来源 IP 取值口径单测：采信头配置 / 未配置两态、
// 逗号首段 + TrimSpace、回落直连、热更新（getter 每请求求值）、
// connect 链与直调取值同源一致。
package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestClientIPFromRequestDirectOnly 未配置采信头（空串）：带 XFF /
// X-Real-IP 也一律取 RemoteAddr host 段，不采信任何转发头。
func TestClientIPFromRequestDirectOnly(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "203.0.113.7:54123"
	r.Header.Set("X-Forwarded-For", "198.51.100.9, 10.0.0.1")
	r.Header.Set("X-Real-IP", "198.51.100.10")
	if got := ClientIPFromRequest(r, ""); got != "203.0.113.7" {
		t.Fatalf("unconfigured: ip = %q, want RemoteAddr host 203.0.113.7", got)
	}

	// nil 头名之外的两态边缘：头值为空 / 首段空白 → 回落直连。
	for _, headerName := range []string{"X-Forwarded-For", "X-Client-IP"} {
		r.Header.Set(headerName, "")
		if got := ClientIPFromRequest(r, headerName); got != "203.0.113.7" {
			t.Fatalf("%s empty value: ip = %q, want direct 203.0.113.7", headerName, got)
		}
	}

	// RemoteAddr 无 host:port（如 unix 套接字）→ 回落原串。
	r.RemoteAddr = "/var/run/sock"
	if got := ClientIPFromRequest(r, ""); got != "/var/run/sock" {
		t.Fatalf("no host:port: ip = %q, want raw RemoteAddr", got)
	}
}

// TestClientIPFromRequestConfiguredHeader 配置采信头：取逗号首段 +
// TrimSpace；自定义头同名取值；头取不到 / 空值回落直连不报错。
func TestClientIPFromRequestConfiguredHeader(t *testing.T) {
	newReq := func(remoteAddr string, header, value string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.RemoteAddr = remoteAddr
		if header != "" {
			r.Header.Set(header, value)
		}
		return r
	}

	// XFF 多段取首段并 TrimSpace。
	r := newReq("10.0.0.1:443", "X-Forwarded-For", " 198.51.100.9 , 10.0.0.1")
	if got := ClientIPFromRequest(r, "X-Forwarded-For"); got != "198.51.100.9" {
		t.Fatalf("xff: ip = %q, want first segment trimmed 198.51.100.9", got)
	}
	// 自定义头同理（header 名大小写不敏感）。
	r = newReq("10.0.0.1:443", "X-Client-IP", "192.0.2.66")
	if got := ClientIPFromRequest(r, "x-client-ip"); got != "192.0.2.66" {
		t.Fatalf("custom header: ip = %q, want 192.0.2.66", got)
	}
	// 头取不到 → 回落直连。
	r = newReq("10.0.0.1:443", "", "")
	if got := ClientIPFromRequest(r, "X-Forwarded-For"); got != "10.0.0.1" {
		t.Fatalf("header missing: ip = %q, want direct 10.0.0.1", got)
	}
	// 首段仅空白 → 回落直连。
	r = newReq("10.0.0.1:443", "X-Forwarded-For", " , 198.51.100.9")
	if got := ClientIPFromRequest(r, "X-Forwarded-For"); got != "10.0.0.1" {
		t.Fatalf("blank first segment: ip = %q, want direct 10.0.0.1", got)
	}
}

// TestWithRequestInfoHandlerGetterPerRequest getter 每请求求值（热更新）：
// 改 getter 返回值后新请求按新采信头取值；connect 链注入的 IP 与直调
// ClientIPFromRequest 同请求同值（echo 链共用同一实现，审计与限流键同 IP）。
func TestWithRequestInfoHandlerGetterPerRequest(t *testing.T) {
	header := "X-Forwarded-For"
	var got RequestInfo
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = RequestInfoFromContext(r.Context())
	})
	h := WithRequestInfoHandler(inner, func() string { return header })

	do := func(hdr map[string]string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", nil)
		r.RemoteAddr = "10.0.0.1:443"
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
	}

	// getter 返回空串 = 未配置：转发头不采信。
	header = ""
	do(map[string]string{"X-Forwarded-For": "198.51.100.9"})
	if got.IP != "10.0.0.1" {
		t.Fatalf("getter empty: ip = %q, want direct 10.0.0.1", got.IP)
	}
	// 热更新：getter 改返回 XFF 后新请求按新头取值。
	header = "X-Forwarded-For"
	do(map[string]string{"X-Forwarded-For": "198.51.100.9, 10.0.0.1"})
	if got.IP != "198.51.100.9" {
		t.Fatalf("getter xff: ip = %q, want 198.51.100.9", got.IP)
	}
	// 同请求与直调同值（echo 链同实现）。
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = "10.0.0.1:443"
	r.Header.Set("X-Forwarded-For", "198.51.100.9, 10.0.0.1")
	if via := ClientIPFromRequest(r, "X-Forwarded-For"); via != got.IP {
		t.Fatalf("same request: handler %q != direct %q", got.IP, via)
	}
}
