// server.go 的装配冒烟测试（尚无真实 service handler，
// 故验证装配口径：mux 路由可达、未注册路径
// 返回 connect 错误形态、非 connect 路径保持原生 404；RegisterRPC 的
// CaptureRawBody 强制包装一并锚定）。
package connect

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestServer 构造测试装配（默认上限）。
func newTestServer() *Server { return NewServer(0) }

// ① 未注册的 connect 形态路径 → 404 + Connect 错误 JSON（code=not_found），
// Content-Type 为 application/json（§1.5 行 184-211）。
func TestServeHTTPUnregisteredConnectPathReturnsConnectError(t *testing.T) {
	s := newTestServer()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"code":"not_found"`) {
		t.Errorf("error body %q missing not_found connect code", body)
	}
	if !strings.HasPrefix(body, "{") || !strings.HasSuffix(body, "}") {
		t.Errorf("error body %q is not a JSON object", body)
	}
}

// ② 非 connect 形态路径（REST 豁免域、任意未知路径）→ 原生 404 空体，
// 不产生 Connect 错误 JSON（gin NoRoute 兜底入口分流口径）。
func TestServeHTTPNonConnectPathStaysPlain404(t *testing.T) {
	s := newTestServer()
	for _, path := range []string{"/api/oidc/authorize", "/api/rpc/x", "/nope", "/api.setup/config"} {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want %d", path, rec.Code, http.StatusNotFound)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("%s: body = %q, want empty (非 connect 路径保持原生 404)", path, rec.Body.String())
		}
	}
}

// ③ isConnectPath 形态判定：服务段须含 .v1.、须有方法段（无方法段或非
// 点分域前缀一律不接管）。
func TestIsConnectPath(t *testing.T) {
	cases := map[string]bool{
		"/api.sso.v1.SsoService/LoginDefault":  true,
		"/api.rpc.v1.RpcService/GetUserProfile": true,
		"/api.setup.v1.SetupService/Status":     true,
		"/api.oidc/x":                           false,
		"/api/rpc/x":                            false,
		"/api.sso.v1.SsoService":                false,
		"/api/v1/x":                             false,
	}
	for path, want := range cases {
		if got := isConnectPath(path); got != want {
			t.Errorf("isConnectPath(%q) = %v, want %v", path, got, want)
		}
	}
}

// ④ Register 挂载的 handler 路由可达且请求路径原样传递（生成 handler 内部
// 按完整 procedure 分发，装配层不得改写路径）。
func TestRegisterRoutesHandler(t *testing.T) {
	s := newTestServer()
	var gotPath string
	s.Register("/api.test.v1.TService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api.test.v1.TService/Do", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotPath != "/api.test.v1.TService/Do" {
		t.Errorf("handler saw path %q, want /api.test.v1.TService/Do (路径不得改写)", gotPath)
	}
}

// ⑤ RegisterRPC 强制包 CaptureRawBody：rpc HMAC 拦截器依赖的原始请求体
// 字节注入 ctx（rawBodyKey）且 body 回填后仍可读（interceptors.go 行
// 194-217；漏挂则拦截器 fail-closed，故装配路径必须锚定）。
func TestRegisterRPCWrapsCaptureRawBody(t *testing.T) {
	s := newTestServer()
	var rawFromCtx, rawFromBody []byte
	s.RegisterRPC("/api.rpc.v1.RpcService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawFromCtx, _ = r.Context().Value(rawBodyKey{}).([]byte)
		rawFromBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))

	payload := []byte(`{"text":"hello"}`)
	req := httptest.NewRequest(http.MethodPost, "/api.rpc.v1.RpcService/GetUserProfile", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !bytes.Equal(rawFromCtx, payload) {
		t.Errorf("ctx raw body = %q, want %q (CaptureRawBody 未生效)", rawFromCtx, payload)
	}
	if !bytes.Equal(rawFromBody, payload) {
		t.Errorf("re-filled body = %q, want %q (body 回填失败)", rawFromBody, payload)
	}
}

// ⑥ readMaxBytes 注入口径：n <= 0 回落默认 1 MiB（§1.6 行 86），显式值原样生效。
func TestNewServerReadMaxBytes(t *testing.T) {
	if got := NewServer(0).readMaxBytes; got != defaultReadMaxBytes {
		t.Errorf("NewServer(0).readMaxBytes = %d, want %d", got, defaultReadMaxBytes)
	}
	if got := NewServer(-1).readMaxBytes; got != defaultReadMaxBytes {
		t.Errorf("NewServer(-1).readMaxBytes = %d, want %d", got, defaultReadMaxBytes)
	}
	if got := NewServer(2048).readMaxBytes; got != 2048 {
		t.Errorf("NewServer(2048).readMaxBytes = %d, want 2048", got)
	}
}

// ⑦ HandlerOptions 非空锚定（选项内容不透明；错误包装补位与
// WithReadMaxBytes 的行为断言待有真实 handler 后端到端验证）。
func TestHandlerOptionsNonEmpty(t *testing.T) {
	s := newTestServer()
	if len(s.HandlerOptions()) == 0 {
		t.Error("HandlerOptions() is empty, want read-max-bytes + interceptor chain options")
	}
}

// ⑧ 未注册路径 POST 带 body 仍 404 Connect JSON（兜底与 RegisterRPC 的
// CaptureRawBody 无关，直接分流）。
func TestServeHTTPUnregisteredWithBody(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/api.admin.v1.AdminService/GetUsers", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if !strings.Contains(rec.Body.String(), `"code":"not_found"`) {
		t.Errorf("error body %q missing not_found connect code", rec.Body.String())
	}
}
