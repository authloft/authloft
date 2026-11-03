// server.go 的装配冒烟测试（随 ServeMux 分流改造：本处不含任何
// 真实 service handler，故验证装配口径：路由
// 收集可达且路径原样传递、注册序保留、RegisterRPC 的 CaptureRawBody 强制
// 包装锚定；顶层 mux 的分发 / 未注册路径兜底归装配层测试（bootstrap_test /
// main_test，§3.1 分流口径——connect.Server 不再自带 mux 与 404 兜底）。
package connect

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
)

// newTestServer 构造测试装配（默认上限）。
func newTestServer() *Server { return NewServer(0) }

// ① 新构造的 Server 无路由（装配层空挂载集合）。
func TestRoutesEmptyOnNewServer(t *testing.T) {
	if got := len(newTestServer().Routes()); got != 0 {
		t.Errorf("Routes() length = %d, want 0 on fresh server", got)
	}
}

// ② Register 收集的 handler 路由可达且请求路径原样传递（顶层 mux 前缀
// 匹配不改写路径，生成 handler 内部按完整 procedure 分发，装配层不得
// 改写路径——经 Routes() 直连 handler 验证）。
func TestRegisterRoutesHandler(t *testing.T) {
	s := newTestServer()
	var gotPath string
	s.Register("/api.test.v1.TService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))

	routes := s.Routes()
	if len(routes) != 1 {
		t.Fatalf("Routes() length = %d, want 1", len(routes))
	}
	if routes[0].Prefix != "/api.test.v1.TService/" {
		t.Errorf("routes[0].Prefix = %q, want /api.test.v1.TService/ (尾斜杠前缀)", routes[0].Prefix)
	}

	rec := httptest.NewRecorder()
	routes[0].Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api.test.v1.TService/Do", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotPath != "/api.test.v1.TService/Do" {
		t.Errorf("handler saw path %q, want /api.test.v1.TService/Do (路径不得改写)", gotPath)
	}
}

// ③ 注册序保留（装配层按序挂载顶层 mux；前缀以注册值原样暴露）。
func TestRegisterPreservesOrderAndPrefixes(t *testing.T) {
	s := newTestServer()
	noop := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})
	s.Register("/api.a.v1.AService/", noop)
	s.RegisterRPC("/api.b.v1.BService/", noop)

	routes := s.Routes()
	if len(routes) != 2 {
		t.Fatalf("Routes() length = %d, want 2", len(routes))
	}
	for i, want := range []string{"/api.a.v1.AService/", "/api.b.v1.BService/"} {
		if routes[i].Prefix != want {
			t.Errorf("routes[%d].Prefix = %q, want %q", i, routes[i].Prefix, want)
		}
	}
}

// ④ RegisterRPC 强制包 CaptureRawBody：rpc HMAC 拦截器依赖的原始请求体
// 字节注入 ctx（rawBodyKey）且 body 回填后仍可读（interceptors.go 行
// 194-217；漏挂则拦截器 fail-closed，故装配路径必须锚定）。
func TestRegisterRPCWrapsCaptureRawBody(t *testing.T) {
	s := newTestServer()
	var rawFromCtx, rawFromBody []byte
	s.RegisterRPC("/api.rpc.v1.UserService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawFromCtx, _ = r.Context().Value(rawBodyKey{}).([]byte)
		rawFromBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))

	routes := s.Routes()
	if len(routes) != 1 {
		t.Fatalf("Routes() length = %d, want 1", len(routes))
	}
	payload := []byte(`{"text":"hello"}`)
	req := httptest.NewRequest(http.MethodPost, "/api.rpc.v1.UserService/GetUserProfile", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	routes[0].Handler.ServeHTTP(rec, req)
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

// ⑤ readMaxBytes 注入口径：n <= 0 回落默认 1 MiB（§1.6 行 86），显式值原样生效。
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

// ⑥ HandlerOptions 非空锚定（选项内容不透明；WithRecover 补位与
// WithReadMaxBytes 的行为断言待有真实 handler 后端到端验证）。
func TestHandlerOptionsNonEmpty(t *testing.T) {
	s := newTestServer()
	if len(s.HandlerOptions()) == 0 {
		t.Error("HandlerOptions() is empty, want read-max-bytes + recover + interceptor chain options")
	}
}

// ⑦ WithRecover 的 panic 归一（§3.3 recover 等效的实证）：注册一个
// panic 的生成形态 handler——HandlerOptions 需经真实 connect handler 才能
// 挂接 WithRecover，此处用最小 connect handler 等效验证 recoverToInternal
// 的行为契约（panic → internal 错误体，不透出 panic 值）。
func TestRecoverToInternalDoesNotLeakPanicValue(t *testing.T) {
	err := recoverToInternal(context.Background(), connect.Spec{}, nil, "secret-panic-value")
	if err == nil {
		t.Fatal("recoverToInternal must return an error")
	}
	if !strings.Contains(err.Error(), "internal") {
		t.Errorf("error %q should map to internal", err.Error())
	}
	if strings.Contains(err.Error(), "secret-panic-value") {
		t.Error("panic value leaked into error")
	}
}
