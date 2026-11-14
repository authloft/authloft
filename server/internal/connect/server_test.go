// server.go 的装配冒烟测试（随 ServeMux 分流改造：本处不含任何
// 真实 service handler，故验证装配口径：路由
// 收集可达且路径原样传递、注册序保留、RegisterRPC 的 CaptureRawBody 强制
// 包装锚定；顶层 mux 的分发 / 未注册路径兜底归装配层测试（bootstrap_test /
// main_test，§3.1 分流口径——connect.Server 不再自带 mux 与 404 兜底）。
package connect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"

	"authloft/internal/logx"
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
	_ = withCapturedLogs(t) // panic 日志不污染测试输出
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

// withCapturedLogs 把全局 logger 换成写入 buf 的 logx handler（自动注入
// request_id），测试结束恢复——CODE_GUIDE §3.8「改动全局 logger 的用例须
// t.Cleanup 恢复」。
func withCapturedLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(logx.NewHandler(buf, "debug", "json")))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func newAnyRequest() connect.AnyRequest { return connect.NewRequest(&emptypb.Empty{}) }

// ⑧ 服务端故障错误：记 procedure / code / 根因，并自动带 request_id。
func TestErrorLogInterceptorLogsServerFault(t *testing.T) {
	buf := withCapturedLogs(t)
	ctx := logx.WithRequestID(context.Background(), "req-test-001")
	next := connect.UnaryFunc(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, errors.New("handler: load user: db connection refused")
	})
	if _, err := NewErrorLogInterceptor()(next)(ctx, newAnyRequest()); err == nil {
		t.Fatal("expected error")
	}
	got := buf.String()
	for _, want := range []string{"connect: request failed", "req-test-001", "unknown", "db connection refused"} {
		if !strings.Contains(got, want) {
			t.Errorf("log %q missing %q", got, want)
		}
	}
}

// ⑨ 业务预期 4xx 不产生错误日志（防攻击流量刷屏）。
func TestErrorLogInterceptorSkipsExpectedClientErrors(t *testing.T) {
	buf := withCapturedLogs(t)
	next := connect.UnaryFunc(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("bad input"))
	})
	if _, err := NewErrorLogInterceptor()(next)(context.Background(), newAnyRequest()); err == nil {
		t.Fatal("expected error")
	}
	if buf.Len() != 0 {
		t.Errorf("业务 4xx 不应产生错误日志, got %q", buf.String())
	}
}

// ⑩ 外层域拦截器 short-circuit 的错误也记录在案，且 sanitizedError 的
// 根因能沿 Unwrap 链回溯（否则日志只剩 "internal error"）。
func TestErrorLogInterceptorCoversDomainShortCircuit(t *testing.T) {
	buf := withCapturedLogs(t)
	domain := connect.UnaryInterceptorFunc(func(connect.UnaryFunc) connect.UnaryFunc {
		return func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
			return nil, connect.NewError(connect.CodeInternal,
				sanitizedError{err: errors.New("redis epoch read failed")})
		}
	})
	inner := domain(connect.UnaryFunc(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		return nil, nil
	}))
	if _, err := NewErrorLogInterceptor()(inner)(context.Background(), newAnyRequest()); err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(buf.String(), "redis epoch read failed") {
		t.Errorf("域拦截器 short-circuit 的根因未进日志: %q", buf.String())
	}
}

// ⑪ panic 归一：堆栈与 request_id 入日志，panic 原始值不落盘、不进错误。
func TestRecoverToInternalLogsPanicWithoutValue(t *testing.T) {
	buf := withCapturedLogs(t)
	ctx := logx.WithRequestID(context.Background(), "req-panic-002")
	err := recoverToInternal(ctx, connect.Spec{}, nil, "secret-panic-value")
	if err == nil {
		t.Fatal("expected error")
	}
	got := buf.String()
	for _, want := range []string{"connect: panic recovered", "req-panic-002", "stack"} {
		if !strings.Contains(got, want) {
			t.Errorf("log %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "secret-panic-value") {
		t.Error("panic value leaked into log")
	}
	if strings.Contains(err.Error(), "secret-panic-value") {
		t.Error("panic value leaked into error")
	}
}
