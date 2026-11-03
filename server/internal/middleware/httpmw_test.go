package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// httpTestChain 构造 Connect 域 requestid→origin 子链（装配层
// 前缀链；全链测试见下方 HTTPLogger/HTTPMetrics 各用例——装配层现为
// requestid → logger → metrics → origin → handler）。返回链与目标
// handler 的到达记录。
func httpTestChain(rootOrigin string) (http.Handler, *bool) {
	hit := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	})
	return HTTPRequestID(HTTPOrigin(rootOrigin, []string{"wxappid"}, next)), &hit
}

// TestHTTPRequestIDWritesHeaderAndCtx Connect 域等效：
// X-Request-Id 全响应回写 + ctx 注入（connect 错误包装 / 日志读取位），
// handler 可达且读到的 ctx 值与响应头一致。
func TestHTTPRequestIDWritesHeaderAndCtx(t *testing.T) {
	var ctxID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxID = RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	HTTPRequestID(next).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	headerID := rec.Header().Get(XRequestIDHeader)
	if headerID == "" {
		t.Fatal("X-Request-Id is empty, want non-empty (全响应回写)")
	}
	if headerID != ctxID {
		t.Errorf("ctx id %q != header id %q, want identical", ctxID, headerID)
	}
	if len(headerID) != 32 {
		t.Errorf("X-Request-Id = %d chars, want 32 (crypto/rand 16 字节 hex)", len(headerID))
	}
}

// TestHTTPOriginConnectDomainEquivalent origin 防护对 Connect 域等效：
// 写方法无 Origin / 跨站 Origin → 403 + Connect 错误 JSON
// permission_denied（§1.5 行 188）；同源与免检前缀（rpc 域）放行到达
// handler；GET 安全方法不校验。
func TestHTTPOriginConnectDomainEquivalent(t *testing.T) {
	const root = "https://authloft.example.com"
	chain, hit := httpTestChain(root)

	do := func(method, target string, headers map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		return rec
	}

	// POST 无 Origin → 403，X-Request-Id 仍回写（requestid 外层先写）。
	rec := do(http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no origin: status = %d, want %d (body %s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (Connect 错误形态)", rec.Header().Get("Content-Type"))
	}
	if rec.Body.String() != originRejectedBody {
		t.Errorf("403 body = %q, want %q", rec.Body.String(), originRejectedBody)
	}
	if rec.Header().Get(XRequestIDHeader) == "" {
		t.Error("X-Request-Id is empty on 403, want non-empty (requestid 先于 origin)")
	}

	// 跨站 Origin → 403。
	if rec := do(http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", map[string]string{"Origin": "https://evil.example.com"}); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// 同源 → 到达 handler。
	if rec := do(http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", map[string]string{"Origin": root}); rec.Code != http.StatusOK || !*hit {
		t.Errorf("same-origin: status = %d hit = %v, want 200 + handler reached", rec.Code, *hit)
	}

	// rpc 域免检前缀：跨站 Origin 也放行（§1.1 行 79 例外）。
	if rec := do(http.MethodPost, "/api.rpc.v1.RpcService/GetUserProfile", map[string]string{"Origin": "https://evil.example.com"}); rec.Code != http.StatusOK {
		t.Errorf("rpc exempt: status = %d, want %d (免检组放行)", rec.Code, http.StatusOK)
	}

	// GET 安全方法：无 Origin 不校验（跨站读由浏览器同源策略阻挡）。
	if rec := do(http.MethodGet, "/api.sso.v1.SsoService/Whatever", nil); rec.Code != http.StatusOK {
		t.Errorf("GET safe method: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestRequestIDFromContextEmpty 未写入时返回空串（零值兜底，不 panic）。
func TestRequestIDFromContextEmpty(t *testing.T) {
	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Errorf("RequestIDFromContext(background) = %q, want empty", got)
	}
}

// —— HTTPLogger / HTTPMetrics（logger/metrics 的 Connect 域等效） ——

// TestHTTPLoggerAccessFields http 版访问日志字段与 gin 版同口径（共用
// logAccess）：request_id / method / path / status / latency 五字段齐全，
// request_id 与响应头一致（HTTPRequestID 先于 logger 注入 ctx）。
func TestHTTPLoggerAccessFields(t *testing.T) {
	logCap := captureSlog(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	HTTPRequestID(HTTPLogger(next)).ServeHTTP(rec,
		httptest.NewRequest(http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if n := len(logCap.records); n != 1 {
		t.Fatalf("captured %d log records, want exactly 1", n)
	}
	attrs := logCap.attrs("access")
	if attrs == nil {
		t.Fatalf("no \"access\" record captured")
	}
	for _, key := range []string{"request_id", "method", "path", "status", "latency"} {
		if _, ok := attrs[key]; !ok {
			t.Errorf("access log missing field %q: %v", key, attrs)
		}
	}
	if attrs["request_id"] == "" || attrs["request_id"] != rec.Header().Get(XRequestIDHeader) {
		t.Errorf("request_id = %q, want non-empty and equal to X-Request-Id header %q",
			attrs["request_id"], rec.Header().Get(XRequestIDHeader))
	}
	if attrs["method"] != http.MethodPost {
		t.Errorf("method = %q, want %q", attrs["method"], http.MethodPost)
	}
	if attrs["path"] != "/api.sso.v1.SsoService/LoginDefault" {
		t.Errorf("path = %q, want procedure path", attrs["path"])
	}
	if attrs["status"] != "200" {
		t.Errorf("status = %q, want \"200\"", attrs["status"])
	}
	if attrs["latency"] == "" {
		t.Errorf("latency is empty, want non-empty duration")
	}
}

// TestHTTPLoggerRecordsOrigin403 状态码取最终值：前缀链内层 origin 403 →
// 访问日志记 403 且 request_id 非空（logger 在 requestid 之内、origin 之外）。
func TestHTTPLoggerRecordsOrigin403(t *testing.T) {
	logCap := captureSlog(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	chain := HTTPRequestID(HTTPLogger(HTTPOrigin("https://authloft.example.com", nil, next)))

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no origin: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	attrs := logCap.attrs("access")
	if attrs == nil {
		t.Fatalf("no \"access\" record for 403 (logger 须对 origin 拒绝也输出)")
	}
	if attrs["status"] != "403" {
		t.Errorf("status = %q, want \"403\"", attrs["status"])
	}
	if attrs["request_id"] == "" {
		t.Error("request_id is empty, want non-empty (logger 须在 HTTPRequestID 之内)")
	}
}

// TestHTTPLoggerImplicitWriteStatus handler 只 Write 不 WriteHeader →
// statusWriter 按标准库语义记隐式 200；handler 未写任何响应亦记 200。
func TestHTTPLoggerImplicitWriteStatus(t *testing.T) {
	writeOnly := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	silent := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})

	for name, handler := range map[string]http.Handler{"write-only": writeOnly, "silent": silent} {
		logCap := captureSlog(t)
		rec := httptest.NewRecorder()
		HTTPLogger(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api.sso.v1.SsoService/X", nil))
		attrs := logCap.attrs("access")
		if attrs == nil {
			t.Fatalf("%s: no \"access\" record captured", name)
		}
		if attrs["status"] != "200" {
			t.Errorf("%s: status = %q, want \"200\" (隐式 WriteHeader 语义)", name, attrs["status"])
		}
	}
}

// TestHTTPLoggerIgnoresQueryAndHeaders query 与头不进日志（只读
// r.Method / r.URL.Path——与 gin 版同口径，无 body/query/头读取，
// §3.3 行 302 敏感信息约束）。
func TestHTTPLoggerIgnoresQueryAndHeaders(t *testing.T) {
	logCap := captureSlog(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/api.sso.v1.SsoService/LoginDefault?login_token=SECRET-TOKEN-123", nil)
	req.Header.Set("Authorization", "Bearer SECRET-TOKEN-123")
	HTTPLogger(next).ServeHTTP(httptest.NewRecorder(), req)

	if out := logCap.text(); strings.Contains(out, "SECRET-TOKEN-123") {
		t.Errorf("access log leaks sensitive value: %q", out)
	}
	if attrs := logCap.attrs("access"); attrs == nil || attrs["path"] != "/api.sso.v1.SsoService/LoginDefault" {
		t.Errorf("path = %v, want query stripped", attrs)
	}
}

// TestHTTPMetricsCountsRequests http 版指标计数（与 gin 版
// TestMetricsCountsRequests 同口径）：请求后 requests/duration 递增、
// handler 执行期间在途为 1、结束后归零。
func TestHTTPMetricsCountsRequests(t *testing.T) {
	resetMetrics()
	var inflightSeen int64
	h := HTTPMetrics(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		inflightSeen = inFlight.Load()
		time.Sleep(2 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api.sso.v1.SsoService/X", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i, rec.Code, http.StatusOK)
		}
	}
	if got := requestsTotal.Load(); got != 3 {
		t.Errorf("requests_total = %d, want 3", got)
	}
	if inflightSeen != 1 {
		t.Errorf("in_flight during handler = %d, want 1", inflightSeen)
	}
	if got := inFlight.Load(); got != 0 {
		t.Errorf("in_flight after requests = %d, want 0", got)
	}
	if got := durationNanosTotal.Load(); got < 1_000_000 {
		t.Errorf("duration_nanos_total = %d, want >= 1000000 (3x2ms sleeps)", got)
	}
}

// TestHTTPMetricsCountsPanickedRequest panic 请求也计数（defer 累加语义）。
// Connect 域的 panic 由 connect-go WithRecover 在 handler 内归一为正常返回
//（internal/connect/server.go），defer 照常执行；本用例走另一路径——
// panic 穿过前缀链 unwind（模拟 http.Server 连接级恢复），defer 同样触发。
func TestHTTPMetricsCountsPanickedRequest(t *testing.T) {
	resetMetrics()
	h := HTTPMetrics(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { panic("boom") }))
	func() {
		defer func() { _ = recover() }() // 模拟连接级恢复：panic 已穿过 HTTPMetrics 的 defer
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/boom", nil))
	}()
	if got := requestsTotal.Load(); got != 1 {
		t.Errorf("requests_total after panic = %d, want 1", got)
	}
	if got := inFlight.Load(); got != 0 {
		t.Errorf("in_flight after panic = %d, want 0", got)
	}
}

// TestHTTPMetricsSharesCountersWithGin 零复制实证：gin 版 Metrics 与 http 版
// HTTPMetrics 写同一组包级原子变量——各计一请求，requests_total 恰 +2
//（Connect 域流量与 gin 全局链共同计入 /metrics 的口径基础）。
func TestHTTPMetricsSharesCountersWithGin(t *testing.T) {
	resetMetrics()
	r := newTestRouter(Metrics())
	r.GET("/ping", okHandler)
	serve(r, "/ping", "")

	h := HTTPMetrics(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api.sso.v1.SsoService/X", nil))

	if got := requestsTotal.Load(); got != 2 {
		t.Errorf("requests_total = %d, want 2 (gin + http 共用同一组包级计数器)", got)
	}
}

// TestHTTPLoggerForwardsFlush statusWriter 显式转发 Flush：connect-go 对
// server 流式 RPC 断言 w 实现 http.Flusher（connect v1.21.1 protocol.go
// checkServerStreamsCanFlush）——内嵌接口不透传底层能力，缺转发会误伤
// 流式 RPC；转发须真实到达底层（rec.Flushed）。
func TestHTTPLoggerForwardsFlush(t *testing.T) {
	h := HTTPLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Error("inner writer does not implement http.Flusher, want forwarded")
			return
		}
		f.Flush()
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api.sso.v1.SsoService/X", nil))
	if !rec.Flushed {
		t.Error("flush not forwarded to underlying recorder")
	}
}
