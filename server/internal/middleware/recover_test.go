package middleware

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/proto"

	api "authloft/gen/go/api/common"
	"authloft/internal/codec"
)

// slogCapture 收集经 slog 默认 logger 输出的记录（recover / logger 测试共用）。
type slogCapture struct {
	records []slog.Record
}

func (h *slogCapture) Enabled(context.Context, slog.Level) bool { return true }

func (h *slogCapture) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}

func (h *slogCapture) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *slogCapture) WithGroup(string) slog.Handler      { return h }

// attrs 返回第一条 message 匹配的记录的属性表；无匹配返回 nil。
func (h *slogCapture) attrs(msg string) map[string]string {
	for _, r := range h.records {
		if r.Message != msg {
			continue
		}
		m := make(map[string]string, r.NumAttrs())
		r.Attrs(func(a slog.Attr) bool {
			m[a.Key] = a.Value.String()
			return true
		})
		return m
	}
	return nil
}

// text 把全部记录拼成一段文本（敏感信息泄漏断言用）。
func (h *slogCapture) text() string {
	var b strings.Builder
	for _, r := range h.records {
		b.WriteString(r.Message)
		b.WriteByte(' ')
		r.Attrs(func(a slog.Attr) bool {
			b.WriteString(a.Key)
			b.WriteByte('=')
			b.WriteString(a.Value.String())
			b.WriteByte(' ')
			return true
		})
	}
	return b.String()
}

// captureSlog 临时替换 slog 默认 logger 为捕获 handler，测试结束自动恢复。
func captureSlog(t *testing.T) *slogCapture {
	t.Helper()
	h := &slogCapture{}
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(old) })
	return h
}

// serveBody 发起带请求体与自定义头的请求（doRequest 不支持 body；logger
// 敏感信息测试需要把 login_token 同时塞进 query / body / 头三处）。
func serveBody(r *gin.Engine, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// ① panic 路由 → 500 + 统一 JSON 错误体：code=internal_error、message 固定
// 文案、request_id 非空（requestid 在 recover 内层、handler 之前已写入 ctx），
// panic 值不透出到响应体。
func TestRecoverWritesUnifiedErrorBody(t *testing.T) {
	r := newTestRouter(Recover(), RequestID())
	r.GET("/boom", func(c *gin.Context) { panic("boom") })

	rec := serveBody(r, http.MethodGet, "/boom", "", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	body := decodeErrorBody(t, rec)
	if got := body["status"]; got != codec.StatusError {
		t.Errorf("status = %v, want %q (信封形状)", got, codec.StatusError)
	}
	errObj := errorObject(t, body)
	if got := errObj["code"]; got != codec.CodeInternalError {
		t.Errorf("error.code = %v, want %q", got, codec.CodeInternalError)
	}
	if got := errObj["message"]; got != "internal error" {
		t.Errorf("error.message = %v, want %q (不透出 panic 内容)", got, "internal error")
	}
	if got, _ := errObj["request_id"].(string); got == "" {
		t.Errorf("error.request_id is empty, want non-empty")
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Errorf("error body leaks panic value: %s", rec.Body.String())
	}
}

// ② Protobuf 协商下 panic → 错误体按 proto 编码，proto.Unmarshal 解出
// api.ErrorEnvelope{status:"error"} 且内层 code=internal_error
// （错误体编码随协商，接口文档 §1.5 行 195）。
func TestRecoverProtobufNegotiatedErrorBody(t *testing.T) {
	r := newTestRouter(Recover(), RequestID(), NegotiateFormat())
	r.GET("/boom", func(c *gin.Context) { panic("boom") })

	rec := serveBody(r, http.MethodGet, "/boom", "", map[string]string{"Accept": contentTypeProto})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Header().Get("Content-Type"); got != contentTypeProto {
		t.Fatalf("Content-Type = %q, want %q", got, contentTypeProto)
	}
	var envelope api.ErrorEnvelope
	if err := proto.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("proto.Unmarshal error body %x: %v", rec.Body.Bytes(), err)
	}
	if envelope.Status != codec.StatusError {
		t.Errorf("status = %q, want %q (信封形状)", envelope.Status, codec.StatusError)
	}
	if envelope.Error == nil {
		t.Fatalf("envelope.Error is nil, want inner error object")
	}
	if envelope.Error.Code != codec.CodeInternalError {
		t.Errorf("code = %q, want %q", envelope.Error.Code, codec.CodeInternalError)
	}
	if envelope.Error.RequestId == "" {
		t.Errorf("request_id is empty, want non-empty")
	}
}

// ③ 已写过部分响应后 panic → 不再二次写：响应字节不被追加错误体
// （§3.14 行 486 禁止半截输出），已写出的状态码不被覆盖。
func TestRecoverPartialResponseNotAppended(t *testing.T) {
	r := newTestRouter(Recover(), RequestID())
	r.GET("/partial", func(c *gin.Context) {
		c.String(http.StatusOK, "partial-data")
		panic("boom after write")
	})

	rec := serveBody(r, http.MethodGet, "/partial", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (已写出的 200 不被覆盖)", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != "partial-data" {
		t.Errorf("body = %q, want %q (不得追加错误体)", got, "partial-data")
	}
}

// ④ panic 值与堆栈进日志（slog 捕获验证），并携带 request_id 与请求定位字段。
func TestRecoverLogsPanicAndStack(t *testing.T) {
	logCap := captureSlog(t)
	r := newTestRouter(Recover(), RequestID())
	r.GET("/boom", func(c *gin.Context) { panic("boom-value-xyz") })

	serveBody(r, http.MethodGet, "/boom", "", nil)

	attrs := logCap.attrs("panic recovered")
	if attrs == nil {
		t.Fatalf("no \"panic recovered\" record captured (records = %d)", len(logCap.records))
	}
	if got := attrs["panic"]; got != "boom-value-xyz" {
		t.Errorf("panic attr = %q, want %q", got, "boom-value-xyz")
	}
	if !strings.Contains(attrs["stack"], "recover_test.go") {
		t.Errorf("stack attr missing test file frame:\n%s", attrs["stack"])
	}
	if attrs["request_id"] == "" {
		t.Errorf("request_id attr is empty, want non-empty")
	}
}

// ⑤ 链中段中间件 panic → 后续中间件与 handler 不执行、恰一次 500 错误体。
// gin 的 Next 是共享 index 的 for 循环（gin v1.12.0 context.go:188-196）：
// panic 点非链尾时 unwind 回 engine 侧循环会从 index+1 继续执行剩余链段，
// 缺 c.Abort() 时标记中间件 B 与 handler 照跑，500 之后再写响应即半截混合输出。
func TestRecoverMidChainPanicAbortsChain(t *testing.T) {
	r := newTestRouter(Recover(), RequestID())
	afterRan := false
	handlerRan := false
	// 中间件 A：链中段（handler 之前）panic
	r.Use(func(c *gin.Context) { panic("mid-chain-boom") })
	// 中间件 B：A 的后续链段，Abort 缺失时会被 engine 侧循环继续执行
	r.Use(func(c *gin.Context) { afterRan = true; c.Next() })
	r.GET("/mid", func(c *gin.Context) { handlerRan = true; c.Status(http.StatusOK) })

	rec := serveBody(r, http.MethodGet, "/mid", "", nil)
	if afterRan {
		t.Errorf("panic 之后的中间件 B 仍被执行（缺 c.Abort() 截断链）")
	}
	if handlerRan {
		t.Errorf("panic 之后 handler 仍被执行（缺 c.Abort() 截断链）")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	// 恰一次错误体：B/handler 均未执行（无第二次写入），且 body 是单个合法
	// JSON 对象（追加第二段会让 json.Unmarshal 失败）。
	body := decodeErrorBody(t, rec)
	if got := body["status"]; got != codec.StatusError {
		t.Errorf("status = %v, want %q (信封形状)", got, codec.StatusError)
	}
	errObj := errorObject(t, body)
	if got := errObj["code"]; got != codec.CodeInternalError {
		t.Errorf("error.code = %v, want %q", got, codec.CodeInternalError)
	}
	if got := errObj["message"]; got != "internal error" {
		t.Errorf("error.message = %v, want %q", got, "internal error")
	}
	if strings.Contains(rec.Body.String(), "mid-chain-boom") {
		t.Errorf("error body leaks panic value: %s", rec.Body.String())
	}
}
