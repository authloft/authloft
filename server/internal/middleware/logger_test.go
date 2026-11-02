package middleware

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// ⑤ 正常请求输出恰好一条访问日志，request_id / method / path / status /
// latency 五字段齐全且值正确。
func TestLoggerOutputsAccessFields(t *testing.T) {
	logCap := captureSlog(t)
	r := newTestRouter(RequestID(), Logger())
	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	rec := serveBody(r, http.MethodGet, "/ping", "", nil)
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
	if attrs["request_id"] == "" {
		t.Errorf("request_id is empty, want non-empty (logger 须挂载在 RequestID 之后)")
	}
	if attrs["method"] != http.MethodGet {
		t.Errorf("method = %q, want %q", attrs["method"], http.MethodGet)
	}
	if attrs["path"] != "/ping" {
		t.Errorf("path = %q, want %q", attrs["path"], "/ping")
	}
	if attrs["status"] != "200" {
		t.Errorf("status = %q, want \"200\"", attrs["status"])
	}
	if attrs["latency"] == "" {
		t.Errorf("latency is empty, want non-empty duration")
	}
}

// ⑥ 请求带 login_token（query / body / 头）与 Authorization 头时，日志输出
// 不含敏感值（§3.3 行 309：日志不得打印 login_token / 密钥）。
func TestLoggerDoesNotLogSensitiveData(t *testing.T) {
	logCap := captureSlog(t)
	r := newTestRouter(RequestID(), Logger())
	r.POST("/login", okHandler)

	rec := serveBody(r, http.MethodPost, "/login?login_token=SECRET-TOKEN-123",
		`{"login_token":"SECRET-TOKEN-123"}`,
		map[string]string{
			"login_token":   "SECRET-TOKEN-123",
			"Authorization": "Bearer SECRET-TOKEN-123",
		})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if out := logCap.text(); strings.Contains(out, "SECRET-TOKEN-123") {
		t.Errorf("access log leaks sensitive value: %q", out)
	}
}

// ⑦ 状态码取最终值：未注册路由 → gin NoRoute 404，全局 logger 仍执行且记 404。
func TestLoggerRecordsFinalStatus(t *testing.T) {
	logCap := captureSlog(t)
	r := newTestRouter(RequestID(), Logger())
	// 故意不注册 /missing。

	rec := serveBody(r, http.MethodGet, "/missing", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	attrs := logCap.attrs("access")
	if attrs == nil {
		t.Fatalf("no \"access\" record for NoRoute request (全局中间件须对 404 也生效)")
	}
	if attrs["status"] != "404" {
		t.Errorf("status = %q, want \"404\" (取 c.Writer.Status() 最终值)", attrs["status"])
	}
}
