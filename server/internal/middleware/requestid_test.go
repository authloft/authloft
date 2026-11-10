package middleware

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"authloft/internal/logx"
)

func newTestRouter(mw ...gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(mw...)
	return r
}

func serve(r *gin.Engine, path, accept string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// requestIDHeader 取响应头 X-Request-Id（所有响应统一回写）。
func requestIDHeader(rec *httptest.ResponseRecorder) string {
	return rec.Header().Get(XRequestIDHeader)
}

// ① 两次请求 ID 非空、32 位 hex、逐请求不同；响应头 X-Request-Id 与 ctx 值一致。
func TestRequestIDGeneratesUniqueHexIDs(t *testing.T) {
	r := newTestRouter(RequestID())
	ids := make([]string, 0, 2)
	r.GET("/ping", func(c *gin.Context) {
		ids = append(ids, c.GetString(RequestIDKey))
	})

	for i := 0; i < 2; i++ {
		rec := serve(r, "/ping", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i, rec.Code, http.StatusOK)
		}
		if got := requestIDHeader(rec); got == "" {
			t.Errorf("request %d: X-Request-Id header is empty, want non-empty (所有响应统一回写)", i)
		}
	}
	if len(ids) != 2 {
		t.Fatalf("captured %d ids, want 2", len(ids))
	}

	seen := make(map[string]bool, len(ids))
	for i, id := range ids {
		if id == "" {
			t.Errorf("request %d: request id is empty", i)
		}
		if len(id) != 32 {
			t.Errorf("request %d: id %q length = %d, want 32 hex chars", i, id, len(id))
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Errorf("request %d: id %q not valid hex: %v", i, id, err)
		}
		if seen[id] {
			t.Errorf("request id %q repeated, must differ per request", id)
		}
		seen[id] = true
	}
}

// ② 纯生成口径锁定：入站 X-Request-Id 不透传（防客户端伪造/注入）——
// ctx 值与响应头均不得取自入站头（docs/接口文档.md §1.1 行 83）。
func TestRequestIDIgnoresInboundHeader(t *testing.T) {
	r := newTestRouter(RequestID())
	r.GET("/ping", okHandler)

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("X-Request-Id", "spoofed-id")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if got := rec.Header().Get(XRequestIDHeader); got == "spoofed-id" || got == "" {
		t.Errorf("X-Request-Id = %q, must be server-generated (非空且不透传入站头)", got)
	}
}

// ③ 所有响应统一回写（§1.1 行 83）：成功 200、未知路径 404、
// 链上中间件 Abort 403——三种出口的响应头均存在。
func TestRequestIDHeaderOnAllResponses(t *testing.T) {
	r := newTestRouter(RequestID())
	r.GET("/ok", okHandler)

	if rec := serve(r, "/ok", ""); requestIDHeader(rec) == "" {
		t.Errorf("200 response: X-Request-Id is empty, want non-empty")
	}
	if rec := serve(r, "/missing", ""); requestIDHeader(rec) == "" {
		t.Errorf("404 response: X-Request-Id is empty, want non-empty")
	}

	// 链上中间件 Abort 的失败响应（如 origin 403）同样带头：requestid 挂在
	// origin 之前，c.Header 已写入头表。
	r2 := newTestRouter(RequestID(), Origin("https://authloft.example.com", nil))
	r2.POST("/api/x", okHandler)
	rec := doRequest(r2, http.MethodPost, "/api/x", map[string]string{"Origin": "https://evil.example.com"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("origin reject: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if requestIDHeader(rec) == "" {
		t.Errorf("403 response: X-Request-Id is empty, want non-empty")
	}
}

// ④ 链路 ID 同步注入标准请求 ctx：gin 域 handler 用 c.Request.Context()
// 调下游时，logx.Warn(ctx, …) / slog.WarnContext(ctx, …) 能拿到同一个 ID
//（Connect 域 HTTPRequestID 共用 logx.WithRequestID，口径唯一）。
func TestRequestIDInRequestContext(t *testing.T) {
	r := newTestRouter(RequestID())
	var ctxID, ginID string
	r.GET("/ping", func(c *gin.Context) {
		ctxID = logx.RequestID(c.Request.Context())
		ginID = c.GetString(RequestIDKey)
	})
	rec := serve(r, "/ping", "")

	if ctxID == "" {
		t.Fatal("request ctx has no request_id, want downstream service logs to be correlatable")
	}
	if ctxID != ginID {
		t.Errorf("ctx id %q != gin.Context id %q", ctxID, ginID)
	}
	if got := requestIDHeader(rec); ctxID != got {
		t.Errorf("ctx id %q != X-Request-Id header %q", ctxID, got)
	}
}
