package middleware

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"authloft/internal/codec"
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

// ① 两次请求 ID 非空、32 位 hex、逐请求不同。
func TestRequestIDGeneratesUniqueHexIDs(t *testing.T) {
	r := newTestRouter(RequestID())
	ids := make([]string, 0, 2)
	r.GET("/ping", func(c *gin.Context) {
		ids = append(ids, c.GetString(codec.RequestIDKey))
	})

	for i := 0; i < 2; i++ {
		rec := serve(r, "/ping", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i, rec.Code, http.StatusOK)
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

// 纯生成口径锁定：入站 X-Request-Id 不透传（防客户端伪造/注入）。
func TestRequestIDIgnoresInboundHeader(t *testing.T) {
	r := newTestRouter(RequestID())
	r.GET("/ping", func(c *gin.Context) {
		if got := c.GetString(codec.RequestIDKey); got == "spoofed-id" {
			t.Errorf("request id = %q, must not be taken from inbound header", got)
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("X-Request-Id", "spoofed-id")
	r.ServeHTTP(httptest.NewRecorder(), req)
}

// ② 集成：挂 requestid 后，codec.WriteError 的错误体 request_id 非空（接口文档 §1.5 行 201）。
func TestRequestIDFeedsWriteError(t *testing.T) {
	r := newTestRouter(RequestID())
	r.GET("/boom", func(c *gin.Context) {
		codec.WriteError(c, http.StatusBadRequest, codec.CodeBadRequest, "x")
	})

	rec := serve(r, "/boom", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body %q: %v", rec.Body.String(), err)
	}
	if got := body["status"]; got != codec.StatusError {
		t.Errorf("status = %v, want %q (信封形状)", got, codec.StatusError)
	}
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("envelope missing \"error\" object: %v", body)
	}
	if got := errObj["code"]; got != codec.CodeBadRequest {
		t.Errorf("error.code = %v, want %q", got, codec.CodeBadRequest)
	}
	got, _ := errObj["request_id"].(string)
	if got == "" {
		t.Errorf("error body request_id is empty, want non-empty")
	}
}
