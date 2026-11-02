package middleware

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	api "authloft/gen/go/api/common"
	"authloft/internal/codec"
	"google.golang.org/protobuf/proto"
)

const (
	contentTypeProto = "application/octet-stream"
	contentTypeJSON  = "application/json; charset=utf-8"
)

// ③ Accept: application/octet-stream → 路由内 codec.Write 输出 octet-stream。
func TestNegotiateFormatProtoContentType(t *testing.T) {
	r := newTestRouter(NegotiateFormat())
	r.GET("/api/sso/methods", func(c *gin.Context) {
		codec.Write(c, http.StatusOK, &api.Error{Code: "payload"})
	})

	rec := serve(r, "/api/sso/methods", "application/octet-stream")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != contentTypeProto {
		t.Errorf("Content-Type = %q, want %q", got, contentTypeProto)
	}
}

// ④ Accept 无 octet-stream（缺失 / */* / 其他类型）→ JSON。
func TestNegotiateFormatFallsBackToJSON(t *testing.T) {
	r := newTestRouter(NegotiateFormat())
	r.GET("/api/sso/methods", func(c *gin.Context) {
		codec.Write(c, http.StatusOK, &api.Error{Code: "payload"})
	})

	for _, accept := range []string{"", "*/*", "text/html", "application/json"} {
		rec := serve(r, "/api/sso/methods", accept)
		if got := rec.Header().Get("Content-Type"); got != contentTypeJSON {
			t.Errorf("Accept %q: Content-Type = %q, want %q", accept, got, contentTypeJSON)
		}
	}
}

// ⑤ 免协商白名单 /api/oidc/** 恒 JSON（后端架构 §3.14 行 485）。
func TestNegotiateFormatOIDCWhitelistAlwaysJSON(t *testing.T) {
	r := newTestRouter(NegotiateFormat())
	r.GET("/api/oidc/x", func(c *gin.Context) {
		codec.Write(c, http.StatusOK, &api.Error{Code: "payload"})
	})

	rec := serve(r, "/api/oidc/x", "application/octet-stream")
	if got := rec.Header().Get("Content-Type"); got != contentTypeJSON {
		t.Errorf("Content-Type = %q, oidc whitelist must stay JSON", got)
	}
}

// ⑥ 闭环：requestid + negotiate 两中间件 + WriteError，
// Protobuf 协商下 proto.Unmarshal 解出 api.Error 且 request_id 非空。
func TestRequestIDAndNegotiateProtoErrorIntegration(t *testing.T) {
	r := newTestRouter(RequestID(), NegotiateFormat())
	r.GET("/boom", func(c *gin.Context) {
		codec.WriteError(c, http.StatusBadRequest, codec.CodeBadRequest, "x")
	})

	rec := serve(r, "/boom", "application/octet-stream")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if got := rec.Header().Get("Content-Type"); got != contentTypeProto {
		t.Fatalf("Content-Type = %q, want %q", got, contentTypeProto)
	}
	var errBody api.Error
	if err := proto.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("unmarshal api.Error: %v", err)
	}
	if errBody.GetCode() != codec.CodeBadRequest {
		t.Errorf("code = %q, want %q", errBody.GetCode(), codec.CodeBadRequest)
	}
	if errBody.GetRequestId() == "" {
		t.Errorf("api.Error.request_id is empty, want non-empty")
	}
}
