package middleware

import (
	"net/http"
	"testing"

	"authloft/internal/codec"
)

// ① application/json 通过（§21 行 1786）：charset 参数忽略、大小写不敏感（与 codec.Bind 同口径）。
func TestContentTypeJSONAllowed(t *testing.T) {
	r := newTestRouter(ContentType())
	r.POST("/api/x", okHandler)

	for _, ct := range []string{
		"application/json",
		"application/json; charset=utf-8",
		"application/json;charset=UTF-8",
		"APPLICATION/JSON",
	} {
		rec := doRequest(r, http.MethodPost, "/api/x", map[string]string{"Content-Type": ct})
		if rec.Code != http.StatusOK {
			t.Errorf("Content-Type %q: status = %d, want %d (body %s)", ct, rec.Code, http.StatusOK, rec.Body.String())
		}
	}
}

// ② application/octet-stream 通过（§21 行 1786）。
func TestContentTypeProtoAllowed(t *testing.T) {
	r := newTestRouter(ContentType())
	r.POST("/api/x", okHandler)

	rec := doRequest(r, http.MethodPost, "/api/x", map[string]string{"Content-Type": "application/octet-stream"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// ③ text/plain → 415（§21 行 1786）：错误体走 codec.WriteError（code=unsupported_media_type、
// §1.5 行 199），协商中间件未执行 → 回落 JSON；Content-Type 缺失同样 415。
func TestContentTypeTextPlainRejected(t *testing.T) {
	r := newTestRouter(ContentType())
	r.POST("/api/x", okHandler)

	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", ""} {
		headers := map[string]string{}
		if ct != "" {
			headers["Content-Type"] = ct
		}
		rec := doRequest(r, http.MethodPost, "/api/x", headers)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("Content-Type %q: status = %d, want %d", ct, rec.Code, http.StatusUnsupportedMediaType)
			continue
		}
		body := decodeErrorBody(t, rec)
		if got := body["status"]; got != codec.StatusError {
			t.Errorf("Content-Type %q: status = %v, want %q (信封形状)", ct, got, codec.StatusError)
		}
		if got := errorObject(t, body)["code"]; got != codec.CodeUnsupportedMediaType {
			t.Errorf("Content-Type %q: error code = %v, want %q", ct, got, codec.CodeUnsupportedMediaType)
		}
	}
}

// ④ 写方法不止 POST：PUT / PATCH / DELETE 同样受限。
func TestContentTypeWriteMethodVariants(t *testing.T) {
	r := newTestRouter(ContentType())
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		r.Handle(m, "/api/x", okHandler)
	}

	for _, m := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rec := doRequest(r, m, "/api/x", map[string]string{"Content-Type": "text/plain"})
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%s: status = %d, want %d (写方法均受限)", m, rec.Code, http.StatusUnsupportedMediaType)
		}
	}
}

// ⑤ GET / HEAD / OPTIONS 不受 Content-Type 限制（安全方法无请求体语义，§1.1 行 56）。
func TestContentTypeSafeMethodsSkip(t *testing.T) {
	r := newTestRouter(ContentType())
	r.GET("/api/x", okHandler)
	r.HEAD("/api/x", okHandler)
	r.OPTIONS("/api/x", okHandler)

	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		rec := doRequest(r, m, "/api/x", map[string]string{"Content-Type": "text/plain"})
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want %d (安全方法不受限)", m, rec.Code, http.StatusOK)
		}
	}
}

// ⑥ OIDC 免检（§21 行 1786）：/api/oidc/** 的 x-www-form-urlencoded 通过；
// 前缀判定带 `/` 边界：/api/oidcfoo 不免检。
func TestContentTypeOIDCExempt(t *testing.T) {
	r := newTestRouter(ContentType())
	r.POST("/api/oidc/token", okHandler)
	r.POST("/api/oidcfoo", okHandler)

	if rec := doRequest(r, http.MethodPost, "/api/oidc/token", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); rec.Code != http.StatusOK {
		t.Errorf("oidc x-www-form-urlencoded: status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec := doRequest(r, http.MethodPost, "/api/oidcfoo", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("/api/oidcfoo: status = %d, want %d (前缀不含 / 边界外)", rec.Code, http.StatusUnsupportedMediaType)
	}
}

// ⑦ multipart 端点免检（§21 行 1786、接口文档 §1.1 行 65-67）：
// /api/account/avatar 按路径免检（该端点 Content-Type 由上传服务层校验）；
// 其余端点发 multipart 一律 415。
func TestContentTypeMultipartExempt(t *testing.T) {
	r := newTestRouter(ContentType())
	r.POST("/api/account/avatar", okHandler)
	r.POST("/api/account/profile", okHandler)

	if rec := doRequest(r, http.MethodPost, "/api/account/avatar", map[string]string{"Content-Type": "multipart/form-data; boundary=xyz"}); rec.Code != http.StatusOK {
		t.Errorf("avatar multipart: status = %d, want %d (multipart 端点免检)", rec.Code, http.StatusOK)
	}
	if rec := doRequest(r, http.MethodPost, "/api/account/profile", map[string]string{"Content-Type": "multipart/form-data; boundary=xyz"}); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("profile multipart: status = %d, want %d (非清单端点不受 multipart 免检)", rec.Code, http.StatusUnsupportedMediaType)
	}
}
