package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// httpTestChain 构造 Connect 域等效链（与装配层 bootstrap.go buildHandler
// 同序：HTTPRequestID 外层 → HTTPOrigin → 目标 handler），返回链与目标
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
