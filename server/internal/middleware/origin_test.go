package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"authloft/internal/codec"
)

const (
	testRootOrigin = "https://authloft.example.com"
	testAppID      = "wx1234567890abcdef"
)

// okHandler 标记请求到达业务 handler（origin / contenttype 测试共用）。
func okHandler(c *gin.Context) {
	c.String(http.StatusOK, "ok")
}

// doRequest 发起带自定义头的请求（origin / contenttype 测试共用；Content-Type
// 仅作为头设置，不读 body——中间件只判头，见 contenttype.go）。
func doRequest(r *gin.Engine, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// decodeErrorBody 解出 §1.5 错误信封的顶层 JSON 对象（origin / contenttype 的
// 403 / 415 都走 codec.WriteError，协商中间件未执行时按 write.go 回落 JSON）。
func decodeErrorBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body %q: %v", rec.Body.String(), err)
	}
	return body
}

// errorObject 取出信封内层 error 对象（§1.0 行 57：{"status":"error","error":{…}}；
// middleware 包内各错误体断言共用）。
func errorObject(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	obj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("envelope missing \"error\" object: %v", body)
	}
	return obj
}

// ① 同源通过（§21 行 1785）；scheme / host 大小写不敏感。
func TestOriginSameOriginPasses(t *testing.T) {
	r := newTestRouter(Origin(testRootOrigin, []string{testAppID}))
	r.POST("/api/x", okHandler)

	for _, origin := range []string{testRootOrigin, "HTTPS://AUTHLOFT.EXAMPLE.COM"} {
		rec := doRequest(r, http.MethodPost, "/api/x", map[string]string{"Origin": origin})
		if rec.Code != http.StatusOK {
			t.Errorf("Origin %q: status = %d, want %d (body %s)", origin, rec.Code, http.StatusOK, rec.Body.String())
		}
	}
}

// ② 跨站 403，错误体走 codec.WriteError：code=forbidden（§1.5 行 199）、
// 协商中间件未执行 → 回落 JSON（write.go 行 32-35）。
func TestOriginCrossOriginRejected(t *testing.T) {
	r := newTestRouter(Origin(testRootOrigin, []string{testAppID}))
	r.POST("/api/x", okHandler)

	for _, origin := range []string{
		"https://evil.example.com",
		"https://authloft.example.com.evil.com",
		"https://authloft.example.com:8443", // 端口不同 = 不同源
		"null",                              // 沙箱 iframe / 隐私模式下的 Origin: null
	} {
		rec := doRequest(r, http.MethodPost, "/api/x", map[string]string{"Origin": origin})
		if rec.Code != http.StatusForbidden {
			t.Errorf("Origin %q: status = %d, want %d", origin, rec.Code, http.StatusForbidden)
			continue
		}
		if got := rec.Header().Get("Content-Type"); got != contentTypeJSON {
			t.Errorf("Origin %q: Content-Type = %q, want %q (negotiate 前回落 JSON)", origin, got, contentTypeJSON)
		}
		body := decodeErrorBody(t, rec)
		if got := body["status"]; got != codec.StatusError {
			t.Errorf("Origin %q: status = %v, want %q (信封形状)", origin, got, codec.StatusError)
		}
		if got := errorObject(t, body)["code"]; got != codec.CodeForbidden {
			t.Errorf("Origin %q: error code = %v, want %q", origin, got, codec.CodeForbidden)
		}
	}
}

// ③ 无 Origin 时走 Referer 白名单（§21 行 1785）：servicewechat.com/{appid} 命中白名单通过；
// appid 不在白名单、host 不符（含子域）、无 Referer 一律 403（接口文档 §1.1 行 58）。
func TestOriginRefererAllowlist(t *testing.T) {
	r := newTestRouter(Origin(testRootOrigin, []string{testAppID}))
	r.POST("/api/x", okHandler)

	cases := []struct {
		name   string
		referer string
		want    int
	}{
		{"allowlisted appid", "https://servicewechat.com/" + testAppID + "/1/page-frame.html", http.StatusOK},
		{"appid not in allowlist", "https://servicewechat.com/wx0000000000000000/x", http.StatusForbidden},
		{"wrong host", "https://evil.com/" + testAppID + "/x", http.StatusForbidden},
		{"subdomain not accepted", "https://sub.servicewechat.com/" + testAppID + "/x", http.StatusForbidden},
		{"no referer", "", http.StatusForbidden},
	}
	for _, tc := range cases {
		headers := map[string]string{}
		if tc.referer != "" {
			headers["Referer"] = tc.referer
		}
		rec := doRequest(r, http.MethodPost, "/api/x", headers)
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d (body %s)", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}
}

// ④ 免检组 /api/oidc/**、/api/rpc/**、/api/gateway/** 跨站也通过（§3.3 行 302）；
// 前缀判定带 `/` 边界：/api/oidcfoo 不属于免检组。
func TestOriginExemptGroups(t *testing.T) {
	r := newTestRouter(Origin(testRootOrigin, []string{testAppID}))
	r.POST("/api/x", okHandler)
	for _, p := range []string{"/api/oidc/x", "/api/rpc/x", "/api/gateway/x", "/api/oidcfoo"} {
		r.POST(p, okHandler)
	}

	for _, p := range []string{"/api/oidc/x", "/api/rpc/x", "/api/gateway/x"} {
		rec := doRequest(r, http.MethodPost, p, map[string]string{"Origin": "https://evil.example.com"})
		if rec.Code != http.StatusOK {
			t.Errorf("%s: exempt group status = %d, want %d", p, rec.Code, http.StatusOK)
		}
	}
	rec := doRequest(r, http.MethodPost, "/api/oidcfoo", map[string]string{"Origin": "https://evil.example.com"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("/api/oidcfoo: status = %d, want %d (前缀不含 / 边界外)", rec.Code, http.StatusForbidden)
	}
}

// ⑤ 未配置（rootOrigin 空串、白名单 nil）时保守拒绝：同源判断与 Referer 白名单恒失败
//（宁可整站拒绝也不让 CSRF 防护默认失效），仅免检组可用。
func TestOriginEmptyConfigConservative(t *testing.T) {
	r := newTestRouter(Origin("", nil))
	r.POST("/api/x", okHandler)

	if rec := doRequest(r, http.MethodPost, "/api/x", map[string]string{"Origin": testRootOrigin}); rec.Code != http.StatusForbidden {
		t.Errorf("same-origin with empty rootOrigin: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if rec := doRequest(r, http.MethodPost, "/api/x", map[string]string{"Referer": "https://servicewechat.com/" + testAppID + "/x"}); rec.Code != http.StatusForbidden {
		t.Errorf("allowlisted referer with empty allowlist: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// ⑥ 安全方法（GET / HEAD / OPTIONS）不校验 Origin：CSRF 只针对状态变更请求。
func TestOriginSafeMethodsSkip(t *testing.T) {
	r := newTestRouter(Origin(testRootOrigin, []string{testAppID}))
	r.GET("/api/x", okHandler)
	r.HEAD("/api/x", okHandler)
	r.OPTIONS("/api/x", okHandler)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		rec := doRequest(r, method, "/api/x", map[string]string{"Origin": "https://evil.example.com"})
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want %d (安全方法不校验 Origin)", method, rec.Code, http.StatusOK)
		}
	}
}
