package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

const (
	testRootOrigin = "https://authloft.example.com"
	testAppID      = "wx1234567890abcdef"
)

// okHandler 标记请求到达业务 handler（middleware 各链路测试共用）。
func okHandler(c *gin.Context) {
	c.String(http.StatusOK, "ok")
}

// doRequest 发起带自定义头的请求（middleware 各链路测试共用）。
func doRequest(r *gin.Engine, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// decodeJSONBody 解出响应体的顶层 JSON 对象（403 出口为 Connect 错误
// 形态 {"code","message"}，接口文档 §1.5 行 184-211）。
func decodeJSONBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body %q: %v", rec.Body.String(), err)
	}
	return body
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

// ② 跨站 403，错误体为 Connect 形态 JSON：code=permission_denied
//（§1.5 行 188 Origin 跨站 → permission_denied/403，无 ErrorInfo detail）。
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
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Origin %q: Content-Type = %q, want application/json (Connect 错误形态)", origin, got)
		}
		body := decodeJSONBody(t, rec)
		if got := body["code"]; got != "permission_denied" {
			t.Errorf("Origin %q: error code = %v, want permission_denied (§1.5 行 188)", origin, got)
		}
	}
}

// ③ 无 Origin 时走 Referer 白名单（§21 行 1785）：servicewechat.com/{appid} 命中白名单通过；
// appid 不在白名单、host 不符（含子域）、无 Referer 一律 403（接口文档 §1.1 行 80）。
func TestOriginRefererAllowlist(t *testing.T) {
	r := newTestRouter(Origin(testRootOrigin, []string{testAppID}))
	r.POST("/api/x", okHandler)

	cases := []struct {
		name    string
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

// ④ 免检组（§3.3 行 289、§1.1 行 79 例外）：/api/oidc/**（REST 原路径）、
// rpc 域 Connect 路径 /api.rpc.v1.**、/api/gateway/** 跨站也通过；
// 前缀判定带边界：/api/oidcfoo 与旧 rpc 路径 /api/rpc/** 不再免检。
func TestOriginExemptGroups(t *testing.T) {
	r := newTestRouter(Origin(testRootOrigin, []string{testAppID}))
	r.POST("/api/x", okHandler)
	for _, p := range []string{"/api/oidc/x", "/api/gateway/x", "/api/oidcfoo", "/api/rpc/x", "/api.rpc.v1.RpcService/GetUserProfile"} {
		r.POST(p, okHandler)
	}

	for _, p := range []string{"/api/oidc/x", "/api/gateway/x", "/api.rpc.v1.RpcService/GetUserProfile"} {
		rec := doRequest(r, http.MethodPost, p, map[string]string{"Origin": "https://evil.example.com"})
		if rec.Code != http.StatusOK {
			t.Errorf("%s: exempt group status = %d, want %d", p, rec.Code, http.StatusOK)
		}
	}
	// 非免检：前缀不含 / 边界（/api/oidcfoo）与 rpc 域旧路径（/api/rpc/**，
	// Connect 化后免检面迁移至 /api.rpc.v1.**）→ 403。
	for _, p := range []string{"/api/oidcfoo", "/api/rpc/x"} {
		rec := doRequest(r, http.MethodPost, p, map[string]string{"Origin": "https://evil.example.com"})
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want %d (不在免检组)", p, rec.Code, http.StatusForbidden)
		}
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
