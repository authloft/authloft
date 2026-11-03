// Gateway 中间件单测（docs/接口文档.md §6 行 1342-1344、docs/后端架构.md
// §3.3 行 293）：有效 token 放行、无效 / 缺头 403（豁免端点原生形态：
// 纯响应头无响应体，§1.0 行 66）、tokens 函数快照热生效。
package middleware

import (
	"net/http"
	"testing"
)

// ① X-Gateway-Token 在令牌列表 → 放行。
func TestGatewayValidTokenPasses(t *testing.T) {
	r := newTestRouter(Gateway(func() []string { return []string{"tok-a", "tok-b"} }))
	r.GET("/api/gateway/decode", okHandler)

	rec := doRequest(r, http.MethodGet, "/api/gateway/decode", map[string]string{"X-Gateway-Token": "tok-b"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// ② X-Gateway-Token 不在列表 → 403，且响应体为空（gateway 豁免形态：
// 纯响应头、无响应体，接口文档 §1.0 行 66 / §6 行 1347-1358）。
func TestGatewayInvalidTokenReturns403(t *testing.T) {
	r := newTestRouter(Gateway(func() []string { return []string{"tok-a"} }))
	r.GET("/api/gateway/decode", okHandler)

	rec := doRequest(r, http.MethodGet, "/api/gateway/decode", map[string]string{"X-Gateway-Token": "tok-x"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty (gateway 纯响应头、无响应体)", rec.Body.String())
	}
}

// ③ 未携带 Header → 403（缺凭据同无效，无免匿名路径）。
func TestGatewayMissingHeaderReturns403(t *testing.T) {
	r := newTestRouter(Gateway(func() []string { return []string{"tok-a"} }))
	r.GET("/api/gateway/decode", okHandler)

	rec := doRequest(r, http.MethodGet, "/api/gateway/decode", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// ④ tokens 函数每请求读取（settings 键 gateway_tokens 快照）：热更新对
// 后续请求生效。
func TestGatewayTokensHotReload(t *testing.T) {
	tokens := []string{"tok-old"}
	r := newTestRouter(Gateway(func() []string { return tokens }))
	r.GET("/api/gateway/decode", okHandler)

	rec := doRequest(r, http.MethodGet, "/api/gateway/decode", map[string]string{"X-Gateway-Token": "tok-new"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("热更前 status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	tokens = append(tokens, "tok-new") // 模拟后台增配 gateway_tokens
	rec2 := doRequest(r, http.MethodGet, "/api/gateway/decode", map[string]string{"X-Gateway-Token": "tok-new"})
	if rec2.Code != http.StatusOK {
		t.Fatalf("热更后 status = %d, want %d", rec2.Code, http.StatusOK)
	}
}

// ⑤ tokens 为 nil（未装配）→ 保守拒绝，不放行任何请求。
func TestGatewayNilTokensRejects(t *testing.T) {
	r := newTestRouter(Gateway(nil))
	r.GET("/api/gateway/decode", okHandler)

	rec := doRequest(r, http.MethodGet, "/api/gateway/decode", map[string]string{"X-Gateway-Token": "anything"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d（nil 保守拒绝）", rec.Code, http.StatusForbidden)
	}
}
