// CSP 中间件单测（docs/后端架构.md §21.2 E 行 1869）：nonce 每请求不同、
// CSPSupporter 指令被追加、nonce 写入 ctx 供 handler 消费、基线指令齐全。
package middleware

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// fakeCSPSupporter 固定指令片段的 CSPSupporter 假实现（§12.1 行 1411 接口）。
type fakeCSPSupporter struct{ directive string }

func (f fakeCSPSupporter) CSP() string { return f.directive }

// ① nonce 每请求不同（§21.2 E 行 1869）且写 ctx（CSPNonceKey）供 handler 消费。
func TestCSPNonceUniquePerRequest(t *testing.T) {
	nonces := make([]string, 0, 2)
	r := newTestRouter(CSP())
	r.GET("/", func(c *gin.Context) {
		nonces = append(nonces, c.GetString(CSPNonceKey))
		c.String(http.StatusOK, "ok")
	})

	for i := 0; i < 2; i++ {
		if rec := doRequest(r, http.MethodGet, "/", nil); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i, rec.Code, http.StatusOK)
		}
	}
	if len(nonces) != 2 {
		t.Fatalf("captured %d nonces, want 2", len(nonces))
	}
	for i, n := range nonces {
		if n == "" {
			t.Errorf("request %d: ctx nonce 为空", i)
		}
		if len(n) != cspNonceLen {
			t.Errorf("request %d: nonce 长度 = %d, want %d", i, len(n), cspNonceLen)
		}
	}
	if nonces[0] == nonces[1] {
		t.Errorf("nonce %q 重复，必须 per-request 随机（§3.3 行 310）", nonces[0])
	}
}

// ② CSP 响应头含 ctx 中同一 nonce 与终稿基线指令（接口文档 §8
// 行 1521-1532：default-src / script-src nonce+strict-dynamic / style-src
// nonce+'self' / font-src / img-src 'self' data: https: / connect-src）。
func TestCSPHeaderContainsNonceAndBaseDirectives(t *testing.T) {
	var nonce string
	r := newTestRouter(CSP())
	r.GET("/", func(c *gin.Context) {
		nonce = c.GetString(CSPNonceKey)
		c.String(http.StatusOK, "ok")
	})

	rec := doRequest(r, http.MethodGet, "/", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy 响应头缺失")
	}
	for _, want := range []string{
		"default-src 'self'",
		"script-src 'nonce-" + nonce + "' 'strict-dynamic'",
		"style-src 'nonce-" + nonce + "' 'self'",
		"font-src 'self'",
		"img-src 'self' data: https:",
		"connect-src 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP 头缺少基线指令 %q：%s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP 头禁 unsafe-inline：%s", csp)
	}
}

// ③ CSPSupporter 指令被追加（§21.2 E 行 1869 / §3.13 行 484）：追加在基线
// 之后；空白返回值的 supporter 不产生空指令。
func TestCSPSupporterDirectivesAppended(t *testing.T) {
	r := newTestRouter(CSP(
		fakeCSPSupporter{directive: "script-src https://cdn.example.com"},
		fakeCSPSupporter{directive: "  "}, // 空白片段应被跳过
	))
	r.GET("/", okHandler)

	rec := doRequest(r, http.MethodGet, "/", nil)
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src https://cdn.example.com") {
		t.Errorf("CSP 头未追加 supporter 指令：%s", csp)
	}
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "img-src 'self' data: https:") {
		t.Errorf("追加后基线指令丢失：%s", csp)
	}
	if strings.Contains(csp, "; ;") || strings.HasSuffix(csp, ";") {
		t.Errorf("CSP 头出现空指令段：%s", csp)
	}
}
