// CSP 中间件单测（docs/后端架构.md §21.2 E 行 1869 / §3.3 行 316、§9.4
// 行 1135、接口文档 §8 行 1538 同名指令合并语义）：nonce 每请求不同、
// 无贡献时与基线逐字一致、支持者片段按指令名聚合单条输出（基线源在前、
// 源级去重、顺序稳定）、nonce 写入 ctx 供 handler 消费。
package middleware

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// fakeCSPSupporter 固定指令片段的 CSPSupporter 假实现（§12.1 行 1461 接口）。
type fakeCSPSupporter struct{ directive string }

func (f fakeCSPSupporter) CSP() string { return f.directive }

// baseDirectives 测试期望基线（六指令，接口文档 §8 行 1521-1532
// 逐项表；与 initBase 同构，供逐字对账）。
func baseDirectives(nonce string) string {
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'nonce-" + nonce + "' 'strict-dynamic'",
		"style-src 'nonce-" + nonce + "' 'self'",
		"font-src 'self'",
		"img-src 'self' data: https:",
		"connect-src 'self'",
	}, "; ")
}

// nonceFromHeader 从 CSP 头 script-src 首源提取 nonce（聚合后 nonce 仍是
// 首源，段首格式不变）。
func nonceFromHeader(t *testing.T, csp string) string {
	t.Helper()
	const head = "script-src 'nonce-"
	i := strings.Index(csp, head)
	if i < 0 {
		t.Fatalf("CSP 头缺 script-src nonce 段：%s", csp)
	}
	rest := csp[i+len(head):]
	j := strings.Index(rest, "'")
	if j < 0 {
		t.Fatalf("CSP 头 nonce 源未闭合：%s", csp)
	}
	return rest[:j]
}

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

// ② 无 supporter：CSP 响应头与基线逐字一致（接口文档 §8 行
// 1521-1532；§8 行 1538 合并语义下无贡献 = 基线原样），禁 unsafe-inline。
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
	if got, want := csp, baseDirectives(nonce); got != want {
		t.Errorf("CSP 头 = %q, want 基线逐字 %q", got, want)
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP 头禁 unsafe-inline：%s", csp)
	}
}

// ③ 支持者片段按指令名聚合（§9.4 行 1135 / 接口文档 §8 行 1538）：同名
// 指令与基线合并单条输出（基线源在前、支持者源追加，整串仅一次）；空白
// 返回值的 supporter 不产生空指令段。
func TestCSPSupporterDirectivesAppended(t *testing.T) {
	r := newTestRouter(CSP(
		fakeCSPSupporter{directive: "script-src https://cdn.example.com"},
		fakeCSPSupporter{directive: "  "}, // 空白片段应被跳过
	))
	r.GET("/", okHandler)

	rec := doRequest(r, http.MethodGet, "/", nil)
	csp := rec.Header().Get("Content-Security-Policy")
	nonce := nonceFromHeader(t, csp)
	want := "script-src 'nonce-" + nonce + "' 'strict-dynamic' https://cdn.example.com"
	if !strings.Contains(csp, want) {
		t.Errorf("CSP 头未按合并形态聚合 script-src（want %q）：%s", want, csp)
	}
	if n := strings.Count(csp, "script-src"); n != 1 {
		t.Errorf("script-src 出现 %d 次, want 1（同名指令仅首条生效，§8 行 1538）：%s", n, csp)
	}
	if strings.Contains(csp, "; ;") || strings.HasSuffix(csp, ";") {
		t.Errorf("CSP 头出现空指令段：%s", csp)
	}
}

// ④ 无贡献 supporter（验收 a）：零 supporter / 空串片段 / 空白片段时
// header 与基线逐字一致——「未启用 provider 不写入任何域名」（§8 行
// 1534）在中间件侧的形态即贡献空串 = 基线原样（captcha 侧各降级态由
// captcha 包 TestCatalogCSPNoContribution 覆盖）。
func TestCSPNoContributionExactBaseline(t *testing.T) {
	build := func(supporters ...CSPSupporter) string {
		r := newTestRouter(CSP(supporters...))
		r.GET("/", okHandler)
		return doRequest(r, http.MethodGet, "/", nil).Header().Get("Content-Security-Policy")
	}
	for name, got := range map[string]string{
		"零 supporter": build(),
		"空串片段":       build(fakeCSPSupporter{directive: ""}),
		"空白片段":       build(fakeCSPSupporter{directive: " \t "}),
	} {
		nonce := nonceFromHeader(t, got)
		if want := baseDirectives(nonce); got != want {
			t.Errorf("%s：CSP 头 = %q, want 基线逐字 %q", name, got, want)
		}
	}
}

// ⑤ 单 supporter 同名指令合并（验收 b）：基线源在前、支持者源追加，
// 同名指令整串仅一次。
func TestCSPSupporterMergeBaselineFirst(t *testing.T) {
	r := newTestRouter(CSP(
		fakeCSPSupporter{directive: "style-src https://x.example.com; connect-src https://api.example.com"},
	))
	r.GET("/", okHandler)
	rec := doRequest(r, http.MethodGet, "/", nil)
	csp := rec.Header().Get("Content-Security-Policy")
	nonce := nonceFromHeader(t, csp)
	for _, want := range []string{
		"style-src 'nonce-" + nonce + "' 'self' https://x.example.com",
		"connect-src 'self' https://api.example.com",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP 头缺合并指令 %q：%s", want, csp)
		}
	}
	for _, d := range []string{"style-src", "connect-src"} {
		if n := strings.Count(csp, d); n != 1 {
			t.Errorf("%s 出现 %d 次, want 1（同名指令单条输出）：%s", d, n, csp)
		}
	}
}

// ⑥ 多 supporter 聚合（验收 c）：源级去重（两 supporter 贡献同一指令
// 同源仅一次、支持者源与基线源重复亦去重）、支持者按装配序追加、基线六
// 指令顺序不变、基线外新指令（frame-src）按首次出现顺序追加在基线之后。
func TestCSPSupporterDedupStableOrder(t *testing.T) {
	r := newTestRouter(CSP(
		fakeCSPSupporter{directive: "frame-src https://a.example.com; connect-src https://api.example.com"},
		fakeCSPSupporter{directive: "connect-src https://api.example.com https://api2.example.com; style-src https://s.example.com; font-src 'self'"},
	))
	r.GET("/", okHandler)
	rec := doRequest(r, http.MethodGet, "/", nil)
	csp := rec.Header().Get("Content-Security-Policy")
	nonce := nonceFromHeader(t, csp)

	want := strings.Join([]string{
		"default-src 'self'",
		"script-src 'nonce-" + nonce + "' 'strict-dynamic'",
		"style-src 'nonce-" + nonce + "' 'self' https://s.example.com",
		"font-src 'self'",
		"img-src 'self' data: https:",
		"connect-src 'self' https://api.example.com https://api2.example.com",
		"frame-src https://a.example.com",
	}, "; ")
	if got := csp; got != want {
		t.Errorf("CSP 头 = %q\nwant 聚合 %q", got, want)
	}
}
