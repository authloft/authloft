package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"authloft/internal/security"
)

// CSPSupporter Provider 可选接口（docs/后端架构.md §12.1 行 1411）：
// CSP() 返回追加到基线的指令片段（如 script-src https://cdn.example.com
// ——§3.13 行 484：script/style/font 追加 static_base 源）。CSP 规范同名
// 指令多次出现取并集，与基线直接拼接即语义合并，无需逐指令归并。
type CSPSupporter interface {
	CSP() string
}

// CSPNonceKey 每请求 CSP nonce 在 *gin.Context 中的键；handler（§3.4
// 行 323 page.go）读它注入空壳 HTML 的 <script nonce="…">。
const CSPNonceKey = "csp_nonce"

// cspNonceLen nonce 字符数：22 个 URL-safe 字符 × 6 bit ≈ 132-bit 熵
// （crypto/rand 经 security.RandomString，§3.3 行 310「nonce 必须
// per-request 随机」）。
const cspNonceLen = 22

// CSP 内容安全策略中间件（docs/后端架构.md §3.3 行 310、§3.13 行 484）：
// 每请求随机 nonce 写 ctx（CSPNonceKey）+ 输出 Content-Security-Policy
// 响应头；supporter（可变参数，可为空）的指令片段**每请求**追加——内容
// 可能随配置热变（static_base / Storage domain），不在构造期固化。
//
// 基线为最小可辩护口径（文档只定义追加项、未逐字定义基线）：
// default-src 'self'；script-src 'nonce-{n}'
// 'strict-dynamic'；style-src / font-src 'self'（配 CDN 时由 supporter
// 追加 static_base 源）；img-src https:（渠道图标域名无法预知，行 484）。
//
// nonce 生成失败（crypto/rand 实际不可达）时不出伪劣 CSP 头（空 nonce
// 的 script-src 无防护意义）、不放行伪造值——降级为无 CSP 继续请求
// （同 requestid「不伪造值」口径），加固层失败不拒绝业务请求。
func CSP(supporters ...CSPSupporter) gin.HandlerFunc {
	return func(c *gin.Context) {
		nonce, err := security.RandomString(cspNonceLen)
		if err != nil {
			c.Next()
			return
		}
		c.Set(CSPNonceKey, nonce)
		directives := cspBaseDirectives(nonce)
		for _, s := range supporters {
			if extra := strings.TrimSpace(s.CSP()); extra != "" {
				directives = append(directives, extra)
			}
		}
		c.Header("Content-Security-Policy", strings.Join(directives, "; "))
		c.Next()
	}
}

// cspBaseDirectives CSP 基线指令（口径与依据见 CSP 注释）。
func cspBaseDirectives(nonce string) []string {
	return []string{
		"default-src 'self'",
		"script-src 'nonce-" + nonce + "' 'strict-dynamic'",
		"style-src 'self'",
		"font-src 'self'",
		"img-src https:",
	}
}
