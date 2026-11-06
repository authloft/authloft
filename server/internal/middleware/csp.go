package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"authloft/internal/security"
)

// CSPSupporter Provider 可选接口（docs/后端架构.md §12.1 行 1411）：
// CSP() 返回追加到基线的指令片段（如 script-src https://cdn.example.com
// ——§3.13 行 488：script/style/font 追加 static_base 源）。CSP 规范同名
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

// CSP 内容安全策略中间件（docs/后端架构.md §3.3 行 310、§3.13 行 488）：
// 每请求随机 nonce 写 ctx（CSPNonceKey）+ 输出 Content-Security-Policy
// 响应头；supporter（可变参数，可为空）的指令片段**每请求**追加——内容
// 可能随配置热变（static_base CDN 源 / Provider 追加项），不在构造期固化。
//
// 基线 = CSP 终稿（接口文档 §8 行 1521-1532 逐项表，正常模式与
// setup 模式统一基线）：default-src 'self'；script-src 'nonce-{n}'
// 'strict-dynamic'；style-src 'nonce-{n}' 'self'（内联 <style> 与带 nonce
// 的样式标签经 nonce 放行，外链 css 经 'self'，禁 'unsafe-inline'）；
// font-src 'self'；img-src 'self' data: https:（data: 覆盖 captcha base64
// 图、https: 覆盖渠道图标——域名不可预知）；connect-src 'self'。配 CDN
// 时 script / style / font 三条资源类指令由 supporter 追加 static_base
// 源（script-src CDN 源仅为不支持 strict-dynamic 的旧浏览器回退）。
//
// nonce 生成失败（crypto/rand 实际不可达）时不出伪劣 CSP 头（空 nonce
// 的 script-src 无防护意义）、不放行伪造值——降级为无 CSP 继续请求
// （同 requestid「不伪造值」口径，壳层 RenderGinShell 侧自生成兜底），
// 加固层失败不拒绝业务请求。
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

// cspBaseDirectives CSP 终稿基线指令（逐项口径与依据见 CSP 注释；
// setup 壳经 setup 引擎同挂本中间件取得同一基线，§8 行 1521）。
func cspBaseDirectives(nonce string) []string {
	return []string{
		"default-src 'self'",
		"script-src 'nonce-" + nonce + "' 'strict-dynamic'",
		"style-src 'nonce-" + nonce + "' 'self'",
		"font-src 'self'",
		"img-src 'self' data: https:",
		"connect-src 'self'",
	}
}
