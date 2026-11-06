package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"authloft/internal/security"
)

// CSPSupporter Provider 可选接口（docs/后端架构.md §12.1 行 1461）：
// CSP() 返回追加到基线的指令片段（如 script-src https://cdn.example.com
// ——§3.13 行 488：script/style/font 追加 static_base 源；captcha 侧注册
// 契约见 §9.4）。CSP 规范同一 policy 内同名指令仅首条生效、其余被忽略
//（非取并集，接口文档 §8 行 1538），故片段由 CSP 按指令名聚合后单条输出，
// 不得以多条同名指令拼接生效。
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

// CSP 内容安全策略中间件（docs/后端架构.md §3.3 行 316、§9.4 行 1135、
// docs/接口文档.md §8 行 1521-1548）：每请求随机 nonce 写 ctx
//（CSPNonceKey）+ 输出 Content-Security-Policy 响应头；supporter（可变
// 参数，可为空）的指令片段**每请求**聚合——内容可能随配置热变（static_base
// CDN 源 / captcha 当前生效 Provider，§9.4），不在构造期固化。
//
// 聚合语义（接口文档 §8 行 1538「同名指令合并」）：CSP 规范同一
// policy 内同名指令仅首条生效、其余被忽略，故支持者片段按指令名与基线
// 聚合后**单条指令输出**——源并集 + 源级去重（首次出现保留）+ 顺序稳定
//（基线六指令顺序不变：default/script/style/font/img/connect；基线源在
// 前、支持者源按装配序追加；基线外新指令按片段中首次出现顺序追加在基线
// 之后）。空白片段跳过。中间件只做聚合与去重，**不出现任何厂商名 /
// provider type 分支特判**（§9.4 行 1133）。
//
// 基线 = CSP 终稿（接口文档 §8 行 1521-1532 逐项表，正常模式与
// setup 模式统一基线）：default-src 'self'；script-src 'nonce-{n}'
// 'strict-dynamic'；style-src 'nonce-{n}' 'self'（内联 <style> 与带 nonce
// 的样式标签经 nonce 放行，外链 css 经 'self'，禁 'unsafe-inline'）；
// font-src 'self'；img-src 'self' data: https:（data: 覆盖 captcha base64
// 图、https: 覆盖渠道图标——域名不可预知）；connect-src 'self'。配 CDN
// 时 script / style / font 三条资源类指令由 supporter 追加 static_base
// 源（script-src CDN 源仅为不支持 strict-dynamic 的旧浏览器回退）；captcha
// provider 贡献源按「当前启用且已配置」聚合进各指令（§8 行 1534）。
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
		policy := cspPolicyBuilder{nonce: nonce}
		policy.initBase()
		for _, s := range supporters {
			if extra := strings.TrimSpace(s.CSP()); extra != "" {
				policy.merge(extra)
			}
		}
		c.Header("Content-Security-Policy", policy.String())
		c.Next()
	}
}

// cspPolicyBuilder 有序 CSP 指令聚合器（§3.3 行 316 / §9.4 行 1135）：
// order 记指令名出现顺序（基线六指令在前），tokens 记各指令去重后的源
// token 列表（CSP 源不含空白，token 即源；'nonce-…' / 'self' / host 同级）。
type cspPolicyBuilder struct {
	nonce  string
	order  []string
	tokens map[string][]string
}

// initBase 写入基线六指令（逐项口径见 CSP 注释；setup 壳经 setup
// 引擎同挂本中间件取得同一基线，§8 行 1521）。
func (b *cspPolicyBuilder) initBase() {
	b.tokens = map[string][]string{}
	b.add("default-src", "'self'")
	b.add("script-src", "'nonce-"+b.nonce+"'", "'strict-dynamic'")
	b.add("style-src", "'nonce-"+b.nonce+"'", "'self'")
	b.add("font-src", "'self'")
	b.add("img-src", "'self'", "data:", "https:")
	b.add("connect-src", "'self'")
}

// merge 并入一个支持者片段：按 ";" 分段，段首 token 为指令名、其余为源
// token；空白段与只有指令名无源的段跳过。同名指令与既有源合并（去重、
// 既有源在前），新指令按首次出现顺序追加在基线之后。
func (b *cspPolicyBuilder) merge(fragment string) {
	for _, seg := range strings.Split(fragment, ";") {
		fields := strings.Fields(seg)
		if len(fields) < 2 {
			continue
		}
		b.add(fields[0], fields[1:]...)
	}
}

// add 追加指令源：指令已存在时源 token 去重追加（首次出现保留），否则
// 新建指令并登记出现顺序。
func (b *cspPolicyBuilder) add(name string, sources ...string) {
	existing, ok := b.tokens[name]
	if !ok {
		b.order = append(b.order, name)
		b.tokens[name] = append([]string{}, sources...)
		return
	}
	for _, s := range sources {
		if !containsToken(existing, s) {
			existing = append(existing, s)
		}
	}
	b.tokens[name] = existing
}

// String 按出现顺序输出：每条指令单条输出（指令名 + 源列表），"; " 连接；
// 无支持者贡献时与基线逐字一致。
func (b *cspPolicyBuilder) String() string {
	segs := make([]string, 0, len(b.order))
	for _, name := range b.order {
		segs = append(segs, name+" "+strings.Join(b.tokens[name], " "))
	}
	return strings.Join(segs, "; ")
}

// containsToken 指令内源级去重（首次出现保留）；指令源数量个位数，线性
// 查找零分配。
func containsToken(tokens []string, tok string) bool {
	for _, t := range tokens {
		if t == tok {
			return true
		}
	}
	return false
}
