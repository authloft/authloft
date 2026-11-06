// csp.go 是 captcha Provider 的 CSP 源注册（docs/后端架构.md
// §9.4 行 1129-1137 / docs/接口文档.md §8 行 1534-1548「provider 贡献源」）：
// 三家第三方 captcha 按指令分组的数据登记自身所需 CSP 源，Catalog 实现
// middleware.CSPSupporter——每请求按「当前启用且已配置」判定（与
// Current 同源，§9.4 行 1134：CSP 贡献与下发配置、拦截校验同源），未启用 /
// 未配置 / 查询失败 / 未登记 type 一律贡献空串（不 panic、不阻塞响应头），
// 未启用的 Provider 不写入任何域名。image（自绘）不贡献任何源（§8 行
// 1548）；script-src 不放通（三家脚本经 nonce 标签信任链，§8 行 1537）；
// 登记仅限可扩展指令白名单四项 frame-src / connect-src / style-src /
// img-src（§8 行 1536），白名单外指令不登记。
package captcha

import (
	"context"
	"strings"

	"authloft/internal/middleware"
)

// cspDirectiveOrder 登记片段的固定指令输出序（§8 行 1536 白名单四项的
// 文档序）：map 遍历序随机，固定切片序保证片段内指令顺序稳定。
var cspDirectiveOrder = [...]string{"frame-src", "connect-src", "style-src", "img-src"}

// cspSourcesByType 按 type 的声明式 CSP 源登记表（§9.4 行 1133「注册时
// 声明、按指令分组的数据登记，非按 type / 厂商名的分支判断」）。三家
// 参考源清单 = 接口文档 §8 行 1542-1546 表（禁止在 middleware/csp.go
// 写死厂商域）：turnstile 仅 frame-src；recaptcha 另需 connect-src；
// hcaptcha 三指令（frame/connect/style 各两源）。
var cspSourcesByType = map[string]map[string][]string{
	TypeTurnstile: {
		"frame-src": {"https://challenges.cloudflare.com"},
	},
	TypeRecaptcha: {
		"frame-src":   {"https://www.google.com/recaptcha/", "https://recaptcha.google.com/recaptcha/"},
		"connect-src": {"https://www.google.com/recaptcha/"},
	},
	TypeHcaptcha: {
		"frame-src":   {"https://hcaptcha.com", "https://*.hcaptcha.com"},
		"connect-src": {"https://hcaptcha.com", "https://*.hcaptcha.com"},
		"style-src":   {"https://hcaptcha.com", "https://*.hcaptcha.com"},
	},
}

// 编译期断言 Catalog 实现 middleware.CSPSupporter（§12.1 行 1461 可选
// 接口：Provider 侧按需实现，装配层追加为 CSP 中间件的 supporter）。
var _ middleware.CSPSupporter = (*Catalog)(nil)

// CSP 每请求按「当前生效 Provider」贡献 CSP 源（§9.4 行 1134：判定与
// Current / gate.go 下发配置同源，每次现算不缓存、热更新语义一致）。
// Current 为 nil（键空串 / 行不存在 / 未启用）、error（基础设施错误，
// 不 panic、不阻塞响应头）或 type 未登记（image / 未知值）时返回空串；
// 命中时返回各指令片段按 "; " 连接的串——中间件按指令名聚合后单条输出
//（接口文档 §8 行 1538 同名指令合并语义，非拼接生效）。
func (c *Catalog) CSP() string {
	p, err := c.Current(context.Background())
	if err != nil || p == nil {
		return ""
	}
	groups, ok := cspSourcesByType[p.Type]
	if !ok {
		return ""
	}
	parts := make([]string, 0, len(groups))
	for _, directive := range cspDirectiveOrder {
		if sources := groups[directive]; len(sources) > 0 {
			parts = append(parts, directive+" "+strings.Join(sources, " "))
		}
	}
	return strings.Join(parts, "; ")
}
