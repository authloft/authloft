// csp.go 是 captcha Provider 的 CSP 源贡献（docs/后端架构.md §9.4 /
// docs/接口文档.md §8「provider 贡献源」）：源声明随实现走——各 captcha
// type 子包注册时以按指令分组的数据写入 provider.Meta.CSPSources（§9.4
// 工厂化收口，本文件不写死厂商域、禁按 type / 厂商名特判），Catalog 实现
// middleware.CSPSupporter——每请求按「当前启用且已配置」判定（与 Current
// 同源：CSP 贡献与下发配置、拦截校验同源），未启用 / 未配置 / 查询失败 /
// 未登记 type 一律贡献空串（不 panic、不阻塞响应头），未启用的 Provider
// 不写入任何域名。image（自绘）不贡献任何源（§8）；script-src 不放通
// （三家脚本经 nonce 标签信任链，§8）；登记仅限可扩展指令白名单四项
// frame-src / connect-src / style-src / img-src（§8），白名单外指令不登记。
package captcha

import (
	"context"
	"strings"

	"authloft/internal/middleware"
	"authloft/internal/provider"
)

// cspDirectiveOrder 登记片段的固定指令输出序（§8 白名单四项的文档序）：
// map 遍历序随机，固定切片序保证片段内指令顺序稳定。
var cspDirectiveOrder = [...]string{"frame-src", "connect-src", "style-src", "img-src"}

// 编译期断言 Catalog 实现 middleware.CSPSupporter（§12.1 可选接口：
// Provider 侧按需实现，装配层追加为 CSP 中间件的 supporter）。
var _ middleware.CSPSupporter = (*Catalog)(nil)

// CSP 每请求按「当前生效 Provider」贡献 CSP 源（§9.4：判定与 Current /
// gate.go 下发配置同源，每次现算不缓存、热更新语义一致）。Current 为
// nil（键空串 / 行不存在 / 未启用）、error（基础设施错误，不 panic、
// 不阻塞响应头）或 type 未注册 / 未声明源（image / 未知值）时返回空串；
// 命中时经注册表读该 type 的 Meta.CSPSources 聚合，返回各指令片段按
// "; " 连接的串——中间件按指令名聚合后单条输出（接口文档 §8 同名指令
// 合并语义，非拼接生效）。
func (c *Catalog) CSP() string {
	p, err := c.Current(context.Background())
	if err != nil || p == nil {
		return ""
	}
	meta, ok := provider.Lookup(p.Type)
	if !ok || len(meta.CSPSources) == 0 {
		return ""
	}
	parts := make([]string, 0, len(meta.CSPSources))
	for _, directive := range cspDirectiveOrder {
		if sources := meta.CSPSources[directive]; len(sources) > 0 {
			parts = append(parts, directive+" "+strings.Join(sources, " "))
		}
	}
	return strings.Join(parts, "; ")
}
