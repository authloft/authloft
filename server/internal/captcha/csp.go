// csp.go 是 captcha Provider 的 CSP 源贡献（docs/后端架构.md §9.4 /
// docs/接口文档.md §8「provider 贡献源」）：源声明随实现走——各 captcha
// type 子包注册时以按指令分组的数据写入 provider.Meta.CSPSources，按行
// 配置派生源（域名不可枚举，capjs）另经 Meta.CSPSourcesOf 按当前生效
// Provider 实例现算（§9.4 工厂化收口，本文件不写死厂商域、禁按 type /
// 厂商名特判），Catalog 实现
// middleware.CSPSupporter——每请求按「当前生效且已配置」判定（与 Current
// 同源：CSP 贡献与下发配置、拦截校验同源），键空 / 行不存在 / 查询失败 /
// 未登记 type 一律贡献空串（不 panic、不阻塞响应头）。image（自绘）不贡献
// 任何源（§8）；script-src 不放通（三家脚本经 nonce 标签信任链，§8）；输出
// 仅限可扩展指令白名单五项 frame-src / connect-src / style-src / img-src /
// worker-src（worker-src 为 Capjs PoW Web Worker 补入，§8），白名单外指令
// 的声明一律不生效——聚合只遍历白名单指令序，静态与派生声明中其余指令名
// 静默丢弃。
package captcha

import (
	"context"
	"strings"

	"authloft/internal/middleware"
	"authloft/internal/provider"
)

// cspDirectiveOrder 登记片段的固定指令输出序，同时是白名单的判定口径：
// 只有序内指令（§8 五项）进片段，声明中白名单外指令一律不生效。map 遍历
// 序随机，固定切片序保证片段内指令顺序稳定。
var cspDirectiveOrder = [...]string{"frame-src", "connect-src", "style-src", "img-src", "worker-src"}

// 编译期断言 Catalog 实现 middleware.CSPSupporter（§12.1 可选接口：
// Provider 侧按需实现，装配层追加为 CSP 中间件的 supporter）。
var _ middleware.CSPSupporter = (*Catalog)(nil)

// CSP 每请求按「当前生效 Provider」贡献 CSP 源（§9.4：判定与 Current /
// gate.go 下发配置同源，每次现算不缓存、热更新语义一致）。Current 为
// nil（键空串 / 行不存在）、error（基础设施错误，不 panic、
// 不阻塞响应头）或 type 未注册 / 未声明源（image / 未知值）时返回空串；
// 命中时经注册表读该 type 的 Meta.CSPSources（静态）与 Meta.CSPSourcesOf
// （按行派生，§9.4「按行配置派生源」）聚合：同白名单序输出、静态在前、
// 同指令去重，返回各指令片段按 "; " 连接的串——中间件按指令名聚合后单条
// 输出（接口文档 §8 同名指令合并语义，非拼接生效）。派生返回的 map 与
// 静态声明走同一白名单过滤：只遍历白名单指令序，白名单外指令一律不生效。
func (c *Catalog) CSP() string {
	p, err := c.Current(context.Background())
	if err != nil || p == nil {
		return ""
	}
	meta, ok := provider.Lookup(p.Type)
	if !ok {
		return ""
	}
	var derived map[string][]string
	if meta.CSPSourcesOf != nil {
		derived = meta.CSPSourcesOf(p)
	}
	if len(meta.CSPSources) == 0 && len(derived) == 0 {
		return ""
	}
	parts := make([]string, 0, len(meta.CSPSources)+len(derived))
	for _, directive := range cspDirectiveOrder {
		if sources := cspMergeSources(meta.CSPSources[directive], derived[directive]); len(sources) > 0 {
			parts = append(parts, directive+" "+strings.Join(sources, " "))
		}
	}
	return strings.Join(parts, "; ")
}

// cspMergeSources 合并单条指令的静态与按行派生源（§9.4 聚合与去重）：
// 静态在前、派生在后，同指令去重保序；派生为空时原样返回静态切片，
// 既有静态输出逐字节不变。
func cspMergeSources(static, derived []string) []string {
	if len(derived) == 0 {
		return static
	}
	seen := make(map[string]struct{}, len(static)+len(derived))
	out := make([]string, 0, len(static)+len(derived))
	for _, group := range [][]string{static, derived} {
		for _, src := range group {
			if _, dup := seen[src]; dup {
				continue
			}
			seen[src] = struct{}{}
			out = append(out, src)
		}
	}
	return out
}
