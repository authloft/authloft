// catalog.go 是 gate.go ProviderCatalog 接口的实装（docs/后端架构.md §9.1
// 「下发与拦截永远同源」、docs/接口文档.md §2.5 降级规则）：settings 键
// captcha_provider_key（空串 = 内置，§5.6）→ provider 表 category=captcha
// 且 is_enabled=1 的生效行，每次现算不缓存。无可用项（未配置 / 禁用 /
// 查不到）返回 nil,nil，降级语义归 Gate（builtin_image）。
//
// 直读通道（§9.1 阶段三定稿）：provider 行经 provider.Loader 的不读 LRU 的
// GetDirect 取完整 *provider.Provider（行读取 + Ext 组装 + 代理解析同语义，
// §15.3），不经 60s 缓存窗口——「下发、拦截与错误体永远同源、配置改动立即
// 生效」由直读保证；普通读路径（白名单等）仍走 LRU + singleflight。工厂化
// 后本包不再自持 repo 窄投影（原 provider_source 窄投影随直读通道退役，
// factory 所需的 secret / 代理直接取自完整实例）。
package captcha

import (
	"context"
	"fmt"

	"authloft/internal/provider"
	"authloft/internal/settings"
)

// CategoryCaptcha provider 表 category 取值（§4.1：oauth|captcha|sms|
// email|storage|notify|union；单一来源在 provider 包）。
const CategoryCaptcha = provider.CategoryCaptcha

// KeyReader 读 settings 字符串键（热更新快照，§5.6 只对后续请求生效）。
// 生产注入 *settings.Store。
type KeyReader interface {
	GetString(key string) (string, bool)
}

// CurrentSource 当前生效 provider 直读源（§9.1 不缓存通道）：
// *provider.Loader 天然满足（GetDirect 绕过本地 LRU 与 singleflight）。
// key 无此行返回 nil,nil；error = 基础设施错误（由 Gate 按健康检查失败
// 降级，§9.1）。
type CurrentSource interface {
	GetDirect(ctx context.Context, providerKey string) (*provider.Provider, error)
}

// Catalog ProviderCatalog 实装。
type Catalog struct {
	keys   KeyReader
	source CurrentSource
}

// NewCatalog 注入 settings 键读取与 provider 直读源（装配层构造）。
func NewCatalog(keys KeyReader, source CurrentSource) *Catalog {
	return &Catalog{keys: keys, source: source}
}

// Current 每次现算当前生效 captcha Provider（直读、不缓存，§9.1）：
// 键空串 / 键缺失 / 行不存在 / category≠captcha / 未启用 → nil,nil；
// 基础设施错误原样上抛。返回完整 *provider.Provider——下发配置（Gate 取
// ext.client_id 作 siteKey）与 factory 构造（secret / 代理）同源取值。
func (c *Catalog) Current(ctx context.Context) (*provider.Provider, error) {
	if c == nil || c.keys == nil || c.source == nil {
		return nil, nil
	}
	key, _ := c.keys.GetString(settings.KeyCaptchaProviderKey)
	if key == "" {
		return nil, nil
	}
	p, err := c.source.GetDirect(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("captcha: load provider %q: %w", key, err)
	}
	if p == nil || p.Row == nil || p.Row.Category != CategoryCaptcha || !p.Enabled() {
		return nil, nil
	}
	return p, nil
}
