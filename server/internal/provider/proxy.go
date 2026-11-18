// proxy 基建（docs/后端架构.md §15.4 工厂化阶段五、§15.3 接口归属）：
// proxy 槽 factory 产出 proxyclient.Config 值对象而非服务接口——proxy 与
// captcha / storage 的工厂化不同构：只有单一 type、需进程级 PoolSet 参与，
// PoolSet 仍由解析链显式注入（bootstrap 一处构造、注入点结构不变），factory
// 不产出 Pool、不持有池，属「所有 provider 构造都经 factory」的形式统一。
// 实现位于 provider/proxy/<type>/ 子包，init() 经 RegisterProxy 自注册，
// bootstrap 以 blank import 触发（CODE_GUIDE §3.3）。
package provider

import (
	"fmt"

	"authloft/internal/proxyclient"
)

// ProxyFactory proxy 槽 factory：由 Provider 实例构造出站代理配置值对象
// （§15.4：五个真实 Ext 字段 scheme/host/port/user/password 经
// proxyclient.NewConfig 产出，字段组合合法性单一来源不变；outbound 解析链
// 取 Config 后再 PoolSet.Get 按键取池）。
type ProxyFactory func(p *Provider) (proxyclient.Config, error)

// WithProxy 挂 proxy 槽（proxy 行配置工厂）。
func WithProxy(f ProxyFactory) Option {
	return func(e *entry) error {
		if f == nil {
			return fmt.Errorf("%w: proxy slot", ErrNilFactory)
		}
		if e.proxy != nil {
			return fmt.Errorf("%w: proxy slot", ErrSlotConflict)
		}
		e.proxy = f
		return nil
	}
}

// RegisterProxy 注册 proxy 行配置工厂（§15.3 薄封装：转调唯一入口 register +
// WithProxy，type 子包 init() 调用）。重复注册 / 空 type / 空 factory /
// category 非 proxy 属程序错误，直接 panic（init 无法返回错误）。
func RegisterProxy(proxyType string, meta Meta, factory ProxyFactory) {
	if proxyType == "" {
		panic(fmt.Errorf("%w: empty proxy type", ErrUnknownType))
	}
	if factory == nil {
		panic(fmt.Errorf("%w: proxy %q", ErrNilFactory, proxyType))
	}
	if meta.Category != CategoryProxy {
		panic(fmt.Errorf("provider: register proxy %q: category %q must be %q",
			proxyType, meta.Category, CategoryProxy))
	}
	if err := register(proxyType, meta, WithProxy(factory)); err != nil {
		panic(err)
	}
}

// NewProxy proxy 槽取件（§15.4）：按 Provider 实例的 type 经注册表分派，
// 产出配置值对象。type 未注册或未挂 proxy 槽 → ErrUnknownType（outbound
// 解析链对任何失败一律 fail-closed 包装 ErrProxyRefUnresolvable，不会构造
// 出假配置）；factory 自身错误原样上抛（NewConfig 的校验类别不改写）。
func NewProxy(p *Provider) (proxyclient.Config, error) {
	if p == nil {
		return proxyclient.Config{}, ErrNilProvider
	}
	registry.mu.RLock()
	e, ok := registry.entries[p.Type]
	registry.mu.RUnlock()
	if !ok || e.proxy == nil {
		return proxyclient.Config{}, fmt.Errorf("%w: %q", ErrUnknownType, p.Type)
	}
	cfg, err := e.proxy(p)
	if err != nil {
		return proxyclient.Config{}, fmt.Errorf("provider: new proxy %q: %w", p.Type, err)
	}
	return cfg, nil
}
