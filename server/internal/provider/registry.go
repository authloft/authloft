// 统一注册表（docs/后端架构.md §15.3）：provider 包一张注册表，entry 多槽
// （meta + auth / sender / storage / verifier / proxy 五类 factory 槽），
// 唯一注册入口 register(type, meta, opts...) + Option 模式，按槽取产
// NewAdapter / NewSender / NewVerifier / NewProxy。auth 渠道包经 Register、
// 消息厂商包经 RegisterSender、captcha / proxy 实现包经 RegisterVerifier /
// RegisterProxy 薄封装接入（既有调用面一行不改）；虚拟类型在包内 init() 只
// 注册 meta（virtual.go），服务型 meta 与 factory 同处实现子包。
// meta 同时驱动管理后台 /schema（接口文档 §5.3）：动态 schema 由渠道包在
// 构造期组装进 meta.Schema，不另建注册表。
package provider

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// 注册表可判别错误。
var (
	// ErrNilProvider NewAdapter / NewSender 入参为空。
	ErrNilProvider = errors.New("provider: nil provider")
	// ErrUnknownType 未注册的 provider type（含已注册但无对应 factory 槽）。
	ErrUnknownType = errors.New("provider: unknown provider type")
	// ErrAlreadyRegistered 重复注册同一 type。
	ErrAlreadyRegistered = errors.New("provider: provider type already registered")
	// ErrNilFactory 注册时 factory 为空。
	ErrNilFactory = errors.New("provider: nil factory")
	// ErrNilAdapter factory 返回空适配器。
	ErrNilAdapter = errors.New("provider: factory returned nil adapter")
	// ErrSlotConflict 同一注册挂了多种 factory 槽（§15.3：同一 type 至多一种
	// factory，防误配）。
	ErrSlotConflict = errors.New("provider: multiple factory slots on one type")
)

// AuthProvider auth 注册表语境的 Provider 语义别名（§15.3）：struct 本身不改名，
// storage / captcha / pages 等调用方零改动。
type AuthProvider = Provider

// AuthFactory auth 槽 factory：由 Provider 实例构造渠道适配器（§13.0：装配期
// 取 Ext，运行期不回读配置）。
type AuthFactory func(p *AuthProvider) (AuthAdapter, error)

// Meta 统一注册表元信息（§15.3：meta 同时是管理后台 /schema 的数据源）。
// Fields 是渠道包构造期的 Ext 字段清单：NewMeta 产出后渠道包可就地改写
// Label / Help（与 Schema 闭包共享底层数组，改动天然同步），管理后台只消费
// Schema()；直接复用 sender.go 的 FieldMeta——它本就是域中立的单字段渲染
// 口径（§5.3）。nil = 仅表列基线，不追加 Ext 字段。Channel 仅 auth 槽条目
// 携带（登录快照的交互通道口径）；消息厂商经 RegisterSender 转换而来、
// 服务型 / 虚拟类型为空。
type Meta struct {
	Type        string
	DisplayName string
	Category    string
	Channel     ThirdPartyChannel
	Fields      []FieldMeta
	Schema      func() []FieldMeta // 完整字段声明（含表列与 Ext）；nil = 无声明
	// CSPSources captcha 类型子包注册时按指令分组的 CSP 源声明（§9.4：
	// 声明随实现走，Catalog.CSP() 经注册表聚合输出，禁按 type / 厂商名
	// 特判；指令限接口文档 §8 白名单三项 frame-src / style-src /
	// worker-src）。nil = 不贡献源。
	CSPSources map[string][]string
}

// entry 注册表条目：meta 恒有，factory 槽按注册来源挂零或一个（同一 type
// 至多一种 factory，§15.3）。
type entry struct {
	meta     Meta
	auth     AuthFactory
	sender   SenderFactory
	storage  StorageFactory
	verifier VerifierFactory
	proxy    ProxyFactory
}

// Option 注册选项：向 entry 声明 factory 槽。nil factory / 重复槽位在应用期
// 即报错（唯一入口校验的一部分，§15.3）。
type Option func(*entry) error

// WithAuth 挂 auth 槽（auth 渠道适配器工厂）。
func WithAuth(f AuthFactory) Option {
	return func(e *entry) error {
		if f == nil {
			return fmt.Errorf("%w: auth slot", ErrNilFactory)
		}
		if e.auth != nil {
			return fmt.Errorf("%w: auth slot", ErrSlotConflict)
		}
		e.auth = f
		return nil
	}
}

// WithSender 挂 sender 槽（消息厂商工厂）。
func WithSender(f SenderFactory) Option {
	return func(e *entry) error {
		if f == nil {
			return fmt.Errorf("%w: sender slot", ErrNilFactory)
		}
		if e.sender != nil {
			return fmt.Errorf("%w: sender slot", ErrSlotConflict)
		}
		e.sender = f
		return nil
	}
}

// WithStorage 挂 storage 槽（存储实现工厂）。
func WithStorage(f StorageFactory) Option {
	return func(e *entry) error {
		if f == nil {
			return fmt.Errorf("%w: storage slot", ErrNilFactory)
		}
		if e.storage != nil {
			return fmt.Errorf("%w: storage slot", ErrSlotConflict)
		}
		e.storage = f
		return nil
	}
}

var registry = struct {
	mu      sync.RWMutex
	entries map[string]*entry
}{entries: make(map[string]*entry)}

// register 唯一注册入口（可返回错误版，§15.3）：auth 渠道包的 Register 与
// 消息厂商包的 RegisterSender 薄封装转调至此，服务型 / 虚拟类型 init() 直调
// （只注册 meta，不带 Option）。校验：type 非空且唯一、meta.Type 一致、同一
// 注册至多挂一种 factory。重复注册 / 空 type / 槽位误配属程序错误，公开封装
// 侧直接 panic（init 无法返回错误）。
func register(providerType string, meta Meta, opts ...Option) error {
	if providerType == "" {
		return fmt.Errorf("%w: empty type", ErrUnknownType)
	}
	if meta.Type == "" {
		meta.Type = providerType
	}
	if meta.Type != providerType {
		return fmt.Errorf("provider: register %q: meta.Type %q mismatch", providerType, meta.Type)
	}
	e := &entry{meta: meta}
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return err
		}
	}
	// 同一 type 至多挂一种 factory（§15.3）：跨槽合计判定，防误配。
	slots := 0
	if e.auth != nil {
		slots++
	}
	if e.sender != nil {
		slots++
	}
	if e.storage != nil {
		slots++
	}
	if e.verifier != nil {
		slots++
	}
	if e.proxy != nil {
		slots++
	}
	if slots > 1 {
		return fmt.Errorf("%w: %q", ErrSlotConflict, providerType)
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, ok := registry.entries[providerType]; ok {
		return fmt.Errorf("%w: %q", ErrAlreadyRegistered, providerType)
	}
	registry.entries[providerType] = e
	return nil
}

// Register 注册 auth 渠道（渠道包 init() 既有调用面，§15.3：薄封装转调唯一
// 入口 + WithAuth，渠道包一行不改）。
func Register(providerType string, meta Meta, factory AuthFactory) {
	if err := register(providerType, meta, WithAuth(factory)); err != nil {
		panic(err)
	}
}

// NewAdapter auth 槽取件（§15.3）：type 未注册或无 auth 槽（消息厂商 / 服务型 /
// 虚拟类型）→ ErrUnknownType，不会构造出假适配器。
func NewAdapter(p *Provider) (AuthAdapter, error) {
	if p == nil {
		return nil, ErrNilProvider
	}
	registry.mu.RLock()
	e, ok := registry.entries[p.Type]
	registry.mu.RUnlock()
	if !ok || e.auth == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, p.Type)
	}
	a, err := e.auth(p)
	if err != nil {
		return nil, fmt.Errorf("provider: new adapter %q: %w", p.Type, err)
	}
	if a == nil {
		return nil, fmt.Errorf("%w: %q", ErrNilAdapter, p.Type)
	}
	return a, nil
}

// Lookup 返回 type 的统一注册表元信息（登录快照与管理后台 schema 卡使用）；
// type 未注册 → miss。
func Lookup(providerType string) (Meta, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	e, ok := registry.entries[providerType]
	if !ok {
		return Meta{}, false
	}
	return e.meta, true
}

// AdapterTypes 登录方式快照数据源（§15.3）：仅 auth 槽非空的类型（auth 渠道），
// 排序快照。消息厂商 / 服务型 / 虚拟类型不进本列表，不得污染登录方式快照。
func AdapterTypes() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	out := make([]string, 0, len(registry.entries))
	for t, e := range registry.entries {
		if e.auth != nil {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}
