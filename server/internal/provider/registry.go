// 渠道注册表（docs/后端架构.md §12.1 行 1433、§15.3 行 1714）：
// Register(type, meta, factory) + NewAdapter(p)，各渠道包 init() 自注册。
// meta 同时驱动管理后台 /schema（接口文档 §5.3），后续 admin 卡在此字段
// 基础上补齐动态 schema，不另建注册表。
package provider

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// 注册表可判别错误。
var (
	// ErrNilProvider NewAdapter 入参为空。
	ErrNilProvider = errors.New("provider: nil provider")
	// ErrUnknownType 未注册的 provider type。
	ErrUnknownType = errors.New("provider: unknown provider type")
	// ErrAlreadyRegistered 重复注册同一 type。
	ErrAlreadyRegistered = errors.New("provider: provider type already registered")
	// ErrNilFactory 注册时 factory 为空。
	ErrNilFactory = errors.New("provider: nil factory")
	// ErrNilAdapter factory 返回空适配器。
	ErrNilAdapter = errors.New("provider: factory returned nil adapter")
)

// Meta 渠道元信息（§15.3 行 1714：meta 同时是管理后台 /schema 的数据源）。
// 只落最小集合；字段级 schema 随 admin 实现扩展，避免提前实现。
type Meta struct {
	Type        string
	DisplayName string
	Category    string
	Channel     ThirdPartyChannel
}

// Factory 由 Provider 实例构造适配器（§13.0：装配期取 Ext，运行期不
// 回读配置）。
type Factory func(p *Provider) (AuthAdapter, error)

var registry = struct {
	mu      sync.RWMutex
	entries map[string]*entry
}{entries: make(map[string]*entry)}

type entry struct {
	meta    Meta
	factory Factory
}

// Register 注册渠道（在包 init() 中调用，§15.3）。重复注册 / 空 type /
// 空 factory 属程序错误，直接 panic（init 无法返回错误）。
func Register(providerType string, meta Meta, factory Factory) {
	if err := register(providerType, meta, factory); err != nil {
		panic(err)
	}
}

// register Register 的可返回错误版本（供测试与内部复用）。
func register(providerType string, meta Meta, factory Factory) error {
	if providerType == "" {
		return fmt.Errorf("%w: empty type", ErrUnknownType)
	}
	if factory == nil {
		return fmt.Errorf("%w: %q", ErrNilFactory, providerType)
	}
	if meta.Type == "" {
		meta.Type = providerType
	}
	if meta.Type != providerType {
		return fmt.Errorf("provider: register %q: meta.Type %q mismatch", providerType, meta.Type)
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, ok := registry.entries[providerType]; ok {
		return fmt.Errorf("%w: %q", ErrAlreadyRegistered, providerType)
	}
	registry.entries[providerType] = &entry{meta: meta, factory: factory}
	return nil
}

// NewAdapter 按 Provider 实例的 type 构造适配器（§15.3）。
func NewAdapter(p *Provider) (AuthAdapter, error) {
	if p == nil {
		return nil, ErrNilProvider
	}
	registry.mu.RLock()
	e, ok := registry.entries[p.Type]
	registry.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, p.Type)
	}
	a, err := e.factory(p)
	if err != nil {
		return nil, fmt.Errorf("provider: new adapter %q: %w", p.Type, err)
	}
	if a == nil {
		return nil, fmt.Errorf("%w: %q", ErrNilAdapter, p.Type)
	}
	return a, nil
}

// Lookup 返回 type 的元信息（管理后台 schema 卡使用）。
func Lookup(providerType string) (Meta, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	e, ok := registry.entries[providerType]
	if !ok {
		return Meta{}, false
	}
	return e.meta, true
}

// Types 返回已注册 type 的排序快照（确定性输出，供 schema / 诊断）。
func Types() []string {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	out := make([]string, 0, len(registry.entries))
	for t := range registry.entries {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
