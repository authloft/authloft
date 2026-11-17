// 存储 Storage 基建（docs/后端架构.md §15.1、§15.3）：Storage 接口与
// ErrNotConfigured / ErrUnsupportedType 哨兵从 internal/storage 上移定义
// （§15.3 接口归属：factory 产物类型必须让 provider 可见，provider 父包
// 永不 import 子包，故接口先上移；原包以别名保持调用方零改动）。实现位于
// provider/storage/<type>/ 子包，init() 经 RegisterStorage 自注册，bootstrap
// 以 blank import 触发（CODE_GUIDE §3.3）。
package provider

import (
	"context"
	"errors"
	"fmt"
)

// 可判别错误（自 internal/storage 平移，文案不变，errors.Is 判别面不变）。
var (
	// ErrNotConfigured storage provider 未配置 / 未启用 / 关键字段缺失。
	ErrNotConfigured = errors.New("storage: provider not configured")
	// ErrUnsupportedType type 未实现（s3 等，归后续实现）。
	ErrUnsupportedType = errors.New("storage: unsupported provider type")
)

// Storage 存储 Provider 接口（《后端架构》§15.1 逐字）。key 为业务侧
// object key（码图：storage_path 渲染结果；§15.1「渲染后的 key 再拼
// path_prefix」——prefix 拼接由各实现内部完成，调用方只传渲染结果）。
type Storage interface {
	Put(ctx context.Context, key string, body []byte, contentType string) (url string, err error)
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	URL(key string) string // 拼接 domain / CDN

	// PresignPut 直传模式：签发一个有时效的 PUT URL，前端据此直传对象存储
	PresignPut(ctx context.Context, key string, contentType string, size int64) (uploadURL string, headers map[string]string, err error)
}

// StorageFactory storage 槽 factory：由 Provider 实例构造存储实现（§13.0：
// 装配期取 Ext，运行期不回读配置；local 只依赖 bucket / domain / path_prefix，
// 纯 Ext，无额外运行时依赖）。
type StorageFactory func(p *Provider) (Storage, error)

// RegisterStorage 注册存储实现（§15.3 薄封装：转调唯一入口 register +
// WithStorage，type 子包 init() 调用）。重复注册 / 空 type / 空 factory 属
// 程序错误，直接 panic（init 无法返回错误）。
func RegisterStorage(storageType string, meta Meta, factory StorageFactory) {
	if err := register(storageType, meta, WithStorage(factory)); err != nil {
		panic(err)
	}
}

// NewStorage storage 槽取件（§15.3）：按 Provider 实例的 type 经注册表分派。
// type 未注册或未挂 storage 槽 → 同时包装 ErrNotConfigured 与
// ErrUnsupportedType（storage.Resolver 既有双哨兵判别面，调用方统一按
// provider_disabled 收敛），不回落任何实现（§13.0 优先级口径）；factory
// 自身错误原样上抛（local 未配置等域内语义不改写）。
func NewStorage(p *Provider) (Storage, error) {
	if p == nil {
		return nil, ErrNilProvider
	}
	registry.mu.RLock()
	e, ok := registry.entries[p.Type]
	registry.mu.RUnlock()
	if !ok || e.storage == nil {
		return nil, fmt.Errorf("%w: %w: %q", ErrNotConfigured, ErrUnsupportedType, p.Type)
	}
	return e.storage(p)
}
