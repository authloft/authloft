// Package storage 是存储 Provider（category=storage，§15.1）的薄壳：
// Storage 接口与 ErrNotConfigured / ErrUnsupportedType 哨兵已上移 provider
// 包定义（§15.3 接口归属），本包以类型别名 / 同值变量保持调用方（qrcode /
// wxacode / account-avatar）import 路径与签名零改动；storage_path 模板渲染
// （RenderKey，§15.1）留在本包。当前只落 local 实现（provider/storage/local
// 子包 init 自注册，bootstrap blank import 触发）；s3 系需引入第三方 SDK
// （未授权新依赖），归头像上传 / storage 扩展实现。
//
// 解析口径（§13.0「未配置按失败处理」）：storage provider 行不存在 /
// is_enabled=0 / category≠storage → ErrNotConfigured；type 未注册支持 /
// 实现构造失败（如 local 关键字段缺失）由注册表分派（provider.NewStorage）
// 返回，未注册 type 同时命中 ErrUnsupportedType——一律显式报错，不伪装
// 成功、不回落 local。调用方（扫码拉码链）统一按 provider_disabled 收敛。
package storage

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"authloft/internal/provider"
)

// 接口与哨兵定义在 provider 包（§15.3 上移），别名保持既有调用面。
type Storage = provider.Storage

var (
	// ErrNotConfigured storage provider 未配置 / 未启用 / 关键字段缺失。
	ErrNotConfigured = provider.ErrNotConfigured
	// ErrUnsupportedType type 未实现（s3 等，归后续实现）。
	ErrUnsupportedType = provider.ErrUnsupportedType
)

// ProviderGetter 按 provider_key 读 Provider 实例：*provider.Loader 天然
// 满足（§13.0 装配期口径经 Loader 取行，运行期不读 config）。
type ProviderGetter interface {
	Get(ctx context.Context, providerKey string) (*provider.Provider, error)
}

// Resolver 按 provider_key 解析 Storage 实现（§3.4 行 468「按 provider_key
// 解析实现」；§15.3 阶段二起为薄壳：行校验留在本包，实现分派转调
// provider.NewStorage，不再 switch type）。
type Resolver struct {
	get ProviderGetter
}

// NewResolver 构造。get 为 nil 时 Resolve 一律 ErrNotConfigured（半装配
// 防御，测试口径同先例）。
func NewResolver(get ProviderGetter) *Resolver {
	return &Resolver{get: get}
}

// Resolve 解析 storageProviderKey（引用方：wechat_mp_scan 的
// Ext.storage_provider，接口文档 §12.1）。查询故障原样上抛（基础设施
// 错误与「未配置」区分，§1.5 语义）。
func (r *Resolver) Resolve(ctx context.Context, storageProviderKey string) (Storage, error) {
	if r == nil || r.get == nil || storageProviderKey == "" {
		return nil, fmt.Errorf("%w: empty storage provider key", ErrNotConfigured)
	}
	p, err := r.get.Get(ctx, storageProviderKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %q not found", ErrNotConfigured, storageProviderKey)
		}
		return nil, fmt.Errorf("storage: load provider: %w", err)
	}
	if p == nil || p.Row == nil || !p.Enabled() || p.Row.Category != "storage" {
		return nil, fmt.Errorf("%w: %q not a storage provider or disabled", ErrNotConfigured, storageProviderKey)
	}
	// 分派经统一注册表（§15.3）：未注册 type → ErrNotConfigured 内含
	// ErrUnsupportedType，不回落 local（§13.0 优先级口径）；local 构造失败
	// （bucket / domain 缺失）的 ErrNotConfigured 原样上抛。
	return provider.NewStorage(p)
}
