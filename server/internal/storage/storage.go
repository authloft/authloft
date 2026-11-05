// Package storage 是存储 Provider（category=storage，§15.1）的最小抽象：
// Storage 接口按《后端架构》§15.1 逐字落，按 provider_key 解析
// 实现。当前只落 local 实现（写入本地目录、Nginx 静态分发，§15.1 表）；
// s3 系需引入第三方 SDK（未授权新依赖），归头像上传 / storage 扩展
// 实现——遇未支持 type 一律显式报错，不伪装成功。
//
// 解析口径（§13.0「未配置按失败处理」）：storage provider 行不存在 /
// is_enabled=0 / category≠storage / 本地目录（Ext.bucket）或公开域名
// （Ext.domain）为空 → ErrNotConfigured；type 未注册支持 → 包装
// ErrUnsupportedType。调用方（扫码拉码链）统一按 provider_disabled 收敛。
package storage

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"authloft/internal/provider"
)

// ErrNotConfigured storage provider 未配置 / 未启用 / 关键字段缺失。
var ErrNotConfigured = errors.New("storage: provider not configured")

// ErrUnsupportedType type 未实现（s3 等，归后续实现）。
var ErrUnsupportedType = errors.New("storage: unsupported provider type")

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

// ProviderGetter 按 provider_key 读 Provider 实例：*provider.Loader 天然
// 满足（§13.0 装配期口径经 Loader 取行，运行期不读 config）。
type ProviderGetter interface {
	Get(ctx context.Context, providerKey string) (*provider.Provider, error)
}

// Resolver 按 provider_key 解析 Storage 实现（§3.4 行 468「按 provider_key
// 解析实现」）。
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
	switch p.Type {
	case "local":
		return NewLocal(p.Ext)
	default:
		// s3 / oss 等兼容实现需第三方 SDK（§15.1 表），归后续实现；此处显式
		// 失败，不回落 local（跨 provider 回落违反 §13.0 优先级口径）。
		return nil, fmt.Errorf("%w: %w: %q", ErrNotConfigured, ErrUnsupportedType, p.Type)
	}
}
