// catalog.go 是 gate.go ProviderCatalog 接口的实装（docs/后端架构.md
// §9.1 行 1092-1094、docs/接口文档.md §2.5 行 513-517 降级规则）：
// settings 键 captcha_provider_key（空串 = 内置，§5.6 行 1334）→ provider
// 表 category=captcha 且 is_enabled=1 的生效行，每次现算不缓存。无可用项
// （未配置 / 禁用 / 查不到）返回 nil,nil，降级语义归 Gate（builtin_image）。
// 本包不自持 DB 句柄（gate.go 包口径）：provider 行经 ProviderSource 窄
// 接口注入，装配层用 repo + ext 解析实现（§12.1：site_key=client_id、
// secret=client_secret、endpoint=自定义校验地址），同 image.go Store 的
// 依赖倒置模式。
package captcha

import (
	"context"
	"fmt"

	"authloft/internal/settings"
)

// CategoryCaptcha provider 表 category 取值（§4.1：oauth|captcha|sms|
// email|storage|notify|union）。
const CategoryCaptcha = "captcha"

// KeyReader 读 settings 字符串键（热更新快照，§5.6 行 1342 只对后续
// 请求生效）。生产注入 *settings.Store。
type KeyReader interface {
	GetString(key string) (string, bool)
}

// ProviderRecord 是 provider 表行对本包的窄投影：装配层查表并解析 ext
// 后构造。Enabled 即 is_enabled=1；Secret 仅供 Verifier 调第三方
// siteverify，不进 Config（前台永不返回凭证，§12.1 行 1720）。
type ProviderRecord struct {
	ProviderKey string
	Category    string
	Type        string
	Enabled     bool
	SiteKey     string // ext.client_id（§9.1 行 1083）
	Secret      string // ext.client_secret
	VerifyURL   string // ext.endpoint，自定义校验地址（空 = 厂商默认）
}

// ProviderSource 按 provider_key 取 provider 行投影；nil,nil = 无此行，
// error = 基础设施错误（由 Gate 按健康检查失败降级，§9.1 行 1095）。
type ProviderSource interface {
	Find(ctx context.Context, providerKey string) (*ProviderRecord, error)
}

// Catalog ProviderCatalog 实装。
type Catalog struct {
	keys   KeyReader
	source ProviderSource
}

// NewCatalog 注入 settings 键读取与 provider 行源。
func NewCatalog(keys KeyReader, source ProviderSource) *Catalog {
	return &Catalog{keys: keys, source: source}
}

// Current 每次现算当前生效 captcha Provider（不缓存，§9.1 行 1094
//「下发与拦截永远同源」）：键空串 / 键缺失 / 行不存在 / category≠captcha /
// 未启用 → nil,nil；基础设施错误原样上抛。
func (c *Catalog) Current(ctx context.Context) (*Provider, error) {
	if c == nil || c.keys == nil || c.source == nil {
		return nil, nil
	}
	key, _ := c.keys.GetString(settings.KeyCaptchaProviderKey)
	if key == "" {
		return nil, nil
	}
	rec, err := c.source.Find(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("captcha: load provider %q: %w", key, err)
	}
	if rec == nil || rec.Category != CategoryCaptcha || !rec.Enabled {
		return nil, nil
	}
	return &Provider{
		ProviderKey: rec.ProviderKey,
		Type:        rec.Type,
		SiteKey:     rec.SiteKey,
	}, nil
}
