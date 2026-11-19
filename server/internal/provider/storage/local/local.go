// Package local local 存储实现（§15.1 表：写入本地目录，由 Nginx 静态分发；
// 不支持直传模式——无预签名能力，配置为 direct 时自动回退 proxy 由调用方
// （头像上传，接口文档 §10.8 行 840）处理，本实现 PresignPut 恒错误）。
//
// 工厂化（§15.3 阶段二）：init() 经 RegisterStorage 自注册进统一注册表
// （meta 与 factory 同处注册），bootstrap 以 blank import 触发；factory 只从
// Ext 取配置（无额外运行时依赖）。类型常量取 provider.StorageTypeLocal，
// 字面量单一来源在 provider 包（servicetype.go）。
//
// 字段映射（Ext 字段语义见接口文档 §12.1 行 1251 storage 追加清单）：
//   - Ext.bucket  → 本地目录（绝对或相对工作目录均可，Nginx 指向同目录分发）；
//   - Ext.domain  → 公开访问域名（URL 拼接基准，§15.1「拼接 domain / CDN」），
//     为空视为未配置——拉码响应的 qrcodeUrl 必须是可直接访问的绝对地址；
//   - Ext.path_prefix → key 前缀（§15.1「渲染后的 key 再拼 path_prefix」）。
//
// key 安全：key 由服务端模板渲染（非前端提交），本实现仍做路径穿越
// 防护（空 key / 绝对 key / ".." 段 / 盘符 / 反斜杠一律拒绝）——写磁盘
// 的实现必须自守，不信任上游；渲染侧（internal/storage path.go）按同一
// 规则前置校验。
package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"authloft/internal/provider"

	providerpb "authloft/gen/go/provider"
)

// Type 注册类型（§15.1 内置清单：当前仅 local 实装，s3 归后续经同机制注册）。
const Type = provider.StorageTypeLocal

// ErrPresignNotSupported local 无预签名能力（§15.1）。
var ErrPresignNotSupported = errors.New("storage: local: presign not supported")

// init 注册进统一注册表（§15.3）：meta 的 Schema 是 /schema 的唯一数据源
// （表列 + Ext，接口文档 §5.3），自 servicetype.go 原样平移，声明形态与
// 工厂化前逐字段一致；local 仅本地磁盘、无网络外呼，不声明引用键（§5.3
// 类别裁剪），oauth 专属的登录建号开关亦不出现。
func init() {
	provider.RegisterStorage(Type, provider.Meta{
		DisplayName: "本地存储",
		Category:    provider.CategoryStorage,
		Schema:      storageLocalSchema,
	}, newStorage)
}

// newStorage 注册表工厂：从 Provider 实例取 Ext 构造（§15.1：纯 Ext，
// bucket / domain / path_prefix，无额外运行时依赖）。
func newStorage(p *provider.Provider) (provider.Storage, error) {
	return NewLocal(p.Ext)
}

// Local 本地磁盘存储。
type Local struct {
	dir    string
	prefix string
	domain string
}

// NewLocal 从 Ext 构造；bucket / domain 为空即未配置（§13.0「按失败处理」）。
func NewLocal(ext *providerpb.Ext) (*Local, error) {
	if ext == nil {
		return nil, fmt.Errorf("%w: nil ext", provider.ErrNotConfigured)
	}
	dir := strings.TrimSpace(ext.GetBucket())
	domain := strings.TrimRight(strings.TrimSpace(ext.GetDomain()), "/")
	if dir == "" || domain == "" {
		return nil, fmt.Errorf("%w: local: bucket(%q) / domain(%q) empty", provider.ErrNotConfigured, ext.GetBucket(), ext.GetDomain())
	}
	return &Local{dir: dir, prefix: trimPrefix(ext.GetPathPrefix()), domain: domain}, nil
}

// Put 写入本地并返回公开 URL。contentType local 实现不落盘（MIME 由
// Nginx 按扩展名分发），仅保留接口形态。
func (l *Local) Put(_ context.Context, key string, body []byte, _ string) (string, error) {
	path, err := l.path(key)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("storage: local: mkdir: %w", err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return "", fmt.Errorf("storage: local: write: %w", err)
	}
	return l.URL(key), nil
}

// Get 读取；文件不存在返回 os.ErrNotExist 包装（调用方按需判别）。
func (l *Local) Get(_ context.Context, key string) ([]byte, error) {
	path, err := l.path(key)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("storage: local: read: %w", err)
	}
	return body, nil
}

// Delete 删除码图 / 对象；文件已不存在视为成功（§13.3 删除幂等——重试
// 与 TTL 过期后的重复删除不报错）。
func (l *Local) Delete(_ context.Context, key string) error {
	path, err := l.path(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("storage: local: delete: %w", err)
	}
	return nil
}

// URL 拼接公开地址：domain + "/" + prefix + key。
func (l *Local) URL(key string) string {
	if l.prefix == "" {
		return l.domain + "/" + key
	}
	return l.domain + "/" + l.prefix + "/" + key
}

// PresignPut local 不支持直传（§15.1 表）。
func (l *Local) PresignPut(context.Context, string, string, int64) (string, map[string]string, error) {
	return "", nil, ErrPresignNotSupported
}

// path 校验 key 并拼出磁盘绝对路径（prefix + key 相对 dir）。
func (l *Local) path(key string) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	rel := key
	if l.prefix != "" {
		rel = l.prefix + "/" + key
	}
	return filepath.Join(l.dir, filepath.FromSlash(rel)), nil
}

// validateKey 路径穿越防护（渲染侧同规则前置校验，两处须保持同步）。
func validateKey(key string) error {
	if key == "" || strings.HasPrefix(key, "/") || strings.Contains(key, "\\") ||
		strings.Contains(key, ":") {
		return fmt.Errorf("storage: local: invalid key %q", key)
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." {
			return fmt.Errorf("storage: local: invalid key %q", key)
		}
	}
	return nil
}

// trimPrefix path_prefix 去两端斜杠（空串保持空）。
func trimPrefix(raw string) string {
	return strings.Trim(strings.TrimSpace(raw), "/")
}

// storageLocalSchema storage/local 的完整字段声明（表列 + Ext，接口文档 §5.3），
// 每次调用返回新切片。storage 恒可用（不消费 is_enabled），is_enabled 不在
// 声明内——列表页 / 编辑表单对该类别不出现启停。
func storageLocalSchema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 9)
	fields = append(fields,
		provider.FieldMeta{Key: "provider_key", Label: "admin.schemaField.providerKeyLabel", Type: "text", Section: "basic", Required: true,
			Pattern: "^[a-z0-9_]+$", Help: "admin.schemaField.providerKeyHelp", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "display_name", Label: "admin.schemaField.displayNameLabel", Type: "text", Section: "basic", Required: true, Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "bucket", Label: "admin.schemaField.storageBucketLabel", Type: "text", Section: "endpoint", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "domain", Label: "admin.schemaField.storageDomainLabel", Type: "text", Section: "endpoint", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "path_prefix", Label: "admin.schemaField.storagePathPrefixLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "icon_url", Label: "admin.schemaField.iconUrlLabel", Type: "text", Section: "display",
			Pattern: "^https?://", Help: "admin.schemaField.iconUrlHelp", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "ui_group", Label: "admin.schemaField.uiGroupLabel", Type: "select", Section: "display",
			Options: []string{"social", "enterprise", "dev", "other"}, Default: "social", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "sort_order", Label: "admin.schemaField.sortOrderLabel", Type: "number", Section: "display", Default: "0", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "remark", Label: "admin.schemaField.remarkLabel", Type: "text", Section: "display", Advanced: true, Storage: provider.StorageColumn},
	)
	return fields
}
