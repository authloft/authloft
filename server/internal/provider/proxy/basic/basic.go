// Package basic 基础代理（category=proxy、type=proxy）出站代理配置实现
// （docs/后端架构.md §15.4 工厂化阶段五）：init() 经 RegisterProxy 自注册
// 进统一注册表（meta 与 factory 同处注册，§15.3），bootstrap 与各测试二进制
// 以 blank import 触发（CODE_GUIDE §3.3，漏 import 即类型「凭空消失」）。
// proxy 行只作被引配置行供 outbound 解析链解析，自身不外呼也不自引（接口
// 文档 §5.3 代理提供商与出站代理引用约定）；factory 读五个真实 Ext 字段调
// proxyclient.NewConfig 产出 Config 值对象——规则源仍是 NewConfig 单一来源，
// golang.org/x/net/proxy 仍只在 proxyclient 内 import；PoolSet 仍由解析链
// 显式注入，factory 不产出 Pool、不持有池。
package basic

import (
	"authloft/internal/provider"
	"authloft/internal/proxyclient"
)

// Type 注册类型（字面量单一来源在 provider 包 servicetype.go）。
const Type = provider.ProxyType

// init 注册进统一注册表（§15.3）：Schema 是 /schema 的唯一数据源（表列 +
// 五真实 Ext 字段，接口文档 §5.3）；proxy 行不声明引用键（不自引）、无
// oauth 登录建号开关。
func init() {
	provider.RegisterProxy(Type, provider.Meta{
		DisplayName: "基础代理",
		Category:    provider.CategoryProxy,
		Schema:      Schema,
	}, newConfig)
}

// Schema type=proxy 的完整字段声明（表列 + 五真实 Ext 字段，接口文档 §5.3
// 代理提供商与出站代理引用约定）：scheme 封闭集 socks5/http/https、host 禁
// 空白与 /?#@[]、port 1..65535 且必填（required 经 Create 的 number-aware
// 缺省判定生效）、user / password 可选且 password 须伴随 user；五行
// section=endpoint。字段组合合法性单一来源在 proxyclient.NewConfig（保存期
// CreateProvider / UpdateProvider 与运行期 factory 两处同一函数），本声明
// 只管表单呈现。每次调用返回新切片。
func Schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 12)
	fields = append(fields,
		provider.FieldMeta{Key: "provider_key", Label: "admin.schemaField.providerKeyLabel", Type: "text", Section: "basic", Required: true,
			Pattern: "^[a-z0-9_]+$", Help: "admin.schemaField.providerKeyHelp", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "display_name", Label: "admin.schemaField.displayNameLabel", Type: "text", Section: "basic", Required: true, Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "scheme", Label: "admin.schemaField.proxySchemeLabel", Type: "select", Section: "endpoint", Required: true,
			Options: []string{"socks5", "http", "https"}, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "host", Label: "admin.schemaField.proxyHostLabel", Type: "text", Section: "endpoint", Required: true,
			Pattern: "^[^\\s/?#@\\[\\]]+$", Help: "admin.schemaField.proxyHostHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "port", Label: "admin.schemaField.proxyPortLabel", Type: "number", Section: "endpoint", Required: true,
			Help: "admin.schemaField.proxyPortHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "user", Label: "admin.schemaField.proxyUserLabel", Type: "text", Section: "endpoint", Advanced: false, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "password", Label: "admin.schemaField.proxyPasswordLabel", Type: "secret", Section: "endpoint", Advanced: false,
			Help: "admin.schemaField.proxyPasswordHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "icon_url", Label: "admin.schemaField.iconUrlLabel", Type: "text", Section: "display",
			Pattern: "^https?://", Help: "admin.schemaField.iconUrlHelp", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "ui_group", Label: "admin.schemaField.uiGroupLabel", Type: "select", Section: "display",
			Options: []string{"social", "enterprise", "dev", "other"}, Default: "social", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "sort_order", Label: "admin.schemaField.sortOrderLabel", Type: "number", Section: "display", Default: "0", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "remark", Label: "admin.schemaField.remarkLabel", Type: "text", Section: "display", Advanced: true, Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "is_enabled", Label: "admin.schemaField.isEnabledLabel", Type: "checkbox", Section: "policy", Default: "true", Storage: provider.StorageColumn},
	)
	return fields
}

// newConfig 注册表工厂：从 Provider 实例取五个真实 Ext 字段（scheme/host/
// port/user/password，§15.4）产出配置值对象；字段组合非法（scheme 封闭集、
// host 字符集、port 越界、password 须伴随 user 等）由 proxyclient.NewConfig
// 拒绝，本包不做第二套校验。nil Ext 的 getter 全空串 → NewConfig 以 scheme
// 非法拒绝，fail-closed（§15.4 运行期拦脏数据同一规则源）。
func newConfig(p *provider.Provider) (proxyclient.Config, error) {
	return proxyclient.NewConfig(p.Ext.GetScheme(), p.Ext.GetHost(), p.Ext.GetPort(), p.Ext.GetUser(), p.Ext.GetPassword())
}
