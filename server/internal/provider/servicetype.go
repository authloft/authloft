// 服务型 Provider 类型元数据（docs/后端架构.md §15.1、§15.2、§9.1、§15.4）：
// captcha（turnstile / recaptcha / hcaptcha）与 storage（local）有各自的运行时
// 解析链（captcha.Catalog / Verifier、storage.Resolver），proxy（type=proxy）仅
// 作被引配置行供出站代理解析，都不属于 provider 包的 oauth 适配器注册表或消息
// Sender 注册表——前者工厂签名是 AuthAdapter、后者把 category 限死在 sms|email，
// 均容不下。与 Union 一样，这里以静态 meta 单独登记，只喂给管理后台的类型下拉 /
// schema / 写路径键集，不产生 adapter / sender。区别于 Union 的是它们有真实
// 运行时实现（proxy 的运行时角色是被 outbound.go 的解析链引用），不是虚拟归并类型。
//
// type 字符串与 captcha.TypeTurnstile / storage 的 local 分支取值一致，但不
// import 这两个包：storage 依赖 provider，反向引用会成环；静态字面量也让本表
// 不受 blank import 顺序影响。
package provider

// 服务型 category 常量（docs/后端架构.md §4.1 provider.category 取值）。
// CategorySMS / CategoryEmail 在 sender.go、CategoryOAuth / CategoryUnion 在
// virtual.go 声明，此处补齐 captcha / storage / proxy。
const (
	CategoryCaptcha = "captcha"
	CategoryStorage = "storage"
	CategoryProxy   = "proxy"
)

// 服务型 provider type 常量（captcha 见 captcha.Verifier 的 support 分支，
// storage 见 storage.Resolver 的 local 分支，proxy 行自身仅作被引配置）。
const (
	CaptchaTypeTurnstile = "turnstile"
	CaptchaTypeRecaptcha = "recaptcha"
	CaptchaTypeHcaptcha  = "hcaptcha"
	StorageTypeLocal     = "local"
	ProxyType            = "proxy"
)

// 出站代理引用键的 schema key 与 options 注入键（接口文档 §5.3 代理提供商与
// 出站代理引用约定）：Schema 声明（本表 / schemafield）、写入侧校验
// （service/admin）与 handler 查库注入共用同一来源，防多份字面量漂移。
const (
	ProxyRefKey        = "proxy_provider_key"
	ProxyRefDynamicKey = "proxy_provider_keys"
)

// ProxyRef 出站代理引用键 proxy_provider_key 的单一声明（接口文档 §5.3
// 代理提供商与出站代理引用约定）：endpoint/select、非必填，Kind=
// FieldDynamicOptions + DynamicKey——options 运行时由 handler 查库注入
// category=proxy 行的 provider_key（含未启用实例，允许先引用后启用），
// 构造器不下发候选值，形态同 schemafield.UnionProvider 先例。schemafield.
// ProxyRef 委托至此保持渠道包（oauthcore / smtp / sms）单一取用入口：
// provider 包不可反向 import schemafield（会成环）。保存期仅校字符集、
// 不校存在性（service/admin.validateProxyRef）。
func ProxyRef() FieldMeta {
	return FieldMeta{
		Key: ProxyRefKey, Label: "admin.schemaField.proxyProviderKeyLabel",
		Type: "select", Section: "endpoint",
		Help:    "admin.schemaField.proxyProviderKeyHelp",
		Storage: StorageExt,
		Kind:    FieldDynamicOptions, DynamicKey: ProxyRefDynamicKey,
	}
}

// serviceMetas 服务型类型静态表。Schema 是 /schema 的唯一数据源（表列 + Ext，
// 接口文档 §5.3）：captcha 三家统一用 client_id 作 site_key、client_secret 作
// 密钥、endpoint 作自定义校验地址（captcha.ProviderSource 的投影口径），且类别
// 呈现 proxy_provider_key 引用键；local 用 bucket 作本地目录、domain 作公开域名、
// path_prefix 作 key 前缀（storage.NewLocal 的必填口径），仅本地磁盘无网络外呼、
// 不声明引用键；proxy 承载五真实代理字段（§5.3），供引用方解析出站连接池、自身
// 不外呼也不自引。
var serviceMetas = map[string]TypeMeta{
	CaptchaTypeTurnstile: {
		Type:        CaptchaTypeTurnstile,
		DisplayName: "Cloudflare Turnstile",
		Category:    CategoryCaptcha,
		Schema:      captchaSchema,
	},
	CaptchaTypeRecaptcha: {
		Type:        CaptchaTypeRecaptcha,
		DisplayName: "Google reCAPTCHA",
		Category:    CategoryCaptcha,
		Schema:      captchaSchema,
	},
	CaptchaTypeHcaptcha: {
		Type:        CaptchaTypeHcaptcha,
		DisplayName: "hCaptcha",
		Category:    CategoryCaptcha,
		Schema:      captchaSchema,
	},
	StorageTypeLocal: {
		Type:        StorageTypeLocal,
		DisplayName: "本地存储（local）",
		Category:    CategoryStorage,
		Schema:      storageLocalSchema,
	},
	ProxyType: {
		Type:        ProxyType,
		DisplayName: "出站代理（proxy）",
		Category:    CategoryProxy,
		Schema:      proxySchema,
	},
}

// captchaFields 三家 captcha Ext 字段的单一来源（site_key / secret / 自定义
// 校验地址），供 captchaSchema 组装完整声明；每次返回独立切片，调用方补
// Storage 落点不会污染其他调用。
func captchaFields() []FieldMeta {
	return []FieldMeta{
		{Key: "client_id", Label: "admin.schemaField.captchaSiteKeyLabel", Type: "text", Section: "credential", Required: true},
		{Key: "client_secret", Label: "admin.schemaField.captchaSecretLabel", Type: "secret", Section: "credential", Required: true},
		{Key: "endpoint", Label: "admin.schemaField.captchaEndpointLabel", Type: "text", Section: "endpoint", Advanced: true},
	}
}

// captchaSchema 三家 captcha 共用的完整字段声明（表列 + Ext + 引用键，接口
// 文档 §5.3），每次调用返回新切片。Ext 复用 captchaFields 单一来源并补 Storage
// 落点，防两份声明漂移；is_enabled 单独声明——登录 / 建号 / 自动绑定开关是
// oauth 专属，captcha 类别不下发。
func captchaSchema() []FieldMeta {
	fields := make([]FieldMeta, 0, 11)
	fields = append(fields,
		FieldMeta{Key: "provider_key", Label: "admin.schemaField.providerKeyLabel", Type: "text", Section: "basic", Required: true,
			Pattern: "^[a-z0-9_]+$", Help: "admin.schemaField.providerKeyHelp", Storage: StorageColumn},
		FieldMeta{Key: "display_name", Label: "admin.schemaField.displayNameLabel", Type: "text", Section: "basic", Required: true, Storage: StorageColumn},
	)
	ext := captchaFields()
	for i := range ext {
		ext[i].Storage = StorageExt
	}
	fields = append(fields, ext...)
	fields = append(fields,
		FieldMeta{Key: "icon_url", Label: "admin.schemaField.iconUrlLabel", Type: "text", Section: "display",
			Pattern: "^https?://", Help: "admin.schemaField.iconUrlHelp", Storage: StorageColumn},
		FieldMeta{Key: "ui_group", Label: "admin.schemaField.uiGroupLabel", Type: "select", Section: "display",
			Options: []string{"social", "enterprise", "dev", "other"}, Default: "social", Storage: StorageColumn},
		FieldMeta{Key: "sort_order", Label: "admin.schemaField.sortOrderLabel", Type: "number", Section: "display", Default: "0", Storage: StorageColumn},
		FieldMeta{Key: "remark", Label: "admin.schemaField.remarkLabel", Type: "text", Section: "display", Advanced: true, Storage: StorageColumn},
		FieldMeta{Key: "is_enabled", Label: "admin.schemaField.isEnabledLabel", Type: "checkbox", Section: "policy", Default: "true", Storage: StorageColumn},
		ProxyRef(),
	)
	return fields
}

// proxySchema type=proxy 的完整字段声明（表列 + 五真实 Ext 字段，接口文档
// §5.3 代理提供商与出站代理引用约定）：scheme 封闭集 socks5/http/https、host
// 禁空白与 /?#@[]、port 1..65535 且必填（required 经 Create 的 number-aware
// 缺省判定生效）、user / password 可选且 password 须伴随 user；五行
// section=endpoint。proxy 行自身不声明引用键（不自引）、无 oauth 登录建号
// 开关；字段组合合法性单一来源在 proxyclient.NewConfig（保存期
// CreateProvider / UpdateProvider 调用），本声明只管表单呈现。每次调用返回
// 新切片。
func proxySchema() []FieldMeta {
	fields := make([]FieldMeta, 0, 12)
	fields = append(fields,
		FieldMeta{Key: "provider_key", Label: "admin.schemaField.providerKeyLabel", Type: "text", Section: "basic", Required: true,
			Pattern: "^[a-z0-9_]+$", Help: "admin.schemaField.providerKeyHelp", Storage: StorageColumn},
		FieldMeta{Key: "display_name", Label: "admin.schemaField.displayNameLabel", Type: "text", Section: "basic", Required: true, Storage: StorageColumn},
		FieldMeta{Key: "scheme", Label: "admin.schemaField.proxySchemeLabel", Type: "select", Section: "endpoint", Required: true,
			Options: []string{"socks5", "http", "https"}, Help: "admin.schemaField.proxySchemeHelp", Storage: StorageExt},
		FieldMeta{Key: "host", Label: "admin.schemaField.proxyHostLabel", Type: "text", Section: "endpoint", Required: true,
			Pattern: "^[^\\s/?#@\\[\\]]+$", Help: "admin.schemaField.proxyHostHelp", Storage: StorageExt},
		FieldMeta{Key: "port", Label: "admin.schemaField.proxyPortLabel", Type: "number", Section: "endpoint", Required: true,
			Help: "admin.schemaField.proxyPortHelp", Storage: StorageExt},
		FieldMeta{Key: "user", Label: "admin.schemaField.proxyUserLabel", Type: "text", Section: "endpoint", Advanced: true,
			Help: "admin.schemaField.proxyUserHelp", Storage: StorageExt},
		FieldMeta{Key: "password", Label: "admin.schemaField.proxyPasswordLabel", Type: "secret", Section: "endpoint", Advanced: true,
			Help: "admin.schemaField.proxyPasswordHelp", Storage: StorageExt},
		FieldMeta{Key: "icon_url", Label: "admin.schemaField.iconUrlLabel", Type: "text", Section: "display",
			Pattern: "^https?://", Help: "admin.schemaField.iconUrlHelp", Storage: StorageColumn},
		FieldMeta{Key: "ui_group", Label: "admin.schemaField.uiGroupLabel", Type: "select", Section: "display",
			Options: []string{"social", "enterprise", "dev", "other"}, Default: "social", Storage: StorageColumn},
		FieldMeta{Key: "sort_order", Label: "admin.schemaField.sortOrderLabel", Type: "number", Section: "display", Default: "0", Storage: StorageColumn},
		FieldMeta{Key: "remark", Label: "admin.schemaField.remarkLabel", Type: "text", Section: "display", Advanced: true, Storage: StorageColumn},
		FieldMeta{Key: "is_enabled", Label: "admin.schemaField.isEnabledLabel", Type: "checkbox", Section: "policy", Default: "true", Storage: StorageColumn},
	)
	return fields
}

// storageLocalSchema storage/local 的完整字段声明（表列 + Ext，接口文档 §5.3）。
// local 仅本地磁盘、无网络外呼，与 union / proxy 行自身同样不声明引用键（§5.3
// 类别裁剪）；oauth 专属的登录建号开关亦不出现。
func storageLocalSchema() []FieldMeta {
	fields := make([]FieldMeta, 0, 10)
	fields = append(fields,
		FieldMeta{Key: "provider_key", Label: "admin.schemaField.providerKeyLabel", Type: "text", Section: "basic", Required: true,
			Pattern: "^[a-z0-9_]+$", Help: "admin.schemaField.providerKeyHelp", Storage: StorageColumn},
		FieldMeta{Key: "display_name", Label: "admin.schemaField.displayNameLabel", Type: "text", Section: "basic", Required: true, Storage: StorageColumn},
		FieldMeta{Key: "bucket", Label: "admin.schemaField.storageBucketLabel", Type: "text", Section: "endpoint", Required: true, Storage: StorageExt},
		FieldMeta{Key: "domain", Label: "admin.schemaField.storageDomainLabel", Type: "text", Section: "endpoint", Required: true, Storage: StorageExt},
		FieldMeta{Key: "path_prefix", Label: "admin.schemaField.storagePathPrefixLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: StorageExt},
		FieldMeta{Key: "icon_url", Label: "admin.schemaField.iconUrlLabel", Type: "text", Section: "display",
			Pattern: "^https?://", Help: "admin.schemaField.iconUrlHelp", Storage: StorageColumn},
		FieldMeta{Key: "ui_group", Label: "admin.schemaField.uiGroupLabel", Type: "select", Section: "display",
			Options: []string{"social", "enterprise", "dev", "other"}, Default: "social", Storage: StorageColumn},
		FieldMeta{Key: "sort_order", Label: "admin.schemaField.sortOrderLabel", Type: "number", Section: "display", Default: "0", Storage: StorageColumn},
		FieldMeta{Key: "remark", Label: "admin.schemaField.remarkLabel", Type: "text", Section: "display", Advanced: true, Storage: StorageColumn},
		FieldMeta{Key: "is_enabled", Label: "admin.schemaField.isEnabledLabel", Type: "checkbox", Section: "policy", Default: "true", Storage: StorageColumn},
	)
	return fields
}
