// 服务型 Provider 类型元数据（docs/后端架构.md §15.1、§15.2、§9.1）：
// captcha（turnstile / recaptcha / hcaptcha）与 storage（local）有各自的运行时
// 解析链（captcha.Catalog / Verifier、storage.Resolver），但都不属于 provider
// 包的 oauth 适配器注册表或消息 Sender 注册表——前者工厂签名是 AuthAdapter、
// 后者把 category 限死在 sms|email，均容不下。与 Union 一样，这里以静态 meta
// 单独登记，只喂给管理后台的类型下拉 / schema / 写路径键集，不产生 adapter /
// sender。区别于 Union 的是它们有真实运行时实现，不是虚拟归并类型。
//
// type 字符串与 captcha.TypeTurnstile / storage 的 local 分支取值一致，但不
// import 这两个包：storage 依赖 provider，反向引用会成环；静态字面量也让本表
// 不受 blank import 顺序影响。
package provider

// 服务型 category 常量（docs/后端架构.md §4.1 provider.category 取值）。
// CategorySMS / CategoryEmail 在 sender.go、CategoryOAuth / CategoryUnion 在
// virtual.go 声明，此处补齐 captcha / storage。
const (
	CategoryCaptcha = "captcha"
	CategoryStorage = "storage"
)

// 服务型 provider type 常量（captcha 见 captcha.Verifier 的 support 分支，
// storage 见 storage.Resolver 的 local 分支）。
const (
	CaptchaTypeTurnstile = "turnstile"
	CaptchaTypeRecaptcha = "recaptcha"
	CaptchaTypeHcaptcha  = "hcaptcha"
	StorageTypeLocal     = "local"
)

// serviceMetas 服务型类型静态表。Schema 是 /schema 的完整声明形态（表列 + Ext，
// 接口文档 §5.3）：captcha 三家统一用 client_id 作 site_key、client_secret 作
// 密钥、endpoint 作自定义校验地址（captcha.ProviderSource 的投影口径），且类别
// 呈现 proxy_url；local 用 bucket 作本地目录、domain 作公开域名、path_prefix 作
// key 前缀（storage.NewLocal 的必填口径），仅本地磁盘无网络外呼、不声明
// proxy_url。Fields 为迁移期数据源（仅 Ext 声明），消费方翻转前二者并存。
var serviceMetas = map[string]TypeMeta{
	CaptchaTypeTurnstile: {
		Type:        CaptchaTypeTurnstile,
		DisplayName: "Cloudflare Turnstile",
		Category:    CategoryCaptcha,
		Fields:      captchaFields(),
		Schema:      captchaSchema,
	},
	CaptchaTypeRecaptcha: {
		Type:        CaptchaTypeRecaptcha,
		DisplayName: "Google reCAPTCHA",
		Category:    CategoryCaptcha,
		Fields:      captchaFields(),
		Schema:      captchaSchema,
	},
	CaptchaTypeHcaptcha: {
		Type:        CaptchaTypeHcaptcha,
		DisplayName: "hCaptcha",
		Category:    CategoryCaptcha,
		Fields:      captchaFields(),
		Schema:      captchaSchema,
	},
	StorageTypeLocal: {
		Type:        StorageTypeLocal,
		DisplayName: "本地存储（local）",
		Category:    CategoryStorage,
		Fields: []FieldMeta{
			{Key: "bucket", Label: "admin.schemaField.storageBucketLabel", Type: "text", Section: "endpoint", Required: true},
			{Key: "domain", Label: "admin.schemaField.storageDomainLabel", Type: "text", Section: "endpoint", Required: true},
			{Key: "path_prefix", Label: "admin.schemaField.storagePathPrefixLabel", Type: "text", Section: "endpoint", Advanced: true},
		},
		Schema: storageLocalSchema,
	},
}

// captchaFields 三家 captcha 共用的 Ext 字段声明（site_key / secret / 自定义
// 校验地址），每家返回独立切片避免调用方改动污染其他条目。
func captchaFields() []FieldMeta {
	return []FieldMeta{
		{Key: "client_id", Label: "admin.schemaField.captchaSiteKeyLabel", Type: "text", Section: "credential", Required: true},
		{Key: "client_secret", Label: "admin.schemaField.captchaSecretLabel", Type: "secret", Section: "credential", Required: true},
		{Key: "endpoint", Label: "admin.schemaField.captchaEndpointLabel", Type: "text", Section: "endpoint", Advanced: true},
	}
}

// captchaSchema 三家 captcha 共用的完整字段声明（表列 + Ext + proxy_url，接口
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
		FieldMeta{Key: "proxy_url", Label: "admin.schemaField.proxyUrlLabel", Type: "text", Section: "endpoint", Advanced: true,
			Help: "admin.schemaField.proxyUrlHelp", Storage: StorageExt},
	)
	return fields
}

// storageLocalSchema storage/local 的完整字段声明（表列 + Ext，接口文档 §5.3）。
// local 仅本地磁盘、无网络外呼，与 union 同样不声明 proxy_url（§5.3 类别裁剪）；
// oauth 专属的登录建号开关亦不出现。
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
