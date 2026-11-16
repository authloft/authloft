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

// serviceMetas 服务型类型静态表。Fields 是该类型消费的 Ext 字段声明，管理后台
// 表单按此渲染（接口文档 §5.3）：captcha 三家统一用 client_id 作 site_key、
// client_secret 作密钥、endpoint 作自定义校验地址（captcha.ProviderSource 的
// 投影口径）；local 用 bucket 作本地目录、domain 作公开域名、path_prefix 作 key
// 前缀（storage.NewLocal 的必填口径）。proxy_url 是通用 Ext 基线，由 dto 按
// category/type 裁剪统一下发，不在各类型 Fields 内重复声明。
var serviceMetas = map[string]TypeMeta{
	CaptchaTypeTurnstile: {
		Type:        CaptchaTypeTurnstile,
		DisplayName: "Cloudflare Turnstile",
		Category:    CategoryCaptcha,
		Fields:      captchaFields(),
	},
	CaptchaTypeRecaptcha: {
		Type:        CaptchaTypeRecaptcha,
		DisplayName: "Google reCAPTCHA",
		Category:    CategoryCaptcha,
		Fields:      captchaFields(),
	},
	CaptchaTypeHcaptcha: {
		Type:        CaptchaTypeHcaptcha,
		DisplayName: "hCaptcha",
		Category:    CategoryCaptcha,
		Fields:      captchaFields(),
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
