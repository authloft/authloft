// 服务型 Provider 类型字面量单一来源（docs/后端架构.md §15.1、§15.2、§9.1、
// §15.4）：storage（local）、captcha 三家与 proxy 的 meta / factory 已随
// 工厂化迁入 provider/<域>/<type>/ 子包 init() 自注册，本文件只保留 type /
// category 常量与引用键声明，不再注册 meta（防止与子包自注册重复 panic）。
// 实现包 import 本包取常量并注册 factory；proxy 行仅作出站代理解析链的被引
// 配置行，区别于 Union 的虚拟归并，有真实运行时角色。
package provider

// 服务型 category 常量（docs/后端架构.md §4.1 provider.category 取值）。
// CategorySMS / CategoryEmail 在 sender.go、CategoryOAuth / CategoryUnion 在
// virtual.go 声明，此处补齐 captcha / storage / proxy。
const (
	CategoryCaptcha = "captcha"
	CategoryStorage = "storage"
	CategoryProxy   = "proxy"
)

// 服务型 provider type 常量（captcha 三家见 provider/captcha/<type> 子包注册、
// gate 经注册表 NewVerifier 分派，storage 见 provider/storage/local 子包注册、
// Resolver 经注册表分派，proxy 行自身仅作被引配置）。
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

// proxy 行五真实 Ext 字段的声明已随 factory 迁入 provider/proxy/basic（§15.4），
// 引用键的呈现范围由各 provider 的 Schema 是否声明决定。
