// Package schemafield 提供可复用的 provider.FieldMeta 构造器。
//
// 每个构造器只描述「怎么展示、落到哪」，不决定「谁该拥有」——由各 provider 的
// Schema() 自行挑选与就地改写。所有构造器返回独立切片/值，调用方改动不会污染
// 其他 provider；不含任何 category 参数。
//
// 字段口径（Label / Help 为 admin.schemaField.* i18n 键、Key/Type/Section/
// Required/Default/Advanced/Pattern/Options、Storage、Kind）逐项对齐现有 dto
// 基线、oauthcore.NewMeta 与各静态表，不新增、不裁剪、不改 wire。
package schemafield

import "authloft/internal/provider"

// ProviderKey 表列 provider_key（basic/text/required），含格式正则。
func ProviderKey() provider.FieldMeta {
	return provider.FieldMeta{
		Key: "provider_key", Label: "admin.schemaField.providerKeyLabel",
		Type: "text", Section: "basic", Required: true,
		Pattern: "^[a-z0-9_]+$", Help: "admin.schemaField.providerKeyHelp",
		Storage: provider.StorageColumn,
	}
}

// DisplayName 表列 display_name（basic/text/required）。
func DisplayName() provider.FieldMeta {
	return provider.FieldMeta{
		Key: "display_name", Label: "admin.schemaField.displayNameLabel",
		Type: "text", Section: "basic", Required: true,
		Storage: provider.StorageColumn,
	}
}

// UnionProvider 表列 union_provider（basic/select）。options 运行时按
// DynamicKey 注入，构造器本身不下发候选值。
func UnionProvider() provider.FieldMeta {
	return provider.FieldMeta{
		Key: "union_provider", Label: "admin.schemaField.unionProviderLabel",
		Type: "select", Section: "basic",
		Help:    "admin.schemaField.unionProviderHelp",
		Storage: provider.StorageColumn,
		Kind:    provider.FieldDynamicOptions, DynamicKey: "union_provider_keys",
	}
}

// IconURL 表列 icon_url（display/text），含 URL 前缀正则。
func IconURL() provider.FieldMeta {
	return provider.FieldMeta{
		Key: "icon_url", Label: "admin.schemaField.iconUrlLabel",
		Type: "text", Section: "display",
		Pattern: "^https?://", Help: "admin.schemaField.iconUrlHelp",
		Storage: provider.StorageColumn,
	}
}

// UiGroup 表列 ui_group（display/select）；Options 是写库取值，非 i18n 键。
func UiGroup() provider.FieldMeta {
	return provider.FieldMeta{
		Key: "ui_group", Label: "admin.schemaField.uiGroupLabel",
		Type: "select", Section: "display",
		Options: []string{"social", "enterprise", "dev", "other"},
		Default: "social",
		Storage: provider.StorageColumn,
	}
}

// SortOrder 表列 sort_order（display/number），默认 0。
func SortOrder() provider.FieldMeta {
	return provider.FieldMeta{
		Key: "sort_order", Label: "admin.schemaField.sortOrderLabel",
		Type: "number", Section: "display", Default: "0",
		Storage: provider.StorageColumn,
	}
}

// Remark 表列 remark（display/text/advanced）。
func Remark() provider.FieldMeta {
	return provider.FieldMeta{
		Key: "remark", Label: "admin.schemaField.remarkLabel",
		Type: "text", Section: "display", Advanced: true,
		Storage: provider.StorageColumn,
	}
}

// EnableFlags 策略区块五个表列开关；provider 可按类别只挑子集。
func EnableFlags() []provider.FieldMeta {
	return []provider.FieldMeta{
		{Key: "is_enabled", Label: "admin.schemaField.isEnabledLabel", Type: "checkbox", Section: "policy", Default: "true", Storage: provider.StorageColumn},
		{Key: "enable_signin", Label: "admin.schemaField.enableSigninLabel", Type: "checkbox", Section: "policy", Default: "true", Storage: provider.StorageColumn},
		{Key: "enable_signup", Label: "admin.schemaField.enableSignupLabel", Type: "checkbox", Section: "policy", Default: "true", Help: "admin.schemaField.enableSignupHelp", Storage: provider.StorageColumn},
		{Key: "auto_bind", Label: "admin.schemaField.autoBindLabel", Type: "checkbox", Section: "policy", Default: "false", Storage: provider.StorageColumn},
		{Key: "auto_bind_fields", Label: "admin.schemaField.autoBindFieldsLabel", Type: "text", Section: "policy", Default: "email,phone", Help: "admin.schemaField.autoBindFieldsHelp", Storage: provider.StorageColumn},
	}
}

// ProxyURL 通用 Ext 基线字段 proxy_url（endpoint/advanced/text）。
func ProxyURL() provider.FieldMeta {
	return provider.FieldMeta{
		Key: "proxy_url", Label: "admin.schemaField.proxyUrlLabel",
		Type: "text", Section: "endpoint", Advanced: true,
		Help:    "admin.schemaField.proxyUrlHelp",
		Storage: provider.StorageExt,
	}
}

// Metadata 各 Ext 通用尾字段 metadata（json/advanced）；section 为空按 basic。
// 各域 section 不同（oauth=basic、smtp/短信=credential），由调用方传参或就地改写。
func Metadata(section string) provider.FieldMeta {
	if section == "" {
		section = "basic"
	}
	return provider.FieldMeta{
		Key: "metadata", Label: "admin.schemaField.metadataLabel",
		Type: "json", Section: section, Advanced: true,
		Storage: provider.StorageExt,
	}
}

// OAuthCredentials oauth 通用 Ext 字段集（11 项，末项为 metadata），逐字段
// 对齐 oauthcore.NewMeta 基线。
func OAuthCredentials() []provider.FieldMeta {
	return []provider.FieldMeta{
		{Key: "client_id", Label: "admin.schemaField.clientIdLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		{Key: "client_secret", Label: "admin.schemaField.clientSecretLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		{Key: "app_id", Label: "admin.schemaField.appIdLabel", Type: "text", Section: "credential", Advanced: true, Storage: provider.StorageExt},
		{Key: "cert", Label: "admin.schemaField.certLabel", Type: "secret", Section: "credential", Advanced: true, Storage: provider.StorageExt},
		{Key: "scopes", Label: "admin.schemaField.scopesLabel", Type: "text", Section: "credential", Advanced: true, Storage: provider.StorageExt},
		{Key: "provider_url", Label: "admin.schemaField.providerUrlLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		{Key: "custom_auth_url", Label: "admin.schemaField.customAuthUrlLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		{Key: "custom_token_url", Label: "admin.schemaField.customTokenUrlLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		{Key: "custom_user_info_url", Label: "admin.schemaField.customUserInfoUrlLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		{Key: "user_mapping", Label: "admin.schemaField.userMappingLabel", Type: "json", Section: "endpoint", Advanced: true, Help: "admin.schemaField.userMappingHelp", Storage: provider.StorageExt},
		{Key: "metadata", Label: "admin.schemaField.metadataLabel", Type: "json", Section: "basic", Advanced: true, Storage: provider.StorageExt},
	}
}

// SMSFields 短信域 Ext 字段基线，对齐现有阿里云短信注册口径；各厂商可在
// 返回值上就地改写 Label / Required。
func SMSFields() []provider.FieldMeta {
	return []provider.FieldMeta{
		{Key: "client_id", Label: "admin.schemaField.aliyunAccessKeyIdLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		{Key: "client_secret", Label: "admin.schemaField.aliyunAccessKeySecretLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		{Key: "sign_name", Label: "admin.schemaField.aliyunSignNameLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		{Key: "template_code", Label: "admin.schemaField.aliyunTemplateCodeLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		{Key: "intranet_endpoint", Label: "admin.schemaField.aliyunIntranetEndpointLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		{Key: "metadata", Label: "admin.schemaField.metadataLabel", Type: "json", Section: "credential", Advanced: true, Help: "admin.schemaField.aliyunMetadataHelp", Storage: provider.StorageExt},
	}
}

// CaptchaFields 三家 captcha 共用的 Ext 字段（site_key / secret / 自定义校验地址）。
func CaptchaFields() []provider.FieldMeta {
	return []provider.FieldMeta{
		{Key: "client_id", Label: "admin.schemaField.captchaSiteKeyLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		{Key: "client_secret", Label: "admin.schemaField.captchaSecretLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		{Key: "endpoint", Label: "admin.schemaField.captchaEndpointLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
	}
}

// StorageLocalFields 本地存储 local 的 Ext 字段（bucket / domain / path_prefix）。
func StorageLocalFields() []provider.FieldMeta {
	return []provider.FieldMeta{
		{Key: "bucket", Label: "admin.schemaField.storageBucketLabel", Type: "text", Section: "endpoint", Required: true, Storage: provider.StorageExt},
		{Key: "domain", Label: "admin.schemaField.storageDomainLabel", Type: "text", Section: "endpoint", Required: true, Storage: provider.StorageExt},
		{Key: "path_prefix", Label: "admin.schemaField.storagePathPrefixLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
	}
}
