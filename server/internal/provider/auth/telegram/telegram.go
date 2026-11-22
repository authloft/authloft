// telegram 薄封装适配器（docs/后端架构.md §15.5 薄封装总则、§12.2 内置清单）：
// 复用 auth/oidc 基座构造器与 discovery 机制，构造期固化 discovery 基址，
// Schema 只声明管理员填写项；channel=redirect。旧 hash Login Widget 已归档，
// 不支持（§12.2）。用户 id 为大整数，按字符串处理，禁转数值；不返回邮箱，
// 手机号仅在管理员追加 phone scope 且用户授权后返回。
package telegram

import (
	"authloft/internal/provider"
	"authloft/internal/provider/auth/oauthcore"
	"authloft/internal/provider/auth/oidc"
)

// Type 渠道类型（§12.2 内置清单：telegram）。
const Type = "telegram"

// ProviderURL discovery 基址，构造期注入 oidc 基座（§15.5：固化参数不进
// Schema、不在表单透出）。
const ProviderURL = "https://oauth.telegram.org"

// 预设值随 Schema 字段 default 下发（§15.5：管理员可改写，适配器照常消费）。
// scope 预设 profile 取公开资料；OIDC scope 命名以 discovery 实际声明为准，
// 管理员可按需追加。user_mapping 预设映射 photo_url 与 phone_number——后者
// 未授权时求值为空、保留渠道抽取值（oauthcore 空值跳过语义），无害。
const (
	defaultScopes      = "profile"
	defaultUserMapping = `{"open_id":"$.sub","username":"$.username","nickname":"$.first_name","avatar_url":"$.photo_url","phone":"$.phone_number"}`
)

func init() {
	m := oauthcore.NewMeta(Type, "Telegram", provider.ChannelRedirect)
	// 预设值就地写进字段 Default 再经 KeepFields 收窄（改写与 Schema 闭包
	// 共享底层数组，天然同步）；keep 集不含 provider_url——固化端点不透出，
	// keep 外键（cert / custom_* / metadata 等）对纯 OIDC 渠道是死字段。
	for i := range m.Fields {
		switch m.Fields[i].Key {
		case "scopes":
			m.Fields[i].Default = defaultScopes
		case "user_mapping":
			m.Fields[i].Default = defaultUserMapping
		}
	}
	provider.Register(Type, oauthcore.KeepFields(m, oauthcore.StdKeepFields...), newAdapter)
}

// newAdapter 注册表工厂：provider_url 构造期固化，其余取值口径同 oidc 基座。
func newAdapter(p *provider.Provider) (provider.AuthAdapter, error) {
	return oidc.New(p, ProviderURL)
}
