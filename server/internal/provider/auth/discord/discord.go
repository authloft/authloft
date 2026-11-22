// discord 薄封装适配器（docs/后端架构.md §15.5 薄封装总则、§12.2 内置清单）：
// 复用 auth/oidc 基座构造器与 discovery 机制，构造期固化 discovery 基址，
// Schema 只声明管理员填写项；channel=redirect。用户 id 为雪花数，按字符串
// 处理，禁转数值。
package discord

import (
	"authloft/internal/provider"
	"authloft/internal/provider/auth/oauthcore"
	"authloft/internal/provider/auth/oidc"
)

// Type 渠道类型（§12.2 内置清单：discord）。
const Type = "discord"

// ProviderURL discovery 基址，构造期注入 oidc 基座（§15.5：固化参数不进
// Schema、不在表单透出）。
const ProviderURL = "https://discord.com"

// 预设值随 Schema 字段 default 下发（§15.5：管理员可改写，适配器照常消费）。
// scope 含 openid 走 OIDC id_token；email 需用户邮箱已验证；identify 为基础
// 资料。头像 avatar 是 hash 而非 URL，user_mapping 预设拼接 CDN URL。
const (
	defaultScopes      = "identify email openid"
	defaultUserMapping = `{"open_id":"$.id","username":"$.username","nickname":"$.global_name","email":"$.email","avatar_url":"'https://cdn.discordapp.com/avatars/' & $.id & '/' & $.avatar & '.png'"}`
)

func init() {
	m := oauthcore.NewMeta(Type, "Discord", provider.ChannelRedirect)
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
