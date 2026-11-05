// Package provider 是第三方登录 / 外部服务 Provider 的基础设施
// （docs/后端架构.md §3.9 行 399-410、§12.1 行 1391-1434、§15.3 行 1712-1718）：
// 注册表（registry.go）、Provider 加载与缓存（provider.go）、Referer 白名单
// 来源（whitelist.go）以及适配器公共类型（本文件）。各渠道实现按
// internal/provider/oauth/<type>/ 分层，init() 自注册。
package provider

import "context"

// ThirdPartyChannel 第三方因子的通道形态（§12.1 行 1411-1417）。
type ThirdPartyChannel string

const (
	// ChannelRedirect 跳转授权码流程。
	ChannelRedirect ThirdPartyChannel = "redirect"
	// ChannelAPI 前端拿 code 直接提交（如微信小程序）。
	ChannelAPI ThirdPartyChannel = "api"
	// ChannelQRCode 扫码流程。
	ChannelQRCode ThirdPartyChannel = "qrcode"
)

// ExternalIdentity 第三方返回的统一身份（§12.1 行 1394-1402）。
// Raw 落 user_thirdparty_bind.extra（msgpack 序列化），不得携带任何厂商
// 会话密钥 / 凭证类字段。
type ExternalIdentity struct {
	ProviderKey   string // 引用 provider_key
	ProviderType  string
	OpenID        string
	UnionID       string
	Username      string
	Nickname      string
	Email         string
	Phone         string
	AvatarURL     string
	EmailVerified bool
	PhoneVerified bool
	Raw           map[string]any
}

// Token 第三方令牌（§12.1 行 1404-1409）。
type Token struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	IDToken      string
	Raw          map[string]any
}

// AuthContext 跳转授权上下文（§12.4 行 1476-1478）。本实现补齐 redirect
// 渠道组装授权 URL 所需字段：state 由 service 层生成（带 l/b 前缀，行
// 1477）后传入，adapter 只透传不生成；scope 缺省时渠道按自身默认拼装。
// PKCESupporter / CSPSupporter 等可选接口仍按 §12.1 行 1429-1434 随对应
// 渠道按需补齐，不提前实现。
type AuthContext struct {
	ProviderKey string
	RedirectURI string
	State       string
	Scope       string
}

// ExchangeInput 用授权码换取令牌的入参（channel=api 时即为前端提交的 code）。
type ExchangeInput struct {
	Code        string
	RedirectURI string
}

// AuthAdapter 渠道适配器（§12.1 行 1429-1434）。本次落最小必需集合
// Channel / BuildAuthURL / Exchange / FetchUser；可选接口
// （CSPSupporter / TokenRefresher / PKCESupporter / QRCodeSupporter）
// 随对应渠道卡按需补齐，不提前实现。
type AuthAdapter interface {
	Channel() ThirdPartyChannel
	BuildAuthURL(ctx *AuthContext) (string, error)
	Exchange(ctx context.Context, in ExchangeInput) (*Token, error)
	FetchUser(ctx context.Context, t *Token) (*ExternalIdentity, error)
}
