// 百度渠道适配器（docs/需求.md §4.3.1 行 160 渠道清单「百度」、
// docs/后端架构.md §12.2 行 1473 内置清单 `baidu`；此处补齐）：
// 标准 authorization code 跳转流程，channel=redirect。端点为百度开放
// 平台官方固定地址；scope 可经 Ext.scopes 覆盖（缺省 basic）；用户字段
// 可经 Ext.user_mapping 覆盖内置抽取（openid 为百度用户唯一标识，
// portrait 为头像路径键，拼接 himg.bdimg.com 完整 URL）。凭证装配期
// 取自 Provider 实例（§13.0 唯一口径），运行期不回读配置。
// 真机联调未覆盖（无百度开放平台应用凭据）。
package baidu

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

// Type 渠道类型（§12.2 行 1473）。
const Type = "baidu"

// 端点（百度开放平台官方固定地址；授权与令牌路径均为 oauth/2.0；
// 授权端点笔误已修正——原 oauth2.0/authorize 实测 404；端点正确性由
// baidu_test.go 的独立字面量断言守护，真机联调未覆盖）。
const (
	authURL     = "https://openapi.baidu.com/oauth/2.0/authorize"
	tokenURL    = "https://openapi.baidu.com/oauth/2.0/token"
	userInfoURL = "https://openapi.baidu.com/rest/2.0/passport/users/getInfo"
)

// defaultScopes 缺省授权范围（basic：读取用户基本资料）。
const defaultScopes = "basic"

// avatarPrefix 百度 portrait 头像路径键的拼接前缀（百度公开协议口径：
// portrait 值非完整 URL，完整地址 = 前缀 + portrait）。
const avatarPrefix = "https://himg.bdimg.com/sys/portrait/item/"

// ErrNotConfigured client_id / client_secret 缺失（§13.0：视为未配置）。
var ErrNotConfigured = errors.New("baidu: provider not configured")

func init() {
	provider.Register(Type, oauthcore.NewMeta(Type, "百度", provider.ChannelRedirect), newAdapter)
}

// Adapter 百度适配器（channel=redirect）。
type Adapter struct {
	key          string
	clientID     string
	clientSecret string
	scopes       string
	userMapping  map[string]string
	hc           *http.Client // nil → oauthcore 默认客户端；测试注入改写客户端
}

// newAdapter 注册表工厂。build 仅供测试注入 http.Client。
func newAdapter(p *provider.Provider) (provider.AuthAdapter, error) { return build(p, nil) }

func build(p *provider.Provider, hc *http.Client) (*Adapter, error) {
	if p == nil || p.Ext == nil {
		return nil, provider.ErrNilProvider
	}
	if p.Ext.GetClientId() == "" || p.Ext.GetClientSecret() == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	a := &Adapter{
		key:          p.Key,
		clientID:     p.Ext.GetClientId(),
		clientSecret: p.Ext.GetClientSecret(),
		scopes:       p.Ext.GetScopes(),
		userMapping:  p.Ext.GetUserMapping(),
		hc:           hc,
	}
	if a.scopes == "" {
		a.scopes = defaultScopes
	}
	return a, nil
}

// Channel 固定为 redirect。
func (a *Adapter) Channel() provider.ThirdPartyChannel { return provider.ChannelRedirect }

// BuildAuthURL 组装跳转授权 URL（state 由 service 层生成后透传，§12.4）。
func (a *Adapter) BuildAuthURL(ctx *provider.AuthContext) (string, error) {
	return oauthcore.BuildAuthURL(authURL, a.clientID, ctx, a.scopes, nil)
}

// Exchange 授权码换令牌（POST form，JSON 响应）。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	return oauthcore.ExchangePostForm(ctx, a.hc, tokenURL, a.clientID, a.clientSecret, in, nil, nil)
}

// FetchUser 拉取用户信息并抽取统一身份：openid 为唯一标识；portrait 为
// 头像路径键，拼接完整 URL（user_mapping 覆盖后仍有 portrait 时保留拼接）。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	user, err := oauthcore.GetUserInfo(ctx, a.hc, userInfoURL, t.AccessToken, false, nil, nil)
	if err != nil {
		return nil, err
	}
	spec := oauthcore.IdentitySpec{
		OpenID:   []string{"openid"},
		Username: []string{"username"},
		Nickname: []string{"username"},
	}
	id, err := oauthcore.ExtractIdentity(a.key, Type, spec, t, user, a.userMapping)
	if err != nil {
		return nil, err
	}
	// 头像：portrait 拼接完整 URL；user_mapping 已覆盖 avatar_url 时以
	// 映射结果优先，仅在映射未覆盖时才用渠道内置拼接。
	if id.AvatarURL == "" {
		if portrait, ok := user["portrait"].(string); ok && portrait != "" {
			id.AvatarURL = avatarPrefix + portrait
		}
	}
	return id, nil
}
