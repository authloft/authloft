// oidc 通用 OIDC 兜底适配器（docs/后端架构.md §12.2 行 1478：填
// provider_url 自动 discovery，任何未在清单里的标准协议渠道零开发接入）：
// channel=redirect。构造期按 {provider_url}/.well-known/openid-configuration
// 拉取授权 / 令牌 / 用户信息三端点（§13.0 装配期取配置口径）；scope 可经
// Ext.scopes 覆盖（缺省 openid profile email）；用户字段可经 Ext.user_mapping
// 覆盖内置抽取。凭证装配期取自 Provider 实例，运行期不回读配置。
//
// discovery 不做进程内缓存：NewAdapter 按请求构造，真源 URL 不变时各次
// discovery 幂等；登录 QPS 下一次额外 GET 的开销可接受，避免提前设计缓存。
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

// Type 渠道类型（§12.2：oidc）。
const Type = "oidc"

// defaultScopes 缺省授权范围（OIDC 基础档 + 邮箱）。
const defaultScopes = "openid profile email"

// ErrNotConfigured client_id / client_secret / provider_url 缺失（§13.0：
// 视为未配置；provider_url 是 discovery 唯一入口，必填）。
var ErrNotConfigured = errors.New("oidc: provider not configured")

func init() {
	m := oauthcore.NewMeta(Type, "OIDC（标准协议）", provider.ChannelRedirect)
	// oidc 走 discovery，custom_* 手工端点不消费——从 schema 移除防误导。
	fields := make([]provider.FieldMeta, 0, len(m.Fields))
	for _, f := range m.Fields {
		switch f.Key {
		case "custom_auth_url", "custom_token_url", "custom_user_info_url":
			continue
		case "provider_url":
			f.Required = true
			f.Help = "admin.schemaField.oidcProviderUrlHelp"
		}
		fields = append(fields, f)
	}
	m.Fields = fields
	provider.Register(Type, m, newAdapter)
}

// Adapter 通用 OIDC 适配器（channel=redirect）。
type Adapter struct {
	key          string
	clientID     string
	clientSecret string
	scopes       string
	authURL      string
	tokenURL     string
	userInfoURL  string
	userMapping  map[string]string
	hc           *http.Client // nil → oauthcore 默认客户端；测试注入改写客户端
}

// newAdapter 注册表工厂。build 仅供测试注入 http.Client。
func newAdapter(p *provider.Provider) (provider.AuthAdapter, error) { return build(p, nil) }

func build(p *provider.Provider, hc *http.Client) (*Adapter, error) {
	if p == nil || p.Ext == nil {
		return nil, provider.ErrNilProvider
	}
	if p.Ext.GetClientId() == "" || p.Ext.GetClientSecret() == "" || p.Ext.GetProviderUrl() == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	auth, token, userInfo, err := oauthcore.DiscoverOIDC(context.Background(), hc, p.Ext.GetProviderUrl())
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery %q: %w", p.Ext.GetProviderUrl(), err)
	}
	a := &Adapter{
		key:          p.Key,
		clientID:     p.Ext.GetClientId(),
		clientSecret: p.Ext.GetClientSecret(),
		scopes:       p.Ext.GetScopes(),
		authURL:      auth,
		tokenURL:     token,
		userInfoURL:  userInfo,
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
	return oauthcore.BuildAuthURL(a.authURL, a.clientID, ctx, a.scopes, nil)
}

// Exchange 授权码换令牌（POST form，JSON 响应）。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	return oauthcore.ExchangePostForm(ctx, a.hc, a.tokenURL, a.clientID, a.clientSecret, in, nil, nil)
}

// FetchUser 拉取 OIDC userinfo 并抽取统一身份（sub 为 openid；union_id
// 键供厂商响应携带，无则空）。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	user, err := oauthcore.GetUserInfo(ctx, a.hc, a.userInfoURL, t.AccessToken, true, nil, nil)
	if err != nil {
		return nil, err
	}
	spec := oauthcore.IdentitySpec{
		OpenID:   []string{"sub"},
		UnionID:  []string{"union_id", "unionid"},
		Username: []string{"name"},
		Nickname: []string{"name"},
		Email:    []string{"email"},
		Avatar:   []string{"picture"},
	}
	return oauthcore.ExtractIdentity(a.key, Type, spec, t, user, a.userMapping)
}
