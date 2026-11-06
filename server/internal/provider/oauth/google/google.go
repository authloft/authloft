// Google 渠道适配器（docs/后端架构.md §12.2 行 1477 内置清单）：标准
// authorization code 跳转流程（OIDC userinfo），channel=redirect。端点为
// Google 官方固定地址；scope 可经 Ext.scopes 覆盖（缺省 openid profile
// email）；用户字段可经 Ext.user_mapping 覆盖内置抽取。凭证装配期取自
// Provider 实例（§13.0 唯一口径），运行期不回读配置。
package google

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

// Type 渠道类型（§12.2）。
const Type = "google"

// 端点（Google 官方固定地址）。
const (
	authURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	tokenURL    = "https://oauth2.googleapis.com/token"
	userInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
)

// defaultScopes 缺省授权范围（OIDC 基础档 + 邮箱）。
const defaultScopes = "openid profile email"

// ErrNotConfigured client_id / client_secret 缺失（§13.0：视为未配置）。
var ErrNotConfigured = errors.New("google: provider not configured")

func init() {
	provider.Register(Type, oauthcore.NewMeta(Type, "Google", provider.ChannelRedirect), newAdapter)
}

// Adapter Google 适配器（channel=redirect）。
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

// Exchange 授权码换令牌（POST form，JSON 响应；redirect_uri 在授权请求
// 出现过时 token 交换必须原样携带，授权请求未带则不带——由
// ExchangeInput.RedirectURI 透传决定，adapter 不自行伪造）。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	return oauthcore.ExchangePostForm(ctx, a.hc, tokenURL, a.clientID, a.clientSecret, in, nil, nil)
}

// FetchUser 拉取 OIDC userinfo 并抽取统一身份（sub 为 openid）。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	user, err := oauthcore.GetUserInfo(ctx, a.hc, userInfoURL, t.AccessToken, true, nil, nil)
	if err != nil {
		return nil, err
	}
	spec := oauthcore.IdentitySpec{
		OpenID:   []string{"sub"},
		Username: []string{"name"},
		Nickname: []string{"name"},
		Email:    []string{"email"},
		Avatar:   []string{"picture"},
	}
	return oauthcore.ExtractIdentity(a.key, Type, spec, t, user, a.userMapping)
}
