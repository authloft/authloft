// GitHub 渠道适配器（docs/后端架构.md §12.2 行 1477 内置清单）：标准
// authorization code 跳转流程，channel=redirect。端点为 GitHub 官方固定
// 地址；scope 可经 Ext.scopes 覆盖（缺省 read:user user:email）；用户字段
// 可经 Ext.user_mapping（JSONata 表达式）覆盖内置抽取。凭证装配期取自
// Provider 实例（§13.0 唯一口径），运行期不回读配置。
package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

// Type 渠道类型（§12.2）。
const Type = "github"

// 端点（GitHub 官方固定地址）。
const (
	authURL     = "https://github.com/login/oauth/authorize"
	tokenURL    = "https://github.com/login/oauth/access_token"
	userInfoURL = "https://api.github.com/user"
)

// defaultScopes 缺省授权范围（读取用户资料与邮箱）。
const defaultScopes = "read:user user:email"

// ErrNotConfigured client_id / client_secret 缺失（§13.0：视为未配置）。
var ErrNotConfigured = errors.New("github: provider not configured")

func init() {
	provider.Register(Type, oauthcore.NewMeta(Type, "GitHub", provider.ChannelRedirect), newAdapter)
}

// Adapter GitHub 适配器（channel=redirect）。
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

// Exchange 授权码换令牌。GitHub 令牌端点默认回 form 编码，须带
// Accept: application/json 才返回 JSON。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	return oauthcore.ExchangePostForm(ctx, a.hc, tokenURL, a.clientID, a.clientSecret, in, nil,
		map[string]string{"Accept": "application/json"})
}

// FetchUser 拉取用户信息并抽取统一身份（id 数字键整数化）。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	user, err := oauthcore.GetUserInfo(ctx, a.hc, userInfoURL, t.AccessToken, true, nil, nil)
	if err != nil {
		return nil, err
	}
	spec := oauthcore.IdentitySpec{
		OpenID:   []string{"id"},
		Username: []string{"login"},
		Nickname: []string{"name", "login"},
		Email:    []string{"email"},
		Avatar:   []string{"avatar_url"},
	}
	return oauthcore.ExtractIdentity(a.key, Type, spec, t, user, a.userMapping)
}
