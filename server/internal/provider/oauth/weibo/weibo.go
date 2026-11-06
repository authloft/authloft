// 微博渠道适配器（docs/后端架构.md §12.2 行 1473 内置清单）：标准
// authorization code 跳转流程，channel=redirect。端点为微博官方固定
// 地址；令牌响应自带 uid（openid 来源）；用户信息须带 uid 查询参数再次
// 拉取。用户字段可经 Ext.user_mapping 覆盖内置抽取。凭证装配期取自
// Provider 实例（§13.0 唯一口径），运行期不回读配置。
// 真机联调未覆盖（无微博应用凭据）。
package weibo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

// Type 渠道类型（§12.2）。
const Type = "weibo"

// 端点（微博官方固定地址）。
const (
	authURL     = "https://api.weibo.com/oauth2/authorize"
	tokenURL    = "https://api.weibo.com/oauth2/access_token"
	userInfoURL = "https://api.weibo.com/2/users/show.json"
)

// ErrNotConfigured client_id / client_secret 缺失（§13.0：视为未配置）。
var ErrNotConfigured = errors.New("weibo: provider not configured")

func init() {
	provider.Register(Type, oauthcore.NewMeta(Type, "微博", provider.ChannelRedirect), newAdapter)
}

// Adapter 微博适配器（channel=redirect）。
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
	return &Adapter{
		key:          p.Key,
		clientID:     p.Ext.GetClientId(),
		clientSecret: p.Ext.GetClientSecret(),
		scopes:       p.Ext.GetScopes(), // 微博基础授权无 scope 参数，Ext 配置时才携带
		userMapping:  p.Ext.GetUserMapping(),
		hc:           hc,
	}, nil
}

// Channel 固定为 redirect。
func (a *Adapter) Channel() provider.ThirdPartyChannel { return provider.ChannelRedirect }

// BuildAuthURL 组装跳转授权 URL（state 由 service 层生成后透传，§12.4）。
func (a *Adapter) BuildAuthURL(ctx *provider.AuthContext) (string, error) {
	return oauthcore.BuildAuthURL(authURL, a.clientID, ctx, a.scopes, nil)
}

// Exchange 授权码换令牌（POST form，JSON 响应自带 uid = openid）。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	return oauthcore.ExchangePostForm(ctx, a.hc, tokenURL, a.clientID, a.clientSecret, in, nil, nil)
}

// FetchUser 按令牌响应的 uid 拉取用户信息（查询串鉴权），抽取统一身份
// （openid 优先用户信息 idstr，令牌 uid 兜底）。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	uid, _ := t.Raw["uid"].(string)
	user, err := oauthcore.GetUserInfo(ctx, a.hc, userInfoURL, t.AccessToken, false,
		url.Values{"uid": {uid}}, nil)
	if err != nil {
		return nil, err
	}
	spec := oauthcore.IdentitySpec{
		OpenID:   []string{"idstr", "id", "uid"},
		Username: []string{"screen_name"},
		Nickname: []string{"screen_name"},
		Avatar:   []string{"avatar_hd", "profile_image_url"},
	}
	return oauthcore.ExtractIdentity(a.key, Type, spec, t, user, a.userMapping)
}
