// 飞书渠道适配器（docs/后端架构.md §12.2 行 1473 内置清单；飞书
// app_ticket 存 metadata——app_ticket 属 tenant_access_token 链路，用户
// 授权码流程不消费，暂不读取）：标准 authorization code 跳转流程，
// channel=redirect。端点为飞书官方固定地址；scope 可经 Ext.scopes 覆盖
// （用户信息需在飞书开放平台为应用申请对应权限，缺省不携带）；用户字段
// 可经 Ext.user_mapping 覆盖内置抽取。凭证装配期取自 Provider 实例
// （§13.0 唯一口径），运行期不回读配置。真机联调未覆盖（无飞书应用凭据）。
package feishu

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

// Type 渠道类型（§12.2）。
const Type = "feishu"

// 端点（飞书官方固定地址）。
const (
	authURL     = "https://passport.feishu.cn/suite/passport/oauth2/authorize"
	tokenURL    = "https://passport.feishu.cn/suite/passport/oauth2/token"
	userInfoURL = "https://passport.feishu.cn/suite/passport/oauth2/userinfo"
)

// ErrNotConfigured client_id / client_secret 缺失（§13.0：视为未配置）。
var ErrNotConfigured = errors.New("feishu: provider not configured")

func init() {
	provider.Register(Type, oauthcore.NewMeta(Type, "飞书", provider.ChannelRedirect), newAdapter)
}

// Adapter 飞书适配器（channel=redirect）。
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
		scopes:       p.Ext.GetScopes(), // 无渠道缺省：用户信息 scope 按飞书应用申请情况填
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

// Exchange 授权码换令牌（POST form，JSON 响应）。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	return oauthcore.ExchangePostForm(ctx, a.hc, tokenURL, a.clientID, a.clientSecret, in, nil, nil)
}

// FetchUser 拉取用户信息并抽取统一身份（open_id 优先，sub 兜底——
// 飞书 v2 userinfo 两键均可能出现）。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	user, err := oauthcore.GetUserInfo(ctx, a.hc, userInfoURL, t.AccessToken, true, nil, nil)
	if err != nil {
		return nil, err
	}
	spec := oauthcore.IdentitySpec{
		OpenID:   []string{"open_id", "sub"},
		UnionID:  []string{"union_id"},
		Username: []string{"name"},
		Nickname: []string{"name"},
		Email:    []string{"email"},
		Avatar:   []string{"avatar_url", "picture_url"},
	}
	return oauthcore.ExtractIdentity(a.key, Type, spec, t, user, a.userMapping)
}
