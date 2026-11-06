// wechat 微信开放平台（网站应用扫码登录）渠道适配器（docs/需求.md §4.3.1
// 渠道清单「微信开放平台」、docs/后端架构.md §12.2 行 1475「wechat 微信
// 网页」）：channel=redirect。与标准 OAuth2 的差异：授权端点为 qrconnect
// （参数名 appid、须带 #wechat_redirect 尾锚）；令牌走 GET 查询串且响应
// 自带 openid / unionid；用户信息须带 openid 查询参数再次拉取。端点为微信
// 开放平台官方固定地址；scope 可经 Ext.scopes 覆盖（缺省 snsapi_login）；
// 用户字段可经 Ext.user_mapping 覆盖内置抽取。凭证装配期取自 Provider
// 实例（§13.0 唯一口径），运行期不回读配置。
// 真机联调未覆盖（无微信开放平台应用凭据）。
package wechat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

// Type 渠道类型（§12.2：wechat）。
const Type = "wechat"

// 端点（微信开放平台官方固定地址）。
const (
	authURLBase  = "https://open.weixin.qq.com/connect/qrconnect"
	tokenURL     = "https://api.weixin.qq.com/sns/oauth2/access_token"
	userInfoURL  = "https://api.weixin.qq.com/sns/userinfo"
	wechatSuffix = "#wechat_redirect"
)

// defaultScopes 缺省授权范围（网站应用扫码登录）。
const defaultScopes = "snsapi_login"

// ErrNotConfigured client_id / client_secret（= AppID / AppSecret）缺失
// （§13.0：视为未配置）。
var ErrNotConfigured = errors.New("wechat: provider not configured")

func init() {
	provider.Register(Type, oauthcore.NewMeta(Type, "微信开放平台", provider.ChannelRedirect), newAdapter)
}

// Adapter 微信开放平台适配器（channel=redirect）。
type Adapter struct {
	key          string
	clientID     string // AppID
	clientSecret string // AppSecret
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

// BuildAuthURL 组装跳转授权 URL：微信参数名为 appid、须带 #wechat_redirect
// 尾锚（state 由 service 层生成后透传，§12.4；scope ctx 优先、渠道缺省
// snsapi_login）。
func (a *Adapter) BuildAuthURL(ctx *provider.AuthContext) (string, error) {
	if ctx == nil || ctx.State == "" {
		return "", oauthcore.ErrEmptyState
	}
	scope := ctx.Scope
	if scope == "" {
		scope = a.scopes
	}
	q := url.Values{}
	q.Set("appid", a.clientID)
	q.Set("redirect_uri", ctx.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("state", ctx.State)
	return authURLBase + "?" + q.Encode() + wechatSuffix, nil
}

// Exchange 授权码换令牌（GET 查询串，JSON 响应自带 openid / unionid）。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	params := url.Values{
		"appid":      {a.clientID},
		"secret":     {a.clientSecret},
		"code":       {in.Code},
		"grant_type": {"authorization_code"},
	}
	return oauthcore.ExchangeGetQuery(ctx, a.hc, tokenURL, params)
}

// FetchUser 按令牌响应的 openid 拉取用户信息（查询串鉴权），抽取统一身份。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	openid, _ := t.Raw["openid"].(string)
	user, err := oauthcore.GetUserInfo(ctx, a.hc, userInfoURL, t.AccessToken, false,
		url.Values{"openid": {openid}}, nil)
	if err != nil {
		return nil, err
	}
	spec := oauthcore.IdentitySpec{
		OpenID:   []string{"openid"},
		UnionID:  []string{"unionid", "union_id"},
		Nickname: []string{"nickname"},
		Avatar:   []string{"headimgurl"},
	}
	return oauthcore.ExtractIdentity(a.key, Type, spec, t, user, a.userMapping)
}
