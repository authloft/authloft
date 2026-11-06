// oauth2 通用 OAuth2 兜底适配器（docs/后端架构.md §12.2 行 1479：手工填
// 三个 URL + user_mapping，任何未在清单里的标准协议渠道零开发接入）：
// channel=redirect。授权 / 令牌 / 用户信息端点分别取 Ext.custom_auth_url /
// custom_token_url / custom_user_info_url（三端点必填）；scope 取 Ext.scopes
// （无缺省，由管理员按目标渠道填写）；openid 无渠道默认知识——user_mapping
// 必须含 open_id 表达式（§12.2 行 1479 口径），其余 Authloft 字段
// （union_id / username / nickname / email / phone / avatar_url）可选映射。
// 凭证装配期取自 Provider 实例（§13.0 唯一口径），运行期不回读配置。
package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

// Type 渠道类型（§12.2：oauth2）。
const Type = "oauth2"

// 可判别错误。
var (
	// ErrNotConfigured client_id / client_secret / 三端点 / user_mapping.open_id
	// 任一缺失（§13.0：视为未配置）。
	ErrNotConfigured = errors.New("oauth2: provider not configured")
)

func init() {
	m := oauthcore.NewMeta(Type, "OAuth2（标准协议）", provider.ChannelRedirect)
	fields := make([]provider.FieldMeta, 0, len(m.Fields))
	for _, f := range m.Fields {
		switch f.Key {
		case "provider_url":
			continue // oauth2 不做 discovery，服务地址不消费
		case "custom_auth_url", "custom_token_url", "custom_user_info_url":
			f.Required = true
		case "user_mapping":
			f.Required = true
			f.Help = "必填 open_id：三方字段 → Authloft 字段，值为 JSONata 表达式（如 {\"open_id\": \"$.id\"}）"
		}
		fields = append(fields, f)
	}
	m.Fields = fields
	provider.Register(Type, m, newAdapter)
}

// Adapter 通用 OAuth2 适配器（channel=redirect）。
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
	ext := p.Ext
	switch {
	case ext.GetClientId() == "" || ext.GetClientSecret() == "",
		ext.GetCustomAuthUrl() == "" || ext.GetCustomTokenUrl() == "" || ext.GetCustomUserInfoUrl() == "",
		ext.GetUserMapping()["open_id"] == "":
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	return &Adapter{
		key:          p.Key,
		clientID:     ext.GetClientId(),
		clientSecret: ext.GetClientSecret(),
		scopes:       ext.GetScopes(),
		authURL:      ext.GetCustomAuthUrl(),
		tokenURL:     ext.GetCustomTokenUrl(),
		userInfoURL:  ext.GetCustomUserInfoUrl(),
		userMapping:  ext.GetUserMapping(),
		hc:           hc,
	}, nil
}

// Channel 固定为 redirect。
func (a *Adapter) Channel() provider.ThirdPartyChannel { return provider.ChannelRedirect }

// BuildAuthURL 组装跳转授权 URL（state 由 service 层生成后透传，§12.4；
// scope 无渠道默认，Ext.scopes 与 AuthContext.Scope 均空时不携带）。
func (a *Adapter) BuildAuthURL(ctx *provider.AuthContext) (string, error) {
	return oauthcore.BuildAuthURL(a.authURL, a.clientID, ctx, a.scopes, nil)
}

// Exchange 授权码换令牌（POST form；响应按 JSON / form 编码自适应解析）。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	return oauthcore.ExchangePostForm(ctx, a.hc, a.tokenURL, a.clientID, a.clientSecret, in, nil, nil)
}

// FetchUser 拉取用户信息并按 user_mapping 抽取统一身份（无内置路径，
// 全部字段由映射表达式决定；open_id 缺失 → ErrEmptyOpenID）。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	user, err := oauthcore.GetUserInfo(ctx, a.hc, a.userInfoURL, t.AccessToken, true, nil, nil)
	if err != nil {
		return nil, err
	}
	return oauthcore.ExtractIdentity(a.key, Type, oauthcore.IdentitySpec{}, t, user, a.userMapping)
}
