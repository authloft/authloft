// Microsoft Online 渠道适配器（docs/后端架构.md §12.2 行 1477 内置清单：
// microsoft 支持 common/tenant）：标准 authorization code 跳转流程
// （OIDC userinfo），channel=redirect。tenant 经 Ext.provider_url 配置
// （common / organizations / 租户 ID，缺省 common）；scope 可经 Ext.scopes
// 覆盖；用户字段可经 Ext.user_mapping 覆盖内置抽取。凭证装配期取自
// Provider 实例（§13.0 唯一口径），运行期不回读配置。
package microsoft

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

// Type 渠道类型（§12.2）。
const Type = "microsoft"

// 端点（Microsoft 官方固定地址，{tenant} 段按 provider_url 注入）。
const (
	authBase     = "https://login.microsoftonline.com/"
	authSuffix   = "/oauth2/v2.0/authorize"
	tokenSuffix  = "/oauth2/v2.0/token"
	userInfoURL  = "https://graph.microsoft.com/oidc/userinfo"
	defaultScope = "openid profile email"
)

// ErrNotConfigured client_id / client_secret 缺失（§13.0：视为未配置）。
var ErrNotConfigured = errors.New("microsoft: provider not configured")

func init() {
	m := oauthcore.NewMeta(Type, "Microsoft", provider.ChannelRedirect)
	for i, f := range m.Fields {
		if f.Key == "provider_url" {
			m.Fields[i].Label = "admin.schemaField.microsoftTenantLabel"
			m.Fields[i].Help = "admin.schemaField.microsoftTenantHelp"
		}
	}
	provider.Register(Type, m, newAdapter)
}

// Adapter Microsoft 适配器（channel=redirect）。
type Adapter struct {
	key          string
	clientID     string
	clientSecret string
	scopes       string
	tenant       string
	authURL      string
	tokenURL     string
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
	tenant := strings.TrimSpace(p.Ext.GetProviderUrl())
	if tenant == "" {
		tenant = "common"
	}
	a := &Adapter{
		key:          p.Key,
		clientID:     p.Ext.GetClientId(),
		clientSecret: p.Ext.GetClientSecret(),
		scopes:       p.Ext.GetScopes(),
		tenant:       tenant,
		authURL:      authBase + tenant + authSuffix,
		tokenURL:     authBase + tenant + tokenSuffix,
		userMapping:  p.Ext.GetUserMapping(),
		hc:           hc,
	}
	if a.scopes == "" {
		a.scopes = defaultScope
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
	}
	return oauthcore.ExtractIdentity(a.key, Type, spec, t, user, a.userMapping)
}
