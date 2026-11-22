// oauth2 通用 OAuth2 兜底适配器（docs/后端架构.md §12.2 行 1479：手工填
// 三个 URL + user_mapping，任何未在清单里的标准协议渠道零开发接入）：
// channel=redirect。授权 / 令牌 / 用户信息端点分别取 Ext.custom_auth_url /
// custom_token_url / custom_user_info_url（三端点必填）；scope 取 Ext.scopes
// （无缺省，由管理员按目标渠道填写）；openid 无渠道默认知识——user_mapping
// 必须含 open_id 表达式（§12.2 行 1479 口径），其余 Authloft 字段
// （union_id / username / nickname / email / phone / avatar_url）可选映射。
// 凭证装配期取自 Provider 实例（§13.0 唯一口径），运行期不回读配置。
//
// 渠道差异以 Ext.metadata 可选开关键承载（不硬编码任何厂商名；缺省均为
// 标准 OAuth2 形态）：token_method=get 令牌端点走 GET query（GET 形态
// 不带 grant_type，按目标渠道文档组装）；userinfo_token_in=query 用户
// 信息 access_token 走查询串而非 Bearer 头；pkce=s256 授权带
// code_challenge（S256）、令牌带 code_verifier（派生方式见 pkce.go）。
package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"authloft/internal/provider"
	"authloft/internal/provider/auth/oauthcore"
)

// Type 渠道类型（§12.2：oauth2）。
const Type = "oauth2"

// metadata 可选开关键与取值（缺省空 = 标准 OAuth2 形态；未知取值装配期
// fail-closed，见 ErrInvalidOption）。
const (
	metaTokenMethod     = "token_method"      // get：令牌端点 GET query
	metaUserinfoTokenIn = "userinfo_token_in" // query：access_token 走查询串
	metaPKCE            = "pkce"              // s256：强制 PKCE
	valGet              = "get"
	valQuery            = "query"
	valS256             = "s256"
)

// 可判别错误。
var (
	// ErrNotConfigured client_id / client_secret / 三端点 / user_mapping.open_id
	// 任一缺失（§13.0：视为未配置）。
	ErrNotConfigured = errors.New("oauth2: provider not configured")
	// ErrInvalidOption metadata 开关键取值非法（拼错即装配期拒绝，防静默
	// 回落标准形态造成登录期难排查的失败）。
	ErrInvalidOption = errors.New("oauth2: invalid metadata option")
)

func init() {
	m := oauthcore.NewMeta(Type, "OAuth2（标准协议）", provider.ChannelRedirect)
	// 三端点与 user_mapping 无渠道缺省知识，置必填；就地改写随字段值进入
	// 裁剪结果。
	for i, f := range m.Fields {
		switch f.Key {
		case "custom_auth_url", "custom_token_url", "custom_user_info_url":
			m.Fields[i].Required = true
		case "user_mapping":
			m.Fields[i].Required = true
			m.Fields[i].Help = "admin.schemaField.oauth2UserMappingHelp"
		}
	}
	// keep 集 = 标准四件套 + 三端点 + metadata（差异开关键载体），声明即
	// 运行期实际消费——不做 discovery，provider_url 死字段不下发。
	provider.Register(Type, oauthcore.KeepFields(m, append(oauthcore.StdKeepFields,
		"custom_auth_url", "custom_token_url", "custom_user_info_url", "metadata")...), newAdapter)
}

// Adapter 通用 OAuth2 适配器（channel=redirect）。
type Adapter struct {
	key            string
	clientID       string
	clientSecret   string
	scopes         string
	authURL        string
	tokenURL       string
	userInfoURL    string
	userMapping    map[string]string
	hc             *http.Client // nil → oauthcore 默认客户端；测试注入改写客户端
	tokenMethodGet bool         // metadata token_method=get
	userinfoQuery  bool         // metadata userinfo_token_in=query
	pkce           bool         // metadata pkce=s256
}

// newAdapter 注册表工厂。build 仅供测试注入 http.Client。
func newAdapter(p *provider.Provider) (provider.AuthAdapter, error) {
	hc, err := oauthcore.ClientFor(p)
	if err != nil {
		return nil, err
	}
	return build(p, hc)
}

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
	a := Adapter{
		key:          p.Key,
		clientID:     ext.GetClientId(),
		clientSecret: ext.GetClientSecret(),
		scopes:       ext.GetScopes(),
		authURL:      ext.GetCustomAuthUrl(),
		tokenURL:     ext.GetCustomTokenUrl(),
		userInfoURL:  ext.GetCustomUserInfoUrl(),
		userMapping:  ext.GetUserMapping(),
		hc:           hc,
	}
	// 差异开关装配期固化（未知取值拒绝），运行期不回读配置。
	md := ext.GetMetadata()
	switch md[metaTokenMethod] {
	case "", "post":
	case valGet:
		a.tokenMethodGet = true
	default:
		return nil, fmt.Errorf("%w: token_method=%q", ErrInvalidOption, md[metaTokenMethod])
	}
	switch md[metaUserinfoTokenIn] {
	case "", "header":
	case valQuery:
		a.userinfoQuery = true
	default:
		return nil, fmt.Errorf("%w: userinfo_token_in=%q", ErrInvalidOption, md[metaUserinfoTokenIn])
	}
	switch md[metaPKCE] {
	case "", "off":
	case valS256:
		a.pkce = true
	default:
		return nil, fmt.Errorf("%w: pkce=%q", ErrInvalidOption, md[metaPKCE])
	}
	return &a, nil
}

// Channel 固定为 redirect。
func (a *Adapter) Channel() provider.ThirdPartyChannel { return provider.ChannelRedirect }

// BuildAuthURL 组装跳转授权 URL（state 由 service 层生成后透传，§12.4；
// scope 无渠道默认，Ext.scopes 与 AuthContext.Scope 均空时不携带）。PKCE
// 开启时附带 code_challenge（S256）与 code_challenge_method。
func (a *Adapter) BuildAuthURL(ctx *provider.AuthContext) (string, error) {
	var extra map[string]string
	if a.pkce {
		extra = map[string]string{
			"code_challenge":        s256Challenge(a.verifier(ctx.RedirectURI)),
			"code_challenge_method": "S256",
		}
	}
	return oauthcore.BuildAuthURL(a.authURL, a.clientID, ctx, a.scopes, extra)
}

// verifier PKCE code_verifier（无状态派生，见 pkce.go）；redirectURI 须与
// BuildAuthURL / Exchange 两侧同源。
func (a *Adapter) verifier(redirectURI string) string {
	return pkceVerifier(a.clientSecret, a.key, redirectURI)
}

// Exchange 授权码换令牌（缺省 POST form；token_method=get 走 GET query，
// 按目标渠道文档组装、不带 grant_type；响应均按 JSON / form 自适应解析）。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	var verifier string
	if a.pkce {
		verifier = a.verifier(in.RedirectURI)
	}
	if a.tokenMethodGet {
		params := url.Values{
			"client_id":     {a.clientID},
			"client_secret": {a.clientSecret},
			"code":          {in.Code},
		}
		if in.RedirectURI != "" {
			params.Set("redirect_uri", in.RedirectURI)
		}
		if verifier != "" {
			params.Set("code_verifier", verifier)
		}
		return oauthcore.ExchangeGetQuery(ctx, a.hc, a.tokenURL, params)
	}
	var extra url.Values
	if verifier != "" {
		extra = url.Values{"code_verifier": {verifier}}
	}
	return oauthcore.ExchangePostForm(ctx, a.hc, a.tokenURL, a.clientID, a.clientSecret, in, extra, nil)
}

// FetchUser 拉取用户信息并按 user_mapping 抽取统一身份（无内置路径，
// 全部字段由映射表达式决定；open_id 缺失 → ErrEmptyOpenID）。
// userinfo_token_in=query 时 access_token 走查询串，否则 Bearer 头。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	user, err := oauthcore.GetUserInfo(ctx, a.hc, a.userInfoURL, t.AccessToken, !a.userinfoQuery, nil, nil)
	if err != nil {
		return nil, err
	}
	return oauthcore.ExtractIdentity(a.key, Type, oauthcore.IdentitySpec{}, t, user, a.userMapping)
}
