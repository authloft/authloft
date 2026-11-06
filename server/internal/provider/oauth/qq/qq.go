// QQ 渠道适配器（docs/后端架构.md §12.2 行 1473 内置清单）：标准
// authorization code 跳转流程，channel=redirect，但协议有两处 QQ 旧式
// 差异：令牌端点走 GET 查询串、响应 form 编码；openid 须经 /oauth2.0/me
// 端点以 JSONP 形态取得（用户信息端点必须带 openid 参数）。端点为 QQ
// 互联官方固定地址；scope 可经 Ext.scopes 覆盖（缺省 get_user_info）；
// 用户字段可经 Ext.user_mapping 覆盖内置抽取。凭证装配期取自 Provider
// 实例（§13.0 唯一口径），运行期不回读配置。
// 真机联调未覆盖（无 QQ 互联应用凭据）。
package qq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

// Type 渠道类型（§12.2）。
const Type = "qq"

// 端点（QQ 互联官方固定地址）。
const (
	authURL     = "https://graph.qq.com/oauth2.0/authorize"
	tokenURL    = "https://graph.qq.com/oauth2.0/token"
	meURL       = "https://graph.qq.com/oauth2.0/me"
	userInfoURL = "https://graph.qq.com/user/get_user_info"
)

// defaultScopes 缺省授权范围（拉取用户资料）。
const defaultScopes = "get_user_info"

// 可判别错误。
var (
	// ErrNotConfigured client_id / client_secret 缺失（§13.0：视为未配置）。
	ErrNotConfigured = errors.New("qq: provider not configured")
	// ErrEmptyOpenID /me 未返回 openid。
	ErrEmptyOpenID = errors.New("qq: empty openid from /me")
)

func init() {
	provider.Register(Type, oauthcore.NewMeta(Type, "QQ", provider.ChannelRedirect), newAdapter)
}

// Adapter QQ 适配器（channel=redirect）。
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

// Exchange 授权码换令牌：GET 查询串（QQ 旧式），响应 JSON / form 编码
// 自适应解析。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	params := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"code":          {in.Code},
	}
	if in.RedirectURI != "" {
		params.Set("redirect_uri", in.RedirectURI)
	}
	return oauthcore.ExchangeGetQuery(ctx, a.hc, tokenURL, params)
}

// FetchUser 两步拉取：先 /oauth2.0/me（JSONP，取 openid，可能携带
// unionid），再 /user/get_user_info（access_token + oauth_consumer_key +
// openid 查询串，ret != 0 归 *ProviderError）；两步结果合并抽取统一身份。
// Raw 落两步合并的用户侧响应（不含 access_token）。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	me, err := a.fetchMe(ctx, t.AccessToken)
	if err != nil {
		return nil, err
	}
	openID, _ := me["openid"].(string)
	if openID == "" {
		return nil, ErrEmptyOpenID
	}
	params := url.Values{
		"oauth_consumer_key": {a.clientID},
		"openid":             {openID},
	}
	user, err := oauthcore.GetUserInfo(ctx, a.hc, userInfoURL, t.AccessToken, false, params, nil)
	if err != nil {
		return nil, err
	}
	// /me 的 openid / unionid 并入用户信息 map（用户信息响应本身不含
	// openid；ExtractIdentity 的 Raw 也因此含 openid，属用户侧数据非凭证）。
	for k, v := range me {
		user[k] = v
	}
	spec := oauthcore.IdentitySpec{
		OpenID:   []string{"openid"},
		UnionID:  []string{"unionid", "union_id"},
		Nickname: []string{"nickname"},
		Avatar:   []string{"figureurl_qq_2", "figureurl_qq_1", "figureurl_2", "figureurl_1"},
	}
	return oauthcore.ExtractIdentity(a.key, Type, spec, t, user, a.userMapping)
}

// fetchMe 调 /oauth2.0/me 取 openid：响应为 JSONP `callback( {...} );`，
// 剥壳后按 JSON 解析；错误 JSONP（含 error 键）归 *ProviderError。
func (a *Adapter) fetchMe(ctx context.Context, accessToken string) (map[string]any, error) {
	sep := "?"
	if strings.Contains(meURL, "?") {
		sep = "&"
	}
	status, body, err := oauthcore.RawGet(ctx, a.hc,
		meURL+sep+"access_token="+url.QueryEscape(accessToken), nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, &oauthcore.ProviderError{Status: status, Code: "http_" + strconv.Itoa(status), Desc: string(body)}
	}
	m, err := parseJSONP(body)
	if err != nil {
		return nil, err
	}
	if code, desc := jsonErrFields(m); code != "" {
		return nil, &oauthcore.ProviderError{Status: status, Code: code, Desc: desc}
	}
	return m, nil
}

// parseJSONP 剥 `callback( {...} );` 壳后解析 JSON。
func parseJSONP(body []byte) (map[string]any, error) {
	s := strings.TrimSpace(string(body))
	if i := strings.IndexByte(s, '('); i >= 0 {
		if j := strings.LastIndexByte(s, ')'); j > i {
			s = s[i+1 : j]
		}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(s)), &m); err != nil {
		return nil, &oauthcore.ProviderError{Status: 200, Code: "unparsable_me_response", Desc: strings.TrimSpace(string(body))}
	}
	return m, nil
}

// jsonErrFields QQ /me 错误 JSONP 字段（error 数字或字符串 / error_description）。
func jsonErrFields(m map[string]any) (code, desc string) {
	switch t := m["error"].(type) {
	case string:
		if t != "" {
			code = t
		}
	case float64:
		code = strconv.FormatFloat(t, 'f', -1, 64)
	}
	if code == "" {
		return "", ""
	}
	if d, ok := m["error_description"].(string); ok {
		desc = d
	}
	return code, desc
}
