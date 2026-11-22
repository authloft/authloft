// dingtalk 专用适配器（docs/后端架构.md §12.2 内置清单、§15.5 dingtalk 行）：
// channel=redirect。协议私有（类 OAuth2），oauth2 / oidc 兜底无法表达，关键差异：
// 回调参数是 authCode 而非 code；令牌端点是 JSON body（非 form，驼峰字段
// clientId / clientSecret）；用户信息走自定义 Header x-acs-dingtalk-access-token
// （非 Bearer）；refreshToken 30 天经 Refresh 刷新（docs/后端架构.md §12.1
// 可选接口形态）。openId（应用内唯一）/ unionId（跨应用稳定）双落身份记录。
// 端点（login.dingtalk.com / api.dingtalk.com）固化不透出表单；一期仅企业
// 内部应用（client_id=AppKey、client_secret=AppSecret），不做第三方套件与
// 指定企业（无 corp_id）。凭证装配期取自 Provider 实例（§13.0），运行期
// 不回读配置。失败路径全部 fail-closed：网络错 / 响应 JSON 损坏 / errcode
// 非零 / 缺 openId 一律拒绝，不给部分成功的登录。
package dingtalk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"authloft/internal/provider"
	"authloft/internal/provider/auth/oauthcore"
)

// Type 渠道类型（§12.2 内置清单：dingtalk）。
const Type = "dingtalk"

// 端点（钉钉官方固定地址，§15.5：固化不透出表单）。
const (
	authorizeURL = "https://login.dingtalk.com/oauth2/auth"
	tokenURL     = "https://api.dingtalk.com/v1.0/oauth2/userAccessToken"
	userInfoURL  = "https://api.dingtalk.com/v1.0/contact/users/me"
)

// accessHeader 用户信息的自定义访问令牌 Header（钉钉私有协议，非 Bearer）。
const accessHeader = "x-acs-dingtalk-access-token"

// grant types（钉钉 v1.0 网关驼峰字段）。
const (
	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
)

// Schema 预设（§15.5 收窄边界：scopes 与 user_mapping 随字段 default 下发、
// 管理员可改写、适配器照常消费；预设映射对齐钉钉用户信息字段命名）。
const (
	defaultScopes      = "openid"
	defaultUserMapping = `{"open_id":"$.openId","union_id":"$.unionId","nickname":"$.nick","email":"$.email","phone":"$.mobile","avatar_url":"$.avatarUrl"}`
)

// 出站请求默认超时与响应体上限（与 oauthcore 同口径的兜底防御，防异常
// 端点拖垮登录链路 / 日志爆量）。
const (
	defaultTimeout = 10 * time.Second
	maxBodyBytes   = 1 << 20
	// maxErrDesc ProviderError 描述截断上限（字符）。
	maxErrDesc = 200
)

// 可判别错误：独立哨兵供服务层与测试可证伪断言。
var (
	// ErrNotConfigured client_id / client_secret 缺失（§13.0：装配期视为
	// 未配置，fail-closed）。
	ErrNotConfigured = errors.New("dingtalk: provider not configured")
	// ErrCallbackInvalid 回调参数缺失（authCode / state 任一为空）。
	ErrCallbackInvalid = errors.New("dingtalk: invalid callback")
	// ErrEmptyRefreshToken 刷新入参缺 refreshToken（fail-closed 闸门）。
	ErrEmptyRefreshToken = errors.New("dingtalk: empty refresh token")
	// ErrEmptyAccessToken FetchUser 入参令牌缺 accessToken（fail-closed 闸门）。
	ErrEmptyAccessToken = errors.New("dingtalk: empty access token")
)

func init() {
	// Schema 只声明管理员填写项（§15.5 收窄边界）：端点固化不透出，
	// 消费集恰为标准四键（client_id / client_secret / scopes / user_mapping）。
	// 预设值就地写 Default：KeepFields 后 Fields 与 Schema 闭包共享同一
	// 底层数组，改动天然同步。
	meta := oauthcore.NewStandardMeta(Type, "钉钉", provider.ChannelRedirect)
	for i := range meta.Fields {
		switch meta.Fields[i].Key {
		case "scopes":
			meta.Fields[i].Default = defaultScopes
		case "user_mapping":
			meta.Fields[i].Default = defaultUserMapping
		}
	}
	provider.Register(Type, meta, newAdapter)
}

// Callback 跳转回调参数（钉钉私有协议：authCode 而非 code，§15.5）。
type Callback struct {
	AuthCode string
	State    string
}

// ParseCallback 解析跳转回调 query：authCode / state 缺失即
// ErrCallbackInvalid（fail-closed）；state 与 al_login_state 的比对归
// service 层（§12.4），此处只做存在性闸门。
func ParseCallback(query url.Values) (*Callback, error) {
	if query == nil {
		return nil, fmt.Errorf("%w: empty query", ErrCallbackInvalid)
	}
	cb := &Callback{
		AuthCode: query.Get("authCode"),
		State:    query.Get("state"),
	}
	if cb.AuthCode == "" || cb.State == "" {
		return nil, fmt.Errorf("%w: authCode/state missing", ErrCallbackInvalid)
	}
	return cb, nil
}

// Adapter 钉钉登录适配器（channel=redirect）。
type Adapter struct {
	key          string
	providerType string // 身份 ProviderType：build 期固化 p.Type（§15.3 单一真源）
	clientID     string
	clientSecret string
	scopes       string
	userMapping  map[string]string
	hc           *http.Client // nil → 默认客户端；测试注入改写客户端
}

// newAdapter 注册表工厂。
func newAdapter(p *provider.Provider) (provider.AuthAdapter, error) {
	hc, err := oauthcore.ClientFor(p)
	if err != nil {
		return nil, err
	}
	return build(p, hc)
}

// build client 可注入（httptest mock 覆盖令牌 / 用户信息链路）；生产路径经
// newAdapter 固化官方端点。凭证装配期一次解析（§13.0），缺项即构造失败
// （fail-closed），不把未配置的渠道放进运行期。
func build(p *provider.Provider, hc *http.Client) (*Adapter, error) {
	if p == nil || p.Ext == nil {
		return nil, provider.ErrNilProvider
	}
	if p.Ext.GetClientId() == "" || p.Ext.GetClientSecret() == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	scopes := p.Ext.GetScopes()
	if scopes == "" {
		scopes = defaultScopes
	}
	return &Adapter{
		key:          p.Key,
		providerType: p.Type,
		clientID:     p.Ext.GetClientId(),
		clientSecret: p.Ext.GetClientSecret(),
		scopes:       scopes,
		userMapping:  p.Ext.GetUserMapping(),
		hc:           hc,
	}, nil
}

// Channel 固定为 redirect。
func (a *Adapter) Channel() provider.ThirdPartyChannel { return provider.ChannelRedirect }

// BuildAuthURL 组装跳转授权 URL（state 由 service 层生成后透传，§12.4）。
// response_type=code 固定，prompt=consent 固定追加（钉钉进确认页的固定参数）。
func (a *Adapter) BuildAuthURL(ctx *provider.AuthContext) (string, error) {
	return oauthcore.BuildAuthURL(authorizeURL, a.clientID, ctx, a.scopes,
		map[string]string{"prompt": "consent"})
}

// tokenRequest 令牌端点 JSON body（钉钉 v1.0 网关驼峰字段，区别于标准 form
// 编码——这是兜底适配器无法表达的核心差异之一）。
type tokenRequest struct {
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	Code         string `json:"code,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	GrantType    string `json:"grantType"`
}

// Exchange 授权码换令牌：POST JSON body 到 userAccessToken（code 填回调的
// authCode）。钉钉不要求 redirect_uri，故 ExchangeInput.RedirectURI 不上行。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	if in.Code == "" {
		return nil, oauthcore.ErrEmptyCode
	}
	return a.postToken(ctx, tokenRequest{
		ClientId:     a.clientID,
		ClientSecret: a.clientSecret,
		Code:         in.Code,
		GrantType:    grantAuthorizationCode,
	})
}

// TokenRefresher 刷新令牌可选契约（docs/后端架构.md §12.1 可选接口形态）：
// 钉钉 refreshToken 30 天、accessToken 7200 秒，消费方经类型断言取用。
// 基座 provider 包按「可选接口随对应渠道卡按需补齐」暂未落形，故按文档
// 形态在本包声明——Go 结构化类型，消费方自持同形接口即可命中。
type TokenRefresher interface {
	Refresh(ctx context.Context, t *provider.Token) (*provider.Token, error)
}

var _ TokenRefresher = (*Adapter)(nil)

// Refresh 用 refreshToken 换新令牌（grantType=refresh_token）：响应即新
// accessToken / refreshToken。入参缺 refreshToken 或响应缺 accessToken 均
// fail-closed（拒绝下发半截令牌）。
func (a *Adapter) Refresh(ctx context.Context, t *provider.Token) (*provider.Token, error) {
	if t == nil || t.RefreshToken == "" {
		return nil, ErrEmptyRefreshToken
	}
	return a.postToken(ctx, tokenRequest{
		ClientId:     a.clientID,
		ClientSecret: a.clientSecret,
		RefreshToken: t.RefreshToken,
		GrantType:    grantRefreshToken,
	})
}

// postToken JSON POST + 响应解析共用链路（Exchange / Refresh 同构）。
func (a *Adapter) postToken(ctx context.Context, payload tokenRequest) (*provider.Token, error) {
	status, body, err := postJSON(ctx, a.hc, tokenURL, payload)
	if err != nil {
		return nil, err
	}
	return parseTokenResponse(status, body)
}

// FetchUser 拉取用户信息并抽取统一身份：GET /v1.0/contact/users/me，
// accessToken 经自定义 Header 上行（非 Bearer、不进 query——钉钉私有协议）。
// openId / unionId 双落；Raw 只落用户信息响应（§12.1 Raw 红线：绝不携带
// 令牌等凭证）。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	if t.AccessToken == "" {
		return nil, ErrEmptyAccessToken
	}
	status, body, err := oauthcore.RawGet(ctx, a.hc, userInfoURL, map[string]string{accessHeader: t.AccessToken})
	if err != nil {
		return nil, err
	}
	user, err := parseUserInfo(status, body)
	if err != nil {
		return nil, err
	}
	spec := oauthcore.IdentitySpec{
		OpenID:   []string{"openId"},
		UnionID:  []string{"unionId"},
		Nickname: []string{"nick"},
		Email:    []string{"email"},
		Phone:    []string{"mobile"},
		Avatar:   []string{"avatarUrl"},
	}
	return oauthcore.ExtractIdentity(a.key, a.providerType, spec, t, user, a.userMapping)
}

// postJSON JSON body 出站 POST（Content-Type application/json；oauthcore.do
// 仅支持 form 编码，JSON body 是钉钉私有形态故本包自实现）。hc 为 nil 时
// 用默认客户端；响应体限制 maxBodyBytes。
func postJSON(ctx context.Context, hc *http.Client, rawURL string, payload tokenRequest) (int, []byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	buf, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(buf))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, b, nil
}

// parseTokenResponse 解析令牌端点响应：JSON 损坏 / 错误体（errcode 非零或
// v1.0 code）/ 缺 accessToken 均 fail-closed。字段名以官方驼峰为主
// （accessToken / refreshToken / expireIn），兼容旧式下划线形态。
func parseTokenResponse(status int, body []byte) (*provider.Token, error) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return nil, unparsable(status, body, "unparsable_token_response")
	}
	if code, desc := bodyError(m); code != "" {
		return nil, &oauthcore.ProviderError{Status: status, Code: code, Desc: desc}
	}
	at := firstStr(m, "accessToken", "access_token")
	if at == "" {
		return nil, &oauthcore.ProviderError{Status: status, Code: "empty_access_token", Desc: truncate(body)}
	}
	tok := &provider.Token{
		AccessToken:  at,
		RefreshToken: firstStr(m, "refreshToken", "refresh_token"),
		Raw:          m,
	}
	tok.ExpiresIn = firstInt(m, "expireIn", "expires_in")
	return tok, nil
}

// parseUserInfo 解析用户信息响应：非 2xx / 2xx 错误体 / JSON 损坏均归一
// *ProviderError（fail-closed；缺 openId 由 ExtractIdentity 以 ErrEmptyOpenID
// 拒绝）。
func parseUserInfo(status int, body []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return nil, unparsable(status, body, "unparsable_user_info")
	}
	if code, desc := bodyError(m); code != "" {
		return nil, &oauthcore.ProviderError{Status: status, Code: code, Desc: desc}
	}
	if status < 200 || status >= 300 {
		return nil, &oauthcore.ProviderError{
			Status: status, Code: "http_" + strconv.Itoa(status), Desc: truncate(body),
		}
	}
	return m, nil
}

// bodyError 钉钉错误体归一：v1.0 网关 code/message 与旧式 errcode/errmsg
// 两代形态都认；errcode 数值 0 视为成功。code 为空 = 无错误字段。
func bodyError(m map[string]any) (code, desc string) {
	desc = firstStr(m, "message", "errmsg", "error_description")
	switch v := m["errcode"].(type) {
	case float64:
		if v != 0 {
			return strconv.FormatFloat(v, 'f', -1, 64), desc
		}
	case string:
		if v != "" && v != "0" {
			return v, desc
		}
	}
	if s, ok := m["code"].(string); ok && s != "" {
		return s, desc
	}
	return "", ""
}

// firstStr 按 keys 顺序取首个非空字符串字段。
func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// firstInt 按 keys 顺序取首个可解析为整数的字段（JSON 数字或数字串）。
func firstInt(m map[string]any, keys ...string) int64 {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			return int64(v)
		case string:
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				return n
			}
		}
	}
	return 0
}

// unparsable JSON 损坏的统一错误（fail-closed：损坏响应绝不放行）。
func unparsable(status int, body []byte, code string) error {
	return &oauthcore.ProviderError{Status: status, Code: code, Desc: truncate(body)}
}

// truncate 错误描述截断（rune 安全，防日志爆量）。
func truncate(body []byte) string {
	s := string(bytes.TrimSpace(body))
	r := []rune(s)
	if len(r) > maxErrDesc {
		return string(r[:maxErrDesc]) + "…"
	}
	return s
}
