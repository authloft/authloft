// wecom 专用适配器（docs/后端架构.md §12.2 内置清单、§15.5 wecom 行）：
// channel=redirect。协议私有（类 OAuth2），oauth2 / oidc 兜底无法表达，关键差异：
// 授权 URL 参数名为 appid（= CorpID）、必带 agentid 与 #wechat_redirect 尾锚；
// 无标准令牌端点——两段式链路：corpid/corpsecret 先换应用级 access_token
// （缓存复用），再以 access_token + code 换 UserId；错误码在 body 内
// （errcode=0 才算成功，与标准 OAuth2 error 字段语义不同）。企业成员
// getuserinfo 返回 UserId（企业内唯一，作 open_id）；非企业成员无 UserId，
// fail-closed 拒绝。snsapi_privateinfo 授权时可再调 user/get 拉详情（可选
// 增强：失败不打断静默链路已取得的身份）。端点（open.weixin.qq.com /
// qyapi.weixin.qq.com）固化不透出表单；client_id=CorpID、client_secret=
// 自建应用 Secret、agent_id(53) 必填（接口文档 §12.1）。凭证装配期取自
// Provider 实例（§13.0），运行期不回读配置。失败路径全部 fail-closed：
// 网络错 / 响应 JSON 损坏 / errcode 非零 / 缺 UserId 一律拒绝。
// user_ticket 可换成员敏感信息，属凭证类字段，禁入身份 Raw。
package wecom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"authloft/internal/provider"
	"authloft/internal/provider/auth/oauthcore"
)

// Type 渠道类型（§12.2 内置清单：wecom）。
const Type = "wecom"

// 端点（企业微信官方固定地址，§15.5：固化不透出表单）。
const (
	authorizeURL   = "https://open.weixin.qq.com/connect/oauth2/authorize"
	getTokenURL    = "https://qyapi.weixin.qq.com/cgi-bin/gettoken"
	getUserInfoURL = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo"
	userDetailURL  = "https://qyapi.weixin.qq.com/cgi-bin/user/get"
	// wechatRedirectSuffix 授权 URL 尾锚（企业微信 / 微信系私有协议硬约束）。
	wechatRedirectSuffix = "#wechat_redirect"
)

// Schema 预设（§15.5 收窄边界：scopes 与 user_mapping 随字段 default 下发、
// 管理员可改写、适配器照常消费；映射覆盖静默（UserId）与详情（name/avatar/
// email/mobile）两场景，详情字段缺省时求值跳过、保留渠道抽取值）。
const (
	defaultScopes      = "snsapi_base"
	defaultUserMapping = `{"open_id":"$.UserId","nickname":"$.name","avatar_url":"$.avatar","email":"$.email","phone":"$.mobile"}`
	// tokenCacheMargin 应用级令牌提前失效余量（防临界点用到已过期令牌）。
	tokenCacheMargin = 60 * time.Second
	// maxErrDesc ProviderError 描述截断上限（字符）。
	maxErrDesc = 200
)

// scopePrivateInfo 详情授权范围（手动授权，可调 user/get 拉详情）。
const scopePrivateInfo = "snsapi_privateinfo"

// ErrNotConfigured client_id / client_secret / agent_id 任一缺失（§13.0：
// 装配期视为未配置，fail-closed——agent_id 是授权 URL 硬依赖，无缺项降级）。
var ErrNotConfigured = errors.New("wecom: provider not configured")

func init() {
	// Schema 只声明管理员填写项（§15.5 收窄边界）：端点固化不透出，消费集
	// 为标准四键 + agent_id(53)；scopes / user_mapping 预设值随字段 default
	// 下发。字段文案只准 i18n 键（跨端契约）：agentId 键已在前端字典预置，
	// CorpID / Secret 暂复用通用凭证文案（渠道专用文案归前端字典扩展）。
	fields := []provider.FieldMeta{
		{Key: "client_id", Label: "admin.schemaField.clientIdLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		{Key: "client_secret", Label: "admin.schemaField.clientSecretLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		{Key: "agent_id", Label: "admin.schemaField.agentIdLabel", Type: "text", Section: "credential", Required: true, Help: "admin.schemaField.agentIdHelp", Storage: provider.StorageExt},
		{Key: "scopes", Label: "admin.schemaField.scopesLabel", Type: "text", Section: "credential", Default: defaultScopes, Storage: provider.StorageExt},
		{Key: "user_mapping", Label: "admin.schemaField.userMappingLabel", Type: "json", Section: "endpoint", Advanced: true, Help: "admin.schemaField.userMappingHelp", Default: defaultUserMapping, Storage: provider.StorageExt},
	}
	provider.Register(Type, provider.Meta{
		Type:        Type,
		DisplayName: "企业微信",
		Category:    "auth",
		Channel:     provider.ChannelRedirect,
		Fields:      fields,
		Schema:      oauthcore.SchemaFor(fields),
	}, newAdapter)
}

// Adapter 企业微信登录适配器（channel=redirect）。
type Adapter struct {
	key          string
	providerType string // 身份 ProviderType：build 期固化 p.Type（§15.3 单一真源）
	clientID     string // CorpID
	clientSecret string // 自建应用 Secret
	agentID      string // 应用 AgentId（授权 URL agentid）
	scopes       string
	userMapping  map[string]string
	hc           *http.Client // nil → oauthcore 默认客户端；测试注入改写客户端
	now          func() time.Time

	// 应用级 access_token 缓存（mutex + 过期戳，同 apple client_secret 缓存
	// 形态）：未到期直接复用，到期重取。适配器实例按请求构造，缓存命不中
	// 只是多取一次，正确性不受影响。
	mu              sync.Mutex
	cachedToken     string
	cachedExpiresIn int64
	cachedExpiry    time.Time
}

// newAdapter 注册表工厂。
func newAdapter(p *provider.Provider) (provider.AuthAdapter, error) {
	hc, err := oauthcore.ClientFor(p)
	if err != nil {
		return nil, err
	}
	return build(p, hc)
}

// build client 可注入（httptest mock 覆盖两段式链路）；生产路径经 newAdapter
// 固化官方端点。凭证装配期一次解析（§13.0），任一缺项即构造失败
// （fail-closed），不把未配置的渠道放进运行期。
func build(p *provider.Provider, hc *http.Client) (*Adapter, error) {
	if p == nil || p.Ext == nil {
		return nil, provider.ErrNilProvider
	}
	clientID := p.Ext.GetClientId()
	clientSecret := p.Ext.GetClientSecret()
	agentID := p.Ext.GetAgentId()
	if clientID == "" || clientSecret == "" || agentID == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	scopes := p.Ext.GetScopes()
	if scopes == "" {
		scopes = defaultScopes
	}
	return &Adapter{
		key:          p.Key,
		providerType: p.Type,
		clientID:     clientID,
		clientSecret: clientSecret,
		agentID:      agentID,
		scopes:       scopes,
		userMapping:  p.Ext.GetUserMapping(),
		hc:           hc,
		now:          time.Now,
	}, nil
}

// Channel 固定为 redirect（企业微信客户端内网页授权；扫码登录形态独立适配）。
func (a *Adapter) Channel() provider.ThirdPartyChannel { return provider.ChannelRedirect }

// BuildAuthURL 组装跳转授权 URL（state 由 service 层生成后透传，§12.4）。
// 微信系参数名为 appid（= CorpID），agentid 必带（agent_id 硬依赖），
// 尾锚 #wechat_redirect 固定追加（企业微信私有协议约束）。
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
	q.Set("agentid", a.agentID)
	q.Set("redirect_uri", ctx.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("state", ctx.State)
	return authorizeURL + "?" + q.Encode() + wechatRedirectSuffix, nil
}

// Exchange 两段式链路：先取（缓存命中的）应用级 access_token，再以
// access_token + code 调 getuserinfo 换 UserId——企业微信没有「code 换令牌」
// 的标准端点，返回的 Token 即应用级令牌载体（ExpiresIn 为其有效期），
// getuserinfo 响应整体进 Raw 供 FetchUser 抽取。errcode 非零 / HTTP 非 2xx /
// JSON 损坏均拒绝。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	if in.Code == "" {
		return nil, oauthcore.ErrEmptyCode
	}
	at, expiresIn, err := a.appAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	m, err := a.getWecomBody(ctx, getUserInfoURL, url.Values{
		"access_token": {at},
		"code":         {in.Code},
	})
	if err != nil {
		return nil, err
	}
	return &provider.Token{AccessToken: at, ExpiresIn: expiresIn, Raw: m}, nil
}

// appAccessToken 取应用级 access_token（GET gettoken?corpid=&corpsecret=）。
// 锁内做网络调用：适配器实例按请求构造，竞争面极小，换来并发首取只打
// 一次 gettoken。expires_in 提前 margin 秒失效（防临界点用过期令牌）；
// 响应缺 expires_in 视为不可缓存（下次重取）。
func (a *Adapter) appAccessToken(ctx context.Context) (string, int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cachedToken != "" && a.now().Before(a.cachedExpiry) {
		return a.cachedToken, a.cachedExpiresIn, nil
	}
	m, err := a.getWecomBody(ctx, getTokenURL, url.Values{
		"corpid":     {a.clientID},
		"corpsecret": {a.clientSecret},
	})
	if err != nil {
		return "", 0, err
	}
	at := firstStr(m, "access_token")
	if at == "" {
		return "", 0, &oauthcore.ProviderError{Code: "empty_access_token", Desc: firstStr(m, "errmsg")}
	}
	expiresIn := firstInt(m, "expires_in")
	a.cachedToken = at
	a.cachedExpiresIn = expiresIn
	a.cachedExpiry = a.now().Add(time.Duration(expiresIn)*time.Second - tokenCacheMargin)
	return at, expiresIn, nil
}

// FetchUser 抽取统一身份：UserId 取自 Exchange 落在 Raw 的 getuserinfo 响应；
// 有效 scope 含 snsapi_privateinfo 且取得 UserId 时再调 user/get 合并详情
// （昵称 / 头像 / 邮箱 / 手机号）。详情为可选增强，失败不打断登录（静默
// 链路身份已成立，§15.5 wecom 行）；合并值可被 user_mapping 覆盖。
// Raw 落净化后的响应（剔除 user_ticket——可换成员敏感信息的凭证类字段，
// 禁入身份 Raw），绝不携带令牌。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	user := make(map[string]any, len(t.Raw))
	for k, v := range t.Raw {
		if k == "user_ticket" {
			continue
		}
		user[k] = v
	}
	if a.privateInfo() && t.AccessToken != "" {
		if userid := firstStr(user, "UserId", "userid", "user_id"); userid != "" {
			detail, err := a.getWecomBody(ctx, userDetailURL, url.Values{
				"access_token": {t.AccessToken},
				"userid":       {userid},
			})
			if err == nil {
				for k, v := range detail {
					user[k] = v // 详情覆盖同名键（UserId 与 userid 大小写并存）
				}
			}
		}
	}
	spec := oauthcore.IdentitySpec{
		// UserId 为企业成员唯一标识；OpenId 是非成员访客键，不认（缺 UserId
		// 由 ExtractIdentity 以 ErrEmptyOpenID 拒绝，fail-closed）。
		OpenID:   []string{"UserId", "userid", "user_id"},
		UnionID:  []string{"unionid"},
		Nickname: []string{"name"},
		Email:    []string{"email"},
		Phone:    []string{"mobile"},
		Avatar:   []string{"avatar"},
	}
	return oauthcore.ExtractIdentity(a.key, a.providerType, spec, t, user, a.userMapping)
}

// privateInfo 有效 scope（授权上下文覆盖或缺省预设）是否含
// snsapi_privateinfo。
func (a *Adapter) privateInfo() bool {
	for _, s := range strings.Fields(a.scopes) {
		if s == scopePrivateInfo {
			return true
		}
	}
	return false
}

// getWecomBody GET 查询串调企业微信 CGI 端点并解析 body（企业微信三端点
// 均为 GET 查询串鉴权、错误码在 body 的同构形态）。
func (a *Adapter) getWecomBody(ctx context.Context, rawURL string, params url.Values) (map[string]any, error) {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	status, body, err := oauthcore.RawGet(ctx, a.hc, rawURL+sep+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	return parseWecomBody(status, body)
}

// parseWecomBody 解析企业微信 CGI 响应：JSON 损坏 / HTTP 非 2xx / errcode
// 非零均归一 *ProviderError（fail-closed）。errcode=0 视为成功——企业微信
// 成功响应也携带 errcode 字段，不能套用 oauthcore「含 errcode 即错误」的
// 通用归一（会误伤成功响应）。
func parseWecomBody(status int, body []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return nil, unparsable(status, body)
	}
	if code, desc := bodyErrcode(m); code != "" {
		return nil, &oauthcore.ProviderError{Status: status, Code: code, Desc: desc}
	}
	if status < http.StatusOK || status >= 300 {
		return nil, &oauthcore.ProviderError{
			Status: status, Code: "http_" + strconv.Itoa(status), Desc: truncate(body),
		}
	}
	return m, nil
}

// bodyErrcode 企业微信错误体归一：errcode 数值 0（或 "0"）视为成功，非零
// 即错误（如 40029 invalid code、60011 权限不足）。code 为空 = 无错误。
func bodyErrcode(m map[string]any) (code, desc string) {
	desc = firstStr(m, "errmsg")
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
func unparsable(status int, body []byte) error {
	return &oauthcore.ProviderError{Status: status, Code: "unparsable_wecom_body", Desc: truncate(body)}
}

// truncate 错误描述截断（rune 安全，防日志爆量）。
func truncate(body []byte) string {
	s := strings.TrimSpace(string(body))
	r := []rune(s)
	if len(r) > maxErrDesc {
		return string(r[:maxErrDesc]) + "…"
	}
	return s
}
