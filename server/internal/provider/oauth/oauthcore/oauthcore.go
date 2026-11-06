// Package oauthcore 是 redirect 渠道 OAuth2 / OIDC 适配器的共用核心
// （docs/后端架构.md §12.1 行 1425-1467 适配器接口、§12.2
// 行 1469-1481 内置清单）：跳转授权 URL 组装（state 由 service 层生成后
// 传入，adapter 只透传不生成，§12.4 行 1476-1478）、授权码换令牌
// （POST form / GET query 两种形态）、拉取用户信息、统一身份抽取与
// user_mapping（JSONata 表达式，接口文档 §5.3 行 1261-1266）覆盖。
// 渠道实现放 internal/provider/oauth/<type>/，init() 自注册（§15.3 行
// 1754-1760）。
//
// 设计边界：本包不写死任何厂商名——端点 / 默认 scope / 字段路径全部由
// 渠道包以声明式入参传入（标准派渠道为常量端点，通用兜底全走 Provider
// Ext 配置）。第三方侧错误统一归一为 *ProviderError（描述截断防日志
// 爆量），错误串不含任何本地凭证；本地输入校验用哨兵错误，便于渠道
// 包与单测按 errors.Is / errors.As 判别（provider 侧错误映射，服务层
// 统一归 §1.6 failed，不透出厂商原始报文）。
package oauthcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"authloft/internal/jsonata"
	"authloft/internal/provider"
)

// 出站请求默认超时与响应体上限（防异常端点拖垮登录链路 / 日志爆量）。
const (
	defaultTimeout = 10 * time.Second
	maxBodyBytes   = 1 << 20
	// maxErrDesc ProviderError 描述的截断上限（字符）。
	maxErrDesc = 200
)

// 本地输入校验哨兵（渠道包可直接对外断言）。
var (
	// ErrEmptyState AuthContext.State 为空——state 必填（§12.4：service
	// 层生成后传入，adapter 只透传）。
	ErrEmptyState = errors.New("oauthcore: empty state")
	// ErrEmptyCode 授权码为空。
	ErrEmptyCode = errors.New("oauthcore: empty code")
	// ErrNilToken FetchUser 入参为空。
	ErrNilToken = errors.New("oauthcore: nil token")
	// ErrEmptyOpenID 渠道未返回用户唯一标识（含 user_mapping 覆盖后）。
	ErrEmptyOpenID = errors.New("oauthcore: empty openid")
	// ErrMissingEndpoint 端点配置缺失（通用兜底未填 URL 等）。
	ErrMissingEndpoint = errors.New("oauthcore: missing endpoint")
)

// ProviderError 第三方侧错误：HTTP 非 2xx，或 2xx 响应体携带错误字段
// （error / errcode / error_code / ret≠0）。Code / Desc 只含渠道返回的
// 错误码与描述，不含本地凭证。
type ProviderError struct {
	Status int
	Code   string
	Desc   string
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("oauthcore: provider error: status=%d code=%q desc=%q",
		e.Status, e.Code, e.Desc)
}

// AsProviderError 判别 err 是否为 *ProviderError（渠道包 / 单测用）。
func AsProviderError(err error) (*ProviderError, bool) {
	var pe *ProviderError
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}

// NewMeta 组装 oauth 类渠道 Meta：Ext 追加字段为接口文档 §5.3 行 1257 的
// oauth 基线 10 字段 + 行 1261 metadata（与 wechat_mp / wechat_mp_scan
// 同款基线，label / type / section 逐字一致）。渠道包可在
// 返回值上就地改 Label / Required / Help（如 alipay 语义化凭证标签、
// 通用兜底把端点置必填）后再 Register。
func NewMeta(typ, displayName string, ch provider.ThirdPartyChannel) provider.Meta {
	return provider.Meta{
		Type:        typ,
		DisplayName: displayName,
		Category:    "oauth",
		Channel:     ch,
		Fields: []provider.FieldMeta{
			{Key: "client_id", Label: "AppID", Type: "text", Section: "credential", Required: true},
			{Key: "client_secret", Label: "AppSecret", Type: "secret", Section: "credential", Required: true},
			{Key: "app_id", Label: "小程序 AppID", Type: "text", Section: "credential", Advanced: true},
			{Key: "cert", Label: "证书 / 公钥", Type: "secret", Section: "credential", Advanced: true},
			{Key: "scopes", Label: "授权范围", Type: "text", Section: "credential", Advanced: true},
			{Key: "provider_url", Label: "服务地址", Type: "text", Section: "endpoint", Advanced: true},
			{Key: "custom_auth_url", Label: "授权地址", Type: "text", Section: "endpoint", Advanced: true},
			{Key: "custom_token_url", Label: "令牌地址", Type: "text", Section: "endpoint", Advanced: true},
			{Key: "custom_user_info_url", Label: "UserInfo 地址", Type: "text", Section: "endpoint", Advanced: true},
			{Key: "user_mapping", Label: "字段映射", Type: "json", Section: "endpoint", Advanced: true,
				Help: "三方字段 → Authloft 字段，值为 JSONata 表达式"},
			{Key: "metadata", Label: "长尾键值", Type: "json", Section: "basic", Advanced: true},
		},
	}
}

// BuildAuthURL 组装标准 authorization code 跳转授权 URL：response_type=code
// + client_id + state（必填）+ redirect_uri / scope（可选，scope 缺省走渠道
// 默认值）+ extra 渠道固定参数。state 为空 → ErrEmptyState（透传校验，
// §12.4）。渠道参数名非标准（如微信 appid）的渠道自行组装，不经本函数。
func BuildAuthURL(authURL, clientID string, ctx *provider.AuthContext, defaultScope string, extra map[string]string) (string, error) {
	if ctx == nil || ctx.State == "" {
		return "", ErrEmptyState
	}
	if authURL == "" {
		return "", ErrMissingEndpoint
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("state", ctx.State)
	if ctx.RedirectURI != "" {
		q.Set("redirect_uri", ctx.RedirectURI)
	}
	scope := ctx.Scope
	if scope == "" {
		scope = defaultScope
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	for k, v := range extra {
		if v == "" {
			continue
		}
		q.Set(k, v)
	}
	sep := "?"
	if strings.Contains(authURL, "?") {
		sep = "&"
	}
	return authURL + sep + q.Encode(), nil
}

// ExchangePostForm 标准 authorization_code 换令牌：POST form 到令牌端点
// （GitHub / Gitee / Google / Microsoft / 飞书 / 微博 / 通用兜底）。
// 响应体先按 JSON、再回退 form 编码解析（接口文档口径内两类形态）。
func ExchangePostForm(ctx context.Context, hc *http.Client, tokenURL, clientID, clientSecret string,
	in provider.ExchangeInput, extra url.Values, headers map[string]string) (*provider.Token, error) {
	if in.Code == "" {
		return nil, ErrEmptyCode
	}
	if tokenURL == "" {
		return nil, ErrMissingEndpoint
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {in.Code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if in.RedirectURI != "" {
		form.Set("redirect_uri", in.RedirectURI)
	}
	for k, vs := range extra {
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	status, body, err := do(ctx, hc, http.MethodPost, tokenURL, form, headers)
	if err != nil {
		return nil, err
	}
	return parseTokenBody(status, body)
}

// ExchangeGetQuery 查询串换令牌（GET，QQ / 微信开放平台旧式）：params 由
// 渠道组装（含 code 与凭证参数）。
func ExchangeGetQuery(ctx context.Context, hc *http.Client, tokenURL string, params url.Values) (*provider.Token, error) {
	if params.Get("code") == "" {
		return nil, ErrEmptyCode
	}
	if tokenURL == "" {
		return nil, ErrMissingEndpoint
	}
	status, body, err := do(ctx, hc, http.MethodGet, tokenURL+"?"+params.Encode(), nil, nil)
	if err != nil {
		return nil, err
	}
	return parseTokenBody(status, body)
}

// GetUserInfo 拉取用户信息：bearer=true 走 Authorization: Bearer 头（标准
// 派），否则 access_token 以查询串携带（微信 / QQ / 微博）；params 为渠道
// 附加查询参数（如 openid / uid，取自令牌响应）。非 2xx、2xx 错误体
// （error / errcode / error_code）与 QQ 旧式 ret!=0 均归一 *ProviderError。
func GetUserInfo(ctx context.Context, hc *http.Client, userInfoURL, accessToken string,
	bearer bool, params url.Values, headers map[string]string) (map[string]any, error) {
	if userInfoURL == "" {
		return nil, ErrMissingEndpoint
	}
	q := url.Values{}
	if !bearer {
		q.Set("access_token", accessToken)
	}
	for k, vs := range params {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	if bearer {
		if headers == nil {
			headers = map[string]string{}
		}
		headers["Authorization"] = "Bearer " + accessToken
	}
	sep := "?"
	if strings.Contains(userInfoURL, "?") {
		sep = "&"
	}
	status, body, err := do(ctx, hc, http.MethodGet, userInfoURL+sep+q.Encode(), nil, headers)
	if err != nil {
		return nil, err
	}
	if pe := errFromUserBody(status, body); pe != nil {
		return nil, pe
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, &ProviderError{Status: status, Code: "unparsable_user_info", Desc: truncate(string(body))}
	}
	// QQ get_user_info：HTTP 200 但 ret != 0 视为错误。
	if ret, ok := m["ret"].(float64); ok && ret != 0 {
		return nil, &ProviderError{
			Status: status,
			Code:   strconv.FormatFloat(ret, 'f', -1, 64),
			Desc:   truncate(firstString(m, "msg")),
		}
	}
	return m, nil
}

// IdentitySpec 声明式字段抽取路径（键为响应体顶层字段名，按序取第一个
// 非空值）。标准派渠道填用户信息端点的顶层键；微信 / 微博等令牌响应
// 即携带 openid / uid 的渠道，把令牌响应的键排在前面（ExtractIdentity
// 合并两份 map，用户信息优先覆盖同名键）。
type IdentitySpec struct {
	OpenID   []string
	UnionID  []string
	Username []string
	Nickname []string
	Email    []string
	Phone    []string
	Avatar   []string
}

// ExtractIdentity 按 spec 从令牌响应与用户信息合并 map 抽取统一身份，
// 再按 user_mapping（键为 Authloft 字段名，值为 JSONata 表达式，接口文档
// §5.3 行 1261-1266）覆盖；表达式求值失败（语法 / 运行错误）上抛
// （服务端配置错误，服务层归 §1.6 兜底），求值结果为空值（undefined /
// 非字符串）时跳过该键、保留渠道抽取值（可选字段缺失不应打断登录）。
// openid 为空 → ErrEmptyOpenID。Raw 只落用户信息响应（§12.1 行 1428-1436：
// 落 user_thirdparty_bind.extra，不得含任何厂商会话密钥——令牌响应
// （access_token 等）仅参与字段抽取，绝不进 Raw）。
func ExtractIdentity(key, typ string, spec IdentitySpec, tok *provider.Token,
	user map[string]any, mapping map[string]string) (*provider.ExternalIdentity, error) {
	if tok == nil {
		return nil, ErrNilToken
	}
	merged := make(map[string]any, len(tok.Raw)+len(user))
	for k, v := range tok.Raw {
		merged[k] = v
	}
	for k, v := range user {
		merged[k] = v
	}
	id := &provider.ExternalIdentity{
		ProviderKey:  key,
		ProviderType: typ,
		OpenID:       firstString(merged, spec.OpenID...),
		UnionID:      firstString(merged, spec.UnionID...),
		Username:     firstString(merged, spec.Username...),
		Nickname:     firstString(merged, spec.Nickname...),
		Email:        firstString(merged, spec.Email...),
		Phone:        firstString(merged, spec.Phone...),
		AvatarURL:    firstString(merged, spec.Avatar...),
		Raw:          user, // 令牌响应绝不进 Raw（凭证类字段禁入 extra）
	}
	if ev, ok := merged["email_verified"].(bool); ok {
		id.EmailVerified = ev
	}
	if len(mapping) > 0 {
		vars := Flatten(merged)
		for field, expr := range mapping {
			v, err := jsonata.Evaluate(expr, vars)
			if err != nil {
				if errors.Is(err, jsonata.ErrNotString) {
					continue // 空值跳过，保留渠道抽取值
				}
				return nil, fmt.Errorf("oauthcore: user_mapping %q: %w", field, err)
			}
			switch field {
			case "open_id":
				id.OpenID = v
			case "union_id":
				id.UnionID = v
			case "username":
				id.Username = v
			case "nickname":
				id.Nickname = v
			case "email":
				id.Email = v
			case "phone":
				id.Phone = v
			case "avatar_url":
				id.AvatarURL = v
			default:
				return nil, fmt.Errorf("oauthcore: user_mapping: unknown field %q", field)
			}
		}
	}
	if id.OpenID == "" {
		return nil, ErrEmptyOpenID
	}
	return id, nil
}

// DiscoverOIDC 拉取 {provider_url}/.well-known/openid-configuration，
// 返回授权 / 令牌 / 用户信息端点（§12.2 行 1478：填 provider_url 自动
// discovery）。三端点任一缺失视为该 IdP 不被支持，构造期即失败。
func DiscoverOIDC(ctx context.Context, hc *http.Client, providerURL string) (authURL, tokenURL, userInfoURL string, err error) {
	providerURL = strings.TrimSuffix(strings.TrimSpace(providerURL), "/")
	if providerURL == "" {
		return "", "", "", ErrMissingEndpoint
	}
	status, body, err := do(ctx, hc, http.MethodGet, providerURL+"/.well-known/openid-configuration", nil, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("oidc discovery: %w", err)
	}
	if status < 200 || status >= 300 {
		return "", "", "", &ProviderError{Status: status, Code: "http_" + strconv.Itoa(status), Desc: truncate(string(body))}
	}
	var doc struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", "", "", fmt.Errorf("oidc discovery: %w", err)
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" || doc.UserinfoEndpoint == "" {
		return "", "", "", fmt.Errorf("oidc discovery: %w: authorization/token/userinfo endpoint", ErrMissingEndpoint)
	}
	return doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.UserinfoEndpoint, nil
}

// NewRewriteClient 构造把任意请求改写到 base 的 http.Client（渠道单测用
// httptest 扮演厂商端点；生产代码不使用——渠道端点是厂商固定地址，测试
// 需要本地拦截）。
func NewRewriteClient(base string) *http.Client {
	u, err := url.Parse(base)
	if err != nil {
		panic(err)
	}
	return &http.Client{Transport: rewriteTransport{base: u, rt: http.DefaultTransport}, Timeout: defaultTimeout}
}

// RawGet 旧式端点裸 GET（QQ /oauth2.0/me 的 JSONP 等非 JSON 响应用；
// 调用方自行解析响应体），返回原始状态码与响应体。
func RawGet(ctx context.Context, hc *http.Client, rawURL string, headers map[string]string) (int, []byte, error) {
	return do(ctx, hc, http.MethodGet, rawURL, nil, headers)
}

// RawPost 旧式网关裸 form POST（支付宝 openapi 网关等；调用方自行签名、
// 自行解析响应体），返回原始状态码与响应体。
func RawPost(ctx context.Context, hc *http.Client, rawURL string, form url.Values) (int, []byte, error) {
	return do(ctx, hc, http.MethodPost, rawURL, form, nil)
}

// rewriteTransport 把请求 URL 的 scheme / host 改写为 httptest 服务器。
type rewriteTransport struct {
	base *url.URL
	rt   http.RoundTripper
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = t.base.Scheme
	clone.URL.Host = t.base.Host
	return t.rt.RoundTrip(clone)
}

// do 出站 HTTP：POST 时 form 作为请求体（Content-Type 表单编码），headers
// 追加渠道特定头（如 GitHub Accept: application/json）；响应体限制
// maxBodyBytes。hc 为 nil 时用默认客户端（10s 超时）。
func do(ctx context.Context, hc *http.Client, method, rawURL string, form url.Values, headers map[string]string) (int, []byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return 0, nil, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
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

// parseTokenBody 解析令牌端点响应：非 2xx → *ProviderError（尽力提取错误
// 字段）；2xx 先按 JSON（成功：access_token / refresh_token / id_token /
// expires_in，数字或字符串；失败：error / errcode / error_code 归
// *ProviderError），再回退 form 编码（QQ 旧式 access_token=...&expires_in=...）。
func parseTokenBody(status int, body []byte) (*provider.Token, error) {
	if status < 200 || status >= 300 {
		if pe := errFromBody(status, body); pe != nil {
			return nil, pe
		}
		return nil, &ProviderError{Status: status, Code: "http_" + strconv.Itoa(status), Desc: truncate(string(body))}
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err == nil {
		if code, desc := errFields(m); code != "" {
			return nil, &ProviderError{Status: status, Code: code, Desc: desc}
		}
		at := firstString(m, "access_token")
		if at == "" {
			return nil, &ProviderError{Status: status, Code: "empty_access_token", Desc: truncate(string(body))}
		}
		tok := &provider.Token{
			AccessToken:  at,
			RefreshToken: firstString(m, "refresh_token"),
			IDToken:      firstString(m, "id_token"),
			Raw:          m,
		}
		if f, ok := m["expires_in"].(float64); ok {
			tok.ExpiresIn = int64(f)
		} else if s := firstString(m, "expires_in"); s != "" {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				tok.ExpiresIn = n
			}
		}
		return tok, nil
	}
	vals, perr := url.ParseQuery(strings.TrimSpace(string(body)))
	if perr == nil && vals.Get("access_token") != "" {
		tok := &provider.Token{
			AccessToken:  vals.Get("access_token"),
			RefreshToken: vals.Get("refresh_token"),
			IDToken:      vals.Get("id_token"),
		}
		if n, err := strconv.ParseInt(vals.Get("expires_in"), 10, 64); err == nil {
			tok.ExpiresIn = n
		}
		raw := make(map[string]any, len(vals))
		for k := range vals {
			raw[k] = vals.Get(k)
		}
		tok.Raw = raw
		return tok, nil
	}
	return nil, &ProviderError{Status: status, Code: "unparsable_token_response", Desc: truncate(string(body))}
}

// errFromBody 从错误响应体提取 *ProviderError（HTTP 非 2xx 或令牌端点
// 错误体）；无 JSON 错误字段时退化为纯 HTTP 状态。
func errFromBody(status int, body []byte) *ProviderError {
	var m map[string]any
	if json.Unmarshal(body, &m) == nil {
		if code, desc := errFields(m); code != "" {
			return &ProviderError{Status: status, Code: code, Desc: desc}
		}
	}
	return &ProviderError{Status: status, Code: "http_" + strconv.Itoa(status), Desc: truncate(string(body))}
}

// errFromUserBody 用户信息端点的错误归一（非 2xx 或 2xx 错误体）。
func errFromUserBody(status int, body []byte) *ProviderError {
	if status >= 200 && status < 300 {
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			if code, desc := errFields(m); code != "" {
				return &ProviderError{Status: status, Code: code, Desc: desc}
			}
		}
		return nil
	}
	return errFromBody(status, body)
}

// errFields 从响应 map 提取 (code, desc)：code 取 error / errcode /
// error_code 首个非空；desc 取 error_description / errmsg / error_message /
// message 首个非空。code 为空表示响应不含错误字段。
func errFields(m map[string]any) (code, desc string) {
	code = firstString(m, "error", "errcode", "error_code")
	if code == "" {
		return "", ""
	}
	desc = firstString(m, "error_description", "errmsg", "error_message", "message", "sub_msg")
	return code, desc
}

// firstString 按 keys 顺序取首个非空标量字符串（float64 整数化，避免
// GitHub id 渲染成科学计数 / 带 .0）。
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := scalarString(m[k]); s != "" {
			return s
		}
	}
	return ""
}

// scalarString 标量转字符串：string 原样；float64 整数值 FormatInt（避免
// 指数形态）、小数值 FormatFloat；bool FormatBool；其余（nil / 对象 /
// 数组）为空。
func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1e15 {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}

// Flatten 把合并 map 的顶层标量拍平为字符串 map（jsonata.Evaluate 的
// 内置变量集，表达式经 $.<name> 引用，接口文档 §5.3 行 1261）：对象 /
// 数组 JSON 序列化为字符串；nil 跳过。
func Flatten(m map[string]any) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		switch t := v.(type) {
		case string:
			out[k] = t
		case float64, bool:
			out[k] = scalarString(v)
		case nil:
			// 跳过空值
		default:
			if b, err := json.Marshal(t); err == nil {
				out[k] = string(b)
			}
		}
	}
	return out
}

// truncate 错误描述截断（rune 安全）。
func truncate(s string) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > maxErrDesc {
		return string(r[:maxErrDesc]) + "…"
	}
	return s
}
