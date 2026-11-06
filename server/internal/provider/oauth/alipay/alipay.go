// 支付宝渠道适配器（docs/后端架构.md §12.2 行 1473 内置清单：支付宝需
// RSA 签名，cert 存支付宝公钥）：channel=redirect。协议差异：授权端点为
// publicAppAuthorize.htm（scope 固定 auth_user）；令牌与用户信息均走
// openapi 网关、须 RSA2 签名（stdlib 实现，无新第三方依赖）——应用私钥
// 存 Ext.client_secret（PEM），支付宝公钥存 Ext.cert（PEM，用于验签响应
// 签名；未配置时跳过验签，见 build 注释）。Ext.provider_url 可覆盖网关
// （缺省生产网关，沙箱环境可改填）。凭证装配期取自 Provider 实例（§13.0
// 唯一口径），运行期不回读配置。
//
// 真机联调未覆盖（无支付宝应用凭据）：签名链经测试内 RSA 密钥对自证，
// 支付宝真实网关互通性未经真机验证。
package alipay

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

// Type 渠道类型（§12.2）。
const Type = "alipay"

// 端点（支付宝官方固定地址）。
const (
	authURL      = "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm"
	gatewayURL   = "https://openapi.alipay.com/gateway.do"
	authScopes   = "auth_user" // 支付宝仅支持 auth_user / auth_base
	methodToken  = "alipay.system.oauth.token"
	methodShare  = "alipay.user.info.share"
	timestampFmt = "2006-01-02 15:04:05"
)

// 可判别错误。
var (
	// ErrNotConfigured client_id / client_secret（应用私钥）缺失（§13.0：
	// 视为未配置）。
	ErrNotConfigured = errors.New("alipay: provider not configured")
	// ErrBadKey 私钥 PEM 解析失败。
	ErrBadKey = errors.New("alipay: bad private key")
	// ErrBadCert 支付宝公钥 PEM 解析失败。
	ErrBadCert = errors.New("alipay: bad alipay public key")
	// ErrSignVerify 响应签名验签失败（可能被篡改 / 公钥配置错误）。
	ErrSignVerify = errors.New("alipay: response sign verify failed")
)

func init() {
	m := oauthcore.NewMeta(Type, "支付宝", provider.ChannelRedirect)
	for i, f := range m.Fields {
		switch f.Key {
		case "client_id":
			m.Fields[i].Label = "AppID"
		case "client_secret":
			m.Fields[i].Label = "应用私钥（PEM）"
			m.Fields[i].Help = "PKCS8 / PKCS1 RSA 私钥，用于请求 RSA2 签名"
		case "cert":
			m.Fields[i].Label = "支付宝公钥（PEM）"
			m.Fields[i].Help = "用于验签网关响应；留空跳过验签（不推荐）"
		case "provider_url":
			m.Fields[i].Label = "网关地址"
			m.Fields[i].Help = "留空默认 https://openapi.alipay.com/gateway.do（沙箱可改填沙箱网关）"
		}
	}
	provider.Register(Type, m, newAdapter)
}

// Adapter 支付宝适配器（channel=redirect）。
type Adapter struct {
	key         string
	appID       string
	privateKey  *rsa.PrivateKey // 应用私钥（请求签名）
	alipayPub   *rsa.PublicKey  // 支付宝公钥（响应验签；nil = 跳过）
	gateway     string
	scopes      string
	userMapping map[string]string
	hc          *http.Client // nil → oauthcore 默认客户端；测试注入改写客户端
}

// newAdapter 注册表工厂。build 仅供测试注入 http.Client。
func newAdapter(p *provider.Provider) (provider.AuthAdapter, error) { return build(p, nil) }

func build(p *provider.Provider, hc *http.Client) (*Adapter, error) {
	if p == nil || p.Ext == nil {
		return nil, provider.ErrNilProvider
	}
	appID := p.Ext.GetClientId()
	privPEM := p.Ext.GetClientSecret()
	if appID == "" || privPEM == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	priv, err := parsePrivateKey(privPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: provider_key=%q: %v", ErrBadKey, p.Key, err)
	}
	// cert（支付宝公钥）留空时跳过响应验签：令牌链路走 TLS 直连官方网关，
	// 验签是纵深防御而非唯一防线；允许最小配置跑通，注释明示不推荐。
	var pub *rsa.PublicKey
	if cert := p.Ext.GetCert(); cert != "" {
		pub, err = parsePublicKey(cert)
		if err != nil {
			return nil, fmt.Errorf("%w: provider_key=%q: %v", ErrBadCert, p.Key, err)
		}
	}
	gateway := strings.TrimSpace(p.Ext.GetProviderUrl())
	if gateway == "" {
		gateway = gatewayURL
	}
	a := &Adapter{
		key:         p.Key,
		appID:       appID,
		privateKey:  priv,
		alipayPub:   pub,
		gateway:     gateway,
		scopes:      p.Ext.GetScopes(), // 留空默认 auth_user（build 时填充见下）
		userMapping: p.Ext.GetUserMapping(),
		hc:          hc,
	}
	if a.scopes == "" {
		a.scopes = authScopes
	}
	return a, nil
}

// Channel 固定为 redirect。
func (a *Adapter) Channel() provider.ThirdPartyChannel { return provider.ChannelRedirect }

// BuildAuthURL 组装跳转授权 URL：publicAppAuthorize.htm，scope 固定
// auth_user（state 由 service 层生成后透传，§12.4；无 response_type——
// 支付宝协议不带）。
func (a *Adapter) BuildAuthURL(ctx *provider.AuthContext) (string, error) {
	if ctx == nil || ctx.State == "" {
		return "", oauthcore.ErrEmptyState
	}
	scope := ctx.Scope
	if scope == "" {
		scope = a.scopes
	}
	q := url.Values{}
	q.Set("app_id", a.appID)
	q.Set("scope", scope)
	q.Set("redirect_uri", ctx.RedirectURI)
	q.Set("state", ctx.State)
	return authURL + "?" + q.Encode(), nil
}

// Exchange 授权码换令牌：网关 form 请求（method=alipay.system.oauth.token，
// RSA2 签名），响应内层对象含 access_token 与 user_id（= openid）。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	if in.Code == "" {
		return nil, oauthcore.ErrEmptyCode
	}
	biz := map[string]string{
		"app_id":     a.appID,
		"method":     methodToken,
		"charset":    "utf-8",
		"sign_type":  "RSA2",
		"timestamp":  time.Now().Format(timestampFmt),
		"version":    "1.0",
		"grant_type": "authorization_code",
		"code":       in.Code,
	}
	inner, err := a.callGateway(ctx, biz, methodToken)
	if err != nil {
		return nil, err
	}
	at, _ := inner["access_token"].(string)
	if at == "" {
		return nil, &oauthcore.ProviderError{Status: 200, Code: "empty_access_token", Desc: "alipay token response without access_token"}
	}
	tok := &provider.Token{
		AccessToken:  at,
		RefreshToken: asString(inner["refresh_token"]),
		ExpiresIn:    asInt64(inner["expires_in"]),
		Raw:          inner, // user_id 等供 FetchUser 抽取（不含响应签名原文）
	}
	return tok, nil
}

// FetchUser 拉取 alipay.user.info.share（昵称 / 头像，auth_user scope 且
// 应用具备资质时返回）：拉取失败不阻断登录（部分应用仅有 auth_base，无
// 资质属常态），best-effort 跳过、只落 openid。Raw 落 share 内层响应
// （不含任何令牌）。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	user := map[string]any{}
	if at, _ := t.Raw["access_token"].(string); at != "" {
		biz := map[string]string{
			"app_id":     a.appID,
			"method":     methodShare,
			"charset":    "utf-8",
			"sign_type":  "RSA2",
			"timestamp":  time.Now().Format(timestampFmt),
			"version":    "1.0",
			"auth_token": at,
		}
		if inner, err := a.callGateway(ctx, biz, methodShare); err == nil {
			user = inner
		}
		// share 失败 best-effort：不阻断登录（openid 已在令牌响应）。
	}
	spec := oauthcore.IdentitySpec{
		OpenID:   []string{"user_id"},
		Nickname: []string{"nick_name", "nick"},
		Avatar:   []string{"avatar"},
	}
	return oauthcore.ExtractIdentity(a.key, Type, spec, t, user, a.userMapping)
}

// callGateway 网关调用：biz 参数 RSA2 签名（除 sign / sign_type 外按 key
// 升序 k=v 拼接、空值剔除）→ POST form → 解析 {method}_response 内层对象
// / error_response；cert 已配置时验签响应（sign 覆盖内层对象原文——经
// map[string]json.RawMessage 保序提取，不经二次序列化）。
func (a *Adapter) callGateway(ctx context.Context, biz map[string]string, method string) (map[string]any, error) {
	form := url.Values{}
	for k, v := range biz {
		if v != "" {
			form.Set(k, v)
		}
	}
	sign, err := rsa2Sign(signContent(form), a.privateKey)
	if err != nil {
		return nil, fmt.Errorf("alipay: sign: %w", err)
	}
	form.Set("sign", sign)

	status, body, err := oauthcore.RawPost(ctx, a.hc, a.gateway, form)
	if err != nil {
		return nil, err
	}
	// 保序解包：内层对象原文供验签，键值供业务。
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(body, &outer); err != nil {
		return nil, &oauthcore.ProviderError{Status: status, Code: "unparsable_gateway_response", Desc: truncateForErr(body)}
	}
	if rawErr, ok := outer["error_response"]; ok {
		var e map[string]any
		if json.Unmarshal(rawErr, &e) == nil {
			code := asString(e["sub_code"])
			if code == "" {
				code = asString(e["code"])
			}
			return nil, &oauthcore.ProviderError{
				Status: status,
				Code:   code,
				Desc:   asString(e["sub_msg"]),
			}
		}
		return nil, &oauthcore.ProviderError{Status: status, Code: "error_response", Desc: truncateForErr(rawErr)}
	}
	innerRaw, ok := outer[methodResponseKey(method)]
	if !ok {
		return nil, &oauthcore.ProviderError{Status: status, Code: "missing_response", Desc: truncateForErr(body)}
	}
	// 验签（cert 已配置时）：sign 内容 = 内层对象原文。
	if a.alipayPub != nil {
		signB64, _ := outer["sign"]
		var signStr string
		_ = json.Unmarshal(signB64, &signStr)
		if signStr == "" || !rsa2Verify(string(innerRaw), signStr, a.alipayPub) {
			return nil, ErrSignVerify
		}
	}
	var inner map[string]any
	if err := json.Unmarshal(innerRaw, &inner); err != nil {
		return nil, &oauthcore.ProviderError{Status: status, Code: "unparsable_response_object", Desc: truncateForErr(innerRaw)}
	}
	return inner, nil
}

// methodResponseKey 网关响应键：method 的点号替换为下划线再拼 _response
//（支付宝网关惯例：alipay.system.oauth.token → alipay_system_oauth_token_response）。
func methodResponseKey(method string) string {
	return strings.ReplaceAll(method, ".", "_") + "_response"
}

// signContent 支付宝 RSA2 签名原文：除 sign / sign_type 外的参数按 key
// ASCII 升序拼 `k=v`，`&` 连接（空值参数剔除）。
func signContent(form url.Values) string {
	keys := make([]string, 0, len(form))
	for k := range form {
		if k == "sign" || k == "sign_type" || form.Get(k) == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(form.Get(k))
	}
	return b.String()
}

// rsa2Sign SHA256withRSA（PKCS1 v1.5）签名后 base64。
func rsa2Sign(content string, key *rsa.PrivateKey) (string, error) {
	h := sha256.Sum256([]byte(content))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// rsa2Verify SHA256withRSA（PKCS1 v1.5）验签。
func rsa2Verify(content, signB64 string, pub *rsa.PublicKey) bool {
	sig, err := base64.StdEncoding.DecodeString(signB64)
	if err != nil {
		return false
	}
	h := sha256.Sum256([]byte(content))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) == nil
}

// parsePrivateKey 解析 PEM 私钥（PKCS8 优先，PKCS1 回退）。
func parsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("not an RSA private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// parsePublicKey 解析 PEM 公钥（PKIX）。
func parsePublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rk, nil
}

// asString 标量转字符串（数字整数化）。
func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

// asInt64 数字 / 字符串转 int64。
func asInt64(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		return n
	default:
		return 0
	}
}

// truncateForErr 响应体截断（错误描述）。
func truncateForErr(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
