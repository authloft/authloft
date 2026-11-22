// apple 专用适配器（docs/后端架构.md §12.2 内置清单、§15.5 apple 行）：
// channel=redirect。协议差异（docs/后端架构.md §15.5 apple 行）：client_secret 是动态签发的
// ES256 JWT（.p8 私钥 + team_id=iss + key_id=kid，exp 最长 6 个月、适配器内
// 缓存重签）；scope 含 name/email 时 response_mode 必须为 form_post，首次
// 授权回调额外携带 user JSON（昵称仅此一次返回）；身份在 id_token 内而非
// userinfo 接口，经 JWKS 验签（iss / aud / exp / nonce 全部 fail-closed）。
//
// ES256 签名与 JWK 验签以 stdlib 自实现（crypto/ecdsa + crypto/x509 的
// PKCS#8 解析 .p8），零第三方依赖；oidc 兜底无法表达动态 client_secret，
// 不可复用。端点（appleid.apple.com 授权 / 令牌 / JWKS）固化不透出。
// 凭证装配期取自 Provider 实例（§13.0），运行期不回读配置。
//
// 首次授权 user 合并经 ParseCallback + IdentityFromCallback 出口承载：
// form_post 回调解析 → id_token 验签（含 expectedNonce 比对）→ user JSON
// 派生昵称合并（仅回调携带 user 时，即首次授权；后续回调不携带则不产出
// 昵称，不覆盖既有身份记录）。接口契约路径 FetchUser 走令牌响应内的
// id_token（本适配器授权请求不携带 nonce，故该路径拒绝带 nonce 的令牌；
// state 防 CSRF 由 service 层负责，nonce 落库比对属后续接线）。
package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"authloft/internal/provider"
	"authloft/internal/provider/auth/oauthcore"
)

// Type 渠道类型（§12.2 内置清单：apple）。
const Type = "apple"

// 端点与 issuer（Apple 官方固定地址，§15.5：固化不透出表单）。
const (
	authorizeURL = "https://appleid.apple.com/auth/authorize"
	tokenURL     = "https://appleid.apple.com/auth/oauth2/v2/token"
	jwksURL      = "https://appleid.apple.com/auth/keys"
	issuer       = "https://appleid.apple.com"
)

// client_secret JWT 与 Schema 预设（§15.5 apple 行：exp 最长 6 个月
// 15777000 秒、建议缓存并定期重签——取 180 天留安全余量）。
const (
	algES256           = "ES256"
	clientSecretTTL    = 180 * 24 * time.Hour
	defaultScopes      = "name email"
	defaultUserMapping = `{"open_id":"$.sub","nickname":"$.nickname","email":"$.email"}`
)

// 可判别错误：验签各失败路径独立哨兵，供服务层与测试可证伪断言。
var (
	// ErrNotConfigured client_id / team_id / key_id / cert 缺失（§13.0：
	// 装配期视为未配置，fail-closed）。
	ErrNotConfigured = errors.New("apple: provider not configured")
	// ErrBadKey .p8 私钥解析失败（缺 PEM / 非 PKCS#8 / 非 EC P-256）。
	ErrBadKey = errors.New("apple: bad .p8 private key")
	// ErrCallbackInvalid form_post 回调参数缺失或 user JSON 非法。
	ErrCallbackInvalid = errors.New("apple: invalid form_post callback")
	// ErrBadIDToken id_token 结构非法（段数 / base64 / JSON）或缺失。
	ErrBadIDToken = errors.New("apple: bad id_token")
	// ErrBadAlg id_token alg 非 ES256（防算法混淆，fail-closed）。
	ErrBadAlg = errors.New("apple: unexpected id_token alg")
	// ErrUnknownKid id_token 的 kid 不在 JWKS（密钥轮换未同步等）。
	ErrUnknownKid = errors.New("apple: id_token kid not in jwks")
	// ErrSignVerify id_token 签名验证失败（被篡改 / 密钥不符）。
	ErrSignVerify = errors.New("apple: id_token signature verify failed")
	// ErrClaimsInvalid id_token claims 校验不过：iss / aud / exp / nonce
	// 任一不匹配（nonce 语义：必须与期望值相等——授权请求未携带 nonce 时
	// 期望为空串，令牌携带 nonce 即视为异常令牌拒绝）。
	ErrClaimsInvalid = errors.New("apple: id_token claims invalid")
)

func init() {
	// Schema 只声明管理员填写项（§15.5 收窄边界）：client_secret 由适配器
	// 动态签发不透出；端点固化不透出；team_id(51) / key_id(52) 必填，
	// cert(4) 语义扩为承载 .p8 私钥 PEM（接口文档 §12.1）。scopes 与
	// user_mapping 预设值随字段 default 下发，管理员可改写、适配器照常消费。
	// Label / Help 复用前端字典既有键（跨端契约：字段文案只准 i18n 键，
	// 本卡不触 web/——teamId/keyId 系 T-074 为 Apple 预置；cert 渲染文案
	// 「应用私钥（PEM）」语义渠道中立，故复用该键）。
	fields := []provider.FieldMeta{
		{Key: "client_id", Label: "admin.schemaField.clientIdLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		{Key: "team_id", Label: "admin.schemaField.teamIdLabel", Type: "text", Section: "credential", Required: true, Help: "admin.schemaField.teamIdHelp", Storage: provider.StorageExt},
		{Key: "key_id", Label: "admin.schemaField.keyIdLabel", Type: "text", Section: "credential", Required: true, Help: "admin.schemaField.keyIdHelp", Storage: provider.StorageExt},
		{Key: "cert", Label: "admin.schemaField.alipayPrivateKeyLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		{Key: "scopes", Label: "admin.schemaField.scopesLabel", Type: "text", Section: "credential", Default: defaultScopes, Storage: provider.StorageExt},
		{Key: "user_mapping", Label: "admin.schemaField.userMappingLabel", Type: "json", Section: "endpoint", Advanced: true, Default: defaultUserMapping, Storage: provider.StorageExt},
	}
	provider.Register(Type, provider.Meta{
		Type:        Type,
		DisplayName: "Apple",
		Category:    "auth",
		Channel:     provider.ChannelRedirect,
		Fields:      fields,
		Schema:      oauthcore.SchemaFor(fields),
	}, newAdapter)
}

// Callback form_post 回调参数（§15.5 apple 行：回调为 form_post）：code / state
// 每次回调必有；id_token 在请求 response_type 携带时返回；user 为 JSON
// 字符串、仅首次授权返回（后续回调 Apple 不再下发）。
type Callback struct {
	Code    string
	IDToken string
	State   string
	User    string
}

// ParseCallback 解析 form_post 回调（POST application/x-www-form-urlencoded
// 响应体）：code / state 缺失即 ErrCallbackInvalid（fail-closed）；state 与
// al_login_state 的比对归 service 层（§2.7.2），此处只做存在性闸门。
// id_token / user 可缺（后者仅首次授权携带），缺项由下游按路径判定。
func ParseCallback(form url.Values) (*Callback, error) {
	if form == nil {
		return nil, fmt.Errorf("%w: empty form", ErrCallbackInvalid)
	}
	cb := &Callback{
		Code:    form.Get("code"),
		IDToken: form.Get("id_token"),
		State:   form.Get("state"),
		User:    form.Get("user"),
	}
	if cb.Code == "" || cb.State == "" {
		return nil, fmt.Errorf("%w: code/state missing", ErrCallbackInvalid)
	}
	return cb, nil
}

// Adapter Apple 登录适配器（channel=redirect）。
type Adapter struct {
	key          string
	providerType string // 身份 ProviderType：build 期固化 p.Type（§15.3 单一真源）
	clientID     string
	teamID       string
	keyID        string
	privateKey   *ecdsa.PrivateKey
	scopes       string
	userMapping  map[string]string
	authURL      string
	tokenURL     string
	jwksURL      string
	issuer       string
	hc           *http.Client // nil → oauthcore 默认客户端；测试注入改写客户端
	now          func() time.Time

	// client_secret 缓存重签（§15.5）：JWT exp 固定 TTL，未到期
	// 直接复用缓存串；到期重签（iat / exp 随之更新）。适配器实例按请求构造，
	// 缓存命不中只是多签一次，正确性不受影响。
	mu           sync.Mutex
	cachedSecret string
	cachedExpiry time.Time
}

// newAdapter 注册表工厂：官方端点固化。
func newAdapter(p *provider.Provider) (provider.AuthAdapter, error) {
	hc, err := oauthcore.ClientFor(p)
	if err != nil {
		return nil, err
	}
	return build(p, hc, authorizeURL, tokenURL, jwksURL, issuer)
}

// build 端点可注入（httptest mock 覆盖 JWKS / 令牌链路）；生产路径经
// newAdapter 固化官方端点。凭证装配期一次解析（§13.0），.p8 非法即构造
// 失败（fail-closed），不把坏密钥放进运行期。
func build(p *provider.Provider, hc *http.Client, authURL, tokenURL, jwksURL, iss string) (*Adapter, error) {
	if p == nil || p.Ext == nil {
		return nil, provider.ErrNilProvider
	}
	clientID := p.Ext.GetClientId()
	teamID := p.Ext.GetTeamId()
	keyID := p.Ext.GetKeyId()
	cert := p.Ext.GetCert()
	if clientID == "" || teamID == "" || keyID == "" || cert == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	key, err := parseP8(cert)
	if err != nil {
		return nil, fmt.Errorf("apple: provider_key=%q: %w", p.Key, err)
	}
	scopes := p.Ext.GetScopes()
	if scopes == "" {
		scopes = defaultScopes
	}
	return &Adapter{
		key:          p.Key,
		providerType: p.Type,
		clientID:     clientID,
		teamID:       teamID,
		keyID:        keyID,
		privateKey:   key,
		scopes:       scopes,
		userMapping:  p.Ext.GetUserMapping(),
		authURL:      authURL,
		tokenURL:     tokenURL,
		jwksURL:      jwksURL,
		issuer:       iss,
		hc:           hc,
		now:          time.Now,
	}, nil
}

// parseP8 解析 .p8 私钥（PKCS#8 封装的 EC P-256）。Apple 只签发 PKCS#8
// （BEGIN PRIVATE KEY），不回退 PKCS#1 / SEC1 等宽松形态——密钥材料语义
// 收紧在装配期（fail-closed），防错签发 client_secret。
func parseP8(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", ErrBadKey)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: pkcs8: %v", ErrBadKey, err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: not EC key", ErrBadKey)
	}
	if ek.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: not P-256", ErrBadKey)
	}
	return ek, nil
}

// Channel 固定为 redirect。
func (a *Adapter) Channel() provider.ThirdPartyChannel { return provider.ChannelRedirect }

// BuildAuthURL 组装跳转授权 URL（state 由 service 层生成后透传，§12.4）。
// 有效 scope（授权上下文覆盖或缺省预设）含 name / email 时必须
// response_mode=form_post（§15.5：Apple 协议硬约束）。
func (a *Adapter) BuildAuthURL(ctx *provider.AuthContext) (string, error) {
	extra := map[string]string{}
	effective := a.scopes
	if ctx != nil && ctx.Scope != "" {
		effective = ctx.Scope
	}
	for _, s := range strings.Fields(effective) {
		if s == "name" || s == "email" {
			extra["response_mode"] = "form_post"
			break
		}
	}
	return oauthcore.BuildAuthURL(a.authURL, a.clientID, ctx, a.scopes, extra)
}

// Exchange 授权码换令牌：client_secret 取动态签发的 ES256 JWT（缓存重签），
// 其余走标准 POST form（JSON 响应）。
func (a *Adapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	secret, err := a.clientSecret()
	if err != nil {
		return nil, err
	}
	return oauthcore.ExchangePostForm(ctx, a.hc, a.tokenURL, a.clientID, secret, in, nil, nil)
}

// clientSecret 取缓存的 client_secret JWT；未缓存或已到 exp 重签。
func (a *Adapter) clientSecret() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.cachedSecret != "" && now.Before(a.cachedExpiry) {
		return a.cachedSecret, nil
	}
	secret, expiry, err := signClientSecret(a.privateKey, a.teamID, a.keyID, a.clientID, now, clientSecretTTL)
	if err != nil {
		return "", err
	}
	a.cachedSecret = secret
	a.cachedExpiry = expiry
	return secret, nil
}

// FetchUser 接口契约路径：验证令牌响应内的 id_token（JWKS 验签 + iss/aud/
// exp fail-closed，nonce 比对空期望——本适配器授权请求不带 nonce）后抽取
// 统一身份；ProviderType 取构造期固化的 p.Type。首次授权 user JSON 不在
// 令牌响应内，合并走 IdentityFromCallback。
func (a *Adapter) FetchUser(ctx context.Context, t *provider.Token) (*provider.ExternalIdentity, error) {
	if t == nil {
		return nil, oauthcore.ErrNilToken
	}
	claims, err := a.verifyIDToken(ctx, t.IDToken, "")
	if err != nil {
		return nil, err
	}
	spec := oauthcore.IdentitySpec{
		OpenID: []string{"sub"},
		Email:  []string{"email"},
	}
	return oauthcore.ExtractIdentity(a.key, a.providerType, spec, t, normalizeClaims(claims), a.userMapping)
}

// IdentityFromCallback form_post 回调全链路（首次授权 user 合并入口）：
// id_token 验签（aud / nonce / exp fail-closed，expectedNonce 为授权请求
// 侧生成、经状态载荷带回的期望值）→ user JSON 派生昵称合并（仅 cb.User
// 非空即首次授权时；后续回调不带 user，昵称不产出、不覆盖既有身份记录）
// → user_mapping 求值出统一身份。
func (a *Adapter) IdentityFromCallback(ctx context.Context, cb *Callback, expectedNonce string) (*provider.ExternalIdentity, error) {
	if cb == nil {
		return nil, fmt.Errorf("%w: nil callback", ErrCallbackInvalid)
	}
	claims, err := a.verifyIDToken(ctx, cb.IDToken, expectedNonce)
	if err != nil {
		return nil, err
	}
	merged, err := mergeFirstUser(claims, cb.User)
	if err != nil {
		return nil, err
	}
	spec := oauthcore.IdentitySpec{
		OpenID:   []string{"sub"},
		Email:    []string{"email"},
		Nickname: []string{"nickname"},
	}
	// Raw 只落合并后的身份对象（id_token claims 与 user 派生字段均无凭证
	// 语义，§12.1 Raw 红线不受影响）。
	return oauthcore.ExtractIdentity(a.key, a.providerType, spec,
		&provider.Token{IDToken: cb.IDToken}, merged, a.userMapping)
}

// mergeFirstUser 合并首次授权 user JSON：name.firstName + lastName 派生
// nickname、user.email 覆盖 claims email（同为用户侧最新值）。userJSON 为空
// （非首次授权）原样返回 claims；JSON 非法 fail-closed（异常回调不打断
// 验签结论的保守性）。
func mergeFirstUser(claims map[string]any, userJSON string) (map[string]any, error) {
	merged := normalizeClaims(claims)
	if userJSON == "" {
		return merged, nil
	}
	var u struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal([]byte(userJSON), &u); err != nil {
		return nil, fmt.Errorf("%w: user json: %v", ErrCallbackInvalid, err)
	}
	nickname := strings.TrimSpace(strings.Join([]string{u.Name.FirstName, u.Name.LastName}, " "))
	if nickname != "" {
		merged["nickname"] = nickname
	}
	if u.Email != "" {
		merged["email"] = u.Email
	}
	return merged, nil
}

// normalizeClaims 就地归一 Apple id_token 的字符串布尔（email_verified
// 返回 "true"/"false" 字符串，与标准 OIDC 的布尔形态不符）。
func normalizeClaims(claims map[string]any) map[string]any {
	if s, ok := claims["email_verified"].(string); ok {
		claims["email_verified"] = s == "true"
	}
	return claims
}

// verifyIDToken id_token 验签全流程（全部 fail-closed）：结构 → alg 白名单
// → JWKS 按 kid 取公钥 → ES256 验签 → iss / aud / exp / nonce 比对。
func (a *Adapter) verifyIDToken(ctx context.Context, idToken, expectedNonce string) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a JWT", ErrBadIDToken)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &header) != nil {
		return nil, fmt.Errorf("%w: header", ErrBadIDToken)
	}
	if header.Alg != algES256 {
		return nil, fmt.Errorf("%w: %q", ErrBadAlg, header.Alg)
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload", ErrBadIDToken)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload json", ErrBadIDToken)
	}
	pub, err := a.lookupJWK(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	if !verifyES256(parts[0]+"."+parts[1], parts[2], pub) {
		return nil, ErrSignVerify
	}
	if iss, _ := claims["iss"].(string); iss != a.issuer {
		return nil, fmt.Errorf("%w: iss mismatch", ErrClaimsInvalid)
	}
	if !audMatches(claims["aud"], a.clientID) {
		return nil, fmt.Errorf("%w: aud mismatch", ErrClaimsInvalid)
	}
	exp, ok := claims["exp"].(float64)
	if !ok || a.now().Unix() >= int64(exp) {
		return nil, fmt.Errorf("%w: exp expired", ErrClaimsInvalid)
	}
	if nonce, _ := claims["nonce"].(string); nonce != expectedNonce {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrClaimsInvalid)
	}
	return claims, nil
}

// audMatches aud 单字符串（Apple 形态）或数组任一匹配均算命中。
func audMatches(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// lookupJWK 拉 JWKS 并按 kid 取 EC P-256 公钥（kid 空或未命中 →
// ErrUnknownKid）。JWKS 不做进程内缓存：与 oidc discovery 同一口径——
// 适配器按请求构造、登录 QPS 下一次额外 GET 开销可接受，避免提前设计
// 缓存与失效。
func (a *Adapter) lookupJWK(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	if kid == "" {
		return nil, fmt.Errorf("%w: empty kid", ErrUnknownKid)
	}
	status, body, err := oauthcore.RawGet(ctx, a.hc, a.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, &oauthcore.ProviderError{Status: status, Code: "jwks", Desc: "jwks endpoint error"}
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("apple: jwks decode: %w", err)
	}
	for _, k := range jwks.Keys {
		if k.Kid != kid || k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		return ecPubKey(k.X, k.Y)
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownKid, kid)
}

// ecPubKey 由 JWK 坐标构造 P-256 公钥（非法坐标 fail-closed）。
func ecPubKey(xB64, yB64 string) (*ecdsa.PublicKey, error) {
	xb, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("%w: jwk x", ErrUnknownKid)
	}
	yb, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("%w: jwk y", ErrUnknownKid)
	}
	x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("%w: jwk point off curve", ErrUnknownKid)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// verifyES256 JWS ES256 验签：签名为 r||s 各 32 字节的 base64url 串，
// 摘要为 SHA-256（RFC 7518 §3.4）。
func verifyES256(signingInput, sigB64 string, pub *ecdsa.PublicKey) bool {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return false
	}
	h := sha256.Sum256([]byte(signingInput))
	return ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// clientSecretClaims client_secret JWT 载荷（Apple 规范：iss=Team ID、
// sub=Services ID、aud=授权服务器）。
type clientSecretClaims struct {
	Iss string `json:"iss"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Aud string `json:"aud"`
	Sub string `json:"sub"`
}

// signClientSecret 签发动态 client_secret JWT（ES256）：header 带 kid，
// exp = now + ttl（≤ Apple 上限 6 个月）；返回令牌与到期时刻（缓存判定
// 基准与 JWT exp 同源，不另设口径）。
func signClientSecret(key *ecdsa.PrivateKey, teamID, keyID, clientID string, now time.Time, ttl time.Duration) (string, time.Time, error) {
	header, _ := json.Marshal(map[string]string{"alg": algES256, "kid": keyID})
	expiry := now.Add(ttl)
	claims, _ := json.Marshal(clientSecretClaims{
		Iss: teamID,
		Iat: now.Unix(),
		Exp: expiry.Unix(),
		Aud: issuer,
		Sub: clientID,
	})
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	h := sha256.Sum256([]byte(signingInput))
	sigDER, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("apple: sign client_secret: %w", err)
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sigDER, &sig); err != nil {
		return "", time.Time{}, fmt.Errorf("apple: sign client_secret: %w", err)
	}
	sigBuf := make([]byte, 64)
	sig.R.FillBytes(sigBuf[:32])
	sig.S.FillBytes(sigBuf[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBuf), expiry, nil
}
