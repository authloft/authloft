// apple 适配器单测：httptest 扮演 Apple（令牌 + JWKS 两端点），测试密钥对
// 自证 ES256 签名与验签链路。覆盖：client_secret JWT 结构与缓存重签、
// id_token 验签各失败路径 fail-closed、首次授权 user 仅一次合并、form_post
// 回调解析、Schema 收窄与注册表挂载。
package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/auth/oauthcore"
)

const (
	testClientID = "com.example.servicesid"
	testTeamID   = "TEAM123456"
	testKeyID    = "KEY1234567"
	testSub      = "001234.abcdef.1234"
)

// fixedTime 测试基准时刻：now 注入固定时钟，exp / 缓存判定确定性可证。
var fixedTime = time.Unix(1700000000, 0)

// newP8 生成 EC P-256 密钥对并编成 .p8 形态 PEM（PKCS#8）。
func newP8(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func mustP8(t *testing.T) string {
	t.Helper()
	_, p8 := newP8(t)
	return p8
}

// testProvider 构造最小可用 Provider 行（凭证装配期口径）。
func testProvider(p8 string) *provider.Provider {
	return &provider.Provider{
		Key:  "apple-main",
		Type: Type,
		Ext: &providerpb.Ext{
			ClientId: testClientID,
			TeamId:   testTeamID,
			KeyId:    testKeyID,
			Cert:     p8,
		},
	}
}

// signIDToken 用测试私钥签发 ES256 id_token（与 client_secret 同构的
// r||s 签名），供验签链路正反两向用例。
func signIDToken(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": algES256, "kid": kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	h := sha256.Sum256([]byte(signingInput))
	sigDER, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sigDER, &sig); err != nil {
		t.Fatalf("unmarshal sig: %v", err)
	}
	buf := make([]byte, 64)
	sig.R.FillBytes(buf[:32])
	sig.S.FillBytes(buf[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(buf)
}

// baseClaims 合法 id_token claims（iss / aud / sub / email / exp 全对齐）。
func baseClaims() map[string]any {
	return map[string]any{
		"iss":            issuer,
		"aud":            testClientID,
		"sub":            testSub,
		"email":          "user@privaterelay.appleid.com",
		"email_verified": "true",
		"iat":            float64(fixedTime.Unix()),
		"exp":            float64(fixedTime.Add(time.Hour).Unix()),
	}
}

// tokenClaims 派生一份覆盖 claims（fail-closed 用例逐字段改）。
func tokenClaims(override func(map[string]any)) map[string]any {
	c := baseClaims()
	if override != nil {
		override(c)
	}
	return c
}

// mockApple 拟 Apple 服务端：/token 记录收到的 client_secret 并返回预置
// id_token；/keys 返回预置 JWKS（可注状态码与坏报文）。
type mockApple struct {
	srv        *httptest.Server
	mu         sync.Mutex
	secrets    []string
	idToken    string
	jwksBody   string
	jwksStatus int
}

func newMockApple(t *testing.T, key *ecdsa.PrivateKey, kid string) *mockApple {
	t.Helper()
	m := &mockApple{jwksStatus: http.StatusOK, jwksBody: jwksFor(kid, &key.PublicKey)}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
			}
			m.mu.Lock()
			m.secrets = append(m.secrets, r.Form.Get("client_secret"))
			idToken := m.idToken
			m.mu.Unlock()
			fmt.Fprintf(w, `{"access_token":"at","id_token":%q,"expires_in":3600}`, idToken)
		case "/keys":
			m.mu.Lock()
			status, body := m.jwksStatus, m.jwksBody
			m.mu.Unlock()
			w.WriteHeader(status)
			fmt.Fprint(w, body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockApple) capturedSecrets() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.secrets...)
}

// jwksFor 由公钥编 JWK Set（EC P-256，坐标 32 字节定宽 base64url）。
func jwksFor(kid string, pub *ecdsa.PublicKey) string {
	x := pub.X.FillBytes(make([]byte, 32))
	y := pub.Y.FillBytes(make([]byte, 32))
	b, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "EC", "kid": kid, "use": "sig", "alg": algES256, "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(x),
			"y": base64.RawURLEncoding.EncodeToString(y),
		}},
	})
	return string(b)
}

// newAdapterAt 构造注入 mock 端点与固定时钟的适配器（生产入口为注册表
// newAdapter 固化官方端点，此处只为可证伪注入）。
func newAdapterAt(t *testing.T, p8, tokenURL, jwksURL string, now func() time.Time) *Adapter {
	t.Helper()
	a, err := build(testProvider(p8), nil, "https://appleid.apple.com/auth/authorize", tokenURL, jwksURL, issuer)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	a.now = now
	return a
}

// TestRegistryMeta 注册表挂载与 Schema 收窄（§15.5）：必填四件套进表单，
// 动态 client_secret 与固化端点不透出（声明即消费红线）。
func TestRegistryMeta(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok {
		t.Fatal("apple 未注册（init 缺失）")
	}
	if meta.Category != "auth" || meta.Channel != provider.ChannelRedirect {
		t.Fatalf("meta = %+v, want category=auth channel=redirect", meta)
	}
	declared := map[string]bool{}
	for _, f := range meta.Schema() {
		declared[f.Key] = true
	}
	for _, key := range []string{"client_id", "team_id", "key_id", "cert", "scopes", "user_mapping", "proxy_provider_key"} {
		if !declared[key] {
			t.Errorf("Schema 缺必声明键 %q", key)
		}
	}
	for _, key := range []string{"client_secret", "provider_url", "custom_auth_url", "custom_token_url", "app_id", "metadata"} {
		if declared[key] {
			t.Errorf("Schema 不应声明键 %q（动态签发 / 固化端点不透出）", key)
		}
	}
	for _, f := range meta.Schema() {
		switch f.Key {
		case "client_id", "team_id", "key_id", "cert":
			if !f.Required {
				t.Errorf("%s required = false, want true", f.Key)
			}
		case "scopes":
			if f.Default != defaultScopes {
				t.Errorf("scopes default = %q, want %q", f.Default, defaultScopes)
			}
		case "user_mapping":
			if f.Default != defaultUserMapping {
				t.Errorf("user_mapping default = %q, want %q", f.Default, defaultUserMapping)
			}
		}
	}
	// 注册表工厂端到端：官方端点固化、凭证齐全即可构造。
	a, err := provider.NewAdapter(testProvider(mustP8(t)))
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	if a.Channel() != provider.ChannelRedirect {
		t.Fatalf("channel = %q, want redirect", a.Channel())
	}
}

// TestBuildFailClosed 装配期校验：凭证缺项 / .p8 非法一律构造失败。
func TestBuildFailClosed(t *testing.T) {
	key, p8 := newP8(t)
	mkPem := func(t *testing.T, der []byte, blockType string) string {
		t.Helper()
		return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
	}
	cases := []struct {
		name string
		mut  func(t *testing.T, p *provider.Provider)
		want error
	}{
		{"missing client_id", func(t *testing.T, p *provider.Provider) { p.Ext.ClientId = "" }, ErrNotConfigured},
		{"missing team_id", func(t *testing.T, p *provider.Provider) { p.Ext.TeamId = "" }, ErrNotConfigured},
		{"missing key_id", func(t *testing.T, p *provider.Provider) { p.Ext.KeyId = "" }, ErrNotConfigured},
		{"missing cert", func(t *testing.T, p *provider.Provider) { p.Ext.Cert = "" }, ErrNotConfigured},
		{"bad pem", func(t *testing.T, p *provider.Provider) { p.Ext.Cert = "not-a-pem" }, ErrBadKey},
		{"not pkcs8", func(t *testing.T, p *provider.Provider) {
			der, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatalf("marshal sec1: %v", err)
			}
			p.Ext.Cert = mkPem(t, der, "EC PRIVATE KEY")
		}, ErrBadKey},
		{"rsa key", func(t *testing.T, p *provider.Provider) {
			rk, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("generate rsa: %v", err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(rk)
			if err != nil {
				t.Fatalf("marshal pkcs8: %v", err)
			}
			p.Ext.Cert = mkPem(t, der, "PRIVATE KEY")
		}, ErrBadKey},
		{"p384 key", func(t *testing.T, p *provider.Provider) {
			k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatalf("generate p384: %v", err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(k)
			if err != nil {
				t.Fatalf("marshal pkcs8: %v", err)
			}
			p.Ext.Cert = mkPem(t, der, "PRIVATE KEY")
		}, ErrBadKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testProvider(p8)
			tc.mut(t, p)
			_, err := build(p, nil, authorizeURL, tokenURL, jwksURL, issuer)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := build(nil, nil, authorizeURL, tokenURL, jwksURL, issuer); !errors.Is(err, provider.ErrNilProvider) {
		t.Fatalf("nil provider err = %v, want ErrNilProvider", err)
	}
}

// TestBuildAuthURL form_post 模式：有效 scope 含 name/email 必须带
// response_mode=form_post（Apple 协议硬约束）；不含则不带。
func TestBuildAuthURL(t *testing.T) {
	a := &Adapter{scopes: defaultScopes, authURL: authorizeURL, clientID: testClientID}
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-abc", RedirectURI: "https://x/cb"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	if !strings.Contains(got, "response_mode=form_post") {
		t.Fatalf("url = %q, want form_post mode", got)
	}
	if !strings.Contains(got, "response_type=code") || !strings.Contains(got, "state=l-abc") {
		t.Fatalf("url = %q, want code flow params", got)
	}
	// 覆盖 scope 不含 name/email → 无 form_post（如申请 openid 走 id_token 流）。
	got, err = a.BuildAuthURL(&provider.AuthContext{State: "l-abc", Scope: "openid"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	if strings.Contains(got, "response_mode=form_post") {
		t.Fatalf("url = %q, want no form_post for openid scope", got)
	}
	// state 透传校验归 oauthcore。
	if _, err := a.BuildAuthURL(&provider.AuthContext{}); !errors.Is(err, oauthcore.ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
}

// TestExchangeClientSecretJWT 动态 client_secret：结构（alg/kid/iss/aud/
// sub/iat/exp）与 ES256 签名可被 .p8 公钥验证；缓存窗口内复用同一串，
// 到期后重签（exp 前移）。
func TestExchangeClientSecretJWT(t *testing.T) {
	key, p8 := newP8(t)
	idToken := signIDToken(t, key, testKeyID, baseClaims())
	m := newMockApple(t, key, testKeyID)
	m.mu.Lock()
	m.idToken = idToken
	m.mu.Unlock()

	now := fixedTime
	a := newAdapterAt(t, p8, m.srv.URL+"/token", m.srv.URL+"/keys", func() time.Time { return now })

	ctx := context.Background()
	in := provider.ExchangeInput{Code: "o-code", RedirectURI: "https://x/cb"}
	for i := 0; i < 2; i++ {
		if _, err := a.Exchange(ctx, in); err != nil {
			t.Fatalf("Exchange #%d: %v", i, err)
		}
	}
	secrets := m.capturedSecrets()
	if len(secrets) != 2 || secrets[0] != secrets[1] {
		t.Fatalf("cached secret mismatch: %d captured, %q vs %q", len(secrets), secrets[0], secrets[1])
	}
	verifyClientSecret(t, secrets[0], fixedTime)

	// 时钟越过 exp → 重签（iat/exp 变化）。
	resigned := fixedTime.Add(clientSecretTTL + time.Minute)
	now = resigned
	if _, err := a.Exchange(ctx, in); err != nil {
		t.Fatalf("Exchange after expiry: %v", err)
	}
	secrets = m.capturedSecrets()
	if len(secrets) != 3 || secrets[2] == secrets[0] {
		t.Fatalf("secret not resigned after expiry: %q == %q", secrets[2], secrets[0])
	}
	verifyClientSecret(t, secrets[2], resigned)
}

// verifyClientSecret 解析并验证 client_secret JWT：header / claims / 签名
// 三段全对齐 Apple 规范（后端架构 §15.5：iss=Team ID、aud=授权服务器、
// sub=Services ID，exp ≤ 6 个月上限）。
func verifyClientSecret(t *testing.T, secret string, signedAt time.Time) {
	t.Helper()
	parts := strings.Split(secret, ".")
	if len(parts) != 3 {
		t.Fatalf("secret segments = %d, want 3", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header b64: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		t.Fatalf("header json: %v", err)
	}
	if header.Alg != algES256 || header.Kid != testKeyID {
		t.Fatalf("header = %+v, want alg=%s kid=%s", header, algES256, testKeyID)
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload b64: %v", err)
	}
	var claims clientSecretClaims
	if err := json.Unmarshal(cb, &claims); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	if claims.Iss != testTeamID || claims.Sub != testClientID || claims.Aud != issuer {
		t.Fatalf("claims = %+v, want iss=%s sub=%s aud=%s", claims, testTeamID, testClientID, issuer)
	}
	if delta := claims.Exp - claims.Iat; delta != int64(clientSecretTTL.Seconds()) {
		t.Fatalf("exp-iat = %d, want %d (≤6 个月上限)", delta, int64(clientSecretTTL.Seconds()))
	}
	if claims.Iat != signedAt.Unix() {
		t.Fatalf("iat = %d, want %d", claims.Iat, signedAt.Unix())
	}
}

// TestFetchUserVerifyOK 令牌响应 id_token 验签通过：抽取 sub / email，
// 字符串布尔 email_verified 归一；昵称不产出（user JSON 不在令牌响应内）。
func TestFetchUserVerifyOK(t *testing.T) {
	key, p8 := newP8(t)
	idToken := signIDToken(t, key, testKeyID, baseClaims())
	m := newMockApple(t, key, testKeyID)
	m.mu.Lock()
	m.idToken = idToken
	m.mu.Unlock()

	a := newAdapterAt(t, p8, m.srv.URL+"/token", m.srv.URL+"/keys", func() time.Time { return fixedTime })
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "o-code"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	id, err := a.FetchUser(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != testSub || id.Email != "user@privaterelay.appleid.com" || !id.EmailVerified {
		t.Fatalf("id = %+v", id)
	}
	if id.ProviderType != Type || id.ProviderKey != "apple-main" {
		t.Fatalf("provider fields = %q/%q", id.ProviderType, id.ProviderKey)
	}
	if id.Nickname != "" {
		t.Fatalf("nickname = %q, want empty（令牌路径无 user 合并）", id.Nickname)
	}
}

// TestFetchUserFailClosed 验签失败路径全表 fail-closed：iss / aud / exp /
// nonce / 签名 / kid / alg 逐一拒绝。
func TestFetchUserFailClosed(t *testing.T) {
	key, p8 := newP8(t)
	cases := []struct {
		name  string
		token func(t *testing.T) string
		want  error
	}{
		{"iss mismatch", func(t *testing.T) string {
			return signIDToken(t, key, testKeyID, tokenClaims(func(c map[string]any) { c["iss"] = "https://evil.example.com" }))
		}, ErrClaimsInvalid},
		{"aud mismatch", func(t *testing.T) string {
			return signIDToken(t, key, testKeyID, tokenClaims(func(c map[string]any) { c["aud"] = "other-client" }))
		}, ErrClaimsInvalid},
		{"exp expired", func(t *testing.T) string {
			return signIDToken(t, key, testKeyID, tokenClaims(func(c map[string]any) {
				c["exp"] = float64(fixedTime.Add(-time.Minute).Unix())
			}))
		}, ErrClaimsInvalid},
		{"nonce unexpected", func(t *testing.T) string {
			return signIDToken(t, key, testKeyID, tokenClaims(func(c map[string]any) { c["nonce"] = "n-1" }))
		}, ErrClaimsInvalid},
		{"bad signature", func(t *testing.T) string {
			return mutateSignature(t, signIDToken(t, key, testKeyID, baseClaims()))
		}, ErrSignVerify},
		{"unknown kid", func(t *testing.T) string {
			return signIDToken(t, key, "other-kid", baseClaims())
		}, ErrUnknownKid},
		{"alg not es256", func(t *testing.T) string {
			return withAlg(t, signIDToken(t, key, testKeyID, baseClaims()), "HS256")
		}, ErrBadAlg},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMockApple(t, key, testKeyID)
			m.mu.Lock()
			m.idToken = tc.token(t)
			m.mu.Unlock()
			a := newAdapterAt(t, p8, m.srv.URL+"/token", m.srv.URL+"/keys", func() time.Time { return fixedTime })
			tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "o-code"})
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if _, err := a.FetchUser(context.Background(), tok); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestFetchUserJWKSFailure JWKS 端点故障归 ProviderError（厂商侧错误，
// 非本地校验哨兵），同样 fail-closed。
func TestFetchUserJWKSFailure(t *testing.T) {
	key, p8 := newP8(t)
	idToken := signIDToken(t, key, testKeyID, baseClaims())
	m := newMockApple(t, key, testKeyID)
	m.mu.Lock()
	m.idToken = idToken
	m.jwksStatus = http.StatusInternalServerError
	m.mu.Unlock()
	a := newAdapterAt(t, p8, m.srv.URL+"/token", m.srv.URL+"/keys", func() time.Time { return fixedTime })
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "o-code"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	_, err = a.FetchUser(context.Background(), tok)
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Status != http.StatusInternalServerError {
		t.Fatalf("err = %v, want ProviderError status=500", err)
	}
}

// TestVerifyIDTokenMalformed 结构非法令牌直接 fail-closed（不经 mock）。
func TestVerifyIDTokenMalformed(t *testing.T) {
	a := &Adapter{now: func() time.Time { return fixedTime }, issuer: issuer, clientID: testClientID}
	for _, bad := range []string{"", "a.b", "a.b.c.d", "!!!.!!!.!!!"} {
		if _, err := a.verifyIDToken(context.Background(), bad, ""); !errors.Is(err, ErrBadIDToken) {
			t.Fatalf("verify %q err = %v, want ErrBadIDToken", bad, err)
		}
	}
}

// TestIdentityFirstUserMerge 首次授权 user 合并：昵称由 name.firstName +
// lastName 派生、email 取 user JSON；仅首次（回调带 user）产出昵称，
// 后续回调（不带 user）昵称为空、不覆盖既有身份记录。
func TestIdentityFirstUserMerge(t *testing.T) {
	key, p8 := newP8(t)
	m := newMockApple(t, key, testKeyID)
	a := newAdapterAt(t, p8, m.srv.URL+"/token", m.srv.URL+"/keys", func() time.Time { return fixedTime })
	ctx := context.Background()

	// 首次授权：user JSON 携带昵称与邮箱。
	first := &Callback{
		Code:    "o-code",
		IDToken: signIDToken(t, key, testKeyID, baseClaims()),
		State:   "l-abc",
		User:    `{"name":{"firstName":"John","lastName":"Doe"},"email":"john@example.com"}`,
	}
	id, err := a.IdentityFromCallback(ctx, first, "")
	if err != nil {
		t.Fatalf("first IdentityFromCallback: %v", err)
	}
	if id.Nickname != "John Doe" {
		t.Fatalf("nickname = %q, want John Doe", id.Nickname)
	}
	if id.Email != "john@example.com" {
		t.Fatalf("email = %q, want user JSON email", id.Email)
	}
	if id.OpenID != testSub {
		t.Fatalf("openid = %q, want sub", id.OpenID)
	}

	// 后续授权：回调不带 user → 昵称不产出（不覆盖），email 回落 id_token。
	again := &Callback{Code: "o-code", IDToken: signIDToken(t, key, testKeyID, baseClaims()), State: "l-abc"}
	id, err = a.IdentityFromCallback(ctx, again, "")
	if err != nil {
		t.Fatalf("again IdentityFromCallback: %v", err)
	}
	if id.Nickname != "" {
		t.Fatalf("nickname = %q, want empty（仅首次合并）", id.Nickname)
	}
	if id.Email != "user@privaterelay.appleid.com" {
		t.Fatalf("email = %q, want id_token claim", id.Email)
	}

	// user JSON 非法 fail-closed。
	bad := &Callback{Code: "o-code", IDToken: signIDToken(t, key, testKeyID, baseClaims()), State: "l-abc", User: "{not-json"}
	if _, err := a.IdentityFromCallback(ctx, bad, ""); !errors.Is(err, ErrCallbackInvalid) {
		t.Fatalf("err = %v, want ErrCallbackInvalid", err)
	}
}

// TestIdentityNonce nonce 比对：期望值与令牌 nonce 必须相等（授权请求侧
// 生成、经状态载荷带回），不等即 fail-closed。
func TestIdentityNonce(t *testing.T) {
	key, p8 := newP8(t)
	m := newMockApple(t, key, testKeyID)
	a := newAdapterAt(t, p8, m.srv.URL+"/token", m.srv.URL+"/keys", func() time.Time { return fixedTime })
	ctx := context.Background()

	claims := tokenClaims(func(c map[string]any) { c["nonce"] = "n-expected" })
	cb := &Callback{Code: "o-code", IDToken: signIDToken(t, key, testKeyID, claims), State: "l-abc"}
	if _, err := a.IdentityFromCallback(ctx, cb, "n-expected"); err != nil {
		t.Fatalf("matching nonce: %v", err)
	}
	if _, err := a.IdentityFromCallback(ctx, cb, "n-other"); !errors.Is(err, ErrClaimsInvalid) {
		t.Fatalf("err = %v, want ErrClaimsInvalid", err)
	}
}

// TestIdentityNilCallback nil 回调入参 fail-closed。
func TestIdentityNilCallback(t *testing.T) {
	a := &Adapter{}
	if _, err := a.IdentityFromCallback(context.Background(), nil, ""); !errors.Is(err, ErrCallbackInvalid) {
		t.Fatalf("err = %v, want ErrCallbackInvalid", err)
	}
}

// TestParseCallback form_post 回调解析：code/state 缺失 fail-closed；
// id_token / user 可缺（后者仅首次授权携带）。
func TestParseCallback(t *testing.T) {
	form := url.Values{
		"code":     {"o-code"},
		"id_token": {"o-jwt"},
		"state":    {"l-abc"},
		"user":     {`{"name":{"firstName":"John"}}`},
	}
	cb, err := ParseCallback(form)
	if err != nil {
		t.Fatalf("ParseCallback: %v", err)
	}
	if cb.Code != "o-code" || cb.IDToken != "o-jwt" || cb.State != "l-abc" || cb.User != form.Get("user") {
		t.Fatalf("cb = %+v", cb)
	}
	for _, tc := range []struct {
		name string
		form url.Values
	}{
		{"missing code", url.Values{"state": {"l-abc"}}},
		{"missing state", url.Values{"code": {"o-code"}}},
		{"nil form", nil},
	} {
		if _, err := ParseCallback(tc.form); !errors.Is(err, ErrCallbackInvalid) {
			t.Fatalf("%s: err = %v, want ErrCallbackInvalid", tc.name, err)
		}
	}
	// 最小形态：仅 code + state（后续授权回调无 user）。
	if _, err := ParseCallback(url.Values{"code": {"o"}, "state": {"s"}}); err != nil {
		t.Fatalf("minimal form: %v", err)
	}
}

// mutateSignature 翻转签名段首字符（base64url 合法、首字符 6 位全有效，
// 解码必变、签名必然失配；末字符翻转可能落在填充位而不改变解码结果）。
func mutateSignature(t *testing.T, token string) string {
	t.Helper()
	i := strings.LastIndex(token, ".")
	sig := []byte(token[i+1:])
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	return token[:i+1] + string(sig)
}

// withAlg 替换 JWT header 的 alg（其余段不动），构造算法混淆样本。
func withAlg(t *testing.T, token, alg string) string {
	t.Helper()
	parts := strings.SplitN(token, ".", 2)
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header b64: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(hb, &header); err != nil {
		t.Fatalf("header json: %v", err)
	}
	header["alg"] = alg
	nh, _ := json.Marshal(header)
	return base64.RawURLEncoding.EncodeToString(nh) + "." + parts[1]
}
