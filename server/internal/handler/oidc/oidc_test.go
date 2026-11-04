// oidc_test.go 覆盖 OIDC REST 端点的 HTTP 契约：discovery / JWKS / token /
// revoke（200 空 body）/ userinfo 掩码与 401 / get_user_info（docs/接口文档.md §4.1-§4.7）。
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"authloft/gen/go/token"
	"authloft/internal/config"
	oidcimpl "authloft/internal/oidc"
	"authloft/internal/repo/model"
)

type fakeClients map[string]*model.OidcClient

func (f fakeClients) FindOidcClientByClientID(_ context.Context, id string) (*model.OidcClient, error) {
	c, ok := f[id]
	if !ok {
		return nil, errors.New("client not found")
	}
	return c, nil
}

type fakeCodes map[string]*token.OidcCodePayload

func (f fakeCodes) Consume(_ context.Context, code string) (*token.OidcCodePayload, error) {
	p, ok := f[code]
	if !ok {
		return nil, errors.New("code not found")
	}
	return p, nil
}

type fakeRefresh struct {
	rows map[string]*model.OidcRefreshToken
}

func (f *fakeRefresh) Create(_ context.Context, t *model.OidcRefreshToken) error {
	f.rows[t.TokenHash] = t
	return nil
}

func (f *fakeRefresh) FindByTokenHash(_ context.Context, hash string) (*model.OidcRefreshToken, error) {
	row, ok := f.rows[hash]
	if !ok {
		return nil, errors.New("row not found")
	}
	return row, nil
}

func (f *fakeRefresh) RevokeByTokenHash(_ context.Context, hash string, at time.Time) (bool, error) {
	row, ok := f.rows[hash]
	if !ok || row.RevokedAt != nil {
		return false, nil
	}
	row.RevokedAt = &at
	return true, nil
}

type fakeEpoch int64

func (f fakeEpoch) Current(_ context.Context, _ int64) (int64, error) { return int64(f), nil }

type fakeUsers map[int64]*model.User

func (f fakeUsers) FindByID(_ context.Context, id int64) (*model.User, error) {
	u, ok := f[id]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

type fakeProfiles map[int64]*model.UserProfile

func (f fakeProfiles) GetProfile(_ context.Context, uid int64) (*model.UserProfile, error) {
	p, ok := f[uid]
	if !ok {
		return nil, errors.New("profile not found")
	}
	return p, nil
}

type env struct {
	router *gin.Engine
	jwt    *oidcimpl.JWT
	codes  fakeCodes
	store  *fakeRefresh
	now    time.Time
}

func testKey(t *testing.T, kid string) config.OIDCKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return config.OIDCKey{Kid: kid, PrivateKeyPEM: base64.StdEncoding.EncodeToString(block)}
}

func setup(t *testing.T) *env {
	t.Helper()
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	j, err := oidcimpl.NewJWT([]config.OIDCKey{testKey(t, "k1"), testKey(t, "k2")}, "https://authloft.example.com/")
	if err != nil {
		t.Fatalf("NewJWT: %v", err)
	}
	j.Now = func() time.Time { return now }

	phone := "13800008000"
	email := "alice@example.com"
	last := now.Add(-time.Hour)
	user := &model.User{
		ID: 42, Username: "alice", Nickname: "Alice", AvatarURL: "https://cdn.example/a.png",
		Phone: &phone, PhoneVerified: 1, Email: &email, EmailVerified: 1,
		UserStatus: 1, Epoch: 3, LastLoginAt: &last, CreatedAt: now, UpdatedAt: now,
	}
	birthday := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)

	codes := fakeCodes{"c1": &token.OidcCodePayload{
		ClientId: "web", RedirectUri: "https://app.example.com/cb", Uid: 42,
		Scope: "openid profile email phone", Nonce: "n-1", Amr: []string{"pwd"},
	}}
	clients := fakeClients{"web": &model.OidcClient{
		ClientID: "web", ClientSecret: "secret", IsEnabled: 1,
		AccessTokenTTL: 3600, RefreshTokenTTL: 2592000,
	}}
	store := &fakeRefresh{rows: make(map[string]*model.OidcRefreshToken)}

	deps := Deps{
		JWT: j,
		Tokens: &oidcimpl.TokenService{
			JWT: j, Clients: clients, Codes: codes, Tokens: store,
			Epoch: fakeEpoch(3), Now: func() time.Time { return now },
		},
		Revoker: &oidcimpl.Revoker{Clients: clients, Tokens: store, Now: func() time.Time { return now }},
		UserInfo: &oidcimpl.UserInfoService{
			JWT: j, Users: fakeUsers{42: user}, Epoch: fakeEpoch(3),
			Profiles: fakeProfiles{42: &model.UserProfile{
				UserID: 42, Gender: 1, Birthday: &birthday, Locale: "zh-CN", Timezone: "Asia/Shanghai",
			}},
		},
	}
	r := gin.New()
	Register(r, deps)
	return &env{router: r, jwt: j, codes: codes, store: store, now: now}
}

func doForm(r http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return out
}

// TestDiscovery discovery 文档字段与 issuer 逐字一致（§14.1）。
func TestDiscovery(t *testing.T) {
	e := setup(t)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	doc := decode(t, w)
	if doc["issuer"] != "https://authloft.example.com" {
		t.Errorf("issuer = %v", doc["issuer"])
	}
	if doc["token_endpoint"] != "https://authloft.example.com/api/oidc/token" {
		t.Errorf("token_endpoint = %v", doc["token_endpoint"])
	}
	if doc["jwks_uri"] != "https://authloft.example.com/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %v", doc["jwks_uri"])
	}
	algs, _ := doc["id_token_signing_alg_values_supported"].([]any)
	if len(algs) != 1 || algs[0] != "RS256" {
		t.Errorf("alg values = %v, want [RS256]", algs)
	}
}

// TestJWKSEndpoint JWKS 含全部 kid（§14.1 / RFC 7517）。
func TestJWKSEndpoint(t *testing.T) {
	e := setup(t)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	doc := decode(t, w)
	keys, _ := doc["keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(keys))
	}
	for i, kid := range []string{"k1", "k2"} {
		k := keys[i].(map[string]any)
		if k["kid"] != kid || k["kty"] != "RSA" || k["alg"] != "RS256" || k["use"] != "sig" {
			t.Errorf("key[%d] = %v", i, k)
		}
		if k["n"] == "" || k["e"] == "" {
			t.Errorf("key[%d] missing n/e", i)
		}
	}
}

// TestTokenEndpointSuccess 表单编码 grant 成功 + no-store 头。
func TestTokenEndpointSuccess(t *testing.T) {
	e := setup(t)
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"c1"},
		"redirect_uri": {"https://app.example.com/cb"},
		"client_id":    {"web"}, "client_secret": {"secret"},
	}
	w := doForm(e.router, "/api/oidc/token", form)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q", got)
	}
	out := decode(t, w)
	if out["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", out["token_type"])
	}
	if out["access_token"] == "" || out["refresh_token"] == "" || out["id_token"] == "" {
		t.Errorf("missing token: %v", out)
	}
	// RFC 6749 §5.1：expires_in 必须是 JSON number，不能是字符串。
	if expiresIn, ok := out["expires_in"].(float64); !ok || expiresIn != 3600 {
		t.Errorf("expires_in = %v (%T), want number 3600", out["expires_in"], out["expires_in"])
	}
	if _, isString := out["expires_in"].(string); isString {
		t.Errorf("expires_in regressed to string: %v", out["expires_in"])
	}
	if out["scope"] != "openid profile email phone" {
		t.Errorf("scope = %v", out["scope"])
	}
}

// TestTokenEndpointErrors 标准 OAuth 错误体。
func TestTokenEndpointErrors(t *testing.T) {
	e := setup(t)
	cases := []struct {
		name   string
		form   url.Values
		status int
		code   string
	}{
		{"unsupported grant", url.Values{"grant_type": {"password"}, "client_id": {"web"}}, 400, "unsupported_grant_type"},
		{"unknown client", url.Values{"grant_type": {"authorization_code"}, "code": {"c1"}, "redirect_uri": {"https://app.example.com/cb"}, "client_id": {"nope"}}, 400, "invalid_client"},
		{"wrong secret", url.Values{"grant_type": {"authorization_code"}, "code": {"c1"}, "redirect_uri": {"https://app.example.com/cb"}, "client_id": {"web"}, "client_secret": {"wrong"}}, 400, "invalid_client"},
		{"unknown code", url.Values{"grant_type": {"authorization_code"}, "code": {"bad"}, "redirect_uri": {"https://app.example.com/cb"}, "client_id": {"web"}, "client_secret": {"secret"}}, 400, "invalid_grant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doForm(e.router, "/api/oidc/token", tc.form)
			if w.Code != tc.status {
				t.Errorf("status = %d, want %d", w.Code, tc.status)
			}
			if got := w.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("error Cache-Control = %q", got)
			}
			out := decode(t, w)
			if out["error"] != tc.code {
				t.Errorf("error = %v, want %s", out["error"], tc.code)
			}
		})
	}
}

// TestRevokeEndpoint 已知 / 未知 / 已吊销统一 200 且 body 长度 0（§4.4）。
func TestRevokeEndpoint(t *testing.T) {
	e := setup(t)
	seed := &model.OidcRefreshToken{
		TokenHash: sha256Hex("rt-1"), ClientID: "web", UserID: 42,
		ExpiresAt: e.now.Add(time.Hour),
	}
	e.store.rows[seed.TokenHash] = seed

	revoke := func(tokenValue string) *httptest.ResponseRecorder {
		return doForm(e.router, "/api/oidc/revoke", url.Values{
			"token": {tokenValue}, "token_type_hint": {"refresh_token"},
			"client_id": {"web"}, "client_secret": {"secret"},
		})
	}

	for i := 0; i < 2; i++ { // 首次吊销 + 已吊销重复
		w := revoke("rt-1")
		if w.Code != http.StatusOK {
			t.Fatalf("revoke #%d status = %d", i, w.Code)
		}
		if w.Body.Len() != 0 {
			t.Fatalf("revoke #%d body = %q, want empty", i, w.Body.String())
		}
	}
	if w := revoke("unknown"); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("unknown token: status=%d body=%q", w.Code, w.Body.String())
	}

	w := doForm(e.router, "/api/oidc/revoke", url.Values{
		"token": {"rt-1"}, "client_id": {"web"}, "client_secret": {"wrong"},
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad secret status = %d, want 401", w.Code)
	}
	out := decode(t, w)
	if out["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client", out["error"])
	}
}

// TestUserinfoEndpoint 掩码 / plain scope / 401 invalid_token（§4.5）。
func TestUserinfoEndpoint(t *testing.T) {
	e := setup(t)
	tokenMasked := signAccess(t, e, "openid profile email phone")
	tokenPlain := signAccess(t, e, "openid profile email email_plain phone phone_plain")

	call := func(raw string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/oidc/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		w := httptest.NewRecorder()
		e.router.ServeHTTP(w, req)
		return w
	}

	w := call(tokenMasked)
	if w.Code != http.StatusOK {
		t.Fatalf("masked status = %d, body=%q", w.Code, w.Body.String())
	}
	out := decode(t, w)
	if out["sub"] != "42" || out["name"] != "Alice" {
		t.Errorf("sub/name = %v/%v", out["sub"], out["name"])
	}
	if out["email"] != "a***@example.com" || out["phone_number"] != "138****8000" {
		t.Errorf("masked = %v/%v", out["email"], out["phone_number"])
	}
	if out["email_verified"] != true || out["phone_number_verified"] != true {
		t.Errorf("verified = %v/%v", out["email_verified"], out["phone_number_verified"])
	}
	if amr, _ := out["amr"].([]any); len(amr) != 1 || amr[0] != "pwd" {
		t.Errorf("amr = %v", out["amr"])
	}

	if out = decode(t, call(tokenPlain)); out["email"] != "alice@example.com" || out["phone_number"] != "13800008000" {
		t.Errorf("plain = %v/%v", out["email"], out["phone_number"])
	}

	w = call("garbage")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token status = %d, want 401", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Errorf("WWW-Authenticate = %q", got)
	}
	if out := decode(t, w); out["error"] != "invalid_token" {
		t.Errorf("error = %v", out["error"])
	}
}

// TestGetUserInfoEndpoint §3.1 Authloft 结构（lowerCamelCase）+ 掩码。
func TestGetUserInfoEndpoint(t *testing.T) {
	e := setup(t)
	req := httptest.NewRequest(http.MethodGet, "/api/oidc/get_user_info", nil)
	req.Header.Set("Authorization", "Bearer "+signAccess(t, e, "openid email phone"))
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	out := decode(t, w)
	if out["id"] != "42" || out["username"] != "alice" || out["avatarUrl"] != "https://cdn.example/a.png" {
		t.Errorf("basic = %v", out)
	}
	if out["phone"] != "138****8000" || out["email"] != "a***@example.com" {
		t.Errorf("masked = %v/%v", out["phone"], out["email"])
	}
	if out["phoneVerified"] != "1" || out["emailVerified"] != "1" {
		t.Errorf("verified = %v/%v", out["phoneVerified"], out["emailVerified"])
	}
	profile, _ := out["profile"].(map[string]any)
	if profile["birthday"] != "1990-01-01" || profile["timezone"] != "Asia/Shanghai" {
		t.Errorf("profile = %v", profile)
	}
}

func signAccess(t *testing.T, e *env, scope string) string {
	t.Helper()
	raw, err := e.jwt.SignAccessToken(oidcimpl.AccessTokenInput{
		UID: 42, ClientID: "web", Scope: scope, AMR: []string{"pwd"}, Epoch: 3, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("sign access: %v", err)
	}
	return raw
}

// sha256Hex 测试侧计算 refresh token 哈希（与实现口径一致）。
func sha256Hex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
