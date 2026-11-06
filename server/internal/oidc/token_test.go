// token_test.go 覆盖 POST /api/oidc/token 两类 grant 的成功/失败矩阵、
// PKCE S256、revoke 语义与 userinfo 掩码矩阵（接口文档 §4.3-§4.6、§3.1）。
package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"authloft/gen/go/token"
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
		return nil, ErrCodeNotFound
	}
	return p, nil
}

type fakeRefresh struct {
	rows map[string]*model.OidcRefreshToken
}

func newFakeRefresh() *fakeRefresh {
	return &fakeRefresh{rows: make(map[string]*model.OidcRefreshToken)}
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

type fakeEpoch struct {
	v   int64
	err error
}

func (f fakeEpoch) Current(_ context.Context, _ int64) (int64, error) { return f.v, f.err }

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

func webClient() *model.OidcClient {
	return &model.OidcClient{
		ClientID: "web", ClientSecret: "secret", IsEnabled: 1,
		AccessTokenTTL: 3600, RefreshTokenTTL: 2592000,
		Scopes: "openid,profile,email",
	}
}

func newCodePayload(now time.Time) *token.OidcCodePayload {
	return &token.OidcCodePayload{
		ClientId:    "web",
		RedirectUri: "https://app.example.com/cb",
		Uid:         42,
		Scope:       "openid profile email phone",
		Nonce:       "n-1",
		Amr:         []string{"pwd"},
		Iat:         now.Unix(),
		Exp:         now.Unix() + 120,
	}
}

func newTokenService(t *testing.T, codes fakeCodes, store *fakeRefresh) (*TokenService, *JWT, time.Time) {
	t.Helper()
	now := fixedNow()
	j := newTestJWT(t, "k1")
	j.Now = func() time.Time { return now }
	return &TokenService{
		JWT: j, Clients: fakeClients{"web": webClient()}, Codes: codes,
		Tokens: store, Epoch: fakeEpoch{v: 3},
		Now: func() time.Time { return now },
	}, j, now
}

func authCodeInput(code, verifier string) TokenInput {
	return TokenInput{
		GrantType: "authorization_code", Code: code, RedirectURI: "https://app.example.com/cb",
		ClientID: "web", ClientSecret: "secret", CodeVerifier: verifier,
	}
}

// TestAuthorizationCodeSuccess 授权码 grant 成功路径与令牌形态。
func TestAuthorizationCodeSuccess(t *testing.T) {
	store := newFakeRefresh()
	now := fixedNow()
	svc, j, _ := newTokenService(t, fakeCodes{"c1": newCodePayload(now)}, store)
	resp, oe := svc.Token(context.Background(), authCodeInput("c1", ""))
	if oe != nil {
		t.Fatalf("Token: %v", oe)
	}
	if resp.TokenType != "Bearer" || resp.ExpiresIn != 3600 {
		t.Errorf("token type / expires_in = %q/%d, want Bearer/3600", resp.TokenType, resp.ExpiresIn)
	}
	if resp.AccessToken == "" || resp.IdToken == "" || resp.RefreshToken == "" {
		t.Fatal("empty token in response")
	}
	if resp.Scope != "openid profile email phone" {
		t.Errorf("scope = %q", resp.Scope)
	}
	ac, err := j.VerifyAccess(resp.AccessToken)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if ac.Sub != 42 || ac.Scope != "openid profile email phone" || ac.Epoch != 3 {
		t.Errorf("access claims = %+v", ac)
	}
	if len(store.rows) != 1 {
		t.Fatalf("refresh rows = %d, want 1", len(store.rows))
	}
	for _, row := range store.rows {
		if row.ClientID != "web" || row.UserID != 42 || !row.ExpiresAt.After(now) {
			t.Errorf("refresh row = %+v", row)
		}
	}
}

// TestAuthorizationCodeErrors 失败矩阵：unsupported / invalid_request /
// invalid_client / invalid_grant。
func TestAuthorizationCodeErrors(t *testing.T) {
	now := fixedNow()
	cases := []struct {
		name   string
		mutate func(*TokenInput, fakeCodes)
		code   string
		status int
	}{
		{"unsupported grant", func(in *TokenInput, _ fakeCodes) { in.GrantType = "password" }, "unsupported_grant_type", 400},
		{"missing params", func(in *TokenInput, _ fakeCodes) { in.Code = "" }, "invalid_request", 400},
		{"unknown client", func(in *TokenInput, _ fakeCodes) { in.ClientID = "nope" }, "invalid_client", 400},
		{"unknown code", func(in *TokenInput, _ fakeCodes) { in.Code = "nope" }, "invalid_grant", 400},
		{"redirect mismatch", func(in *TokenInput, _ fakeCodes) { in.RedirectURI = "https://evil.example/cb" }, "invalid_grant", 400},
		{"wrong secret", func(in *TokenInput, _ fakeCodes) { in.ClientSecret = "wrong" }, "invalid_client", 400},
		{"code other client", func(_ *TokenInput, codes fakeCodes) {
			codes["c1"].ClientId = "other"
		}, "invalid_grant", 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			codes := fakeCodes{"c1": newCodePayload(now)}
			in := authCodeInput("c1", "")
			tc.mutate(&in, codes)
			store := newFakeRefresh()
			svc, _, _ := newTokenService(t, codes, store)
			_, oe := svc.Token(context.Background(), in)
			if oe == nil {
				t.Fatal("want error, got success")
			}
			if oe.Code != tc.code || oe.Status != tc.status {
				t.Errorf("error = %d/%s, want %d/%s", oe.Status, oe.Code, tc.status, tc.code)
			}
		})
	}
}

// TestPKCE 授权码带 code_challenge 时仅接受 S256。
func TestPKCE(t *testing.T) {
	now := fixedNow()
	verifier := "verifier-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	newPayload := func(method string) fakeCodes {
		p := newCodePayload(now)
		p.CodeChallenge = challenge
		p.CodeChallengeMethod = method
		return fakeCodes{"c1": p}
	}

	svc, _, _ := newTokenService(t, newPayload("S256"), newFakeRefresh())
	resp, oe := svc.Token(context.Background(), TokenInput{
		GrantType: "authorization_code", Code: "c1", RedirectURI: "https://app.example.com/cb",
		ClientID: "web", CodeVerifier: verifier,
	})
	if oe != nil || resp == nil {
		t.Fatalf("PKCE S256 rejected: %v", oe)
	}

	svc, _, _ = newTokenService(t, newPayload("S256"), newFakeRefresh())
	if _, oe := svc.Token(context.Background(), authCodeInput("c1", "wrong")); oe == nil || oe.Code != "invalid_grant" {
		t.Fatalf("wrong verifier error = %v, want invalid_grant", oe)
	}

	svc, _, _ = newTokenService(t, newPayload("plain"), newFakeRefresh())
	if _, oe := svc.Token(context.Background(), authCodeInput("c1", verifier)); oe == nil || oe.Code != "invalid_grant" {
		t.Fatalf("plain method error = %v, want invalid_grant", oe)
	}
}

// TestRefreshTokenSuccess 刷新 grant 成功：返回同一 refresh token（默认不轮换）。
func TestRefreshTokenSuccess(t *testing.T) {
	now := fixedNow()
	store := newFakeRefresh()
	store.rows[hashToken("rt-1")] = &model.OidcRefreshToken{
		TokenHash: hashToken("rt-1"), ClientID: "web", UserID: 42,
		Scopes: "openid,email", ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	}
	svc, j, _ := newTokenService(t, nil, store)
	resp, oe := svc.Token(context.Background(), TokenInput{
		GrantType: "refresh_token", RefreshToken: "rt-1", ClientID: "web", ClientSecret: "secret",
	})
	if oe != nil {
		t.Fatalf("refresh: %v", oe)
	}
	if resp.RefreshToken != "rt-1" {
		t.Errorf("refresh token rotated unexpectedly: %q", resp.RefreshToken)
	}
	if resp.Scope != "openid email" {
		t.Errorf("scope = %q, want space-separated", resp.Scope)
	}
	ac, err := j.VerifyAccess(resp.AccessToken)
	if err != nil || ac.Sub != 42 || ac.Scope != "openid email" {
		t.Fatalf("access claims = %+v, err=%v", ac, err)
	}
	if len(store.rows) != 1 {
		t.Fatalf("rows = %d, want 1 (no rotation)", len(store.rows))
	}
}

// TestRefreshTokenErrors 吊销 / 过期 / 跨 client / 密钥错误。
func TestRefreshTokenErrors(t *testing.T) {
	now := fixedNow()
	future := now.Add(24 * time.Hour)
	past := now.Add(-time.Minute)
	revoked := now.Add(-time.Second)
	cases := []struct {
		name   string
		row    *model.OidcRefreshToken
		in     TokenInput
		code   string
		status int
	}{
		{"revoked", &model.OidcRefreshToken{TokenHash: hashToken("rt-1"), ClientID: "web", UserID: 42, ExpiresAt: future, RevokedAt: &revoked}, refreshInput("rt-1", "secret"), "invalid_grant", 400},
		{"expired", &model.OidcRefreshToken{TokenHash: hashToken("rt-1"), ClientID: "web", UserID: 42, ExpiresAt: past}, refreshInput("rt-1", "secret"), "invalid_grant", 400},
		{"other client", &model.OidcRefreshToken{TokenHash: hashToken("rt-1"), ClientID: "other", UserID: 42, ExpiresAt: future}, refreshInput("rt-1", "secret"), "invalid_grant", 400},
		{"unknown token", nil, refreshInput("rt-1", "secret"), "invalid_grant", 400},
		{"wrong secret", &model.OidcRefreshToken{TokenHash: hashToken("rt-1"), ClientID: "web", UserID: 42, ExpiresAt: future}, refreshInput("rt-1", "wrong"), "invalid_client", 400},
		{"missing params", nil, TokenInput{GrantType: "refresh_token", ClientID: "web"}, "invalid_request", 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeRefresh()
			if tc.row != nil {
				store.rows[hashToken("rt-1")] = tc.row
			}
			svc, _, _ := newTokenService(t, nil, store)
			_, oe := svc.Token(context.Background(), tc.in)
			if oe == nil || oe.Code != tc.code || oe.Status != tc.status {
				t.Fatalf("error = %v, want %d/%s", oe, tc.status, tc.code)
			}
		})
	}
}

func refreshInput(tokenValue, secret string) TokenInput {
	return TokenInput{GrantType: "refresh_token", RefreshToken: tokenValue, ClientID: "web", ClientSecret: secret}
}

// TestRevoke 已知 / 未知 / 已吊销统一成功；错误路径按 RFC。
func TestRevoke(t *testing.T) {
	now := fixedNow()
	store := newFakeRefresh()
	store.rows[hashToken("rt-1")] = &model.OidcRefreshToken{
		TokenHash: hashToken("rt-1"), ClientID: "web", UserID: 42, ExpiresAt: now.Add(time.Hour),
	}
	rev := &Revoker{Clients: fakeClients{"web": webClient()}, Tokens: store, Now: func() time.Time { return now }}

	if oe := rev.Revoke(context.Background(), "web", "secret", "rt-1", "refresh_token"); oe != nil {
		t.Fatalf("known token revoke: %v", oe)
	}
	if store.rows[hashToken("rt-1")].RevokedAt == nil {
		t.Fatal("row was not revoked")
	}
	if oe := rev.Revoke(context.Background(), "web", "secret", "rt-1", "refresh_token"); oe != nil {
		t.Fatalf("already revoked token must succeed: %v", oe)
	}
	if oe := rev.Revoke(context.Background(), "web", "secret", "unknown", "refresh_token"); oe != nil {
		t.Fatalf("unknown token must succeed: %v", oe)
	}

	for _, tc := range []struct {
		name   string
		client string
		secret string
		token  string
		status int
		code   string
	}{
		{"missing token", "web", "secret", "", 400, "invalid_request"},
		{"unknown client", "nope", "secret", "rt-1", 401, "invalid_client"},
		{"wrong secret", "web", "wrong", "rt-1", 401, "invalid_client"},
		{"missing client", "", "secret", "rt-1", 401, "invalid_client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oe := rev.Revoke(context.Background(), tc.client, tc.secret, tc.token, "refresh_token")
			if oe == nil || oe.Status != tc.status || oe.Code != tc.code {
				t.Fatalf("error = %v, want %d/%s", oe, tc.status, tc.code)
			}
		})
	}
}

func testUser() *model.User {
	phone := "13800008000"
	email := "alice@example.com"
	created := fixedNow()
	last := fixedNow().Add(-time.Hour)
	return &model.User{
		ID: 42, Username: "alice", Nickname: "Alice", AvatarURL: "https://cdn.example/a.png",
		Phone: &phone, PhoneVerified: 1, Email: &email, EmailVerified: 1,
		UserStatus: 1, Epoch: 3, LastLoginAt: &last, CreatedAt: created, UpdatedAt: created,
	}
}

func newClaimsService(j *JWT, users fakeUsers, profiles fakeProfiles, epoch int64) *UserInfoService {
	return &UserInfoService{JWT: j, Users: users, Profiles: profiles, Epoch: fakeEpoch{v: epoch}}
}

func signAccess(t *testing.T, j *JWT, scope string, epoch int64) string {
	t.Helper()
	raw, err := j.SignAccessToken(AccessTokenInput{
		UID: 42, ClientID: "web", Scope: scope, AMR: []string{"pwd"}, Epoch: epoch, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("sign access: %v", err)
	}
	return raw
}

// TestUserinfoMasking 默认掩码 / *_plain 明文 / *_verified 不变。
func TestUserinfoMasking(t *testing.T) {
	now := fixedNow()
	j := newTestJWT(t, "k1")
	j.Now = func() time.Time { return now }
	users := fakeUsers{42: testUser()}
	svc := newClaimsService(j, users, fakeProfiles{}, 3)

	resp, oe := svc.Userinfo(context.Background(), signAccess(t, j, "openid profile email phone", 3))
	if oe != nil {
		t.Fatalf("userinfo: %v", oe)
	}
	if resp.Sub != 42 || resp.Name != "Alice" || resp.Picture != "https://cdn.example/a.png" {
		t.Errorf("basic claims = %+v", resp)
	}
	if resp.Email != "a***@example.com" || resp.PhoneNumber != "138****8000" {
		t.Errorf("masked email/phone = %q/%q", resp.Email, resp.PhoneNumber)
	}
	if !resp.EmailVerified || !resp.PhoneNumberVerified {
		t.Error("verified flags changed by masking")
	}
	if len(resp.Amr) != 1 || resp.Amr[0] != "pwd" {
		t.Errorf("amr = %v", resp.Amr)
	}

	resp, oe = svc.Userinfo(context.Background(), signAccess(t, j, "openid profile email email_plain phone phone_plain", 3))
	if oe != nil {
		t.Fatalf("userinfo plain: %v", oe)
	}
	if resp.Email != "alice@example.com" || resp.PhoneNumber != "13800008000" {
		t.Errorf("plain email/phone = %q/%q", resp.Email, resp.PhoneNumber)
	}
	if !resp.EmailVerified || !resp.PhoneNumberVerified {
		t.Error("plain scope must not change verified flags")
	}

	resp, oe = svc.Userinfo(context.Background(), signAccess(t, j, "openid profile", 3))
	if oe != nil {
		t.Fatalf("userinfo without email/phone scope: %v", oe)
	}
	if resp.Email != "" || resp.PhoneNumber != "" {
		t.Errorf("email/phone present without standard scope: %q/%q", resp.Email, resp.PhoneNumber)
	}
}

// TestUserinfoRejectsInvalid epoch / 篡改 / 过期 → 401 invalid_token。
func TestUserinfoRejectsInvalid(t *testing.T) {
	now := fixedNow()
	j := newTestJWT(t, "k1")
	j.Now = func() time.Time { return now }
	users := fakeUsers{42: testUser()}

	svc := newClaimsService(j, users, fakeProfiles{}, 4) // epoch 已递增
	if _, oe := svc.Userinfo(context.Background(), signAccess(t, j, "openid", 3)); oe == nil || oe.Status != 401 {
		t.Fatalf("epoch mismatch error = %v, want 401", oe)
	}

	if _, oe := svc.Userinfo(context.Background(), "garbage"); oe == nil || oe.Status != 401 {
		t.Fatalf("invalid token error = %v, want 401", oe)
	}

	svc = newClaimsService(j, users, fakeProfiles{}, 3)
	raw := signAccess(t, j, "openid", 3)
	j.Now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, oe := svc.Userinfo(context.Background(), raw); oe == nil || oe.Status != 401 {
		t.Fatalf("expired token error = %v, want 401", oe)
	}
}

// TestGetUserInfo Authloft 结构、掩码与 profile / extra。
func TestGetUserInfo(t *testing.T) {
	now := fixedNow()
	j := newTestJWT(t, "k1")
	j.Now = func() time.Time { return now }
	bd := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	profiles := fakeProfiles{42: &model.UserProfile{
		UserID: 42, Gender: 1, Birthday: &bd, Locale: "zh-CN", Timezone: "Asia/Shanghai",
	}}
	svc := newClaimsService(j, fakeUsers{42: testUser()}, profiles, 3)

	resp, oe := svc.GetUserInfo(context.Background(), signAccess(t, j, "openid email phone", 3))
	if oe != nil {
		t.Fatalf("get_user_info: %v", oe)
	}
	if resp.Id != 42 || resp.Username != "alice" || resp.UserStatus != 1 || resp.Epoch != 3 {
		t.Errorf("profile basics = %+v", resp)
	}
	if resp.Email != "a***@example.com" || resp.Phone != "138****8000" {
		t.Errorf("masked = %q/%q", resp.Email, resp.Phone)
	}
	if resp.PhoneVerified != 1 || resp.EmailVerified != 1 {
		t.Errorf("verified = %d/%d", resp.PhoneVerified, resp.EmailVerified)
	}
	if resp.Profile == nil || resp.Profile.GetBirthday() != "1990-01-01" || resp.Profile.GetLocale() != "zh-CN" {
		t.Errorf("profile = %+v", resp.Profile)
	}
	if !strings.HasPrefix(resp.Profile.GetTimezone(), "Asia/") {
		t.Errorf("timezone = %q", resp.Profile.GetTimezone())
	}

	resp, oe = svc.GetUserInfo(context.Background(), signAccess(t, j, "openid email email_plain phone phone_plain", 3))
	if oe != nil {
		t.Fatalf("get_user_info plain: %v", oe)
	}
	if resp.Email != "alice@example.com" || resp.Phone != "13800008000" {
		t.Errorf("plain = %q/%q", resp.Email, resp.Phone)
	}
}

// TestMaskHelpers 掩码格式（§3.1：前 3 + **** + 后 4；首字符 + *** + @域名）。
func TestMaskHelpers(t *testing.T) {
	if got := maskPhone("13800008000"); got != "138****8000" {
		t.Errorf("maskPhone = %q", got)
	}
	if got := maskPhone("1234567"); got != "****" {
		t.Errorf("short maskPhone = %q", got)
	}
	if got := maskEmail("alice@example.com"); got != "a***@example.com" {
		t.Errorf("maskEmail = %q", got)
	}
	if got := maskEmail("bob@example.com"); got != "b***@example.com" {
		t.Errorf("maskEmail = %q", got)
	}
}
