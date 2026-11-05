package account

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"gorm.io/gorm"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/gen/go/api/account/v1/accountv1connect"
	"authloft/gen/go/credential"
	"authloft/gen/go/provider"
	"authloft/gen/go/token"
	"authloft/internal/captcha"
	internalconnect "authloft/internal/connect"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/session"
	"authloft/internal/settings"
)

// fakeEpochReader 隔离型 epoch 读取（口径同 internal/connect/session_test.go）。
type fakeEpochReader struct{ values map[int64]int64 }

func (f *fakeEpochReader) Current(_ context.Context, uid int64) (int64, error) {
	return f.values[uid], nil
}

// fakeUsers UserReader 的 fake：分别控制 user / profile 行与错误。
type fakeUsers struct {
	user      *model.User
	profile   *model.UserProfile
	userErr   error
	profileErr error
}

func (f *fakeUsers) FindByID(_ context.Context, _ int64) (*model.User, error) {
	return f.user, f.userErr
}

func (f *fakeUsers) GetProfile(_ context.Context, _ int64) (*model.UserProfile, error) {
	return f.profile, f.profileErr
}

// fakeCreds CredentialReader 的 fake：kind → 行；未配置的 kind 返回
// 包装 gorm.ErrRecordNotFound（repo.FindByUserAndKind 同款包装）。
type fakeCreds struct {
	rows map[string]*model.UserCredential
	err  error // 非 nil 时对全部 kind 返回该错误
}

func (f *fakeCreds) FindByUserAndKind(_ context.Context, _ int64, kind string) (*model.UserCredential, error) {
	if f.err != nil {
		return nil, f.err
	}
	if row, ok := f.rows[kind]; ok {
		return row, nil
	}
	return nil, fmt.Errorf("credential repo: find by user kind: %w", gorm.ErrRecordNotFound)
}

// fakeSettings SettingsReader 的 fake。
type fakeSettings struct {
	b map[string]bool
	s map[string]string
}

func (f *fakeSettings) GetBool(key string) (bool, bool) {
	v, ok := f.b[key]
	return v, ok
}

func (f *fakeSettings) GetString(key string) (string, bool) {
	v, ok := f.s[key]
	return v, ok
}

// fakeProviders ProviderReader 的 fake：key → 行；未配置的 key 返回
// 包装 gorm.ErrRecordNotFound。
type fakeProviders struct {
	rows map[string]*model.Provider
	err  error
}

func (f *fakeProviders) FindByKey(_ context.Context, key string) (*model.Provider, error) {
	if f.err != nil {
		return nil, f.err
	}
	if row, ok := f.rows[key]; ok {
		return row, nil
	}
	return nil, fmt.Errorf("provider repo: find by key: %w", gorm.ErrRecordNotFound)
}

// fakeCaptcha CaptchaConfiger 的 fake：原样回放固定 Config。
type fakeCaptcha struct{ cfg captcha.Config }

func (f *fakeCaptcha) Config(context.Context) captcha.Config { return f.cfg }

// newSessionHandler 构造挂真实 session 拦截器的生成 handler（自造密钥
// version=1 kid=1，同 internal/connect/session_test.go 口径），返回签发
// 助手与 http.Handler。GetConfig 依赖经 deps 可选注入（nil 取空 fake，
// GetProfile 用例不受影响）。
func newSessionHandler(t *testing.T, users UserReader, deps ...*getConfigDeps) (*session.Tokens, *fakeEpochReader, http.Handler) {
	t.Helper()
	var d *getConfigDeps
	if len(deps) > 0 {
		d = deps[0]
	}
	if d == nil {
		d = &getConfigDeps{}
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x20 + i)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	tokens := session.NewTokens(security.NewCodec(ks))
	epochs := &fakeEpochReader{values: map[int64]int64{}}
	_, h := accountv1connect.NewAccountServiceHandler(
		New(users, d.creds(), d.settings(), d.providers(), d.captcha),
		connect.WithInterceptors(internalconnect.NewSessionInterceptor(
			session.NewVerifier(tokens, epochs),
			session.NewRenewer(tokens, time.Hour),
			session.NewCookie("al_session", "", time.Hour),
			nil,
		)),
	)
	return tokens, epochs, h
}

// getConfigDeps GetConfig 用例的依赖集（缺省字段取空 fake）。
type getConfigDeps struct {
	credsIn    CredentialReader
	settingsIn SettingsReader
	providersIn ProviderReader
	captcha    CaptchaConfiger
}

func (d *getConfigDeps) creds() CredentialReader {
	if d.credsIn == nil {
		return &fakeCreds{}
	}
	return d.credsIn
}

func (d *getConfigDeps) settings() SettingsReader {
	if d.settingsIn == nil {
		return &fakeSettings{}
	}
	return d.settingsIn
}

func (d *getConfigDeps) providers() ProviderReader {
	if d.providersIn == nil {
		return &fakeProviders{}
	}
	return d.providersIn
}

// sessionCookie 签发 uid=10086 epoch=3 的有效会话令牌（exp 1 小时后），
// epoch 读取链同步放行。
func sessionCookie(t *testing.T, tokens *session.Tokens, epochs *fakeEpochReader) string {
	t.Helper()
	p := &token.SessionTokenPayload{
		Id:    10086,
		Epoch: 3,
		Amr:   []string{"pwd"},
		Sid:   "sid-0001",
		Iat:   time.Now().Add(-time.Minute).Unix(),
		Exp:   time.Now().Add(time.Hour).Unix(),
	}
	epochs.values[p.Id] = p.Epoch
	tok, err := tokens.Sign(p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return "al_session=" + tok
}

// wantUser/wantProfile 有会话用例的数据样例（§3.1 行 779-797）。
func wantUser() *model.User {
	phone, email := "13800008000", "alice@example.com"
	lastLogin := time.Unix(1761800000, 0).UTC()
	return &model.User{
		ID: 10086, Username: "zhang_san", Phone: &phone, Email: &email,
		PhoneVerified: 1, EmailVerified: 1, Nickname: "张三",
		AvatarURL: "https://cdn.example.com/a.jpg", UserStatus: 1,
		MfaRequired: 0, Epoch: 3, LastLoginAt: &lastLogin,
		CreatedAt: time.Unix(1761700000, 0).UTC(), UpdatedAt: time.Unix(1761800000, 0).UTC(),
	}
}

func wantProfile(t *testing.T) *model.UserProfile {
	t.Helper()
	// {"company":"Acme"} 的 msgpack 字节：fixmap1 + str7 "company" + str4 "Acme"。
	extra := []byte{0x81, 0xa7, 'c', 'o', 'm', 'p', 'a', 'n', 'y', 0xa4, 'A', 'c', 'm', 'e'}
	birthday := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	return &model.UserProfile{
		UserID: 10086, Gender: 1, Birthday: &birthday,
		Locale: "zh-CN", Timezone: "Asia/Shanghai", Extra: extra,
	}
}

// TestGetProfileWithSession 有会话端到端：带有效 al_session Cookie 打
// GetProfile → 200，protojson 解码后逐项断言 §3.1 字段与掩码
//（138****8000 / a***@example.com）。
func TestGetProfileWithSession(t *testing.T) {
	users := &fakeUsers{user: wantUser(), profile: wantProfile(t)}
	tokens, epochs, h := newSessionHandler(t, users)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+accountv1connect.AccountServiceGetProfileProcedure, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie(t, tokens, epochs))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST GetProfile: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}

	var got accountv1.ProfileResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetId() != 10086 || got.GetUsername() != "zhang_san" || got.GetNickname() != "张三" {
		t.Errorf("basic fields = %+v", &got)
	}
	if got.GetPhone() != "138****8000" {
		t.Errorf("phone = %q, want 138****8000（服务端掩码，§3.1 行 806/813）", got.GetPhone())
	}
	if got.GetEmail() != "a***@example.com" {
		t.Errorf("email = %q, want a***@example.com（服务端掩码，§3.1 行 806/813）", got.GetEmail())
	}
	if got.GetPhoneVerified() != 1 || got.GetEmailVerified() != 1 {
		t.Errorf("verified = (%d, %d), want (1, 1)（原样，不受掩码影响）", got.GetPhoneVerified(), got.GetEmailVerified())
	}
	if got.GetUserStatus() != 1 || got.GetMfaRequired() != 0 || got.GetEpoch() != 3 {
		t.Errorf("status/mfa/epoch = (%d, %d, %d)", got.GetUserStatus(), got.GetMfaRequired(), got.GetEpoch())
	}
	if got.GetLastLoginAt() != 1761800000 || got.GetCreatedAt() != 1761700000 || got.GetUpdatedAt() != 1761800000 {
		t.Errorf("timestamps = (%d, %d, %d)", got.GetLastLoginAt(), got.GetCreatedAt(), got.GetUpdatedAt())
	}
	if got.GetAvatarUrl() != "https://cdn.example.com/a.jpg" {
		t.Errorf("avatarUrl = %q", got.GetAvatarUrl())
	}
	p := got.GetProfile()
	if p == nil || p.GetGender() != 1 || p.GetBirthday() != "1990-01-01" ||
		p.GetLocale() != "zh-CN" || p.GetTimezone() != "Asia/Shanghai" {
		t.Errorf("profile = %+v", p)
	}
	if v := p.GetExtra().GetFields()["company"].GetStringValue(); v != "Acme" {
		t.Errorf("profile.extra.company = %q, want Acme（msgpack → JSON 对象）", v)
	}
}

// TestGetProfileWithoutSession 无会话：session 拦截器放行匿名（既定语义：
// 清 Cookie 不 401），handler 判定 ctx 无 uid → 401 unauthenticated。
func TestGetProfileWithoutSession(t *testing.T) {
	_, _, h := newSessionHandler(t, &fakeUsers{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+accountv1connect.AccountServiceGetProfileProcedure, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST GetProfile: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", resp.StatusCode, raw)
	}
	var errBody struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(raw), &errBody); err != nil {
		t.Fatalf("decode error body %q: %v", raw, err)
	}
	if errBody.Code != "unauthenticated" {
		t.Errorf("code = %q, want unauthenticated (body %s)", errBody.Code, raw)
	}
	// 拦截器对匿名请求清 Cookie（§3.14 语义），handler 401 时响应头已合并。
	if resp.Header.Get("Set-Cookie") == "" {
		t.Error("anonymous request missing Set-Cookie (拦截器清 Cookie)")
	}
}

// TestGetProfileUserNotFound 用户不存在（会话有效但行已删）→ 404
// not_found；user_profile 行缺失 → 200 + 零值 profile，不报错。
func TestGetProfileUserNotFound(t *testing.T) {
	users := &fakeUsers{userErr: fmt.Errorf("user repo: find by id: %w", gorm.ErrRecordNotFound)}
	tokens, epochs, h := newSessionHandler(t, users)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+accountv1connect.AccountServiceGetProfileProcedure, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie(t, tokens, epochs))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST GetProfile: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body %s)", resp.StatusCode, raw)
	}
	var errBody struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(raw), &errBody); err != nil {
		t.Fatalf("decode error body %q: %v", raw, err)
	}
	if errBody.Code != "not_found" {
		t.Errorf("code = %q, want not_found (body %s)", errBody.Code, raw)
	}
}

// TestGetProfileProfileRowMissing user_profile 行缺失（ErrRecordNotFound）
// → 200，profile 为零值消息而非错误。
func TestGetProfileProfileRowMissing(t *testing.T) {
	users := &fakeUsers{
		user:       wantUser(),
		profileErr: fmt.Errorf("user repo: get profile: %w", gorm.ErrRecordNotFound),
	}
	tokens, epochs, h := newSessionHandler(t, users)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+accountv1connect.AccountServiceGetProfileProcedure, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie(t, tokens, epochs))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST GetProfile: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200（profile 行缺失非错误, body %s）", resp.StatusCode, raw)
	}
	var got accountv1.ProfileResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetId() != 10086 {
		t.Errorf("id = %d, want 10086（主信息不受 profile 缺失影响）", got.GetId())
	}
	if p := got.GetProfile(); p == nil || p.GetGender() != 0 || p.GetBirthday() != "" {
		t.Errorf("profile = %+v, want 零值 profile 消息", p)
	}
}

// postGetConfig 打一次带会话 Cookie 的 GetConfig，返回状态码与响应体。
func postGetConfig(t *testing.T, srvURL string, tokens *session.Tokens, epochs *fakeEpochReader) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srvURL+accountv1connect.AccountServiceGetConfigProcedure, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie(t, tokens, epochs))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST GetConfig: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, readBody(t, resp.Body)
}

// wantConfigDeps 全量用例的依赖集：storage provider（s3 + direct + 限额）、
// mfa_setting 行（totp/otp_sms）、password/totp/webauthn/recovery_code 行、
// captcha 第三方配置、mfa_enabled=true。meta / ext 均经 repo 编码出口构造。
func wantConfigDeps(t *testing.T) *getConfigDeps {
	t.Helper()
	mfaMeta, err := repo.MarshalCredentialMeta(&credential.CredentialMeta{
		MfaMethods: []string{"totp", "otp_sms"},
	})
	if err != nil {
		t.Fatalf("marshal mfa meta: %v", err)
	}
	recoveryMeta, err := repo.MarshalCredentialMeta(&credential.CredentialMeta{
		RecoveryCodes: []string{"abcdwxyz", "efghkmnp"},
	})
	if err != nil {
		t.Fatalf("marshal recovery meta: %v", err)
	}
	ext, err := repo.MarshalProviderExt(&provider.Ext{
		UploadMode:   "direct",
		MaxSize:      10 << 20,
		AllowedTypes: "image/png, image/jpeg",
	})
	if err != nil {
		t.Fatalf("marshal provider ext: %v", err)
	}
	return &getConfigDeps{
		credsIn: &fakeCreds{rows: map[string]*model.UserCredential{
			kindPassword:     {Kind: kindPassword, IsEnabled: 1},
			kindTotp:         {Kind: kindTotp, IsEnabled: 1},
			kindWebauthn:     {Kind: kindWebauthn, IsEnabled: 1},
			kindRecoveryCode: {Kind: kindRecoveryCode, IsEnabled: 1, Meta: recoveryMeta},
			kindMfaSetting:   {Kind: kindMfaSetting, IsEnabled: 1, Meta: mfaMeta},
		}},
		settingsIn: &fakeSettings{
			b: map[string]bool{settings.KeyMfaEnabled: true},
			s: map[string]string{settings.KeyAvatarStorageProvider: "minio"},
		},
		providersIn: &fakeProviders{rows: map[string]*model.Provider{
			"minio": {ProviderKey: "minio", Category: "storage", Type: "s3", IsEnabled: 1, Ext: ext},
		}},
		captcha: &fakeCaptcha{cfg: captcha.Config{ProviderKey: "cf", Type: "turnstile", SiteKey: "site-x"}},
	}
}

// TestGetConfigWithSession 有会话端到端：四件全量下发逐项断言（§3.2 行
// 818-847）——avatarUpload 投影（s3 direct）、mfaPolicy（行存在 + 集合 +
// recovery_code 随 totp + required + trustedDeviceDays=0）、captcha 公开
// 视图（无凭证字段）、hasPassword。
func TestGetConfigWithSession(t *testing.T) {
	user := wantUser()
	user.MfaRequired = 1
	tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: user}, wantConfigDeps(t))
	srv := httptest.NewServer(h)
	defer srv.Close()

	status, raw := postGetConfig(t, srv.URL, tokens, epochs)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", status, raw)
	}
	var got accountv1.AccountConfigResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}

	// ① avatarUpload：s3 + direct 直传模式，Ext 三字段投影。
	avatar := got.GetAvatarUpload()
	if avatar.GetMode() != "direct" || avatar.GetMaxSize() != 10<<20 {
		t.Errorf("avatarUpload mode/maxSize = (%q, %d), want (direct, %d)", avatar.GetMode(), avatar.GetMaxSize(), 10<<20)
	}
	if types := avatar.GetAllowedTypes(); len(types) != 2 || types[0] != "image/png" || types[1] != "image/jpeg" {
		t.Errorf("avatarUpload allowedTypes = %v, want [image/png image/jpeg]（逗号分隔 + 去空白）", types)
	}

	// ② mfaPolicy：enabled=行存在、required=mfa_enabled && mfa_required、
	// trustedDeviceDays 恒 0、五因子序 + enabled 按集合 + bound 投影。
	mfa := got.GetMfaPolicy()
	if !mfa.GetEnabled() || !mfa.GetRequired() {
		t.Errorf("mfaPolicy enabled/required = (%v, %v), want (true, true)", mfa.GetEnabled(), mfa.GetRequired())
	}
	if mfa.GetTrustedDeviceDays() != 0 {
		t.Errorf("mfaPolicy trustedDeviceDays = %d, want 0（预留恒 0）", mfa.GetTrustedDeviceDays())
	}
	methods := mfa.GetMethods()
	if len(methods) != 5 {
		t.Fatalf("mfaPolicy methods len = %d, want 5", len(methods))
	}
	wantMethods := []struct {
		factor  string
		enabled bool
		bound   bool
	}{
		{"totp", true, true},          // ∈ 集合；有 kind=totp 行
		{"otp_sms", true, true},       // ∈ 集合；user.phone 非空
		{"otp_email", false, true},    // ∉ 集合；user.email 非空（enabled/bound 独立）
		{"webauthn", false, true},     // ∉ 集合；有 kind=webauthn 行
		{"recovery_code", true, true}, // 随 totp 投影；余量非空
	}
	for i, w := range wantMethods {
		m := methods[i]
		if m.GetFactor() != w.factor || m.GetEnabled() != w.enabled || m.GetBound() != w.bound {
			t.Errorf("methods[%d] = {%s enabled=%v bound=%v}, want {%s enabled=%v bound=%v}",
				i, m.GetFactor(), m.GetEnabled(), m.GetBound(), w.factor, w.enabled, w.bound)
		}
	}

	// ③ captcha：Gate 现算公开视图（无凭证）——三字段下发，结构上不含
	// secret（CaptchaConfig 无该字段），响应亦不得出现凭证键。
	capCfg := got.GetCaptcha()
	if capCfg.GetProviderKey() != "cf" || capCfg.GetType() != "turnstile" || capCfg.GetSiteKey() != "site-x" {
		t.Errorf("captcha = {%s %s %s}, want {cf turnstile site-x}", capCfg.GetProviderKey(), capCfg.GetType(), capCfg.GetSiteKey())
	}
	if strings.Contains(raw, "secret") || strings.Contains(raw, "client_secret") {
		t.Errorf("captcha response leaks credential (body %s)", raw)
	}

	// ④ hasPassword：kind=password 且 is_enabled=1。
	if !got.GetHasPassword() {
		t.Error("hasPassword = false, want true（存在启用 password 行）")
	}
}

// TestGetConfigAvatarUploadUnconfigured avatarUpload 零值投影分支（行 826）：
// 未配置键 / 空串 / 查无该行 / is_enabled=0 / category≠storage →
// {mode:"proxy", maxSize:0, allowedTypes:[]}。
func TestGetConfigAvatarUploadUnconfigured(t *testing.T) {
	ext, err := repo.MarshalProviderExt(&provider.Ext{UploadMode: "direct", MaxSize: 1 << 20})
	if err != nil {
		t.Fatalf("marshal ext: %v", err)
	}
	cases := []struct {
		name      string
		settings  *fakeSettings
		providers *fakeProviders
	}{
		{"键缺失（未配置）", &fakeSettings{}, &fakeProviders{}},
		{"空串", &fakeSettings{s: map[string]string{settings.KeyAvatarStorageProvider: ""}}, &fakeProviders{}},
		{"查无该行", &fakeSettings{s: map[string]string{settings.KeyAvatarStorageProvider: "minio"}}, &fakeProviders{}},
		{"is_enabled=0", &fakeSettings{s: map[string]string{settings.KeyAvatarStorageProvider: "minio"}}, &fakeProviders{
			rows: map[string]*model.Provider{"minio": {ProviderKey: "minio", Category: "storage", Type: "s3", IsEnabled: 0, Ext: ext}},
		}},
		{"category≠storage", &fakeSettings{s: map[string]string{settings.KeyAvatarStorageProvider: "minio"}}, &fakeProviders{
			rows: map[string]*model.Provider{"minio": {ProviderKey: "minio", Category: "sms", Type: "aliyun_sms", IsEnabled: 1, Ext: ext}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := wantConfigDeps(t)
			deps.settingsIn, deps.providersIn = tc.settings, tc.providers
			tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, deps)
			srv := httptest.NewServer(h)
			defer srv.Close()

			status, raw := postGetConfig(t, srv.URL, tokens, epochs)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", status, raw)
			}
			var got accountv1.AccountConfigResponse
			if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
				t.Fatalf("decode response %q: %v", raw, err)
			}
			avatar := got.GetAvatarUpload()
			if avatar.GetMode() != "proxy" || avatar.GetMaxSize() != 0 || len(avatar.GetAllowedTypes()) != 0 {
				t.Errorf("avatarUpload = {%q %d %v}, want 零值投影 {proxy 0 []}", avatar.GetMode(), avatar.GetMaxSize(), avatar.GetAllowedTypes())
			}
		})
	}
}

// TestGetConfigAvatarUploadLocalDirect local 配置 direct 自动回退 proxy
//（行 825、后端架构 §15.1：local 无预签名能力）；maxSize / allowedTypes
// 照常投影。
func TestGetConfigAvatarUploadLocalDirect(t *testing.T) {
	ext, err := repo.MarshalProviderExt(&provider.Ext{
		UploadMode:   "direct",
		MaxSize:      1 << 20,
		AllowedTypes: "image/png",
	})
	if err != nil {
		t.Fatalf("marshal ext: %v", err)
	}
	deps := wantConfigDeps(t)
	deps.providersIn = &fakeProviders{rows: map[string]*model.Provider{
		"local1": {ProviderKey: "local1", Category: "storage", Type: "local", IsEnabled: 1, Ext: ext},
	}}
	deps.settingsIn.(*fakeSettings).s[settings.KeyAvatarStorageProvider] = "local1"
	tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, deps)
	srv := httptest.NewServer(h)
	defer srv.Close()

	status, raw := postGetConfig(t, srv.URL, tokens, epochs)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", status, raw)
	}
	var got accountv1.AccountConfigResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	avatar := got.GetAvatarUpload()
	if avatar.GetMode() != "proxy" {
		t.Errorf("avatarUpload mode = %q, want proxy（local+direct 回退）", avatar.GetMode())
	}
	if avatar.GetMaxSize() != 1<<20 || len(avatar.GetAllowedTypes()) != 1 {
		t.Errorf("avatarUpload maxSize/allowedTypes = (%d, %v), want 照常投影", avatar.GetMaxSize(), avatar.GetAllowedTypes())
	}
}

// TestGetConfigMfaSettingMissing 无 mfa_setting 行 → enabled=false、
// methods[].enabled 全 false（recovery_code 亦 false：无 totp）；bound 照
// 绑定态投影；required=false（user.mfa_required=0）。
func TestGetConfigMfaSettingMissing(t *testing.T) {
	deps := wantConfigDeps(t)
	creds := deps.credsIn.(*fakeCreds)
	delete(creds.rows, kindMfaSetting)
	tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, deps)
	srv := httptest.NewServer(h)
	defer srv.Close()

	status, raw := postGetConfig(t, srv.URL, tokens, epochs)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", status, raw)
	}
	var got accountv1.AccountConfigResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	mfa := got.GetMfaPolicy()
	if mfa.GetEnabled() {
		t.Error("mfaPolicy enabled = true, want false（无 mfa_setting 行）")
	}
	if mfa.GetRequired() {
		t.Error("mfaPolicy required = true, want false（mfa_required=0）")
	}
	for _, m := range mfa.GetMethods() {
		if m.GetEnabled() {
			t.Errorf("methods[%s].enabled = true, want false（集合空）", m.GetFactor())
		}
	}
}

// TestGetConfigHasPasswordStates hasPassword 两态：无 password 行 / 行
// is_enabled=0 → false。
func TestGetConfigHasPasswordStates(t *testing.T) {
	cases := []struct {
		name string
		rows map[string]*model.UserCredential
		want bool
	}{
		{"无行", map[string]*model.UserCredential{}, false},
		{"行存在 is_enabled=0", map[string]*model.UserCredential{
			kindPassword: {Kind: kindPassword, IsEnabled: 0},
		}, false},
		{"行存在 is_enabled=1", map[string]*model.UserCredential{
			kindPassword: {Kind: kindPassword, IsEnabled: 1},
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := wantConfigDeps(t)
			deps.credsIn = &fakeCreds{rows: tc.rows}
			tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, deps)
			srv := httptest.NewServer(h)
			defer srv.Close()

			status, raw := postGetConfig(t, srv.URL, tokens, epochs)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", status, raw)
			}
			var got accountv1.AccountConfigResponse
			if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
				t.Fatalf("decode response %q: %v", raw, err)
			}
			if got.GetHasPassword() != tc.want {
				t.Errorf("hasPassword = %v, want %v", got.GetHasPassword(), tc.want)
			}
		})
	}
}

// TestGetConfigWithoutSession 无会话 → 401 unauthenticated（同 GetProfile）。
func TestGetConfigWithoutSession(t *testing.T) {
	_, _, h := newSessionHandler(t, &fakeUsers{}, wantConfigDeps(t))
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+accountv1connect.AccountServiceGetConfigProcedure, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST GetConfig: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", resp.StatusCode, raw)
	}
	var errBody struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(raw), &errBody); err != nil {
		t.Fatalf("decode error body %q: %v", raw, err)
	}
	if errBody.Code != "unauthenticated" {
		t.Errorf("code = %q, want unauthenticated (body %s)", errBody.Code, raw)
	}
}

// TestOtherMethodsUnimplemented 其余方法一律返回生成基类的 unimplemented
//（GetConfig 已实装，移出桩清单）。
func TestOtherMethodsUnimplemented(t *testing.T) {
	_, _, h := newSessionHandler(t, &fakeUsers{})
	cases := []string{
		accountv1connect.AccountServiceUpdateProfileProcedure,
		accountv1connect.AccountServicePresignAvatarProcedure,
		accountv1connect.AccountServiceCommitAvatarProcedure,
		accountv1connect.AccountServiceChangePasswordProcedure,
		accountv1connect.AccountServiceBindPhoneProcedure,
		accountv1connect.AccountServiceBindEmailProcedure,
		accountv1connect.AccountServiceGetMfaProcedure,
		accountv1connect.AccountServiceSetMfaProcedure,
		accountv1connect.AccountServiceBindTotpProcedure,
		accountv1connect.AccountServiceGetRecoveryCodesProcedure,
		accountv1connect.AccountServiceRegenerateRecoveryCodesProcedure,
		accountv1connect.AccountServiceGetWebauthnCredentialsProcedure,
		accountv1connect.AccountServiceRegisterWebauthnProcedure,
		accountv1connect.AccountServiceRenameWebauthnCredentialProcedure,
		accountv1connect.AccountServiceDeleteWebauthnCredentialProcedure,
		accountv1connect.AccountServiceGetThirdpartyBindingsProcedure,
		accountv1connect.AccountServiceUnbindThirdpartyProcedure,
		accountv1connect.AccountServiceThirdpartyOauthProcedure,
		accountv1connect.AccountServiceGetThirdpartyTicketProcedure,
		accountv1connect.AccountServiceGetEventsProcedure,
	}
	for _, procedure := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, procedure, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rec, req)

		var errBody struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
			t.Fatalf("%s: decode error body %q: %v", procedure, rec.Body.String(), err)
		}
		if errBody.Code != "unimplemented" {
			t.Errorf("%s: code = %q, want unimplemented (body %s)", procedure, errBody.Code, rec.Body.String())
		}
	}
}

func readBody(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
