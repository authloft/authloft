package account

import (
	"context"
	"encoding/base64"
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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/gen/go/api/account/v1/accountv1connect"
	"authloft/gen/go/api/common/v1"
	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/credential"
	"authloft/gen/go/provider"
	"authloft/gen/go/token"
	"authloft/internal/captcha"
	internalconnect "authloft/internal/connect"
	"authloft/internal/factor/webauthn"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service"
	accountsvc "authloft/internal/service/account"
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
	user       *model.User
	profile    *model.UserProfile
	userErr    error
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
// 助手与 http.Handler。GetConfig / 三方绑定族 / UpdateProfile 依赖经 deps
// 可选注入（nil 取空 fake，GetProfile 用例不受影响）。
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
		New(users, d.creds(), d.settings(), d.providers(), d.captcha, d.thirdparty(), d.webauthn(), d.profile()),
		connect.WithInterceptors(internalconnect.NewSessionInterceptor(
			session.NewVerifier(tokens, epochs),
			session.NewRenewer(tokens, time.Hour),
			session.NewCookie("al_session", "", time.Hour),
			nil,
		)),
	)
	return tokens, epochs, h
}

// getConfigDeps GetConfig / 三方绑定族 / 通行密钥族 / UpdateProfile 用例的
// 依赖集（缺省字段取空 fake）。
type getConfigDeps struct {
	credsIn      CredentialReader
	settingsIn   SettingsReader
	providersIn  ProviderReader
	captcha      CaptchaConfiger
	thirdpartyIn Thirdparty
	webauthnIn   Webauthn
	profileIn    ProfileUpdater
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

func (d *getConfigDeps) thirdparty() Thirdparty { return d.thirdpartyIn }
func (d *getConfigDeps) webauthn() Webauthn     { return d.webauthnIn }
func (d *getConfigDeps) profile() ProfileUpdater { return d.profileIn }

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
// （138****8000 / a***@example.com）。
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
// （行 825、后端架构 §15.1：local 无预签名能力）；maxSize / allowedTypes
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
// （GetConfig、三方绑定族四方法、通行密钥族四方法与 UpdateProfile
// 〔GetWebauthnCredentials / RegisterWebauthn / RenameWebauthnCredential /
// DeleteWebauthnCredential〕均已实装，移出桩清单——未装配 service 时的
// unimplemented 由 TestThirdpartyMethodsNotConfigured /
// TestWebauthnMethodsNotConfigured / TestUpdateProfileNotConfigured 单独覆盖）。
func TestOtherMethodsUnimplemented(t *testing.T) {
	_, _, h := newSessionHandler(t, &fakeUsers{})
	cases := []string{
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

// —— UpdateProfile（接口文档 §3.2 行 837）——

// fakeProfileUpdater ProfileUpdater 窄接口的 fake：预置错误回放 + 入参记录。
type fakeProfileUpdater struct {
	err   error
	calls int
	uids  []int64
	reqs  []*accountv1.UpdateProfileRequest
}

func (f *fakeProfileUpdater) UpdateProfile(_ context.Context, uid int64, in *accountv1.UpdateProfileRequest) error {
	f.calls++
	f.uids = append(f.uids, uid)
	f.reqs = append(f.reqs, in)
	return f.err
}

// TestUpdateProfileWithSession 有会话端到端：带有效 al_session Cookie 打
// UpdateProfile → 200 空响应（§3.2 行 837）；service 收到会话 uid=10086
//（仅本人——目标一律取 ctx 身份，不接受入参指定）与请求体原样透传
//（proto3 optional 的 has 位解析归 service，handler 不做裁剪）。
func TestUpdateProfileWithSession(t *testing.T) {
	fp := &fakeProfileUpdater{}
	tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{profileIn: fp})
	srv := httptest.NewServer(h)
	defer srv.Close()

	body := `{"nickname":"李四","avatarUrl":"https://cdn.example.com/b.jpg","profile":{"gender":0,"birthday":"","locale":""}}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+accountv1connect.AccountServiceUpdateProfileProcedure, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie(t, tokens, epochs))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST UpdateProfile: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	// 成功为空响应：protojson 输出 {}。
	if strings.TrimSpace(raw) != "{}" {
		t.Errorf("body = %q, want {}", raw)
	}
	if fp.calls != 1 {
		t.Fatalf("service calls = %d, want 1", fp.calls)
	}
	if fp.uids[0] != 10086 {
		t.Errorf("service uid = %d, want 10086（仅本人：会话身份）", fp.uids[0])
	}
	in := fp.reqs[0]
	if in.GetNickname() != "李四" || in.GetAvatarUrl() != "https://cdn.example.com/b.jpg" {
		t.Errorf("req = (nickname=%q avatarUrl=%q), want 原样透传", in.GetNickname(), in.GetAvatarUrl())
	}
	if p := in.GetProfile(); p == nil || p.GetGender() != 0 || p.GetBirthday() != "" || p.GetLocale() != "" {
		t.Errorf("req profile = %+v, want 显式零值透传（has 位保留）", in.GetProfile())
	}
}

// TestUpdateProfileEmptyBody 有会话空 body（全字段未设置）→ 200：合法空
// 操作直透 service（零写库语义由 service 层测试覆盖，本用例锁定 handler
// 不拦截空 body）。
func TestUpdateProfileEmptyBody(t *testing.T) {
	fp := &fakeProfileUpdater{}
	tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{profileIn: fp})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+accountv1connect.AccountServiceUpdateProfileProcedure, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie(t, tokens, epochs))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST UpdateProfile: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	if fp.calls != 1 || fp.reqs[0].GetProfile() != nil {
		t.Errorf("service calls = %d profile = %v, want (1, nil 原样透传)", fp.calls, fp.reqs[0].GetProfile())
	}
}

// TestUpdateProfileUnauthenticated 无会话 → 401 unauthenticated（§1.2 行
// 96：本域全接口需 al_session；拦截器放行匿名、401 由 handler 判定），
// 且不触 service。
func TestUpdateProfileUnauthenticated(t *testing.T) {
	fp := &fakeProfileUpdater{}
	_, _, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{profileIn: fp})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+accountv1connect.AccountServiceUpdateProfileProcedure, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST UpdateProfile: %v", err)
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
	if fp.calls != 0 {
		t.Errorf("service calls = %d, want 0（401 先于 service）", fp.calls)
	}
}

// TestUpdateProfileUserNotFound service 回 user 不存在（gorm.ErrRecordNotFound
// 包装）→ 404 not_found（口径同 GetProfile）。
func TestUpdateProfileUserNotFound(t *testing.T) {
	fp := &fakeProfileUpdater{err: fmt.Errorf("user repo: find by id: %w", gorm.ErrRecordNotFound)}
	tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{profileIn: fp})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+accountv1connect.AccountServiceUpdateProfileProcedure, strings.NewReader(`{"nickname":"x"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie(t, tokens, epochs))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST UpdateProfile: %v", err)
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

// TestUpdateProfileBadBirthday service 回 ErrProfileInvalidRequest（birthday
// 格式非法）→ 400 invalid_argument + ErrorInfo(account, invalid_request)
//（§1.6 封闭集；文案同 rpc 域先例）。
func TestUpdateProfileBadBirthday(t *testing.T) {
	fp := &fakeProfileUpdater{err: accountsvc.ErrProfileInvalidRequest}
	tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{profileIn: fp})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+accountv1connect.AccountServiceUpdateProfileProcedure, strings.NewReader(`{"profile":{"birthday":"1990/01/01"}}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie(t, tokens, epochs))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST UpdateProfile: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", resp.StatusCode, raw)
	}
	var errBody struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(raw), &errBody); err != nil {
		t.Fatalf("decode error body %q: %v", raw, err)
	}
	if errBody.Code != "invalid_argument" {
		t.Errorf("code = %q, want invalid_argument (body %s)", errBody.Code, raw)
	}
	info := decodeAccountErrorInfo(t, raw)
	if info.GetDomain() != "account" || info.GetCode() != "invalid_request" {
		t.Errorf("ErrorInfo = (domain=%q code=%q), want (account, invalid_request)", info.GetDomain(), info.GetCode())
	}
}

// TestUpdateProfileNotConfigured 未装配资料更新 service（测试桩）→
// unimplemented（TestOtherMethodsUnimplemented 移出 UpdateProfile 后的
// 未装配分支覆盖，口径同三方绑定 / 通行密钥族）。
func TestUpdateProfileNotConfigured(t *testing.T) {
	_, _, h := newSessionHandler(t, &fakeUsers{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, accountv1connect.AccountServiceUpdateProfileProcedure, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)

	var errBody struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	if errBody.Code != "unimplemented" {
		t.Errorf("code = %q, want unimplemented (body %s)", errBody.Code, rec.Body.String())
	}
}

// —— 三方绑定族四方法（接口文档 §3.7 / §3.7.1）——

// fakeThirdparty Thirdparty 窄接口的 fake：预置结果回放 + 入参记录。
type fakeThirdparty struct {
	bindings    *accountsvc.BindingsResult
	bindingsErr error
	bindingsUID int64
	unbindErr   error
	unbindUID   int64
	unbindKey   string
	oauthOut    *accountsvc.BindOutcome
	oauthErr    error
	oauthIn     accountsvc.OauthInput
	ticketResp  *ssov1.LoginFlowResponse
	ticketIn    accountsvc.TicketInput
}

func (f *fakeThirdparty) GetThirdpartyBindings(_ context.Context, uid int64) (*accountsvc.BindingsResult, error) {
	f.bindingsUID = uid
	return f.bindings, f.bindingsErr
}

func (f *fakeThirdparty) UnbindThirdparty(_ context.Context, uid int64, providerKey string) error {
	f.unbindUID, f.unbindKey = uid, providerKey
	return f.unbindErr
}

func (f *fakeThirdparty) ThirdpartyOauth(_ context.Context, in accountsvc.OauthInput) (*accountsvc.BindOutcome, error) {
	f.oauthIn = in
	return f.oauthOut, f.oauthErr
}

func (f *fakeThirdparty) GetThirdpartyTicket(_ context.Context, in accountsvc.TicketInput) *ssov1.LoginFlowResponse {
	f.ticketIn = in
	return f.ticketResp
}

// decodeAccountErrorInfo 从 Connect 错误体 details 解出 ErrorInfo（base64
// value → proto 解码，§1.5 行 203-210；口径同 handler/admin admin_test.go
// decodeErrorInfo——测试包私有，各落一份）。
func decodeAccountErrorInfo(t *testing.T, raw string) *commonv1.ErrorInfo {
	t.Helper()
	var body struct {
		Code    string `json:"code"`
		Details []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"details"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("decode error body %q: %v", raw, err)
	}
	if len(body.Details) != 1 {
		t.Fatalf("details 数量 = %d, want 1 (body %s)", len(body.Details), raw)
	}
	buf, err := base64.RawStdEncoding.DecodeString(body.Details[0].Value)
	if err != nil {
		t.Fatalf("decode detail value: %v", err)
	}
	info := &commonv1.ErrorInfo{}
	if err := proto.Unmarshal(buf, info); err != nil {
		t.Fatalf("unmarshal ErrorInfo: %v", err)
	}
	return info
}

// TestThirdpartyMethodsNotConfigured 未装配三方绑定 service（测试桩）时四方法
// 一律 unimplemented（sso 域 Thirdparty/Qrcode nil 同款口径）。
func TestThirdpartyMethodsNotConfigured(t *testing.T) {
	_, _, h := newSessionHandler(t, &fakeUsers{})
	cases := []string{
		accountv1connect.AccountServiceGetThirdpartyBindingsProcedure,
		accountv1connect.AccountServiceUnbindThirdpartyProcedure,
		accountv1connect.AccountServiceThirdpartyOauthProcedure,
		accountv1connect.AccountServiceGetThirdpartyTicketProcedure,
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

// TestGetThirdpartyBindingsConnect 端到端：双列表投影 + uid 注入 + 无会话 401。
func TestGetThirdpartyBindingsConnect(t *testing.T) {
	tp := &fakeThirdparty{bindings: &accountsvc.BindingsResult{
		Items: []accountsvc.BoundItem{{
			ProviderKey: "qq", DisplayName: "QQ", Type: "qq",
			Channel: "redirect", Icon: "https://q.cn/icon.png", CreatedAt: 1761800000,
		}},
		Available: []accountsvc.BindOption{{
			ProviderKey: "wechat_mp_scan", DisplayName: "微信扫码", Type: "wechat_mp_scan",
			Channel: "qrcode", Icon: "", UiGroup: "social", SortOrder: 20,
		}},
	}}
	tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{thirdpartyIn: tp})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+accountv1connect.AccountServiceGetThirdpartyBindingsProcedure, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie(t, tokens, epochs))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST GetThirdpartyBindings: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, raw)
	}
	if tp.bindingsUID != 10086 {
		t.Errorf("service 收到 uid = %d, want 10086（会话注入）", tp.bindingsUID)
	}
	var got accountv1.ThirdpartyBindingsResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if len(got.GetItems()) != 1 || len(got.GetAvailable()) != 1 {
		t.Fatalf("items/available = (%d, %d), want (1, 1)", len(got.GetItems()), len(got.GetAvailable()))
	}
	if it := got.GetItems()[0]; it.GetProviderKey() != "qq" || it.GetChannel() != "redirect" ||
		it.GetCreatedAt() != 1761800000 || it.GetIcon() != "https://q.cn/icon.png" {
		t.Errorf("items[0] = %+v", it)
	}
	if op := got.GetAvailable()[0]; op.GetProviderKey() != "wechat_mp_scan" || op.GetChannel() != "qrcode" ||
		op.GetUiGroup() != "social" || op.GetSortOrder() != 20 {
		t.Errorf("available[0] = %+v", op)
	}
}

// TestUnbindThirdpartyConnect 端到端：成功空响应 + 入参透传；判定不满足 →
// 400 + ErrorInfo(account, invalid_request)；无会话 401。
func TestUnbindThirdpartyConnect(t *testing.T) {
	post := func(t *testing.T, tp *fakeThirdparty, withSession bool) (int, string, *http.Response) {
		t.Helper()
		tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{thirdpartyIn: tp})
		srv := httptest.NewServer(h)
		defer srv.Close()
		req, err := http.NewRequest(http.MethodPost, srv.URL+accountv1connect.AccountServiceUnbindThirdpartyProcedure,
			strings.NewReader(`{"providerKey":"qq"}`))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if withSession {
			req.Header.Set("Cookie", sessionCookie(t, tokens, epochs))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST UnbindThirdparty: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode, readBody(t, resp.Body), resp
	}

	t.Run("成功空响应", func(t *testing.T) {
		tp := &fakeThirdparty{}
		status, raw, _ := post(t, tp, true)
		if status != http.StatusOK || strings.TrimSpace(raw) != "{}" {
			t.Errorf("status = %d body = %q, want 200 {}", status, raw)
		}
		if tp.unbindUID != 10086 || tp.unbindKey != "qq" {
			t.Errorf("service 收到 (uid=%d, key=%q), want (10086, qq)", tp.unbindUID, tp.unbindKey)
		}
	})
	t.Run("判定不满足 → 400 + ErrorInfo invalid_request", func(t *testing.T) {
		tp := &fakeThirdparty{unbindErr: fmt.Errorf("%w: no sign-in method left", accountsvc.ErrInvalidRequest)}
		status, raw, resp := post(t, tp, true)
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", status, raw)
		}
		info := decodeAccountErrorInfo(t, raw)
		if info.GetDomain() != "account" || info.GetCode() != "invalid_request" {
			t.Errorf("ErrorInfo = (domain=%q code=%q), want (account, invalid_request)", info.GetDomain(), info.GetCode())
		}
		if hasLoginStateCookie(resp) {
			t.Error("解绑不触碰 al_login_state（绑定 / 解绑不改变登录态）")
		}
	})
	t.Run("无会话 401", func(t *testing.T) {
		status, raw, _ := post(t, &fakeThirdparty{}, false)
		if status != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (body %s)", status, raw)
		}
	})
}

// TestThirdpartyOauthConnect 端到端：Cookie 头解析 al_login_state、成功
// {providerKey, displayName}、target_taken → 409 + ErrorInfo、零 Set-Cookie。
func TestThirdpartyOauthConnect(t *testing.T) {
	post := func(t *testing.T, tp *fakeThirdparty, cookie string) (int, string, *http.Response) {
		t.Helper()
		tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{thirdpartyIn: tp})
		srv := httptest.NewServer(h)
		defer srv.Close()
		body := `{"providerKey":"qq","code":"c1","state":"b0123456789abcdef0123456789abcde"}`
		req, err := http.NewRequest(http.MethodPost, srv.URL+accountv1connect.AccountServiceThirdpartyOauthProcedure, strings.NewReader(body))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", sessionCookie(t, tokens, epochs)+"; al_login_state="+cookie)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST ThirdpartyOauth: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode, readBody(t, resp.Body), resp
	}

	t.Run("成功 {providerKey, displayName} + Cookie 头解析", func(t *testing.T) {
		tp := &fakeThirdparty{oauthOut: &accountsvc.BindOutcome{ProviderKey: "qq", DisplayName: "QQ"}}
		status, raw, resp := post(t, tp, "sealed_state")
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", status, raw)
		}
		var got accountv1.ThirdpartyOauthResponse
		if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("decode response %q: %v", raw, err)
		}
		if got.GetProviderKey() != "qq" || got.GetDisplayName() != "QQ" {
			t.Errorf("response = {%q %q}, want {qq QQ}", got.GetProviderKey(), got.GetDisplayName())
		}
		if tp.oauthIn.StateCookie != "sealed_state" {
			t.Errorf("StateCookie = %q, want al_login_state 解析透传", tp.oauthIn.StateCookie)
		}
		if tp.oauthIn.UID != 10086 || tp.oauthIn.Code != "c1" {
			t.Errorf("service 入参 = %+v, want uid=10086 code=c1", tp.oauthIn)
		}
		if hasLoginStateCookie(resp) {
			t.Error("绑定回调不删不签 al_login_state（行 1000 绑定不改变登录态）")
		}
	})
	t.Run("target_taken → 409 + ErrorInfo", func(t *testing.T) {
		tp := &fakeThirdparty{oauthErr: accountsvc.ErrTargetTaken}
		status, raw, resp := post(t, tp, "sealed_state")
		if status != http.StatusConflict {
			t.Fatalf("status = %d, want 409（§1.5 行 191 重复绑定）(body %s)", status, raw)
		}
		info := decodeAccountErrorInfo(t, raw)
		if info.GetDomain() != "account" || info.GetCode() != "target_taken" || info.GetMessage() != "该账号已被其他账号绑定" {
			t.Errorf("ErrorInfo = %+v, want (account, target_taken, 固定文案)", info)
		}
		if hasLoginStateCookie(resp) {
			t.Error("失败路径同样不触碰 al_login_state（行 1000）")
		}
	})
}

// TestGetThirdpartyTicketConnect 端到端：信封透传（success 带 bind 字段）+
// 入参（ticket/poll/uid）+ 不触碰 al_login_state（行 1049）。
func TestGetThirdpartyTicketConnect(t *testing.T) {
	tp := &fakeThirdparty{ticketResp: &ssov1.LoginFlowResponse{
		Status: "success",
		Ticket: &ssov1.TicketStatus{Status: "success", TicketId: "c7Kx9"},
		Bind:   &ssov1.BindResult{Ok: true, ProviderKey: "wechat_mp_scan", DisplayName: "微信扫码"},
	}}
	tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{thirdpartyIn: tp})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+accountv1connect.AccountServiceGetThirdpartyTicketProcedure,
		strings.NewReader(`{"ticket":"tk-1","poll":"15"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie(t, tokens, epochs))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST GetThirdpartyTicket: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200（轮询结论走信封域）(body %s)", resp.StatusCode, raw)
	}
	var got ssov1.LoginFlowResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetStatus() != "success" || got.GetTicket().GetTicketId() != "c7Kx9" {
		t.Errorf("envelope = %s, want status=success + ticketId 回显", raw)
	}
	if b := got.GetBind(); b.GetProviderKey() != "wechat_mp_scan" || b.GetDisplayName() != "微信扫码" {
		t.Errorf("bind = %+v, want {wechat_mp_scan 微信扫码}（行 1040）", b)
	}
	if got.GetLoginToken() != "" || got.GetSessionToken() != "" {
		t.Errorf("envelope 不得携带 login_token / session_token（行 1049）: %s", raw)
	}
	if hasLoginStateCookie(resp) {
		t.Error("绑定轮询不触碰 al_login_state（行 1049 绑定不改变登录态）")
	}
	if tp.ticketIn.Ticket != "tk-1" || tp.ticketIn.Poll != 15 || tp.ticketIn.UID != 10086 {
		t.Errorf("service 入参 = %+v, want {tk-1 15 10086}", tp.ticketIn)
	}
}

// hasLoginStateCookie 响应是否出现 al_login_state 的 Set-Cookie（绑定 / 解绑 /
// 轮询一律不触碰该 Cookie——行 1000 / 1049；al_session 的会话拦截器续期属
// 通用会话机制，随全部鉴权 RPC 同等发生，不在本断言范围）。
func hasLoginStateCookie(resp *http.Response) bool {
	for _, c := range resp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, service.LoginStateCookieName+"=") {
			return true
		}
	}
	return false
}

// —— 通行密钥族（接口文档 §3.6 行 927-947 / 后端架构 §8.3）——

// fakeWebauthn Webauthn 窄接口的 fake：预置结果回放 + 入参记录。
type fakeWebauthn struct {
	list      []accountsvc.WebauthnItem
	listErr   error
	listUID   int64
	begin     *webauthn.RegistrationChallenge
	beginErr  error
	beginUID  int64
	finishErr error
	finishIn  struct {
		uid   int64
		tok   string
		label string
		cred  *structpb.Struct
	}
	renameErr error
	renameIn  struct {
		uid   int64
		id    int64
		label string
	}
	deleteErr error
	deleteIn  struct {
		uid int64
		id  int64
	}
}

func (f *fakeWebauthn) ListCredentials(_ context.Context, uid int64) ([]accountsvc.WebauthnItem, error) {
	f.listUID = uid
	return f.list, f.listErr
}

func (f *fakeWebauthn) BeginRegister(_ context.Context, uid int64) (*webauthn.RegistrationChallenge, error) {
	f.beginUID = uid
	return f.begin, f.beginErr
}

func (f *fakeWebauthn) FinishRegister(_ context.Context, uid int64, tok string, credential *structpb.Struct, label string) error {
	f.finishIn.uid, f.finishIn.tok, f.finishIn.cred, f.finishIn.label = uid, tok, credential, label
	return f.finishErr
}

func (f *fakeWebauthn) RenameCredential(_ context.Context, uid int64, id int64, label string) error {
	f.renameIn.uid, f.renameIn.id, f.renameIn.label = uid, id, label
	return f.renameErr
}

func (f *fakeWebauthn) DeleteCredential(_ context.Context, uid int64, id int64) error {
	f.deleteIn.uid, f.deleteIn.id = uid, id
	return f.deleteErr
}

// postWebauthn 带会话 Cookie POST 指定 procedure，返回状态码与响应体。
func postWebauthn(t *testing.T, wa Webauthn, procedure, body string) (int, string) {
	t.Helper()
	tokens, epochs, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{webauthnIn: wa})
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, err := http.NewRequest(http.MethodPost, srv.URL+procedure, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", sessionCookie(t, tokens, epochs))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", procedure, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, readBody(t, resp.Body)
}

// TestWebauthnMethodsNotConfigured 未装配通行密钥 service（测试桩）时
// 四方法一律 unimplemented（sso / thirdparty nil 同款口径）。
func TestWebauthnMethodsNotConfigured(t *testing.T) {
	_, _, h := newSessionHandler(t, &fakeUsers{})
	cases := []string{
		accountv1connect.AccountServiceGetWebauthnCredentialsProcedure,
		accountv1connect.AccountServiceRegisterWebauthnProcedure,
		accountv1connect.AccountServiceRenameWebauthnCredentialProcedure,
		accountv1connect.AccountServiceDeleteWebauthnCredentialProcedure,
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
			t.Fatalf("%s: decode error body %q: %v", procedure, err, rec.Body.String())
		}
		if errBody.Code != "unimplemented" {
			t.Errorf("%s: code = %q, want unimplemented (body %s)", procedure, errBody.Code, rec.Body.String())
		}
	}
}

// TestGetWebauthnCredentialsConnect 端到端：列表投影 + uid 注入 + 无会话 401。
func TestGetWebauthnCredentialsConnect(t *testing.T) {
	wa := &fakeWebauthn{list: []accountsvc.WebauthnItem{{
		ID: 11, Label: "MacBook Touch ID", CreatedAt: 1764000100, LastUsedAt: 1764100000,
		Transports: []string{"internal", "hybrid"}, AAGUID: "adce0002-35bc-c60a-648b-0b25f1f05503",
	}}}
	status, raw := postWebauthn(t, wa, accountv1connect.AccountServiceGetWebauthnCredentialsProcedure, `{}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", status, raw)
	}
	var got accountv1.WebauthnListResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	items := got.GetItems()
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1: %s", len(items), raw)
	}
	it := items[0]
	if it.GetId() != 11 || it.GetLabel() != "MacBook Touch ID" || it.GetCreatedAt() != 1764000100 ||
		it.GetLastUsedAt() != 1764100000 || it.GetAaguid() != "adce0002-35bc-c60a-648b-0b25f1f05503" {
		t.Errorf("item = {%d %q %d %d %q}", it.GetId(), it.GetLabel(), it.GetCreatedAt(), it.GetLastUsedAt(), it.GetAaguid())
	}
	if len(it.GetTransports()) != 2 || it.GetTransports()[0] != "internal" || it.GetTransports()[1] != "hybrid" {
		t.Errorf("transports = %v", it.GetTransports())
	}
	if wa.listUID != 10086 {
		t.Errorf("service uid = %d, want 10086（会话注入）", wa.listUID)
	}

	// 无会话 → 401（§1.2 行 96 本域全接口需会话）。
	_, _, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{webauthnIn: wa})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, accountv1connect.AccountServiceGetWebauthnCredentialsProcedure, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestRegisterWebauthnConnect 两态端到端：challenge 透传（token /
// challengeData / expiresIn）、verify 错误映射（降级 method_disabled 固定
// 文案、code_expired、step 非法）、verify 成功空响应 {}、无会话 401。
func TestRegisterWebauthnConnect(t *testing.T) {
	challengeData, err := structpb.NewStruct(map[string]any{"rp": map[string]any{"id": "example.com"}})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}

	t.Run("challenge 透传", func(t *testing.T) {
		wa := &fakeWebauthn{begin: &webauthn.RegistrationChallenge{
			Token: "sealed-token", ChallengeData: challengeData, ExpiresIn: 120,
		}}
		status, raw := postWebauthn(t, wa, accountv1connect.AccountServiceRegisterWebauthnProcedure, `{"step":"challenge"}`)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", status, raw)
		}
		var got accountv1.RegisterWebauthnResponse
		if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("decode response %q: %v", raw, err)
		}
		if got.GetToken() != "sealed-token" || got.GetExpiresIn() != 120 {
			t.Errorf("response token/expiresIn = {%q %d}", got.GetToken(), got.GetExpiresIn())
		}
		if d := got.GetChallengeData(); d == nil || d.GetFields()["rp"] == nil {
			t.Errorf("challengeData 未透传: %s", raw)
		}
		if wa.beginUID != 10086 {
			t.Errorf("service uid = %d, want 10086", wa.beginUID)
		}
	})
	t.Run("verify 降级窗口 fail-closed", func(t *testing.T) {
		wa := &fakeWebauthn{finishErr: accountsvc.ErrWebauthnDegraded}
		status, raw := postWebauthn(t, wa, accountv1connect.AccountServiceRegisterWebauthnProcedure,
			`{"step":"verify","token":"t","credential":{},"label":"L"}`)
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400（§8.3 行 1072 method_disabled 经 Connect 错误体）(body %s)", status, raw)
		}
		info := decodeAccountErrorInfo(t, raw)
		if info.GetDomain() != "account" || info.GetCode() != "method_disabled" ||
			info.GetMessage() != "通行密钥暂不可用，请联系管理员" {
			t.Errorf("ErrorInfo = %+v, want (account, method_disabled, 固定文案)", info)
		}
	})
	t.Run("verify token 过期", func(t *testing.T) {
		wa := &fakeWebauthn{finishErr: accountsvc.ErrWebauthnCodeExpired}
		status, raw := postWebauthn(t, wa, accountv1connect.AccountServiceRegisterWebauthnProcedure,
			`{"step":"verify","token":"t","credential":{},"label":"L"}`)
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", status, raw)
		}
		info := decodeAccountErrorInfo(t, raw)
		if info.GetDomain() != "account" || info.GetCode() != "code_expired" {
			t.Errorf("ErrorInfo = %+v, want (account, code_expired)", info)
		}
	})
	t.Run("verify 成功空响应", func(t *testing.T) {
		wa := &fakeWebauthn{}
		status, raw := postWebauthn(t, wa, accountv1connect.AccountServiceRegisterWebauthnProcedure,
			`{"step":"verify","token":"tk","credential":{"rawId":"abc"},"label":"YubiKey"}`)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", status, raw)
		}
		if strings.TrimSpace(raw) != "{}" {
			t.Errorf("verify 成功响应 = %q, want {}（空响应）", raw)
		}
		if wa.finishIn.uid != 10086 || wa.finishIn.tok != "tk" || wa.finishIn.label != "YubiKey" ||
			wa.finishIn.cred.GetFields()["rawId"] == nil {
			t.Errorf("service 入参 = %+v, want token/credential/label 透传 + uid=10086", wa.finishIn)
		}
	})
	t.Run("step 非法", func(t *testing.T) {
		wa := &fakeWebauthn{}
		status, raw := postWebauthn(t, wa, accountv1connect.AccountServiceRegisterWebauthnProcedure, `{"step":"restart"}`)
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", status, raw)
		}
		info := decodeAccountErrorInfo(t, raw)
		if info.GetDomain() != "account" || info.GetCode() != "invalid_request" {
			t.Errorf("ErrorInfo = %+v, want (account, invalid_request)", info)
		}
	})
	t.Run("无会话 401", func(t *testing.T) {
		_, _, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{webauthnIn: &fakeWebauthn{}})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, accountv1connect.AccountServiceRegisterWebauthnProcedure,
			strings.NewReader(`{"step":"challenge"}`))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("no session: status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
		}
	})
}

// TestRenameWebauthnCredentialConnect 端到端：成功空响应 + 入参透传 +
// not_found 404（不存在 / 非本人统一 not_found，不泄露存在性）。
func TestRenameWebauthnCredentialConnect(t *testing.T) {
	t.Run("成功", func(t *testing.T) {
		wa := &fakeWebauthn{}
		status, raw := postWebauthn(t, wa, accountv1connect.AccountServiceRenameWebauthnCredentialProcedure,
			`{"id":"11","label":"new name"}`)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", status, raw)
		}
		if strings.TrimSpace(raw) != "{}" {
			t.Errorf("rename 成功响应 = %q, want {}（空响应）", raw)
		}
		if wa.renameIn.uid != 10086 || wa.renameIn.id != 11 || wa.renameIn.label != "new name" {
			t.Errorf("service 入参 = %+v, want {10086 11 new name}", wa.renameIn)
		}
	})
	t.Run("目标不存在 → 404", func(t *testing.T) {
		wa := &fakeWebauthn{renameErr: fmt.Errorf("account webauthn: rename: %w", gorm.ErrRecordNotFound)}
		status, raw := postWebauthn(t, wa, accountv1connect.AccountServiceRenameWebauthnCredentialProcedure,
			`{"id":"999","label":"x"}`)
		if status != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body %s)", status, raw)
		}
	})
	t.Run("空 label → 400 invalid_request", func(t *testing.T) {
		wa := &fakeWebauthn{renameErr: accountsvc.ErrWebauthnInvalidRequest}
		status, raw := postWebauthn(t, wa, accountv1connect.AccountServiceRenameWebauthnCredentialProcedure,
			`{"id":"11","label":""}`)
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", status, raw)
		}
		info := decodeAccountErrorInfo(t, raw)
		if info.GetDomain() != "account" || info.GetCode() != "invalid_request" {
			t.Errorf("ErrorInfo = %+v, want (account, invalid_request)", info)
		}
	})
}

// TestDeleteWebauthnCredentialConnect 端到端：成功空响应 +
// 入参透传 + not_found 404（不存在 / 非本人统一 not_found）+ 无会话 401。
func TestDeleteWebauthnCredentialConnect(t *testing.T) {
	t.Run("成功", func(t *testing.T) {
		wa := &fakeWebauthn{}
		status, raw := postWebauthn(t, wa, accountv1connect.AccountServiceDeleteWebauthnCredentialProcedure,
			`{"id":"11"}`)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", status, raw)
		}
		if strings.TrimSpace(raw) != "{}" {
			t.Errorf("delete 成功响应 = %q, want {}（空响应）", raw)
		}
		if wa.deleteIn.uid != 10086 || wa.deleteIn.id != 11 {
			t.Errorf("service 入参 = %+v, want {10086 11}", wa.deleteIn)
		}
	})
	t.Run("目标不存在 → 404", func(t *testing.T) {
		wa := &fakeWebauthn{deleteErr: fmt.Errorf("account webauthn: delete: %w", gorm.ErrRecordNotFound)}
		status, raw := postWebauthn(t, wa, accountv1connect.AccountServiceDeleteWebauthnCredentialProcedure,
			`{"id":"999"}`)
		if status != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body %s)", status, raw)
		}
	})
	t.Run("降级窗口 fail-closed → 400 method_disabled", func(t *testing.T) {
		wa := &fakeWebauthn{deleteErr: accountsvc.ErrWebauthnDegraded}
		status, raw := postWebauthn(t, wa, accountv1connect.AccountServiceDeleteWebauthnCredentialProcedure,
			`{"id":"11"}`)
		if status != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", status, raw)
		}
		info := decodeAccountErrorInfo(t, raw)
		if info.GetDomain() != "account" || info.GetCode() != "method_disabled" ||
			info.GetMessage() != "通行密钥暂不可用，请联系管理员" {
			t.Errorf("ErrorInfo = %+v, want (account, method_disabled, 固定文案)", info)
		}
	})
	t.Run("无会话 401", func(t *testing.T) {
		_, _, h := newSessionHandler(t, &fakeUsers{user: wantUser()}, &getConfigDeps{webauthnIn: &fakeWebauthn{}})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, accountv1connect.AccountServiceDeleteWebauthnCredentialProcedure,
			strings.NewReader(`{"id":"11"}`))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("no session: status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
		}
	})
}

func readBody(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
