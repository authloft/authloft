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
	"authloft/gen/go/token"
	internalconnect "authloft/internal/connect"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/session"
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

// newSessionHandler 构造挂真实 session 拦截器的生成 handler（自造密钥
// version=1 kid=1，同 internal/connect/session_test.go 口径），返回签发
// 助手与 http.Handler。
func newSessionHandler(t *testing.T, users UserReader) (*session.Tokens, *fakeEpochReader, http.Handler) {
	t.Helper()
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
		New(users),
		connect.WithInterceptors(internalconnect.NewSessionInterceptor(
			session.NewVerifier(tokens, epochs),
			session.NewRenewer(tokens, time.Hour),
			session.NewCookie("al_session", "", time.Hour),
			nil,
		)),
	)
	return tokens, epochs, h
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

// TestOtherMethodsUnimplemented 其余方法（含 GetConfig 桩）一律返回生成
// 基类的 unimplemented（卡面 NON-GOALS + GetConfig 依赖缺口）。
func TestOtherMethodsUnimplemented(t *testing.T) {
	_, _, h := newSessionHandler(t, &fakeUsers{})
	cases := []string{
		accountv1connect.AccountServiceGetConfigProcedure,
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
