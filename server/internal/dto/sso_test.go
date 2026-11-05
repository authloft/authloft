package dto

import (
	"testing"

	"google.golang.org/protobuf/types/known/structpb"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/internal/factor"
	"authloft/internal/service/orchestrator"
)

// TestLoginDefaultMapsRequestFields 校验 §2.2 请求字段到引擎入参的逐项映射
// （login_token / method / step / payload / captcha），并确认 OIDC 缺省为 nil。
func TestLoginDefaultMapsRequestFields(t *testing.T) {
	req := &ssov1.LoginDefaultRequest{
		LoginToken: "tok-1",
		Method:     "password",
		Step:       "verify",
		Payload: &ssov1.LoginPayload{
			Username: "alice",
			Password: "secret",
			Phone:    "13800000000",
			Email:    "a@b.com",
			Code:     "123456",
			Credential: &structpb.Struct{Fields: map[string]*structpb.Value{
				"id": structpb.NewStringValue("cred-1"),
			}},
			Captcha: &ssov1.CaptchaPayload{
				ProviderKey: "builtin_image",
				Token:       "token-1",
				Id:          "cap-1",
				Answer:      "1234",
			},
		},
	}

	got := LoginDefault(req)
	if got.LoginToken != "tok-1" || got.Method != "password" || got.Step != "verify" {
		t.Fatalf("basic fields = %+v", got)
	}
	wantPayload := factor.Payload{
		Username: "alice",
		Password: "secret",
		Phone:    "13800000000",
		Email:    "a@b.com",
		Code:     "123456",
	}
	if got.Payload.Username != wantPayload.Username || got.Payload.Password != wantPayload.Password ||
		got.Payload.Phone != wantPayload.Phone || got.Payload.Email != wantPayload.Email ||
		got.Payload.Code != wantPayload.Code {
		t.Fatalf("payload = %+v", got.Payload)
	}
	if got.Payload.Credential == nil || got.Payload.Credential.GetFields()["id"].GetStringValue() != "cred-1" {
		t.Fatalf("credential = %+v", got.Payload.Credential)
	}
	if got.Captcha == nil || got.Captcha.ProviderKey != "builtin_image" || got.Captcha.Token != "token-1" ||
		got.Captcha.ID != "cap-1" || got.Captcha.Answer != "1234" {
		t.Fatalf("captcha = %+v", got.Captcha)
	}
	if got.OIDC != nil {
		t.Fatalf("OIDC = %+v, want nil", got.OIDC)
	}
}

// TestLoginDefaultMapsOIDC 校验 /auth/authorize 原始参数（snake_case）到
// login_token.oidc 载荷（§2.2 行 426、§4.2）。
func TestLoginDefaultMapsOIDC(t *testing.T) {
	req := &ssov1.LoginDefaultRequest{
		Payload: &ssov1.LoginPayload{Username: "alice", Password: "p"},
		Oidc: &structpb.Struct{Fields: map[string]*structpb.Value{
			"client_id":             structpb.NewStringValue("client-1"),
			"redirect_uri":          structpb.NewStringValue("https://app.example/cb"),
			"scope":                 structpb.NewStringValue("openid profile"),
			"nonce":                 structpb.NewStringValue("nonce-1"),
			"code_challenge":        structpb.NewStringValue("challenge-1"),
			"code_challenge_method": structpb.NewStringValue("S256"),
			"state":                 structpb.NewStringValue("state-1"),
		}},
	}

	got := LoginDefault(req).OIDC
	if got == nil {
		t.Fatal("OIDC = nil, want mapped payload")
	}
	if got.ClientId != "client-1" || got.RedirectUri != "https://app.example/cb" ||
		got.Scope != "openid profile" || got.Nonce != "nonce-1" ||
		got.CodeChallenge != "challenge-1" || got.CodeChallengeMethod != "S256" || got.State != "state-1" {
		t.Fatalf("OIDC = %+v", got)
	}
}

// TestLoginDefaultNilAndEmpty 确认空消息 / 空 OIDC 的零值行为：payload 与
// captcha 均为 nil，空 Struct 不产生 OIDC 载荷。
func TestLoginDefaultNilAndEmpty(t *testing.T) {
	if got := LoginDefault(nil); got != (orchestrator.Request{}) {
		t.Fatalf("nil request = %+v", got)
	}
	req := &ssov1.LoginDefaultRequest{Oidc: &structpb.Struct{}}
	got := LoginDefault(req)
	if got.Payload != nil || got.Captcha != nil || got.OIDC != nil {
		t.Fatalf("empty request = %+v", got)
	}
}

// TestRegisterMapsRequestFields 校验 §2.3 行 440-450 Register 请求字段到
// 引擎入参的逐项映射（RegisterPayload 无 credential）。
func TestRegisterMapsRequestFields(t *testing.T) {
	req := &ssov1.RegisterRequest{
		LoginToken: "tok-1",
		Method:     "otp_email",
		Step:       "set_password",
		Payload: &ssov1.RegisterPayload{
			Email:    "a@b.com",
			Phone:    "13800000000",
			Code:     "123456",
			Username: "alice01",
			Password: "secret",
			Captcha: &ssov1.CaptchaPayload{
				ProviderKey: "builtin_image",
				Token:       "token-1",
				Id:          "cap-1",
				Answer:      "1234",
			},
		},
		Oidc: &structpb.Struct{Fields: map[string]*structpb.Value{
			"client_id":    structpb.NewStringValue("client-1"),
			"redirect_uri": structpb.NewStringValue("https://app.example/cb"),
		}},
	}

	got := Register(req)
	if got.LoginToken != "tok-1" || got.Method != "otp_email" || got.Step != "set_password" {
		t.Fatalf("basic fields = %+v", got)
	}
	if got.Payload == nil || got.Payload.Email != "a@b.com" || got.Payload.Phone != "13800000000" ||
		got.Payload.Code != "123456" || got.Payload.Username != "alice01" || got.Payload.Password != "secret" {
		t.Fatalf("payload = %+v", got.Payload)
	}
	if got.Payload.Credential != nil {
		t.Fatalf("RegisterPayload 无 credential，got %+v", got.Payload.Credential)
	}
	if got.Captcha == nil || got.Captcha.ProviderKey != "builtin_image" || got.Captcha.ID != "cap-1" {
		t.Fatalf("captcha = %+v", got.Captcha)
	}
	if got.OIDC == nil || got.OIDC.ClientId != "client-1" || got.OIDC.RedirectUri != "https://app.example/cb" {
		t.Fatalf("OIDC = %+v", got.OIDC)
	}
}

// TestRegisterNil 空消息零值行为。
func TestRegisterNil(t *testing.T) {
	if got := Register(nil); got != (orchestrator.Request{}) {
		t.Fatalf("nil request = %+v", got)
	}
	if got := Register(&ssov1.RegisterRequest{}); got.Payload != nil || got.Captcha != nil || got.OIDC != nil {
		t.Fatalf("empty request = %+v", got)
	}
}

// TestResetMapsRequestFields 校验 §2.4 行 458-466 Reset 请求字段到引擎入参
// 的逐项映射（ResetPayload 无 username / credential）。
func TestResetMapsRequestFields(t *testing.T) {
	req := &ssov1.ResetPasswordRequest{
		LoginToken: "tok-1",
		Method:     "otp_email",
		Step:       "set_password",
		Payload: &ssov1.ResetPayload{
			Email:    "a@b.com",
			Phone:    "13800000000",
			Code:     "123456",
			Password: "new-secret",
			Captcha: &ssov1.CaptchaPayload{
				ProviderKey: "builtin_image",
				Id:          "cap-1",
				Answer:      "1234",
			},
		},
	}

	got := Reset(req)
	if got.LoginToken != "tok-1" || got.Method != "otp_email" || got.Step != "set_password" {
		t.Fatalf("basic fields = %+v", got)
	}
	if got.Payload == nil || got.Payload.Email != "a@b.com" || got.Payload.Phone != "13800000000" ||
		got.Payload.Code != "123456" || got.Payload.Password != "new-secret" {
		t.Fatalf("payload = %+v", got.Payload)
	}
	if got.Payload.Username != "" || got.Payload.Credential != nil {
		t.Fatalf("ResetPayload 无 username/credential，got %+v/%+v", got.Payload.Username, got.Payload.Credential)
	}
	if got.Captcha == nil || got.Captcha.ProviderKey != "builtin_image" {
		t.Fatalf("captcha = %+v", got.Captcha)
	}
	if got.OIDC != nil {
		t.Fatalf("OIDC = %+v, want nil（未提交）", got.OIDC)
	}
}

// TestResetNil 空消息零值行为。
func TestResetNil(t *testing.T) {
	if got := Reset(nil); got != (orchestrator.Request{}) {
		t.Fatalf("nil request = %+v", got)
	}
	if got := Reset(&ssov1.ResetPasswordRequest{}); got.Payload != nil || got.Captcha != nil {
		t.Fatalf("empty request = %+v", got)
	}
}
