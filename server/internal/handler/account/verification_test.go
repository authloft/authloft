package account

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"authloft/gen/go/api/account/v1/accountv1connect"
	commonv1 "authloft/gen/go/api/common/v1"
	"authloft/internal/captcha"
	"authloft/internal/service/verification"
)

// fakeVerification Verification 窄接口的 fake：记录入参并回放结论。
type fakeVerification struct {
	startRes     *verification.StartResult
	startFailure *captcha.Failure
	startErr     error
	startIn      verification.StartInput
	startCalls   int
	submitRes    *verification.SubmitResult
	submitErr    error
	submitIn     verification.SubmitInput
	submitCalls  int
}

func (f *fakeVerification) Start(_ context.Context, in verification.StartInput) (*verification.StartResult, *captcha.Failure, error) {
	f.startCalls++
	f.startIn = in
	return f.startRes, f.startFailure, f.startErr
}

func (f *fakeVerification) Submit(_ context.Context, in verification.SubmitInput) (*verification.SubmitResult, error) {
	f.submitCalls++
	f.submitIn = in
	return f.submitRes, f.submitErr
}

// TestAccountStartVerificationConnect：AccountService 组以会话 uid 推导主体，
// 请求体字段（bizPurpose / method / operation / captcha）逐项透传，响应投影
// methods[] / expiresIn / nextStep。
func TestAccountStartVerificationConnect(t *testing.T) {
	fake := &fakeVerification{startRes: &verification.StartResult{
		ChallengeToken: "ch-1",
		ExpiresIn:      300,
		NextStepKind:   "form",
		Methods: []verification.MethodView{{
			Method: "totp", Usage: []string{"secondary"}, Steps: []string{"form"}, CodeLength: 6,
		}},
	}}
	code, raw, _ := postService(t, accountv1connect.AccountServiceStartVerificationProcedure,
		`{"bizPurpose":"unbind_totp","method":"totp","operation":"unbind_totp","captcha":{"providerKey":"builtin_image","id":"cap-1","answer":"abcd"}}`,
		&getConfigDeps{verificationIn: fake})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", code, raw)
	}
	if fake.startCalls != 1 || fake.startIn.Domain != verification.DomainAccount ||
		fake.startIn.SessionUID != "10086" ||
		fake.startIn.BizPurpose != verification.BizPurposeUnbindTOTP ||
		fake.startIn.Method != "totp" || fake.startIn.Operation != "unbind_totp" {
		t.Fatalf("Start 入参 = %+v", fake.startIn)
	}
	if c := fake.startIn.Captcha; c == nil || c.ProviderKey != "builtin_image" || c.ID != "cap-1" || c.Answer != "abcd" {
		t.Fatalf("captcha 入参 = %+v", c)
	}

	var got commonv1.StartVerificationResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetChallengeToken() != "ch-1" || got.GetExpiresIn() != 300 ||
		len(got.GetMethods()) != 1 || got.GetMethods()[0].GetMethod() != "totp" ||
		got.GetMethods()[0].GetCodeLength() != 6 ||
		got.GetNextStep().GetKind() != "form" {
		t.Fatalf("response = %+v", &got)
	}
}

// TestAccountSubmitVerificationConnect：提交字段逐项透传，响应只回
// verificationToken / expiresIn / amr（AccountService 组，§3.8.2）。
func TestAccountSubmitVerificationConnect(t *testing.T) {
	fake := &fakeVerification{submitRes: &verification.SubmitResult{
		VerificationToken: "vt-1", ExpiresIn: 120, AMR: []string{"totp"},
	}}
	code, raw, _ := postService(t, accountv1connect.AccountServiceSubmitVerificationProcedure,
		`{"challengeToken":"ch-1","method":"totp","payload":{"code":"123456"}}`,
		&getConfigDeps{verificationIn: fake})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", code, raw)
	}
	if fake.submitCalls != 1 || fake.submitIn.Domain != verification.DomainAccount ||
		fake.submitIn.ChallengeToken != "ch-1" || fake.submitIn.Method != "totp" ||
		fake.submitIn.Payload.GetFields()["code"].GetStringValue() != "123456" {
		t.Fatalf("Submit 入参 = %+v", fake.submitIn)
	}
	var got commonv1.SubmitVerificationResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetVerificationToken() != "vt-1" || got.GetExpiresIn() != 120 ||
		len(got.GetAmr()) != 1 || got.GetAmr()[0] != "totp" {
		t.Fatalf("response = %+v", &got)
	}
}

// TestAccountVerificationErrorMapping：断言失败只落 ErrorInfo.code；
// captcha 失败并列 ErrorInfo + 当前生效 CaptchaConfig（§3.8.5、§2.5）。
func TestAccountVerificationErrorMapping(t *testing.T) {
	t.Run("verification_invalid", func(t *testing.T) {
		fake := &fakeVerification{startErr: &verification.Error{Code: "verification_invalid"}}
		code, raw, _ := postService(t, accountv1connect.AccountServiceStartVerificationProcedure,
			`{"bizPurpose":"mfa","operation":"step_up"}`, &getConfigDeps{verificationIn: fake})
		if code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", code, raw)
		}
		info, _ := decodeAccountDetails(t, raw)
		if info.GetDomain() != "account" || info.GetCode() != "verification_invalid" {
			t.Fatalf("ErrorInfo = %+v", info)
		}
	})

	t.Run("too_many_requests", func(t *testing.T) {
		fake := &fakeVerification{startErr: &verification.Error{Code: "too_many_requests", RetryAfter: 60}}
		code, raw, _ := postService(t, accountv1connect.AccountServiceStartVerificationProcedure,
			`{"bizPurpose":"mfa","method":"otp_sms","operation":"step_up"}`, &getConfigDeps{verificationIn: fake})
		if code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429 (body %s)", code, raw)
		}
		info, _ := decodeAccountDetails(t, raw)
		if info.GetCode() != "too_many_requests" || info.GetRetryAfter() != 60 {
			t.Fatalf("ErrorInfo = %+v, want too_many_requests + retryAfter 60", info)
		}
	})

	t.Run("captcha_required", func(t *testing.T) {
		fake := &fakeVerification{startFailure: &captcha.Failure{
			Code:   captcha.StatusRequired,
			Config: captcha.Config{ProviderKey: "cf_turnstile", Type: "turnstile", SiteKey: "0xSITE"},
		}}
		code, raw, _ := postService(t, accountv1connect.AccountServiceStartVerificationProcedure,
			`{"bizPurpose":"mfa","method":"totp","operation":"step_up"}`, &getConfigDeps{verificationIn: fake})
		if code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", code, raw)
		}
		info, cfg := decodeAccountDetails(t, raw)
		if info.GetDomain() != "account" || info.GetCode() != captcha.StatusRequired {
			t.Fatalf("ErrorInfo = %+v", info)
		}
		if cfg == nil || cfg.GetProviderKey() != "cf_turnstile" || cfg.GetType() != "turnstile" || cfg.GetSiteKey() != "0xSITE" {
			t.Fatalf("CaptchaConfig = %+v, want 当前生效 turnstile 配置", cfg)
		}
	})

	t.Run("unconfigured", func(t *testing.T) {
		code, raw, _ := postService(t, accountv1connect.AccountServiceStartVerificationProcedure,
			`{"bizPurpose":"mfa","operation":"step_up"}`, &getConfigDeps{})
		if code == http.StatusOK || !strings.Contains(raw, "unimplemented") {
			t.Fatalf("status = %d, body = %s，未装配应返回 unimplemented", code, raw)
		}
	})
}

// TestAccountStartVerificationRequiresSession：无会话直接 401，不进入 service。
func TestAccountStartVerificationRequiresSession(t *testing.T) {
	fake := &fakeVerification{}
	_, _, h := newSessionHandler(t, &fakeUsers{}, &getConfigDeps{verificationIn: fake})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, accountv1connect.AccountServiceStartVerificationProcedure,
		strings.NewReader(`{"bizPurpose":"mfa","operation":"step_up"}`))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}
	if fake.startCalls != 0 {
		t.Fatal("无会话不得进入 service")
	}
}

// TestAccountSubmitRejectsLoginToken：loginToken 仅 SsoService 组可携带，
// AccountService 组收到一律 invalid_request（§3.8.2、§3.8.5），且不进入
// service。
func TestAccountSubmitRejectsLoginToken(t *testing.T) {
	fake := &fakeVerification{submitRes: &verification.SubmitResult{VerificationToken: "vt-1"}}
	code, raw, _ := postService(t, accountv1connect.AccountServiceSubmitVerificationProcedure,
		`{"challengeToken":"ch-1","method":"totp","payload":{"code":"123456"},"loginToken":"lt-1"}`,
		&getConfigDeps{verificationIn: fake})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", code, raw)
	}
	if info, _ := decodeAccountDetails(t, raw); info.GetDomain() != "account" || info.GetCode() != "invalid_request" {
		t.Fatalf("ErrorInfo = %+v, want account/invalid_request", info)
	}
	if fake.submitCalls != 0 {
		t.Fatalf("login_token 应由 handler 直接拒绝，submitCalls = %d", fake.submitCalls)
	}
}

// decodeAccountDetails 解 Connect 错误体 details 里的 ErrorInfo 与 CaptchaConfig
// （base64 编码消息字节，标准 / 无填充 / URL variant 依次尝试）。
func decodeAccountDetails(t *testing.T, raw string) (*commonv1.ErrorInfo, *commonv1.CaptchaConfig) {
	t.Helper()
	var body struct {
		Details []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"details"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("decode error body %q: %v", raw, err)
	}
	var info *commonv1.ErrorInfo
	var cfg *commonv1.CaptchaConfig
	for _, d := range body.Details {
		var b []byte
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
		} {
			if v, err := enc.DecodeString(d.Value); err == nil {
				b = v
				break
			}
		}
		switch d.Type {
		case "api.common.v1.ErrorInfo":
			info = &commonv1.ErrorInfo{}
			if err := proto.Unmarshal(b, info); err != nil {
				t.Fatalf("unmarshal ErrorInfo: %v", err)
			}
		case "api.common.v1.CaptchaConfig":
			cfg = &commonv1.CaptchaConfig{}
			if err := proto.Unmarshal(b, cfg); err != nil {
				t.Fatalf("unmarshal CaptchaConfig: %v", err)
			}
		}
	}
	if info == nil {
		t.Fatalf("details 缺少 ErrorInfo (body %s)", raw)
	}
	return info, cfg
}
