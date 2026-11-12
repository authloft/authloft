package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	commonv1 "authloft/gen/go/api/common/v1"
	"authloft/gen/go/api/sso/v1/ssov1connect"
	"authloft/internal/captcha"
	"authloft/internal/service"
	"authloft/internal/service/orchestrator"
	"authloft/internal/service/verification"
	"authloft/internal/session"
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
	sinkSeen     bool
}

func (f *fakeVerification) Start(_ context.Context, in verification.StartInput) (*verification.StartResult, *captcha.Failure, error) {
	f.startCalls++
	f.startIn = in
	return f.startRes, f.startFailure, f.startErr
}

func (f *fakeVerification) Submit(ctx context.Context, in verification.SubmitInput) (*verification.SubmitResult, error) {
	f.submitCalls++
	f.submitIn = in
	if _, ok := orchestrator.SessionTokenSinkFromContext(ctx); ok {
		f.sinkSeen = true
	}
	return f.submitRes, f.submitErr
}

func newVerificationHandler(f *fakeVerification) http.Handler {
	_, h := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, session.NewCookie("al_session", "", time.Hour), nil, nil, f))
	return h
}

func newVerificationHandlerWithQrcode(f *fakeVerification, qr Qrcode) http.Handler {
	_, h := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, session.NewCookie("al_session", "", time.Hour), nil, qr, f))
	return h
}

// TestSsoStartVerificationScanClaim 扫码场景（无 loginToken）：mfaPendingId 由
// 扫码 service 校验票据并解析目标 uid 后注入验证内核（§2.8 行 884、§3.8.1）。
func TestSsoStartVerificationScanClaim(t *testing.T) {
	fake := &fakeVerification{startRes: &verification.StartResult{ChallengeToken: "ch-scan", ExpiresIn: 300}}
	qr := &fakeQrcode{resolveOut: &service.MFAPending{
		TicketID: "ticket-1", Scene: "login", Status: "mfa_pending", UID: 9,
	}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceStartVerificationProcedure,
		strings.NewReader(`{"bizPurpose":"login","method":"totp","operation":"mfa_verify","mfaPendingId":"ticket-1"}`))
	req.Header.Set("Content-Type", "application/json")
	newVerificationHandlerWithQrcode(fake, qr).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if qr.gotResolve != "ticket-1" {
		t.Fatalf("ResolveMFAPending 入参 = %q, want ticket-1", qr.gotResolve)
	}
	claim := fake.startIn.MFAPending
	if claim == nil || claim.TicketID != "ticket-1" || claim.Scene != "login" || claim.Status != "mfa_pending" || claim.UID != 9 {
		t.Fatalf("MFAPending = %+v", claim)
	}
}

// TestSsoStartVerificationScanErrors 票据不存在 / scene 不符按 §3.8.5 的主体
// 凭证错误口径返回（token_invalid / invalid_request）。
func TestSsoStartVerificationScanErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code string
	}{
		{"票据不存在", service.ErrQrcodeTicketInvalid, "token_invalid"},
		{"scene 不符", service.ErrQrcodeTicketScene, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeVerification{}
			qr := &fakeQrcode{resolveErr: tc.err}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceStartVerificationProcedure,
				strings.NewReader(`{"bizPurpose":"login","method":"totp","operation":"mfa_verify","mfaPendingId":"ticket-1"}`))
			req.Header.Set("Content-Type", "application/json")
			newVerificationHandlerWithQrcode(fake, qr).ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
			info, _ := decodeSsoDetails(t, rec.Body.String())
			if info.GetCode() != tc.code {
				t.Fatalf("ErrorInfo.code = %q, want %q", info.GetCode(), tc.code)
			}
			if fake.startCalls != 0 {
				t.Fatalf("票据校验失败不应进入 Start, calls = %d", fake.startCalls)
			}
		})
	}
}

// TestSsoSubmitVerificationScanCompletesTicket 扫码 step-up 通过后由 handler
// 触发票据终态收尾（§2.8 行 884），响应仍为 success。
func TestSsoSubmitVerificationScanCompletesTicket(t *testing.T) {
	fake := &fakeVerification{submitRes: &verification.SubmitResult{Status: "success", TicketID: "ticket-1", AMR: []string{"totp"}}}
	qr := &fakeQrcode{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceSubmitVerificationProcedure,
		strings.NewReader(`{"challengeToken":"ch-scan","method":"totp","payload":{"code":"123456"}}`))
	req.Header.Set("Content-Type", "application/json")
	newVerificationHandlerWithQrcode(fake, qr).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if qr.gotComplete != "ticket-1" {
		t.Fatalf("CompleteStepUp 入参 = %q, want ticket-1", qr.gotComplete)
	}
	var got commonv1.SubmitVerificationResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	if got.GetStatus() != "success" {
		t.Fatalf("status = %q, want success", got.GetStatus())
	}
}

// TestSsoStartVerificationConnect：SsoService 组以 loginToken / mfaPendingId
// 推导主体，请求字段逐项透传，响应投影 methods[] / expiresIn / nextStep。
func TestSsoStartVerificationConnect(t *testing.T) {
	fake := &fakeVerification{startRes: &verification.StartResult{
		ChallengeToken: "ch-1",
		ExpiresIn:      300,
		NextStepKind:   "form",
		Methods: []verification.MethodView{{
			Method: "totp", Usage: []string{"secondary"}, Steps: []string{"form"}, CodeLength: 6,
		}},
	}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceStartVerificationProcedure,
		strings.NewReader(`{"bizPurpose":"login","method":"totp","operation":"mfa_verify","loginToken":"lt-1","mfaPendingId":"ticket-1","captcha":{"providerKey":"cf_turnstile","token":"tok-1"}}`))
	req.Header.Set("Content-Type", "application/json")
	newVerificationHandler(fake).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if fake.startCalls != 1 || fake.startIn.Domain != verification.DomainSSO ||
		fake.startIn.BizPurpose != verification.BizPurposeLogin ||
		fake.startIn.LoginToken != "lt-1" || fake.startIn.MFAPendingID != "ticket-1" ||
		fake.startIn.Method != "totp" || fake.startIn.Operation != "mfa_verify" {
		t.Fatalf("Start 入参 = %+v", fake.startIn)
	}
	if c := fake.startIn.Captcha; c == nil || c.ProviderKey != "cf_turnstile" || c.Token != "tok-1" {
		t.Fatalf("captcha 入参 = %+v", c)
	}

	var got commonv1.StartVerificationResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	if got.GetChallengeToken() != "ch-1" || got.GetExpiresIn() != 300 ||
		len(got.GetMethods()) != 1 || got.GetMethods()[0].GetMethod() != "totp" ||
		got.GetNextStep().GetKind() != "form" {
		t.Fatalf("response = %+v", &got)
	}
}

// TestSsoSubmitVerificationConnect：提交字段逐项透传；成功走登录终点收尾，
// 响应回 status=success + redirectTo + syncCookieUrl + amr，且 handler 已
// 注入会话令牌写点（Set-Cookie 出口与 LoginDefault 同源）。
func TestSsoSubmitVerificationConnect(t *testing.T) {
	fake := &fakeVerification{submitRes: &verification.SubmitResult{
		Status: "success", RedirectTo: "https://rp.example/cb", SyncCookieURL: "https://sync.example", AMR: []string{"totp"},
	}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceSubmitVerificationProcedure,
		strings.NewReader(`{"challengeToken":"ch-1","method":"totp","payload":{"code":"123456"},"loginToken":"lt-1"}`))
	req.Header.Set("Content-Type", "application/json")
	newVerificationHandler(fake).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if fake.submitCalls != 1 || fake.submitIn.Domain != verification.DomainSSO ||
		fake.submitIn.ChallengeToken != "ch-1" || fake.submitIn.Method != "totp" ||
		fake.submitIn.LoginToken != "lt-1" ||
		fake.submitIn.Payload.GetFields()["code"].GetStringValue() != "123456" {
		t.Fatalf("Submit 入参 = %+v", fake.submitIn)
	}
	if !fake.sinkSeen {
		t.Fatal("Submit 未注入会话令牌写点，Set-Cookie 出口会丢")
	}
	var got commonv1.SubmitVerificationResponse
	if err := protojson.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	if got.GetStatus() != "success" || got.GetRedirectTo() != "https://rp.example/cb" ||
		got.GetSyncCookieUrl() != "https://sync.example" ||
		len(got.GetAmr()) != 1 || got.GetAmr()[0] != "totp" {
		t.Fatalf("response = %+v", &got)
	}
}

// TestSsoSubmitFactorFailureAsFlowStatus：因子类失败按登录流程信封 status
// 表达（HTTP 200），不走 Connect 错误体（§3.8.5）。
func TestSsoSubmitFactorFailureAsFlowStatus(t *testing.T) {
	for _, code := range []string{"invalid_code", "code_expired", "too_many_attempts", "method_disabled"} {
		t.Run(code, func(t *testing.T) {
			fake := &fakeVerification{submitErr: &verification.Error{Code: code}}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceSubmitVerificationProcedure,
				strings.NewReader(`{"challengeToken":"ch-1","method":"totp","payload":{"code":"000000"}}`))
			req.Header.Set("Content-Type", "application/json")
			newVerificationHandler(fake).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}
			var got commonv1.SubmitVerificationResponse
			if err := protojson.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response %q: %v", rec.Body.String(), err)
			}
			if got.GetStatus() != code {
				t.Fatalf("status = %q, want %q", got.GetStatus(), code)
			}
		})
	}
}

// TestSsoVerificationErrorMapping：断言失败只落 ErrorInfo.code；captcha 失败
// 并列 ErrorInfo + 当前生效 CaptchaConfig（§3.8.5、§2.5）。
func TestSsoVerificationErrorMapping(t *testing.T) {
	t.Run("verification_invalid", func(t *testing.T) {
		fake := &fakeVerification{startErr: &verification.Error{Code: "verification_invalid"}}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceStartVerificationProcedure,
			strings.NewReader(`{"bizPurpose":"login","operation":"mfa_verify","loginToken":"lt-1"}`))
		req.Header.Set("Content-Type", "application/json")
		newVerificationHandler(fake).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
		}
		info, _ := decodeSsoDetails(t, rec.Body.String())
		if info.GetDomain() != "sso" || info.GetCode() != "verification_invalid" {
			t.Fatalf("ErrorInfo = %+v", info)
		}
	})

	t.Run("captcha_required", func(t *testing.T) {
		fake := &fakeVerification{startFailure: &captcha.Failure{
			Code:   captcha.StatusRequired,
			Config: captcha.Config{ProviderKey: "cf_turnstile", Type: "turnstile", SiteKey: "0xSITE"},
		}}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceStartVerificationProcedure,
			strings.NewReader(`{"bizPurpose":"login","method":"totp","operation":"mfa_verify","loginToken":"lt-1"}`))
		req.Header.Set("Content-Type", "application/json")
		newVerificationHandler(fake).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
		}
		info, cfg := decodeSsoDetails(t, rec.Body.String())
		if info.GetDomain() != "sso" || info.GetCode() != captcha.StatusRequired {
			t.Fatalf("ErrorInfo = %+v", info)
		}
		if cfg == nil || cfg.GetProviderKey() != "cf_turnstile" || cfg.GetType() != "turnstile" || cfg.GetSiteKey() != "0xSITE" {
			t.Fatalf("CaptchaConfig = %+v, want 当前生效 turnstile 配置", cfg)
		}
	})

	t.Run("too_many_requests", func(t *testing.T) {
		fake := &fakeVerification{startErr: &verification.Error{Code: "too_many_requests", RetryAfter: 60}}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceStartVerificationProcedure,
			strings.NewReader(`{"bizPurpose":"login","method":"otp_sms","operation":"mfa_verify","loginToken":"lt-1"}`))
		req.Header.Set("Content-Type", "application/json")
		newVerificationHandler(fake).ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429 (body %s)", rec.Code, rec.Body.String())
		}
		info, _ := decodeSsoDetails(t, rec.Body.String())
		if info.GetCode() != "too_many_requests" || info.GetRetryAfter() != 60 {
			t.Fatalf("ErrorInfo = %+v, want too_many_requests + retryAfter 60", info)
		}
	})

	t.Run("unconfigured", func(t *testing.T) {
		_, h := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, nil, nil))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceStartVerificationProcedure,
			strings.NewReader(`{"bizPurpose":"login","operation":"mfa_verify","loginToken":"lt-1"}`))
		req.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "unimplemented") {
			t.Fatalf("status = %d, body = %s，未装配应返回 unimplemented", rec.Code, rec.Body.String())
		}
	})
}

// decodeSsoDetails 解 Connect 错误体 details 里的 ErrorInfo 与 CaptchaConfig。
func decodeSsoDetails(t *testing.T, raw string) (*commonv1.ErrorInfo, *commonv1.CaptchaConfig) {
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
		b := decodeDetailValue(t, d.Value)
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
