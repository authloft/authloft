// captcha_failure_test.go 覆盖「缺 captcha 的登录请求 → 非 200 Connect 错误体」
// 的真链路（接口文档 §1.3 例外 / §1.5 / §1.6、后端架构 §3.14 / §9.1）：
// 真 orchestrator.Engine + 真 captcha.Gate + 真 sso.Handler + 生成的
// Connect handler + httptest，断言 ErrorInfo.code 与 details 并列的
// CaptchaConfig 均由真链路产出。
package sso

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

	commonv1 "authloft/gen/go/api/common/v1"
	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/api/sso/v1/ssov1connect"
	"authloft/internal/captcha"
	"authloft/internal/factor"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
	"authloft/internal/settings"
)

// chainSettings 只声明 otp_email 为启用的登录方式；其余键返回零值，由
// 各 helper 采用内建默认（不读配置、不连 DB / Redis）。
type chainSettings struct{}

func (chainSettings) GetString(string) (string, bool) { return "", false }
func (chainSettings) GetInt64(string) (int64, bool)   { return 0, false }
func (chainSettings) GetBool(string) (bool, bool)     { return false, false }
func (chainSettings) GetStringSlice(key string) ([]string, bool) {
	if key == settings.KeyLoginMethods {
		return []string{"otp_email"}, true
	}
	return nil, false
}

// chainFactor 接受 challenge 步的主因子；captcha 失败在因子执行前被拦，
// Start / Verify 不应被触达。
type chainFactor struct{}

func (chainFactor) Kind() factor.FactorKind { return factor.FactorOTPEmail }
func (chainFactor) Usages() []factor.Usage  { return []factor.Usage{factor.UsagePrimary} }
func (chainFactor) Steps() []factor.StepKind {
	return []factor.StepKind{factor.StepChallenge, factor.StepForm}
}
func (chainFactor) Start(*factor.FactorContext) (*factor.StepResult, error) {
	return &factor.StepResult{Kind: factor.StepForm, Method: factor.FactorOTPEmail}, nil
}
func (chainFactor) Verify(*factor.FactorContext) (*factor.VerifyResult, error) {
	return &factor.VerifyResult{Passed: true, UID: 42}, nil
}

type chainRegistry struct{}

func (chainRegistry) Get(kind factor.FactorKind) (factor.Factor, error) {
	if kind == factor.FactorOTPEmail {
		return chainFactor{}, nil
	}
	return nil, factor.ErrKindNotRegistered
}

// chainCatalog 当前生效第三方 captcha Provider（非降级态），使 details
// 三个字段都非空，便于逐项可证伪断言。
type chainCatalog struct{}

func (chainCatalog) Current(context.Context) (*captcha.Provider, error) {
	return &captcha.Provider{ProviderKey: "cf_turnstile", Type: "turnstile", SiteKey: "0xSITE"}, nil
}

type chainVerifier struct{}

func (chainVerifier) Verify(context.Context, string, captcha.Submission) error { return nil }

// newCaptchaChainEngine 组装真引擎（真 State / Dispatcher / Gate），
// 不注入假引擎；仅因子注册表、settings 与 Provider 目录是进程内 fake，
// 编排、gate 判定与错误体编码均为真实现。
func newCaptchaChainEngine(t *testing.T) *orchestrator.Engine {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0xA5
	}
	ks, err := security.NewKeyStore(security.KeyEntry{
		ID: security.KeyID{Version: 1, Kid: 1}, Key: key,
	})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	gate := captcha.NewGate(chainSettings{}, chainCatalog{}, chainVerifier{})
	return orchestrator.NewEngine(orchestrator.EngineDeps{
		State:      orchestrator.NewState(security.NewCodec(ks)),
		Dispatcher: &orchestrator.Dispatcher{Registry: chainRegistry{}, Settings: chainSettings{}},
		Gate:       gate,
		NewTID:     func() (string, error) { return "tid-1", nil },
	})
}

// TestLoginDefaultCaptchaRequiredConnectError 端到端（可证伪）：缺 captcha
// 的 challenge 登录请求不套信封，改走非 200 的 Connect 错误体；ErrorInfo
// 与 CaptchaConfig 两枚 detail 并列，配置取自与 gate 判定同源的当前生效项。
func TestLoginDefaultCaptchaRequiredConnectError(t *testing.T) {
	_, handler := ssov1connect.NewSsoServiceHandler(New(newCaptchaChainEngine(t), nil, nil, nil, nil))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// 缺 captcha 的 challenge 登录请求（§2.5：一次性验证码下发必检）。
	body := `{"method":"otp_email","step":"challenge","payload":{"email":"alice@example.com"}}`
	resp, err := http.Post(srv.URL+ssov1connect.SsoServiceLoginDefaultProcedure,
		"application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST LoginDefault: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("缺 captcha 应为非 200 Connect 错误体, got 200")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d（invalid_argument → 400）", resp.StatusCode, http.StatusBadRequest)
	}

	var envelope struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Details []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"details"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if envelope.Code != "invalid_argument" {
		t.Fatalf("error.code = %q, want invalid_argument", envelope.Code)
	}

	var info *commonv1.ErrorInfo
	var cfg *commonv1.CaptchaConfig
	for _, d := range envelope.Details {
		raw := decodeDetailValue(t, d.Value)
		switch d.Type {
		case "api.common.v1.ErrorInfo":
			m := &commonv1.ErrorInfo{}
			if err := proto.Unmarshal(raw, m); err != nil {
				t.Fatalf("unmarshal ErrorInfo detail: %v", err)
			}
			info = m
		case "api.common.v1.CaptchaConfig":
			m := &commonv1.CaptchaConfig{}
			if err := proto.Unmarshal(raw, m); err != nil {
				t.Fatalf("unmarshal CaptchaConfig detail: %v", err)
			}
			cfg = m
		}
	}
	if info == nil {
		t.Fatal("details 缺少 api.common.v1.ErrorInfo")
	}
	if info.GetDomain() != "sso" || info.GetCode() != captcha.StatusRequired {
		t.Fatalf("ErrorInfo = %+v, want sso/%s", info, captcha.StatusRequired)
	}
	if cfg == nil {
		t.Fatal("details 缺少 api.common.v1.CaptchaConfig（captcha 配置未并列下发）")
	}
	if cfg.GetProviderKey() != "cf_turnstile" || cfg.GetType() != "turnstile" || cfg.GetSiteKey() != "0xSITE" {
		t.Fatalf("CaptchaConfig = %+v, want 当前生效 turnstile 配置", cfg)
	}
}

// decodeDetailValue 解 Connect 错误体 details[].value（base64 编码的消息
// 字节）；按标准 / 无填充 / URL variant 依次尝试。
func decodeDetailValue(t *testing.T, value string) []byte {
	t.Helper()
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(value); err == nil {
			return b
		}
	}
	t.Fatalf("detail value 无法 base64 解码: %q", value)
	return nil
}

// TestCaptchaTopLevelOnly 可证伪（真 engine + 真 gate + 生成的 Connect
// handler + httptest）：三个入口中，只把凭据留在旧位置的请求按「缺 captcha」
// 处理，返回非 200 的 Connect 错误体（ErrorInfo.code=captcha_required、
// details 并列 CaptchaConfig）；请求顶层 captcha 正常通过，返回 HTTP 200
// 登录流程信封（status=next）。两组断言互为反向：顶层若未被读取、旧位置若
// 仍被读取，用例立即失败。
func TestCaptchaTopLevelOnly(t *testing.T) {
	cases := []struct {
		name       string
		procedure  string
		legacyBody string
		topBody    string
	}{
		{
			name:       "LoginDefault",
			procedure:  ssov1connect.SsoServiceLoginDefaultProcedure,
			legacyBody: `{"method":"otp_email","step":"challenge","payload":{"email":"alice@example.com","captcha":{"providerKey":"cf_turnstile","token":"tok-old"}}}`,
			topBody:    `{"method":"otp_email","step":"challenge","payload":{"email":"alice@example.com"},"captcha":{"providerKey":"cf_turnstile","token":"tok-new"}}`,
		},
		{
			name:       "Register",
			procedure:  ssov1connect.SsoServiceRegisterProcedure,
			legacyBody: `{"method":"otp_email","step":"challenge","payload":{"email":"alice@example.com","captcha":{"providerKey":"cf_turnstile","token":"tok-old"}}}`,
			topBody:    `{"method":"otp_email","step":"challenge","payload":{"email":"alice@example.com"},"captcha":{"providerKey":"cf_turnstile","token":"tok-new"}}`,
		},
		{
			name:       "ResetPassword",
			procedure:  ssov1connect.SsoServiceResetPasswordProcedure,
			legacyBody: `{"method":"otp_email","step":"challenge","payload":{"email":"alice@example.com","captcha":{"providerKey":"cf_turnstile","token":"tok-old"}}}`,
			topBody:    `{"method":"otp_email","step":"challenge","payload":{"email":"alice@example.com"},"captcha":{"providerKey":"cf_turnstile","token":"tok-new"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, handler := ssov1connect.NewSsoServiceHandler(New(newCaptchaChainEngine(t), nil, nil, nil, nil))
			srv := httptest.NewServer(handler)
			defer srv.Close()
			url := srv.URL + tc.procedure

			assertCaptchaRequired(t, url, tc.legacyBody)
			assertCaptchaPassed(t, url, tc.topBody)
		})
	}
}

// assertCaptchaRequired 断言请求因缺 captcha 被拦为非 200 的 Connect
// 错误体，ErrorInfo.code 与并列的 CaptchaConfig 均由真链路产出。
func assertCaptchaRequired(t *testing.T, url, body string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("仅旧位置的 captcha 应按缺 captcha 处理（非 200）, got 200")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d（invalid_argument → 400）", resp.StatusCode, http.StatusBadRequest)
	}
	var envelope struct {
		Code    string `json:"code"`
		Details []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"details"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if envelope.Code != "invalid_argument" {
		t.Fatalf("error.code = %q, want invalid_argument", envelope.Code)
	}
	var info *commonv1.ErrorInfo
	var cfg *commonv1.CaptchaConfig
	for _, d := range envelope.Details {
		raw := decodeDetailValue(t, d.Value)
		switch d.Type {
		case "api.common.v1.ErrorInfo":
			m := &commonv1.ErrorInfo{}
			if err := proto.Unmarshal(raw, m); err != nil {
				t.Fatalf("unmarshal ErrorInfo: %v", err)
			}
			info = m
		case "api.common.v1.CaptchaConfig":
			m := &commonv1.CaptchaConfig{}
			if err := proto.Unmarshal(raw, m); err != nil {
				t.Fatalf("unmarshal CaptchaConfig: %v", err)
			}
			cfg = m
		}
	}
	if info == nil || info.GetCode() != captcha.StatusRequired {
		t.Fatalf("ErrorInfo = %+v, want code=%s", info, captcha.StatusRequired)
	}
	if cfg == nil {
		t.Fatal("details 缺少 CaptchaConfig（captcha 配置未并列下发）")
	}
}

// assertCaptchaPassed 断言请求顶层 captcha 经 gate 放行，返回 HTTP 200
// 登录流程信封（status=next）。顶层若未被读取，gate 会拦成 captcha_required
// 的非 200 错误体，本断言随即失败。
func assertCaptchaPassed(t *testing.T, url, body string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("顶层 captcha 应通过（HTTP 200 信封）, got %d (body %s)", resp.StatusCode, raw)
	}
	var got ssov1.LoginFlowResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetStatus() != "next" {
		t.Fatalf("status = %q, want next（captcha 放行后进入因子 Start）", got.GetStatus())
	}
}
