// errors_test.go 覆盖 captcha 失败错误体的 details 并列下发（接口文档
// §1.5 行 228、后端架构 §3.14）：WithCaptchaConfig 与 ErrorInfo 并列挂到
// 同一 connect.Error，CaptchaConfigOf 可按生成类型解出往返。
package connect

import (
	"errors"
	"testing"

	"connectrpc.com/connect"

	commonv1 "authloft/gen/go/api/common/v1"
	"authloft/internal/captcha"
)

// TestWithCaptchaConfigDetail captcha 失败时 ErrorInfo 与 CaptchaConfig
// 两枚 detail 并列，互不覆盖，且配置字段逐项往返。
func TestWithCaptchaConfigDetail(t *testing.T) {
	cfg := &commonv1.CaptchaConfig{ProviderKey: "cf_turnstile", Type: "turnstile", SiteKey: "0xSITE"}
	coded := WithErrorInfo(
		connect.NewError(connect.CodeInvalidArgument, errors.New("captcha required")),
		NewErrorInfo("sso", captcha.StatusRequired, "captcha required"),
	)
	WithCaptchaConfig(coded, cfg)

	if len(coded.Details()) != 2 {
		t.Fatalf("details = %d, want 2（ErrorInfo + CaptchaConfig 并列）", len(coded.Details()))
	}
	got, ok := CaptchaConfigOf(coded)
	if !ok {
		t.Fatal("CaptchaConfigOf 未找到 CaptchaConfig detail")
	}
	if got.GetProviderKey() != cfg.GetProviderKey() || got.GetType() != cfg.GetType() ||
		got.GetSiteKey() != cfg.GetSiteKey() {
		t.Fatalf("detail 往返 = %+v, want %+v", got, cfg)
	}
	info, ok := ErrorInfoOf(coded)
	if !ok || info.GetCode() != captcha.StatusRequired || info.GetDomain() != "sso" {
		t.Fatalf("ErrorInfo detail = (%+v, %v), want sso/%s", info, ok, captcha.StatusRequired)
	}
}

// TestCaptchaConfigOfAbsent 非 connect.Error、仅有 ErrorInfo、以及 nil
// 配置三种情形下均不产出 CaptchaConfig detail。
func TestCaptchaConfigOfAbsent(t *testing.T) {
	if _, ok := CaptchaConfigOf(errors.New("plain")); ok {
		t.Error("非 connect.Error 应返回 false")
	}
	coded := WithErrorInfo(
		connect.NewError(connect.CodeInvalidArgument, errors.New("x")),
		NewErrorInfo("sso", captcha.StatusInvalid, "x"),
	)
	if _, ok := CaptchaConfigOf(coded); ok {
		t.Error("仅有 ErrorInfo detail 时应返回 false")
	}
	bare := connect.NewError(connect.CodeInvalidArgument, errors.New("x"))
	WithCaptchaConfig(bare, nil)
	if len(bare.Details()) != 0 {
		t.Errorf("nil cfg 不应挂 detail, got %d", len(bare.Details()))
	}
}
