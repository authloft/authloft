package orchestrator

import (
	"context"
	"testing"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/repo/model"
	"authloft/internal/service/verification"
	"authloft/internal/settings"
)

// stubFactorPolicy 验证内核策略的测试替身：allow 控制 Allows，
// factors 控制 Factors（§3.7 策略判定唯一入口）。
type stubFactorPolicy struct {
	allow   map[string]bool
	factors []string
}

func (s stubFactorPolicy) Allows(bp verification.BizPurpose, method string) bool {
	return s.allow[method]
}

func (s stubFactorPolicy) Factors(bp verification.BizPurpose) []string {
	return s.factors
}

// TestDispatcherUsageGoesThroughPolicy 二次因子阶段的放行判定改走验证内核
// 策略表（§6.1 / §6.3）：注入拒绝 totp 的策略后，即便因子声明 secondary
// 能力也须被拒；默认内核策略表放行 totp（与既有行为等价）。
func TestDispatcherUsageGoesThroughPolicy(t *testing.T) {
	deps := newTestDeps(t, time.Unix(1_700_000_000, 0))
	deps.registry.factors[factor.FactorTOTP] = totpFactor()
	p := &token.LoginTokenPayload{Tid: "tid-1", Flow: "login", Uid: 42, Passed: []string{"otp_email"}}

	base := &Dispatcher{Registry: deps.registry, Settings: deps.settings}
	if _, status := base.Resolve(context.Background(), "login", p, "totp", "verify"); status != "" {
		t.Fatalf("default policy: status = %q, want pass", status)
	}

	denied := &Dispatcher{
		Registry: deps.registry,
		Settings: deps.settings,
		Policy:   stubFactorPolicy{allow: map[string]bool{}, factors: nil},
	}
	if _, status := denied.Resolve(context.Background(), "login", p, "totp", "verify"); status != StatusStepInvalid {
		t.Fatalf("policy denial: status = %q, want %q", status, StatusStepInvalid)
	}
}

// TestMFABuilderFactorsGoThroughPolicy 可选二次因子集合由验证内核策略表
// 给出上限（§1.10.2），再与 settings.mfa_methods、主体已绑定因子取交集：
// 注入仅允许 totp 的策略后，信封只留下 totp（+ 随其生效的 recovery_code）。
func TestMFABuilderFactorsGoThroughPolicy(t *testing.T) {
	phone := "13800138000"
	email := "alice@example.com"
	user := &model.User{
		ID: 9, Phone: &phone, Email: &email,
		PhoneVerified: 1, EmailVerified: 1, MfaRequired: 1,
	}
	users := &fakeUsers{user: user}
	creds := &fakeCredentials{creds: map[string]*model.UserCredential{
		"totp": {UserID: 9, Kind: "totp", IsEnabled: 1},
	}}
	s := &testSettings{
		bools:  map[string]bool{settings.KeyMfaEnabled: true},
		ints:   map[string]int64{settings.KeyOtpTtl: 300},
		slices: map[string][]string{settings.KeyMfaMethods: {"totp", "otp_sms", "otp_email", "webauthn"}},
	}

	b := NewMFABuilder(users, creds, s)
	b.Policy = stubFactorPolicy{factors: []string{"totp"}, allow: map[string]bool{"totp": true}}
	mfa, required, err := b.Build(context.Background(), 9)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !required || mfa == nil {
		t.Fatal("mfa should be required")
	}
	if len(mfa.Methods) != 2 || mfa.Methods[0].Method != "totp" || mfa.Methods[1].Method != "recovery_code" {
		t.Fatalf("methods = %+v, want only totp + recovery_code", mfa.Methods)
	}

	// 对照：未注入策略时落到内核默认策略表，与 settings 四项取交集 →
	// 主体已绑定的 totp / otp_sms / otp_email 全部可用（零回归）。
	b2 := NewMFABuilder(users, creds, s)
	mfa2, required2, err := b2.Build(context.Background(), 9)
	if err != nil {
		t.Fatalf("Build (default): %v", err)
	}
	if !required2 || mfa2 == nil || len(mfa2.Methods) < 3 {
		t.Fatalf("default policy methods = %+v, required = %v", mfa2.Methods, required2)
	}
}
