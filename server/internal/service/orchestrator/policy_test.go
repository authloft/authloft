package orchestrator

import (
	"context"
	"testing"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/service/verification"
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
