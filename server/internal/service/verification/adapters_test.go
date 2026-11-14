// adapters_test.go step-up 适配层的投影用例（随 adapters.go 下沉）。
package verification

import (
	"context"
	"testing"

	"authloft/internal/factor"
)

// stubVerifyFactor 回放既定的因子校验结论，用于校验 step-up 适配层的投影。
type stubVerifyFactor struct{ res *factor.VerifyResult }

func (f *stubVerifyFactor) Kind() factor.FactorKind  { return factor.FactorTOTP }
func (f *stubVerifyFactor) Usages() []factor.Usage   { return []factor.Usage{factor.UsageSecondary} }
func (f *stubVerifyFactor) Steps() []factor.StepKind { return []factor.StepKind{factor.StepForm} }
func (f *stubVerifyFactor) Start(*factor.FactorContext) (*factor.StepResult, error) {
	return nil, nil
}
func (f *stubVerifyFactor) Verify(*factor.FactorContext) (*factor.VerifyResult, error) {
	return f.res, nil
}

// TestStepUpVerifierCarriesAttemptsLeft 错码且键保留时把因子 VerifyResult 的
// 剩余次数投影进领域结论（§3.8.5、§1.6）。
func TestStepUpVerifierCarriesAttemptsLeft(t *testing.T) {
	reg := factor.NewRegistry()
	if err := reg.Register(factor.FactorTOTP, &stubVerifyFactor{
		res: &factor.VerifyResult{Status: "invalid_code", AttemptsLeft: 3},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	v := NewStepUpVerifier(reg, nil, nil)
	got, err := v.Verify(context.Background(), FactorVerifyInput{
		Method:      "totp",
		BizPurpose:  BizPurposeMFA,
		Subject:     Subject{Kind: SubjectKindUID, ID: "42"},
		ChallengeID: "n1",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Code != "invalid_code" || got.AttemptsLeft != 3 {
		t.Fatalf("FactorVerifyResult = %+v, want invalid_code/3", got)
	}
}
