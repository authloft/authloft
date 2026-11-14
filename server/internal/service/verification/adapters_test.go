// adapters_test.go step-up 适配层的投影用例（随 adapters.go 下沉）。
package verification

import (
	"context"
	"testing"

	"gorm.io/gorm"

	"authloft/internal/factor"
	"authloft/internal/repo/model"
	"authloft/internal/service/mfapolicy"
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

// boundStubUsers boundUserReader 的 fake。
type boundStubUsers struct{ user *model.User }

func (s boundStubUsers) FindByID(context.Context, int64) (*model.User, error) { return s.user, nil }

// boundStubCreds boundCredReader 的 fake：按 kind 命中，未命中按 repo 口径。
type boundStubCreds struct {
	byKind map[string]*model.UserCredential
}

func (c boundStubCreds) FindByUserAndKind(_ context.Context, _ int64, kind string) (*model.UserCredential, error) {
	if row, ok := c.byKind[kind]; ok {
		return row, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (c boundStubCreds) ListByUser(context.Context, int64) ([]model.UserCredential, error) {
	return nil, nil
}

// boundStubSettings mfapolicy.SettingsReader 的 fake。
type boundStubSettings struct{ methods []string }

func (boundStubSettings) GetBool(string) (bool, bool) { return true, true }
func (s boundStubSettings) GetStringSlice(string) ([]string, bool) {
	return s.methods, true
}

// TestBoundWhitelistRecoveryCodeOnlyYieldsNoCandidates 白名单只写
// recovery_code（恢复码随 totp 生效、不单列）时，即便恢复码行 is_enabled=1、
// 用户 mfa_required=1，候选集也必须为空——不得退化成「只剩 recovery_code」
// 可用（恢复码用尽即锁死）。
func TestBoundWhitelistRecoveryCodeOnlyYieldsNoCandidates(t *testing.T) {
	user := &model.User{ID: 42, MfaRequired: 1}
	creds := boundStubCreds{byKind: map[string]*model.UserCredential{
		"recovery_code": {UserID: 42, Kind: "recovery_code", IsEnabled: 1},
	}}
	settings := boundStubSettings{methods: []string{"recovery_code"}}
	r := boundFactorReader{
		users: boundStubUsers{user: user},
		creds: creds,
		policy: mfapolicy.Deps{
			Users:    boundStubUsers{user: user},
			Creds:    creds,
			Settings: settings,
		},
	}
	got, err := r.Bound(context.Background(), Subject{Kind: SubjectKindUID, ID: "42"},
		[]string{"otp_sms", "otp_email", "webauthn", "totp", "recovery_code"})
	if err != nil {
		t.Fatalf("Bound: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("候选集 = %v, want 空（白名单只写 recovery_code 不得放行）", got)
	}
}
