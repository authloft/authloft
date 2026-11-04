package totp

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/repo/model"
)

// fakeCredentials 满足 factor.CredentialRepo，仅内存返回，不连 DB。
type fakeCredentials struct {
	cred *model.UserCredential
	err  error
}

func (f fakeCredentials) FindByUserAndKind(_ context.Context, _ int64, _ string) (*model.UserCredential, error) {
	return f.cred, f.err
}

// rfcSecret RFC 6238 附录 B 的 SHA1 测试密钥（ASCII "12345678901234567890"）。
var rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestFactorShape(t *testing.T) {
	f := New()
	if f.Kind() != factor.FactorTOTP {
		t.Fatalf("Kind = %v, want totp", f.Kind())
	}
	if usages := f.Usages(); len(usages) != 1 || usages[0] != factor.UsageSecondary {
		t.Fatalf("Usages = %v, want [secondary]", usages)
	}
	if steps := f.Steps(); len(steps) != 1 || steps[0] != factor.StepForm {
		t.Fatalf("Steps = %v, want [form]", steps)
	}
}

// TestRFC6238Vectors 验证 HOTP 截断与 6 位取模（RFC 6238 附录 B 取后 6 位）。
func TestRFC6238Vectors(t *testing.T) {
	secret, err := decodeSecret(rfcSecret)
	if err != nil {
		t.Fatalf("decodeSecret: %v", err)
	}
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},         // 94287082
		{1111111109, "081804"}, // 07081804
		{2000000000, "279037"}, // 69279037
	}
	for _, tc := range cases {
		got := hotp(secret, uint64(tc.unix/stepSeconds))
		if got != tc.want {
			t.Fatalf("hotp(%d) = %s, want %s", tc.unix, got, tc.want)
		}
		if !valid(secret, got, time.Unix(tc.unix, 0)) {
			t.Fatalf("valid(%s) at %d = false", got, tc.unix)
		}
	}
}

// TestVerifyAllowsOneStepSkew ±1 时间步内有效，±2 无效。
func TestVerifyAllowsOneStepSkew(t *testing.T) {
	secret, err := decodeSecret(rfcSecret)
	if err != nil {
		t.Fatalf("decodeSecret: %v", err)
	}
	now := time.Unix(59, 0)
	base := now.Unix() / stepSeconds

	cur := hotp(secret, uint64(base))
	if !valid(secret, cur, now) {
		t.Fatal("current step must be valid")
	}
	if !valid(secret, hotp(secret, uint64(base+1)), now) {
		t.Fatal("+1 step must be valid")
	}
	if !valid(secret, hotp(secret, uint64(base-1)), now) {
		t.Fatal("-1 step must be valid")
	}
	if valid(secret, hotp(secret, uint64(base+2)), now) {
		t.Fatal("+2 steps must be rejected")
	}
	if valid(secret, hotp(secret, uint64(base-2)), now) {
		t.Fatal("-2 steps must be rejected")
	}
}

func TestVerifySuccess(t *testing.T) {
	now := time.Unix(1111111109, 0)
	f := &Factor{now: func() time.Time { return now }}
	ctx := &factor.FactorContext{
		Context:     context.Background(),
		Login:       &token.LoginTokenPayload{Uid: 7, Tid: "tid-1", Passed: []string{"password"}},
		Payload:     &factor.Payload{Code: "081804"},
		Credentials: fakeCredentials{cred: &model.UserCredential{UserID: 7, Kind: "totp", Secret: []byte(rfcSecret), IsEnabled: 1}},
	}
	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed || res.UID != 7 {
		t.Fatalf("Verify = %+v, want passed uid=7", res)
	}
}

func TestVerifyRejectsWithoutPrimaryUid(t *testing.T) {
	f := New()
	ctx := &factor.FactorContext{
		Context:     context.Background(),
		Login:       nil,
		Payload:     &factor.Payload{Code: "123456"},
		Credentials: fakeCredentials{},
	}
	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Passed || res.Status != StatusStepInvalid {
		t.Fatalf("Verify = %+v, want step_invalid", res)
	}

	ctx.Login = &token.LoginTokenPayload{Uid: 0, Passed: []string{"password"}}
	res, err = f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify(uid=0): %v", err)
	}
	if res.Passed || res.Status != StatusStepInvalid {
		t.Fatalf("Verify(uid=0) = %+v, want step_invalid", res)
	}
}

func TestVerifyMalformedCode(t *testing.T) {
	f := New()
	ctx := &factor.FactorContext{
		Context:     context.Background(),
		Login:       &token.LoginTokenPayload{Uid: 7},
		Payload:     &factor.Payload{Code: "12a45"},
		Credentials: fakeCredentials{},
	}
	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Passed || res.Status != StatusInvalidRequest {
		t.Fatalf("Verify = %+v, want invalid_request", res)
	}
}

func TestVerifyCredentialFailures(t *testing.T) {
	f := New()
	base := func(cred fakeCredentials) *factor.FactorContext {
		return &factor.FactorContext{
			Context:     context.Background(),
			Login:       &token.LoginTokenPayload{Uid: 7},
			Payload:     &factor.Payload{Code: "123456"},
			Credentials: cred,
		}
	}

	cases := []struct {
		name string
		cred fakeCredentials
	}{
		{"not found", fakeCredentials{err: gorm.ErrRecordNotFound}},
		{"nil credential", fakeCredentials{cred: nil, err: nil}},
		{"disabled", fakeCredentials{cred: &model.UserCredential{IsEnabled: 0}}},
		{"bad secret", fakeCredentials{cred: &model.UserCredential{IsEnabled: 1, Secret: []byte("not-base32!!")}}},
		{"wrong code", fakeCredentials{cred: &model.UserCredential{IsEnabled: 1, Secret: []byte(rfcSecret)}}},
	}
	for _, tc := range cases {
		res, err := f.Verify(base(tc.cred))
		if err != nil {
			t.Fatalf("%s: Verify: %v", tc.name, err)
		}
		if res.Passed || res.Status != StatusInvalidCode {
			t.Fatalf("%s: Verify = %+v, want invalid_code", tc.name, res)
		}
	}
}
