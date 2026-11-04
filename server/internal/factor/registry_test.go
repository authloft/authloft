package factor

import (
	"errors"
	"testing"
)

// fakeFactor 满足 Factor 接口，仅用于注册表测试（不依赖具体因子）。
type fakeFactor struct {
	kind FactorKind
}

func (f *fakeFactor) Kind() FactorKind  { return f.kind }
func (f *fakeFactor) Usages() []Usage   { return []Usage{UsagePrimary} }
func (f *fakeFactor) Steps() []StepKind { return []StepKind{StepForm} }
func (f *fakeFactor) Start(*FactorContext) (*StepResult, error) {
	return &StepResult{Kind: StepForm}, nil
}
func (f *fakeFactor) Verify(*FactorContext) (*VerifyResult, error) {
	return &VerifyResult{Passed: true}, nil
}

func TestRegistryRegisterGet(t *testing.T) {
	r := NewRegistry()
	f := &fakeFactor{kind: FactorPassword}
	if err := r.Register(FactorPassword, f); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := r.Get(FactorPassword)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != Factor(f) {
		t.Fatal("Get must return the registered factor")
	}

	if err := r.Register(FactorPassword, f); !errors.Is(err, ErrKindAlreadyRegistered) {
		t.Fatalf("duplicate Register err = %v, want ErrKindAlreadyRegistered", err)
	}

	if err := r.Register(FactorOTPSMS, &fakeFactor{kind: FactorPassword}); !errors.Is(err, ErrKindMismatch) {
		t.Fatalf("mismatched Register err = %v, want ErrKindMismatch", err)
	}

	if err := r.Register(FactorKind("bogus"), &fakeFactor{kind: FactorKind("bogus")}); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("unknown Register err = %v, want ErrUnknownKind", err)
	}

	if _, err := r.Get(FactorKind("bogus")); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("unknown Get err = %v, want ErrUnknownKind", err)
	}

	if _, err := r.Get(FactorTOTP); !errors.Is(err, ErrKindNotRegistered) {
		t.Fatalf("unregistered Get err = %v, want ErrKindNotRegistered", err)
	}
}

func TestRegistryAssertComplete(t *testing.T) {
	// pendingKinds 必须恰为 4 条显式清单（§3.8 行 390 口径）。
	wantPending := map[FactorKind]bool{
		FactorOTPSMS:     true,
		FactorOTPEmail:   true,
		FactorThirdParty: true,
		FactorDevice:     true,
	}
	if len(pendingKinds) != len(wantPending) {
		t.Fatalf("pendingKinds len = %d, want %d: %v", len(pendingKinds), len(wantPending), pendingKinds)
	}
	seen := make(map[FactorKind]bool, len(pendingKinds))
	for _, kind := range pendingKinds {
		if !wantPending[kind] {
			t.Fatalf("unexpected pending kind %q, want %v", kind, wantPending)
		}
		if seen[kind] {
			t.Fatalf("duplicate pending kind %q", kind)
		}
		seen[kind] = true
	}
	inAll := make(map[FactorKind]bool, len(allKinds))
	for _, kind := range allKinds {
		inAll[kind] = true
	}
	for _, kind := range pendingKinds {
		if !inAll[kind] {
			t.Fatalf("pending kind %q must belong to allKinds", kind)
		}
	}

	r := NewRegistry()
	if err := r.AssertComplete(); !errors.Is(err, ErrRegistryIncomplete) {
		t.Fatalf("empty registry err = %v, want ErrRegistryIncomplete", err)
	}

	// 只注册 pending 之外的实现 kind 即可通过断言。
	for _, kind := range allKinds {
		if isPending(kind) {
			continue
		}
		if err := r.Register(kind, &fakeFactor{kind: kind}); err != nil {
			t.Fatalf("Register(%s): %v", kind, err)
		}
	}
	if err := r.AssertComplete(); err != nil {
		t.Fatalf("complete registry err = %v, want nil", err)
	}

	// 只注册 pendingKinds 仍然不完整：断言只看 allKinds − pendingKinds。
	onlyPending := NewRegistry()
	for _, kind := range pendingKinds {
		if err := onlyPending.Register(kind, &fakeFactor{kind: kind}); err != nil {
			t.Fatalf("Register(%s): %v", kind, err)
		}
	}
	if err := onlyPending.AssertComplete(); !errors.Is(err, ErrRegistryIncomplete) {
		t.Fatalf("pending-only registry err = %v, want ErrRegistryIncomplete", err)
	}
}
