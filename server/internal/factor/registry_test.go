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
	r := NewRegistry()
	if err := r.AssertComplete(); !errors.Is(err, ErrRegistryIncomplete) {
		t.Fatalf("empty registry err = %v, want ErrRegistryIncomplete", err)
	}

	for _, kind := range allKinds {
		if err := r.Register(kind, &fakeFactor{kind: kind}); err != nil {
			t.Fatalf("Register(%s): %v", kind, err)
		}
	}
	if err := r.AssertComplete(); err != nil {
		t.Fatalf("complete registry err = %v, want nil", err)
	}
}
