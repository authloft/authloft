package otp

import (
	"context"
	"errors"
	"testing"

	"authloft/gen/go/token"
	"authloft/internal/cache"
	"authloft/internal/factor"
	core "authloft/internal/otp"
	"authloft/internal/repo/model"
)

type fakeStore struct {
	sendResult   cache.SendResult
	sendErr      error
	verifyResult cache.VerifyResult
	attemptsLeft int64
	verifyErr    error

	gotTarget  string
	gotPurpose string
	gotOwner   string
	gotIP      string
	gotCode    string
	sendCalls  int
}

func (s *fakeStore) Send(_ context.Context, target, purpose, owner, ip, code string) (cache.SendResult, error) {
	s.sendCalls++
	s.gotTarget, s.gotPurpose, s.gotOwner, s.gotIP, s.gotCode = target, purpose, owner, ip, code
	return s.sendResult, s.sendErr
}

func (s *fakeStore) Verify(_ context.Context, target, purpose, owner, code string) (cache.CodeVerifyResult, error) {
	s.gotTarget, s.gotPurpose, s.gotOwner, s.gotCode = target, purpose, owner, code
	return cache.CodeVerifyResult{Result: s.verifyResult, AttemptsLeft: s.attemptsLeft}, s.verifyErr
}

type fakeSender struct {
	calls  int
	target string
	code   string
	err    error
}

func (s *fakeSender) SendCode(_ context.Context, target, code string) error {
	s.calls++
	s.target, s.code = target, code
	return s.err
}

type fakeUsers struct {
	byID    *model.User
	byPhone *model.User
	byEmail *model.User
	err     error
}

func (f fakeUsers) FindByID(_ context.Context, _ int64) (*model.User, error) {
	return f.byID, f.err
}

func (f fakeUsers) FindByPhone(_ context.Context, _ string) (*model.User, error) {
	return f.byPhone, f.err
}

func (f fakeUsers) FindByEmail(_ context.Context, _ string) (*model.User, error) {
	return f.byEmail, f.err
}

func newFactor(t *testing.T, kind factor.FactorKind) (*Factor, *fakeStore, *fakeSender) {
	t.Helper()
	st := &fakeStore{sendResult: cache.SendOK}
	sender := &fakeSender{}
	f, err := New(kind, core.NewService(st, core.DefaultConfig()), sender, nil, core.DefaultConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f, st, sender
}

func TestNewValidatesKind(t *testing.T) {
	if _, err := New(factor.FactorPassword, core.NewService(&fakeStore{}, core.DefaultConfig()), nil, nil, core.DefaultConfig()); err == nil {
		t.Fatal("New must reject non-otp kind")
	}
	if _, err := New(factor.FactorOTPSMS, nil, nil, nil, core.DefaultConfig()); err == nil {
		t.Fatal("New must reject nil service")
	}
}

func TestShape(t *testing.T) {
	f, _, _ := newFactor(t, factor.FactorOTPSMS)
	if f.Kind() != factor.FactorOTPSMS {
		t.Fatalf("Kind = %v", f.Kind())
	}
	if usages := f.Usages(); len(usages) != 2 || usages[0] != factor.UsagePrimary || usages[1] != factor.UsageSecondary {
		t.Fatalf("Usages = %v, want [primary secondary]", usages)
	}
	if steps := f.Steps(); len(steps) != 2 || steps[0] != factor.StepChallenge || steps[1] != factor.StepForm {
		t.Fatalf("Steps = %v, want [challenge form]", steps)
	}
}

func TestStartMFAUsesBoundTarget(t *testing.T) {
	phone := "13800000000"
	f, st, sender := newFactor(t, factor.FactorOTPSMS)
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login: &token.LoginTokenPayload{
			Uid: 7, Tid: "tid-1", Flow: "login", Passed: []string{"password"},
			Ch: &token.Challenge{Purpose: "mfa"},
		},
		Payload: &factor.Payload{Phone: "13900000000"}, // 请求侧注入必须被忽略
		Users:   fakeUsers{byID: &model.User{ID: 7, Phone: &phone, PhoneVerified: 1}},
	}
	res, err := f.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Status != "" || res.Kind != factor.StepForm || res.Method != factor.FactorOTPSMS {
		t.Fatalf("Start = %+v, want form step", res)
	}
	if st.gotTarget != phone || st.gotPurpose != purposeMFA || st.gotOwner != "tid-1" {
		t.Fatalf("store args = %q/%q/%q, want %q/mfa/tid-1", st.gotTarget, st.gotPurpose, st.gotOwner, phone)
	}
	if sender.calls != 1 || sender.target != phone || !core.WellFormed(sender.code) {
		t.Fatalf("sender = %+v, want one delivery to bound phone", sender)
	}
}

func TestStartPrimaryUserNotFound(t *testing.T) {
	f, st, sender := newFactor(t, factor.FactorOTPSMS)
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Payload: &factor.Payload{Phone: "13800000000"},
		Users:   fakeUsers{byPhone: nil},
	}
	res, err := f.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Status != StatusUserNotFound {
		t.Fatalf("Start = %+v, want user_not_found", res)
	}
	// §10.2：目标不存在不写码、不发信、不签 login_token。
	if st.sendCalls != 0 || sender.calls != 0 {
		t.Fatalf("store/sender called: %d/%d, want 0/0", st.sendCalls, sender.calls)
	}
}

func TestStartPrimaryInvalidRequest(t *testing.T) {
	f, _, _ := newFactor(t, factor.FactorOTPSMS)
	res, err := f.Start(&factor.FactorContext{Context: context.Background(), Payload: &factor.Payload{}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Status != StatusInvalidRequest {
		t.Fatalf("Start = %+v, want invalid_request", res)
	}
}

// TestStartPrimaryWritesCodeWithTid engine 在 Start 之前已由 loadPayload 生成
// tid / 选定 flow，首个 challenge 必须按 owner=tid、purpose=flow 写码
// （§10.1 行 1121、§7.3 行 992）。
func TestStartPrimaryWritesCodeWithTid(t *testing.T) {
	phone := "13800000000"
	f, st, sender := newFactor(t, factor.FactorOTPSMS)
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login:   &token.LoginTokenPayload{Tid: "tid-1", Flow: "login"},
		Payload: &factor.Payload{Phone: phone},
		Users:   fakeUsers{byPhone: &model.User{ID: 7, Phone: &phone, PhoneVerified: 1}},
	}
	res, err := f.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Status != "" || res.Kind != factor.StepForm || res.Method != factor.FactorOTPSMS {
		t.Fatalf("Start = %+v, want form step", res)
	}
	if st.gotTarget != phone || st.gotPurpose != "login" || st.gotOwner != "tid-1" {
		t.Fatalf("store args = %q/%q/%q, want %q/login/tid-1", st.gotTarget, st.gotPurpose, st.gotOwner, phone)
	}
	if sender.calls != 1 || sender.target != phone || !core.WellFormed(sender.code) {
		t.Fatalf("sender = %+v, want one delivery with 6-digit code", sender)
	}
}

func TestStartCooldown(t *testing.T) {
	phone := "13800000000"
	f, st, sender := newFactor(t, factor.FactorOTPSMS)
	st.sendResult = cache.SendCooldown
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login: &token.LoginTokenPayload{
			Uid: 7, Tid: "tid-1", Flow: "login", Passed: []string{"password"},
			Ch: &token.Challenge{Purpose: "mfa"},
		},
		Users: fakeUsers{byID: &model.User{ID: 7, Phone: &phone, PhoneVerified: 1}},
	}
	res, err := f.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Status != core.StatusTooManyRequests || res.RetryAfter != 60 {
		t.Fatalf("Start = %+v, want too_many_requests/60", res)
	}
	if sender.calls != 0 {
		t.Fatal("cooldown must not send")
	}
}

func TestStartSenderError(t *testing.T) {
	phone := "13800000000"
	f, _, sender := newFactor(t, factor.FactorOTPSMS)
	sender.err = errors.New("smtp down")
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login: &token.LoginTokenPayload{
			Uid: 7, Tid: "tid-1", Flow: "login", Passed: []string{"password"},
			Ch: &token.Challenge{Purpose: "mfa"},
		},
		Users: fakeUsers{byID: &model.User{ID: 7, Phone: &phone, PhoneVerified: 1}},
	}
	if _, err := f.Start(ctx); err == nil {
		t.Fatal("sender error must propagate")
	}
}

func TestVerifyPrimarySuccess(t *testing.T) {
	phone := "13800000000"
	f, st, _ := newFactor(t, factor.FactorOTPSMS)
	st.verifyResult = cache.VerifyOK
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login: &token.LoginTokenPayload{
			Tid: "tid-1", Flow: "login", Passed: []string{"password"},
			Ch: &token.Challenge{Purpose: "login", Target: phone},
		},
		Payload: &factor.Payload{Code: "123456"},
		Users:   fakeUsers{byPhone: &model.User{ID: 7}},
	}
	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed || res.UID != 7 {
		t.Fatalf("Verify = %+v, want passed uid=7", res)
	}
	if st.gotTarget != phone || st.gotPurpose != "login" || st.gotOwner != "tid-1" || st.gotCode != "123456" {
		t.Fatalf("store args = %q/%q/%q/%q", st.gotTarget, st.gotPurpose, st.gotOwner, st.gotCode)
	}
}

func TestVerifySecondaryUsesBoundTarget(t *testing.T) {
	phone := "13800000000"
	other := "13900000000"
	f, st, _ := newFactor(t, factor.FactorOTPSMS)
	st.verifyResult = cache.VerifyOK
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login: &token.LoginTokenPayload{
			Uid: 7, Tid: "tid-1", Flow: "login", Passed: []string{"password"},
			Ch: &token.Challenge{Purpose: "mfa"},
		},
		Payload: &factor.Payload{Phone: other, Code: "123456"},
		Users:   fakeUsers{byID: &model.User{ID: 7, Phone: &phone, PhoneVerified: 1}},
	}
	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed || res.UID != 7 {
		t.Fatalf("Verify = %+v, want passed uid=7", res)
	}
	if st.gotTarget != phone || st.gotPurpose != purposeMFA {
		t.Fatalf("store args = %q/%q, want %q/mfa", st.gotTarget, st.gotPurpose, phone)
	}
}

func TestVerifyOutcomes(t *testing.T) {
	phone := "13800000000"
	cases := []struct {
		name string
		in   cache.VerifyResult
		want string
	}{
		{"owner mismatch", cache.VerifyMismatch, StatusInvalidCode},
		{"exhausted", cache.VerifyExhausted, StatusTooManyAttempts},
		{"missing", cache.VerifyMissing, StatusCodeExpired},
	}
	for _, tc := range cases {
		f, st, _ := newFactor(t, factor.FactorOTPSMS)
		st.verifyResult = tc.in
		ctx := &factor.FactorContext{
			Context: context.Background(),
			Login: &token.LoginTokenPayload{
				Tid: "other-session", Flow: "login", Passed: []string{"password"},
				Ch: &token.Challenge{Purpose: "login", Target: phone},
			},
			Payload: &factor.Payload{Code: "123456"},
			Users:   fakeUsers{byPhone: &model.User{ID: 7}},
		}
		res, err := f.Verify(ctx)
		if err != nil {
			t.Fatalf("%s: Verify: %v", tc.name, err)
		}
		if res.Passed || res.Status != tc.want {
			t.Fatalf("%s: Verify = %+v, want %s", tc.name, res, tc.want)
		}
	}
}

func TestVerifyMalformedCode(t *testing.T) {
	f, st, _ := newFactor(t, factor.FactorOTPSMS)
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login:   &token.LoginTokenPayload{Tid: "tid-1", Ch: &token.Challenge{Target: "13800000000"}},
		Payload: &factor.Payload{Code: "12ab56"},
	}
	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != StatusInvalidRequest {
		t.Fatalf("Verify = %+v, want invalid_request", res)
	}
	if st.gotCode != "" {
		t.Fatalf("store must not be called for malformed code: %q", st.gotCode)
	}
}

func TestVerifyWithoutLoginToken(t *testing.T) {
	f, _, _ := newFactor(t, factor.FactorOTPSMS)
	res, err := f.Verify(&factor.FactorContext{Context: context.Background(), Payload: &factor.Payload{Code: "123456"}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != StatusStepInvalid {
		t.Fatalf("Verify = %+v, want step_invalid", res)
	}
}

func TestVerifyEmailChannel(t *testing.T) {
	email := "a@example.com"
	f, st, _ := newFactor(t, factor.FactorOTPEmail)
	st.verifyResult = cache.VerifyOK
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login: &token.LoginTokenPayload{
			Tid: "tid-1", Flow: "login", Passed: []string{"password"},
			Ch: &token.Challenge{Purpose: "login", Target: email},
		},
		Payload: &factor.Payload{Code: "123456"},
		Users:   fakeUsers{byEmail: &model.User{ID: 7}},
	}
	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed || res.UID != 7 {
		t.Fatalf("Verify = %+v, want passed uid=7", res)
	}
}

// TestStartResetUnverifiedTarget reset 前提校验（§2.4 行 465）：目标已绑定
// 但未验证 → user_not_found（不写码、不发信）。
func TestStartResetUnverifiedTarget(t *testing.T) {
	phone := "13800000000"
	f, st, sender := newFactor(t, factor.FactorOTPSMS)
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login:   &token.LoginTokenPayload{Tid: "tid-1", Flow: "reset"},
		Payload: &factor.Payload{Phone: phone},
		Users:   fakeUsers{byPhone: &model.User{ID: 7, Phone: &phone, PhoneVerified: 0}},
	}
	res, err := f.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Status != StatusUserNotFound {
		t.Fatalf("Start = %+v, want user_not_found（未验证目标）", res)
	}
	if st.sendCalls != 0 || sender.calls != 0 {
		t.Fatalf("store/sender called: %d/%d, want 0/0", st.sendCalls, sender.calls)
	}
}

// TestStartResetVerifiedTarget reset + 已绑定且已验证 → 正常发码（purpose=reset）。
func TestStartResetVerifiedTarget(t *testing.T) {
	phone := "13800000000"
	f, st, sender := newFactor(t, factor.FactorOTPSMS)
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login:   &token.LoginTokenPayload{Tid: "tid-1", Flow: "reset"},
		Payload: &factor.Payload{Phone: phone},
		Users:   fakeUsers{byPhone: &model.User{ID: 7, Phone: &phone, PhoneVerified: 1}},
	}
	res, err := f.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Status != "" || res.Kind != factor.StepForm {
		t.Fatalf("Start = %+v, want form step", res)
	}
	if st.gotPurpose != "reset" || st.gotTarget != phone {
		t.Fatalf("store args = %q/%q, want reset/%s", st.gotPurpose, st.gotTarget, phone)
	}
	if sender.calls != 1 {
		t.Fatalf("sender calls = %d, want 1", sender.calls)
	}
}

// TestStartRegisterNewTarget register 注册入口：目标不存在才发码
// （purpose=register，§2.3 行 446）。
func TestStartRegisterNewTarget(t *testing.T) {
	f, st, sender := newFactor(t, factor.FactorOTPEmail)
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login:   &token.LoginTokenPayload{Tid: "tid-1", Flow: "register"},
		Payload: &factor.Payload{Email: "new@example.com"},
		Users:   fakeUsers{},
	}
	res, err := f.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Status != "" || res.Kind != factor.StepForm {
		t.Fatalf("Start = %+v, want form step", res)
	}
	if st.gotPurpose != "register" || st.gotTarget != "new@example.com" {
		t.Fatalf("store args = %q/%q, want register/new@example.com", st.gotPurpose, st.gotTarget)
	}
	if sender.calls != 1 {
		t.Fatalf("sender calls = %d, want 1", sender.calls)
	}
}

// TestStartRegisterTargetTaken register + 目标已占用 → target_taken
// （§1.6 行 256，不写码、不发信）。
func TestStartRegisterTargetTaken(t *testing.T) {
	email := "taken@example.com"
	f, st, sender := newFactor(t, factor.FactorOTPEmail)
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login:   &token.LoginTokenPayload{Tid: "tid-1", Flow: "register"},
		Payload: &factor.Payload{Email: email},
		Users:   fakeUsers{byEmail: &model.User{ID: 9, Email: &email, EmailVerified: 1}},
	}
	res, err := f.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.Status != StatusTargetTaken {
		t.Fatalf("Start = %+v, want target_taken", res)
	}
	if st.sendCalls != 0 || sender.calls != 0 {
		t.Fatalf("store/sender called: %d/%d, want 0/0", st.sendCalls, sender.calls)
	}
}

// TestVerifyRegisterNoUserLookup register 流 verify 通过后不反查用户
// （建号在 set_password 步，§7.4）：Passed 且不带 uid。
func TestVerifyRegisterNoUserLookup(t *testing.T) {
	f, st, _ := newFactor(t, factor.FactorOTPEmail)
	st.verifyResult = cache.VerifyOK
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login: &token.LoginTokenPayload{
			Tid: "tid-1", Flow: "register",
			Ch: &token.Challenge{Purpose: "register", Target: "new@example.com"},
		},
		Payload: &factor.Payload{Code: "123456"},
		// Users 不提供已存在用户：login 语义会反查并返回 user_not_found，
		// register 语义必须跳过反查。
		Users: fakeUsers{},
	}
	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed || res.UID != 0 {
		t.Fatalf("Verify = %+v, want passed with uid=0（register 未建号）", res)
	}
}
