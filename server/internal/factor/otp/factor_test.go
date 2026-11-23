package otp

import (
	"context"
	"errors"
	"testing"

	"authloft/gen/go/token"
	"authloft/internal/cache"
	"authloft/internal/factor"
	"authloft/internal/factor/ipres"
	core "authloft/internal/otp"
	"authloft/internal/repo/model"
	"authloft/internal/service/orchestrator"
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
	phone := "+8613800138000"
	f, st, sender := newFactor(t, factor.FactorOTPSMS)
	ctx := &factor.FactorContext{
		Context: context.Background(),
		Login: &token.LoginTokenPayload{
			Uid: 7, Tid: "tid-1", Flow: "login", Passed: []string{"password"},
			Ch: &token.Challenge{Purpose: "mfa"},
		},
		Payload: &factor.Payload{Phone: "+8613900000000"}, // 请求侧注入必须被忽略
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
		Payload: &factor.Payload{Phone: "+8613800138000"},
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

// TestStartRejectsBarePhone 手机号主因子挑战只接受 E.164（§1.11）：裸号在
// register 入口若放行会经 setpass 落库，之后前端 E.164 登录精确匹配不到。
func TestStartRejectsBarePhone(t *testing.T) {
	for _, flow := range []string{"register", "login", "reset"} {
		f, st, sender := newFactor(t, factor.FactorOTPSMS)
		res, err := f.Start(&factor.FactorContext{
			Context: context.Background(),
			Login:   &token.LoginTokenPayload{Tid: "tid-1", Flow: flow},
			Payload: &factor.Payload{Phone: "13800138000"},
			Users:   fakeUsers{byPhone: nil},
		})
		if err != nil {
			t.Fatalf("flow %s Start: %v", flow, err)
		}
		if res.Status != StatusInvalidRequest {
			t.Fatalf("flow %s Start = %+v, want invalid_request", flow, res)
		}
		if st.sendCalls != 0 || sender.calls != 0 {
			t.Fatalf("flow %s: bare phone must not write code or send", flow)
		}
	}
}

// TestStartPrimaryWritesCodeWithTid engine 在 Start 之前已由 loadPayload 生成
// tid / 选定 flow，首个 challenge 必须按 owner=tid、purpose=flow 写码
// （§10.1 行 1121、§7.3 行 992）。
func TestStartPrimaryWritesCodeWithTid(t *testing.T) {
	phone := "+8613800138000"
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
	phone := "+8613800138000"
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
	phone := "+8613800138000"
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
	phone := "+8613800138000"
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
	phone := "+8613800138000"
	other := "+8613900000000"
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
	phone := "+8613800138000"
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
		Login:   &token.LoginTokenPayload{Tid: "tid-1", Ch: &token.Challenge{Target: "+8613800138000"}},
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
	phone := "+8613800138000"
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
	phone := "+8613800138000"
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

// TestVerifyExhaustedIgnoresUpstreamAttemptsLeft 上游 cache 层误带非零
// AttemptsLeft 时，尝试超限态仍不携带剩余次数：以同一非零输入设错码对照，
// 证明「不带」来自失败口径本身（otp/factor.go:218、otp/code.go:187），
// 而非输入恰好为零值。
func TestVerifyExhaustedIgnoresUpstreamAttemptsLeft(t *testing.T) {
	const misreported int64 = 5
	cases := []struct {
		name     string
		outcome  cache.VerifyResult
		wantStat string
		wantLeft int64
	}{
		{"尝试超限：上游误带 5 仍不携带", cache.VerifyExhausted, StatusTooManyAttempts, 0},
		{"错码对照：同一上游 5 必须携带", cache.VerifyMismatch, StatusInvalidCode, misreported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, st, _ := newFactor(t, factor.FactorOTPSMS)
			st.verifyResult = tc.outcome
			st.attemptsLeft = misreported
			ctx := &factor.FactorContext{
				Context: context.Background(),
				Login: &token.LoginTokenPayload{
					Tid: "sess-1", Flow: "login", Passed: []string{"password"},
					Ch: &token.Challenge{Purpose: "login", Target: "+8613800138000"},
				},
				Payload: &factor.Payload{Code: "123456"},
				Users:   fakeUsers{byPhone: &model.User{ID: 7}},
			}
			res, err := f.Verify(ctx)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.Status != tc.wantStat || res.AttemptsLeft != tc.wantLeft {
				t.Fatalf("Verify = %+v, want %s/%d", res, tc.wantStat, tc.wantLeft)
			}
		})
	}
}

// ipLimitStore 有状态 Store：按 ip 计数，复现 cache/code 单 IP 日限额的
// SendIPDailyLimit 结论（键读写与原子判定在生产在 store，本 fake 只验证
// 因子把 resolver 解析出的 ip 送进限额链）。
type ipLimitStore struct {
	ipCounts map[string]int
	ipLimit  int
	gotIPs   []string
}

func (s *ipLimitStore) Send(_ context.Context, _, _, _, ip, _ string) (cache.SendResult, error) {
	s.gotIPs = append(s.gotIPs, ip)
	s.ipCounts[ip]++
	if s.ipLimit > 0 && s.ipCounts[ip] > s.ipLimit {
		return cache.SendIPDailyLimit, nil
	}
	return cache.SendOK, nil
}

func (s *ipLimitStore) Verify(context.Context, string, string, string, string) (cache.CodeVerifyResult, error) {
	return cache.CodeVerifyResult{Result: cache.VerifyOK}, nil
}

// TestStartIPDailyLimitCountsByIP 生产 resolver 注入后单 IP 日限额按真实
// 来源 IP 计数（需求 §4.1.5、后端架构 §10.3）：同 ip 连发达限额即
// too_many_requests 且不再投递，不同 ip 不受累；store 收到的必须是
// resolver 解析值而非 unknown 恒定桶。
func TestStartIPDailyLimitCountsByIP(t *testing.T) {
	phone := "+8613800138000"
	st := &ipLimitStore{ipCounts: map[string]int{}, ipLimit: 2}
	sender := &fakeSender{}
	f, err := New(factor.FactorOTPSMS, core.NewService(st, core.DefaultConfig()), sender, ipres.Resolver{}, core.DefaultConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	users := fakeUsers{byPhone: &model.User{ID: 7, Phone: &phone, PhoneVerified: 1}}
	newCtxWithIP := func(ip string) *factor.FactorContext {
		return &factor.FactorContext{
			Context: orchestrator.WithRequestInfo(context.Background(), orchestrator.RequestInfo{IP: ip}),
			Login:   &token.LoginTokenPayload{Tid: "tid-1", Flow: "login"},
			Payload: &factor.Payload{Phone: phone},
			Users:   users,
		}
	}

	for i := 0; i < 2; i++ {
		res, err := f.Start(newCtxWithIP("203.0.113.10"))
		if err != nil {
			t.Fatalf("Start(#%d): %v", i+1, err)
		}
		if res.Status != "" || res.Kind != factor.StepForm {
			t.Fatalf("Start(#%d) = %+v, want form step", i+1, res)
		}
	}
	res, err := f.Start(newCtxWithIP("203.0.113.10"))
	if err != nil {
		t.Fatalf("Start(limit): %v", err)
	}
	if res.Status != core.StatusTooManyRequests || res.RetryAfter <= 0 {
		t.Fatalf("Start(limit) = %+v, want too_many_requests with retry_after", res)
	}
	if sender.calls != 2 {
		t.Fatalf("sender calls = %d, want 2（限额命中后不投递）", sender.calls)
	}

	// 不同 ip 不受同一桶累加影响。
	res, err = f.Start(newCtxWithIP("198.51.100.5"))
	if err != nil {
		t.Fatalf("Start(other ip): %v", err)
	}
	if res.Status != "" || res.Kind != factor.StepForm {
		t.Fatalf("Start(other ip) = %+v, want form step（异 ip 不得受累）", res)
	}
	if sender.calls != 3 {
		t.Fatalf("sender calls = %d, want 3", sender.calls)
	}
	// Issue 先于 Judge 记账：限额命中那次也写 store，共 4 次 Send。
	if len(st.gotIPs) != 4 || st.gotIPs[0] != "203.0.113.10" || st.gotIPs[3] != "198.51.100.5" {
		t.Fatalf("store 收到 ip 序列 = %v", st.gotIPs)
	}
}
