package orchestrator

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
	"authloft/internal/captcha"
	"authloft/internal/factor"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

// testSettings 是 SettingsReader 的 Fake，支持运行时改动以验证热更新。
type testSettings struct {
	strs   map[string]string
	ints   map[string]int64
	bools  map[string]bool
	slices map[string][]string
}

func (s *testSettings) GetString(key string) (string, bool) {
	v, ok := s.strs[key]
	return v, ok
}

func (s *testSettings) GetInt64(key string) (int64, bool) {
	v, ok := s.ints[key]
	return v, ok
}

func (s *testSettings) GetBool(key string) (bool, bool) {
	v, ok := s.bools[key]
	return v, ok
}

func (s *testSettings) GetStringSlice(key string) ([]string, bool) {
	v, ok := s.slices[key]
	return v, ok
}

type fakeFactor struct {
	kind   factor.FactorKind
	usages []factor.Usage
	steps  []factor.StepKind
	start  func(*factor.FactorContext) (*factor.StepResult, error)
	verify func(*factor.FactorContext) (*factor.VerifyResult, error)
}

func (f *fakeFactor) Kind() factor.FactorKind  { return f.kind }
func (f *fakeFactor) Usages() []factor.Usage   { return f.usages }
func (f *fakeFactor) Steps() []factor.StepKind { return f.steps }

func (f *fakeFactor) Start(ctx *factor.FactorContext) (*factor.StepResult, error) {
	if f.start != nil {
		return f.start(ctx)
	}
	return &factor.StepResult{Kind: factor.StepForm, Method: f.kind}, nil
}

func (f *fakeFactor) Verify(ctx *factor.FactorContext) (*factor.VerifyResult, error) {
	if f.verify != nil {
		return f.verify(ctx)
	}
	return &factor.VerifyResult{Passed: true}, nil
}

type fakeRegistry struct {
	factors map[factor.FactorKind]factor.Factor
	err     error
}

func (r *fakeRegistry) Get(kind factor.FactorKind) (factor.Factor, error) {
	if r.err != nil {
		return nil, r.err
	}
	f, ok := r.factors[kind]
	if !ok {
		return nil, factor.ErrKindNotRegistered
	}
	return f, nil
}

type fakeCatalog struct {
	p   *captcha.Provider
	err error
}

func (f fakeCatalog) Current(context.Context) (*captcha.Provider, error) { return f.p, f.err }

type fakeCaptchaVerifier struct {
	err   error
	calls int
}

func (f *fakeCaptchaVerifier) Verify(context.Context, string, captcha.Submission) error {
	f.calls++
	return f.err
}

// fakeFactorCaptcha 是 factor.CaptchaVerifier 的 Fake（与 captcha.Verifier 不同契约）。
type fakeFactorCaptcha struct{}

func (fakeFactorCaptcha) Verify(context.Context, *factor.CaptchaInput) error { return nil }

type fakeFailures struct {
	n   int64
	err error
}

func (f fakeFailures) Count(context.Context, string) (int64, error) { return f.n, f.err }

type fakeUsers struct {
	user *model.User
	err  error
}

func (f *fakeUsers) FindByID(context.Context, int64) (*model.User, error) { return f.user, f.err }
func (f *fakeUsers) FindByPhone(context.Context, string) (*model.User, error) {
	return nil, gorm.ErrRecordNotFound
}
func (f *fakeUsers) FindByEmail(context.Context, string) (*model.User, error) {
	return nil, gorm.ErrRecordNotFound
}

type fakeCredentials struct {
	creds    map[string]*model.UserCredential
	webauthn []model.UserCredentialWebauthn
}

func (f *fakeCredentials) FindByUserAndKind(_ context.Context, _ int64, kind string) (*model.UserCredential, error) {
	if c, ok := f.creds[kind]; ok {
		return c, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (f *fakeCredentials) ListWebauthn(context.Context, int64) ([]model.UserCredentialWebauthn, error) {
	return f.webauthn, nil
}

type fakeSessionWriter struct {
	calls int
	sid   string
	stok  string
	err   error
}

func (f *fakeSessionWriter) Write(context.Context, int64, []string) (string, string, error) {
	f.calls++
	return f.sid, f.stok, f.err
}

type fakeOIDCIssuer struct {
	in   OIDCIssue
	code string
	err  error
}

func (f *fakeOIDCIssuer) Issue(_ context.Context, in OIDCIssue) (string, error) {
	f.in = in
	return f.code, f.err
}

type fakeEvents struct {
	got []LoginEvent
}

func (f *fakeEvents) Record(_ context.Context, ev LoginEvent) error {
	f.got = append(f.got, ev)
	return nil
}

type fakeSyncBuilder struct {
	got string
	url string
	err error
}

func (f *fakeSyncBuilder) Build(_ context.Context, cookieName, cookieValue, cookieTTL string, domains []string, finalURL string) (string, error) {
	f.got = cookieName + "|" + cookieValue + "|" + cookieTTL + "|" + strings.Join(domains, ",") + "|" + finalURL
	return f.url, f.err
}

// testEngineDeps 汇总一套全 Fake 的引擎依赖。
type testEngineDeps struct {
	settings *testSettings
	registry *fakeRegistry
	gate     *captcha.Gate
	mfa      *MFABuilder
	terminal *Terminal
	users    *fakeUsers
	creds    *fakeCredentials
	failures PasswordFailures
	verifier *fakeCaptchaVerifier
	sessions *fakeSessionWriter
	oidc     *fakeOIDCIssuer
	events   *fakeEvents
	sync     *fakeSyncBuilder
}

func newTestDeps(t *testing.T, at time.Time) *testEngineDeps {
	t.Helper()
	s := &testSettings{
		strs:   map[string]string{settings.KeyCookieName: "al_session"},
		ints:   map[string]int64{settings.KeyPwdFailCapture: 3, settings.KeyOtpTtl: 300, settings.KeySessionTtl: 604800},
		bools:  map[string]bool{settings.KeyMfaEnabled: true, settings.KeyAllowRegistration: true, settings.KeyAllowSignupPassword: true, settings.KeyAllowSignupPhone: true, settings.KeyAllowSignupEmail: true, settings.KeyAllowPasswordReset: true},
		slices: map[string][]string{settings.KeyLoginMethods: {"password", "otp_sms", "otp_email", "webauthn", "thirdparty"}, settings.KeyMfaMethods: {"totp", "otp_sms", "otp_email", "webauthn"}},
	}
	reg := &fakeRegistry{factors: map[factor.FactorKind]factor.Factor{}}
	verifier := &fakeCaptchaVerifier{}
	catalog := fakeCatalog{p: &captcha.Provider{ProviderKey: "builtin_image", Type: "image"}}
	gate := captcha.NewGate(s, catalog, verifier)
	users := &fakeUsers{}
	creds := &fakeCredentials{creds: map[string]*model.UserCredential{}}
	mfa := NewMFABuilder(users, creds, s)
	sessions := &fakeSessionWriter{sid: "sid-1", stok: "stok-1"}
	oidc := &fakeOIDCIssuer{code: "code-1"}
	events := &fakeEvents{}
	sync := &fakeSyncBuilder{url: "https://sync.example/sso"}
	terminal := NewTerminal(sessions, oidc, events, sync, s)
	terminal.Now = func() time.Time { return at }

	return &testEngineDeps{
		settings: s, registry: reg, gate: gate, mfa: mfa, terminal: terminal,
		users: users, creds: creds, verifier: verifier,
		sessions: sessions, oidc: oidc, events: events, sync: sync,
	}
}

func (d *testEngineDeps) engine(state *State) *Engine {
	dispatcher := &Dispatcher{Registry: d.registry, Settings: d.settings}
	return NewEngine(EngineDeps{
		State:      state,
		Dispatcher: dispatcher,
		Gate:       d.gate,
		MFA:        d.mfa,
		Terminal:   d.terminal,
		Failures:   d.failures,
		Factor: FactorDeps{
			CaptchaVerifier: fakeFactorCaptcha{},
			Users:           d.users,
			Credentials:     d.creds,
		},
		NewTID: func() (string, error) { return "tid-1", nil },
	})
}

func otpEmailFactor() *fakeFactor {
	return &fakeFactor{
		kind:   factor.FactorOTPEmail,
		usages: []factor.Usage{factor.UsagePrimary, factor.UsageSecondary},
		steps:  []factor.StepKind{factor.StepChallenge, factor.StepForm},
		verify: func(*factor.FactorContext) (*factor.VerifyResult, error) {
			return &factor.VerifyResult{Passed: true, UID: 42}, nil
		},
	}
}

func otpSMSFactor() *fakeFactor {
	return &fakeFactor{
		kind:   factor.FactorOTPSMS,
		usages: []factor.Usage{factor.UsagePrimary, factor.UsageSecondary},
		steps:  []factor.StepKind{factor.StepChallenge, factor.StepForm},
	}
}

func passwordFactor(uid int64) *fakeFactor {
	return &fakeFactor{
		kind:   factor.FactorPassword,
		usages: []factor.Usage{factor.UsagePrimary},
		steps:  []factor.StepKind{factor.StepForm},
		verify: func(*factor.FactorContext) (*factor.VerifyResult, error) {
			return &factor.VerifyResult{Passed: true, UID: uid}, nil
		},
	}
}

func totpFactor() *fakeFactor {
	return &fakeFactor{
		kind:   factor.FactorTOTP,
		usages: []factor.Usage{factor.UsageSecondary},
		steps:  []factor.StepKind{factor.StepForm},
	}
}

func captchaSubmission() *factor.CaptchaInput {
	return &factor.CaptchaInput{ProviderKey: "builtin_image", ID: "id-1", Answer: "1234"}
}

func TestEngineTokenInvalid(t *testing.T) {
	state := testState(t, time.Unix(1_700_000_000, 0))
	deps := newTestDeps(t, time.Unix(1_700_000_000, 0))
	e := deps.engine(state)

	got := e.Submit(context.Background(), "login", Request{LoginToken: "not-a-token", Method: "password", Step: "verify"})
	if got.Status != StatusTokenInvalid {
		t.Fatalf("status = %q, want %q", got.Status, StatusTokenInvalid)
	}
}

func TestEngineTokenExpired(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	codec := testCodec(t)
	issuer := NewState(codec)
	issuer.now = func() time.Time { return at }
	tok, err := issuer.Issue(&token.LoginTokenPayload{Tid: "tid-1", Flow: "login"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	parser := NewState(codec)
	parser.now = func() time.Time { return at.Add(20 * time.Minute) }
	deps := newTestDeps(t, at)
	e := deps.engine(parser)

	got := e.Submit(context.Background(), "login", Request{LoginToken: tok, Method: "password", Step: "verify"})
	if got.Status != StatusTokenExpired {
		t.Fatalf("status = %q, want %q", got.Status, StatusTokenExpired)
	}
}

func TestEngineStepInvalid(t *testing.T) {
	deps := newTestDeps(t, time.Unix(1_700_000_000, 0))
	deps.registry.factors[factor.FactorPassword] = passwordFactor(7)
	deps.registry.factors[factor.FactorTOTP] = totpFactor()
	deps.settings.slices[settings.KeyLoginMethods] = []string{"password", "totp"}
	e := deps.engine(testState(t, time.Unix(1_700_000_000, 0)))

	// password 只有 form 步，challenge 非法。
	got := e.Submit(context.Background(), "login", Request{Method: "password", Step: "challenge"})
	if got.Status != StatusStepInvalid {
		t.Fatalf("password/challenge status = %q, want %q", got.Status, StatusStepInvalid)
	}

	// 仅 secondary 的 totp 在主因子未过时使用，非法（uid=0、passed 空）。
	got = e.Submit(context.Background(), "login", Request{Method: "totp", Step: "verify"})
	if got.Status != StatusStepInvalid {
		t.Fatalf("totp/verify status = %q, want %q", got.Status, StatusStepInvalid)
	}
}

func TestEngineMethodDisabled(t *testing.T) {
	deps := newTestDeps(t, time.Unix(1_700_000_000, 0))
	deps.settings.slices[settings.KeyLoginMethods] = []string{"otp_email"}
	deps.registry.factors[factor.FactorPassword] = passwordFactor(7)
	e := deps.engine(testState(t, time.Unix(1_700_000_000, 0)))

	got := e.Submit(context.Background(), "login", Request{Method: "password", Step: "verify"})
	if got.Status != StatusMethodDisabled {
		t.Fatalf("status = %q, want %q", got.Status, StatusMethodDisabled)
	}
}

func TestEngineCaptchaRequiredAndInvalid(t *testing.T) {
	deps := newTestDeps(t, time.Unix(1_700_000_000, 0))
	deps.registry.factors[factor.FactorOTPEmail] = otpEmailFactor()
	e := deps.engine(testState(t, time.Unix(1_700_000_000, 0)))

	got := e.Submit(context.Background(), "login", Request{Method: "otp_email", Step: "challenge"})
	if got.Status != captcha.StatusRequired {
		t.Fatalf("status = %q, want %q", got.Status, captcha.StatusRequired)
	}
	if got.Captcha == nil || got.Captcha.ProviderKey != "builtin_image" || got.Captcha.Type != "image" {
		t.Fatalf("captcha = %+v", got.Captcha)
	}

	bogus := captchaSubmission()
	bogus.ProviderKey = "other"
	got = e.Submit(context.Background(), "login", Request{Method: "otp_email", Step: "challenge", Captcha: bogus})
	if got.Status != captcha.StatusInvalid {
		t.Fatalf("status = %q, want %q", got.Status, captcha.StatusInvalid)
	}
}

func TestEnginePasswordCaptchaAfterFailures(t *testing.T) {
	deps := newTestDeps(t, time.Unix(1_700_000_000, 0))
	deps.failures = fakeFailures{n: 3}
	deps.registry.factors[factor.FactorPassword] = passwordFactor(7)
	e := deps.engine(testState(t, time.Unix(1_700_000_000, 0)))

	got := e.Submit(context.Background(), "login", Request{
		Method: "password", Step: "verify", Payload: &factor.Payload{Username: "u", Password: "p"},
	})
	if got.Status != captcha.StatusRequired {
		t.Fatalf("status = %q, want captcha_required after 3 failures", got.Status)
	}
}

func TestEngineMFACaptchaSuccess(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	state := testState(t, at)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorOTPEmail] = otpEmailFactor()
	deps.registry.factors[factor.FactorOTPSMS] = otpSMSFactor()
	deps.settings.slices[settings.KeySsoDomains] = []string{"a.example", "b.example"}

	phone := "13800138000"
	email := "alice@example.com"
	deps.users.user = &model.User{ID: 42, Phone: &phone, Email: &email, PhoneVerified: 1, EmailVerified: 1, MfaRequired: 1}
	deps.creds.creds["totp"] = &model.UserCredential{UserID: 42, Kind: "totp", IsEnabled: 1}

	e := deps.engine(state)

	// 第一步：challenge 下发验证码。
	resp := e.Submit(context.Background(), "login", Request{
		Method: "otp_email", Step: "challenge", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Email: email},
	})
	if resp.Status != StatusNext || resp.LoginToken == "" || resp.NextStep == nil {
		t.Fatalf("challenge resp = %+v", resp)
	}
	p, err := state.Parse(resp.LoginToken)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.GetFlow() != "login" || p.GetCh().GetPurpose() != "login" || p.GetCh().GetTarget() != email {
		t.Fatalf("challenge payload = %+v", p)
	}

	// 第二步：主因子通过 → 该用户启用 MFA → mfa_required。
	resp = e.Submit(context.Background(), "login", Request{
		LoginToken: resp.LoginToken, Method: "otp_email", Step: "verify",
		Payload: &factor.Payload{Email: email, Code: "123456"},
	})
	if resp.Status != StatusMFARequired || resp.Mfa == nil {
		t.Fatalf("mfa resp = %+v", resp)
	}
	if len(resp.Mfa.Methods) < 3 {
		t.Fatalf("mfa methods = %+v", resp.Mfa.Methods)
	}
	var masked string
	for _, m := range resp.Mfa.Methods {
		if m.Method == "otp_sms" {
			masked = m.MaskedTarget
		}
	}
	if masked != "138****8000" {
		t.Fatalf("masked_target = %q, want from uid binding", masked)
	}
	p, err = state.Parse(resp.LoginToken)
	if err != nil {
		t.Fatalf("Parse mfa token: %v", err)
	}
	if p.GetUid() != 42 || len(p.GetPassed()) != 1 || p.GetCh() != nil {
		t.Fatalf("mfa token = %+v", p)
	}

	// 第三步：二次因子 challenge。
	resp = e.Submit(context.Background(), "login", Request{
		LoginToken: resp.LoginToken, Method: "otp_sms", Step: "challenge", Captcha: captchaSubmission(),
	})
	if resp.Status != StatusNext {
		t.Fatalf("mfa challenge resp = %+v", resp)
	}
	p, err = state.Parse(resp.LoginToken)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.GetCh().GetPurpose() != "mfa" || p.GetCh().GetTarget() != "" {
		t.Fatalf("mfa challenge = %+v", p.Ch)
	}

	// 第四步：二次因子通过 → success。
	resp = e.Submit(context.Background(), "login", Request{
		LoginToken: resp.LoginToken, Method: "otp_sms", Step: "verify",
		Payload: &factor.Payload{Code: "123456"},
	})
	if resp.Status != StatusSuccess {
		t.Fatalf("success resp = %+v", resp)
	}
	if resp.SessionId != "sid-1" || resp.UserId != 42 || resp.RedirectTo != "" {
		t.Fatalf("success fields = %+v", resp)
	}
	if deps.sessions.calls != 1 {
		t.Fatalf("session writes = %d, want exactly 1", deps.sessions.calls)
	}
	if len(deps.events.got) != 1 || deps.events.got[0].UID != 42 {
		t.Fatalf("events = %+v", deps.events.got)
	}
	if resp.SyncCookieUrl != "https://sync.example/sso" {
		t.Fatalf("sync url = %q", resp.SyncCookieUrl)
	}
	if !strings.Contains(deps.sync.got, "al_session|stok-1|604800|a.example,b.example|") {
		t.Fatalf("sync builder args = %q", deps.sync.got)
	}
}

func TestEngineSuccessWithOIDCAndSessionBody(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorPassword] = passwordFactor(7)
	e := deps.engine(testState(t, at))

	oidc := &token.Oidc{
		ClientId:    "client-1",
		RedirectUri: "https://app.example/cb?from=sso",
		State:       "state-1",
	}
	resp := e.Submit(context.Background(), "login", Request{
		Method: "password", Step: "verify", OIDC: oidc, SessionInBody: true,
		Payload: &factor.Payload{Username: "alice", Password: "p"},
	})
	if resp.Status != StatusSuccess {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.LoginToken != "" {
		t.Fatalf("success must not return login_token, got %q", resp.LoginToken)
	}
	if resp.SessionToken != "stok-1" {
		t.Fatalf("session token = %q", resp.SessionToken)
	}
	u, err := url.Parse(resp.RedirectTo)
	if err != nil {
		t.Fatalf("redirect_to: %v", err)
	}
	if u.Query().Get("code") != "code-1" || u.Query().Get("state") != "state-1" || u.Query().Get("from") != "sso" {
		t.Fatalf("redirect_to = %q", resp.RedirectTo)
	}
	if deps.oidc.in.UID != 7 || deps.oidc.in.ClientID != "client-1" {
		t.Fatalf("oidc issue = %+v", deps.oidc.in)
	}
}

func TestEngineFlowMismatchAndSecondaryWithoutPrimary(t *testing.T) {
	deps := newTestDeps(t, time.Unix(1_700_000_000, 0))
	deps.registry.factors[factor.FactorOTPEmail] = otpEmailFactor()
	state := testState(t, time.Unix(1_700_000_000, 0))
	e := deps.engine(state)

	regTok, err := state.Issue(&token.LoginTokenPayload{Tid: "tid-1", Flow: "register"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got := e.Submit(context.Background(), "login", Request{LoginToken: regTok, Method: "otp_email", Step: "challenge"})
	if got.Status != StatusTokenInvalid {
		t.Fatalf("flow mismatch status = %q, want token_invalid", got.Status)
	}

	// register 端点接受 login flow（§7.4）。
	loginTok, err := state.Issue(&token.LoginTokenPayload{Tid: "tid-2", Flow: "login"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got = e.Submit(context.Background(), "register", Request{LoginToken: loginTok, Method: "otp_email", Step: "challenge", Captcha: captchaSubmission()})
	if got.Status != StatusNext {
		t.Fatalf("register accepting login flow status = %q, want next", got.Status)
	}
}

func TestEngineTOTPSecondaryNotGatedByLoginMethods(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	state := testState(t, at)
	deps := newTestDeps(t, at)
	// totp 不在 login_methods（默认就不含），但作为二次因子应可用。
	deps.registry.factors[factor.FactorTOTP] = totpFactor()
	deps.users.user = &model.User{ID: 42, MfaRequired: 1}
	deps.creds.creds["totp"] = &model.UserCredential{UserID: 42, Kind: "totp", IsEnabled: 1}
	e := deps.engine(state)

	tok, err := state.Issue(&token.LoginTokenPayload{
		Tid: "tid-1", Flow: "login", Uid: 42, Passed: []string{"otp_email"}, Amr: []string{"otp_email"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	resp := e.Submit(context.Background(), "login", Request{
		LoginToken: tok, Method: "totp", Step: "verify", Payload: &factor.Payload{Code: "123456"},
	})
	if resp.Status != StatusSuccess {
		t.Fatalf("totp secondary resp = %+v, want success", resp)
	}
	if deps.sessions.calls != 1 {
		t.Fatalf("session writes = %d", deps.sessions.calls)
	}
}

func TestEngineStartStatusSkipsToken(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorOTPEmail] = &fakeFactor{
		kind:   factor.FactorOTPEmail,
		usages: []factor.Usage{factor.UsagePrimary},
		steps:  []factor.StepKind{factor.StepChallenge, factor.StepForm},
		start: func(*factor.FactorContext) (*factor.StepResult, error) {
			return &factor.StepResult{Status: "too_many_requests", RetryAfter: 60}, nil
		},
	}
	e := deps.engine(testState(t, at))

	resp := e.Submit(context.Background(), "login", Request{
		Method: "otp_email", Step: "challenge", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Email: "missing@example.com"},
	})
	if resp.Status != "too_many_requests" {
		t.Fatalf("status = %q, want too_many_requests", resp.Status)
	}
	if resp.LoginToken != "" {
		t.Fatalf("status terminal must not issue login_token, got %q", resp.LoginToken)
	}
	if resp.NextStep != nil {
		t.Fatalf("status terminal must not carry next_step")
	}
	// 重试建议回填信封 error.retryAfter（接口文档 §1.6 行 242）。
	if resp.Error == nil || resp.Error.RetryAfter == nil || *resp.Error.RetryAfter != 60 {
		t.Fatalf("error = %+v, want retryAfter 60", resp.Error)
	}
}

// TestEngineFirstChallengeExposesTidFlow 首步 challenge 在因子 Start 前就必须
// 拿到已生成的 tid 与选定 flow（否则主因子验证码无法按 §10.1 行 1121 绑定写码）。
func TestEngineFirstChallengeExposesTidFlow(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	var seen *token.LoginTokenPayload
	deps.registry.factors[factor.FactorOTPEmail] = &fakeFactor{
		kind:   factor.FactorOTPEmail,
		usages: []factor.Usage{factor.UsagePrimary},
		steps:  []factor.StepKind{factor.StepChallenge, factor.StepForm},
		start: func(fctx *factor.FactorContext) (*factor.StepResult, error) {
			seen = fctx.Login
			return &factor.StepResult{Kind: factor.StepForm, Method: factor.FactorOTPEmail}, nil
		},
	}
	state := testState(t, at)
	e := deps.engine(state)

	resp := e.Submit(context.Background(), "login", Request{
		Method: "otp_email", Step: "challenge", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Email: "alice@example.com"},
	})
	if resp.Status != StatusNext || resp.LoginToken == "" {
		t.Fatalf("resp = %+v, want next with login_token", resp)
	}
	if seen == nil || seen.GetTid() == "" || seen.GetFlow() != "login" {
		t.Fatalf("factor Login = %+v, want tid/flow available before Start", seen)
	}
	issued, err := state.Parse(resp.LoginToken)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if issued.GetTid() != seen.GetTid() {
		t.Fatalf("issued tid = %q, factor tid = %q, want same", issued.GetTid(), seen.GetTid())
	}
}

func TestEngineWebAuthnChallengeSkipsCaptcha(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorWebAuthn] = &fakeFactor{
		kind:   factor.FactorWebAuthn,
		usages: []factor.Usage{factor.UsagePrimary, factor.UsageSecondary},
		steps:  []factor.StepKind{factor.StepChallenge, factor.StepForm},
	}
	e := deps.engine(testState(t, at))

	resp := e.Submit(context.Background(), "login", Request{Method: "webauthn", Step: "challenge"})
	if resp.Status != StatusNext || resp.LoginToken == "" {
		t.Fatalf("webauthn options resp = %+v, want next", resp)
	}
	if deps.verifier.calls != 0 {
		t.Fatalf("captcha verifier calls = %d, want 0 for webauthn options", deps.verifier.calls)
	}
}

func TestEngineMethodFallbackFromLoginToken(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	state := testState(t, at)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorOTPEmail] = otpEmailFactor()
	deps.users.user = &model.User{ID: 42}
	e := deps.engine(state)

	tok, err := state.Issue(&token.LoginTokenPayload{Tid: "tid-1", Flow: "login", Factor: "otp_email"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	resp := e.Submit(context.Background(), "login", Request{
		LoginToken: tok, Step: "verify", Payload: &factor.Payload{Code: "123456"},
	})
	if resp.Status != StatusSuccess {
		t.Fatalf("method fallback resp = %+v, want success", resp)
	}

	// method 与 login_token.factor 都为空才拒（§2.2 行 421）。
	noFactor, err := state.Issue(&token.LoginTokenPayload{Tid: "tid-2", Flow: "login"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	resp = e.Submit(context.Background(), "login", Request{LoginToken: noFactor, Step: "verify"})
	if resp.Status != StatusInvalidRequest {
		t.Fatalf("empty method+factor status = %q, want invalid_request", resp.Status)
	}
}

func TestBindingOverwritesThirdParty(t *testing.T) {
	p := &token.LoginTokenPayload{}
	SetThirdParty(p, &token.ThirdParty{ProviderKey: "qq", OpenId: "open-1", UnionId: "union-1", Nickname: "n1", AvatarUrl: "a1"})
	SetThirdParty(p, &token.ThirdParty{ProviderKey: "wechat", OpenId: "open-2", UnionId: "union-2", Nickname: "n2", AvatarUrl: "a2"})
	if p.Tp.ProviderKey != "wechat" || p.Tp.OpenId != "open-2" || p.Tp.UnionId != "union-2" || p.Tp.Nickname != "n2" {
		t.Fatalf("tp not overwritten: %+v", p.Tp)
	}

	b := BindingEnvelope(p, "微信", true)
	if b.ProviderKey != "wechat" || b.DisplayName != "微信" || !b.AllowSignup || b.Nickname != "n2" || b.AvatarUrl != "a2" {
		t.Fatalf("binding = %+v", b)
	}
}

func TestMfaOnlyFromBoundProfile(t *testing.T) {
	phone := "13900001111"
	user := &model.User{ID: 9, Phone: &phone, PhoneVerified: 1, EmailVerified: 0, MfaRequired: 1}
	creds := &fakeCredentials{creds: map[string]*model.UserCredential{
		"totp": {UserID: 9, Kind: "totp", IsEnabled: 1},
	}}
	s := &testSettings{slices: map[string][]string{settings.KeyMfaMethods: {"totp", "otp_sms", "otp_email", "webauthn"}}}
	b := NewMFABuilder(&fakeUsers{user: user}, creds, s)

	mfa, required, err := b.Build(context.Background(), 9)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !required || mfa == nil {
		t.Fatal("mfa should be required for mfa_required=1 user with enabled creds")
	}
	var otp *ssov1.MfaMethod
	for _, m := range mfa.Methods {
		if m.Method == "otp_sms" {
			otp = m
		}
	}
	if otp == nil || otp.MaskedTarget != "139****1111" {
		t.Fatalf("otp_sms method = %+v", otp)
	}
	for _, m := range mfa.Methods {
		if m.Method == "otp_email" {
			t.Fatal("unverified email must not be offered as MFA target")
		}
	}
}
