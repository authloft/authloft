package verification

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"authloft/internal/captcha"
	"authloft/internal/settings"
)

// startSettings Settings 的 fake：map 引用语义，持有句柄可热改值。
type startSettings struct{ m map[string]int64 }

func (s *startSettings) GetInt64(key string) (int64, bool) {
	v, ok := s.m[key]
	return v, ok
}

// startGate CaptchaGate 的 fake：回放一次判定结论，并记录调用次数与场景。
type startGate struct {
	outcome captcha.Outcome
	err     error
	calls   int
	scene   string
}

func (g *startGate) Evaluate(_ context.Context, req captcha.Request) (captcha.Outcome, error) {
	g.calls++
	g.scene = req.Scene
	return g.outcome, g.err
}

// passGate 放行全部场景的守卫 fake（不参与场景判定的用例使用）。
func passGate() *startGate { return &startGate{} }

// startBound BoundFactorReader 的 fake：factors 为 nil 表示不限制（返回候选全量）。
type startBound struct {
	factors []string
	err     error
	got     Subject
}

func (b *startBound) Bound(_ context.Context, subject Subject, candidates []string) ([]string, error) {
	b.got = subject
	if b.err != nil {
		return nil, b.err
	}
	if b.factors == nil {
		return candidates, nil
	}
	return b.factors, nil
}

// startLoginTokens LoginTokenReader 的 fake。
type startLoginTokens struct {
	uid    int64
	passed bool
	err    error
	got    string
}

func (l *startLoginTokens) Read(_ context.Context, tok string) (int64, bool, error) {
	l.got = tok
	return l.uid, l.passed, l.err
}

// startStarter FactorStarter 的 fake：记录入参并回放结论。
type startStarter struct {
	res   FactorStartResult
	err   error
	got   FactorStartInput
	calls int
}

func (s *startStarter) Start(_ context.Context, in FactorStartInput) (FactorStartResult, error) {
	s.calls++
	s.got = in
	return s.res, s.err
}

func newStartService(t *testing.T, configure func(*Deps)) (*Service, *AssertionCodec) {
	t.Helper()
	codec, _, _ := fixedCodec(t, time.Unix(1_700_000_000, 0))
	d := Deps{Codec: codec}
	if configure != nil {
		configure(&d)
	}
	return NewService(d), codec
}

func errorCode(t *testing.T, err error) string {
	t.Helper()
	var ve *Error
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want *verification.Error", err)
	}
	return ve.Code
}

func TestStartRejectsInvalidPurposeOrOperation(t *testing.T) {
	svc, _ := newStartService(t, nil)
	base := StartInput{Domain: DomainAccount, SessionUID: "42", Operation: "step_up"}

	badPurpose := base
	badPurpose.BizPurpose = BizPurpose("bogus")
	if _, _, err := svc.Start(context.Background(), badPurpose); errorCode(t, err) != "invalid_request" {
		t.Fatalf("表外 biz_purpose 应拒绝，code = %s", errorCode(t, err))
	}

	noOperation := base
	noOperation.BizPurpose = BizPurposeMFA
	noOperation.Operation = ""
	if _, _, err := svc.Start(context.Background(), noOperation); errorCode(t, err) != "invalid_request" {
		t.Fatalf("缺 operation 应拒绝，code = %s", errorCode(t, err))
	}
}

func TestStartEnforcesDomainPurpose(t *testing.T) {
	svc, _ := newStartService(t, nil)
	cases := []struct {
		name string
		in   StartInput
	}{
		{"SSO 只接受 login", StartInput{Domain: DomainSSO, BizPurpose: BizPurposeMFA, Operation: "mfa_verify", SessionUID: "42"}},
		{"Account 拒绝 login", StartInput{Domain: DomainAccount, BizPurpose: BizPurposeLogin, Operation: "mfa_verify", SessionUID: "42"}},
		{"Account 拒绝 webauthn_enroll", StartInput{Domain: DomainAccount, BizPurpose: BizPurposeWebAuthnEnroll, Operation: "webauthn_register", SessionUID: "42"}},
		{"未知域", StartInput{Domain: "admin", BizPurpose: BizPurposeMFA, Operation: "step_up", SessionUID: "42"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := svc.Start(context.Background(), tc.in); errorCode(t, err) != "invalid_request" {
				t.Fatalf("code = %s, want invalid_request", errorCode(t, err))
			}
		})
	}
}

func TestStartSSOLoginSubject(t *testing.T) {
	tokens := &startLoginTokens{uid: 42, passed: true}
	svc, codec := newStartService(t, func(d *Deps) {
		d.LoginTokens = tokens
		d.Gate = passGate()
	})

	// method 为空：只返回 methods[]，不签发挑战令牌（§10.2 步骤 5）。
	res, failure, err := svc.Start(context.Background(), StartInput{
		Domain: DomainSSO, BizPurpose: BizPurposeLogin, Operation: "mfa_verify", LoginToken: "lt-1",
	})
	if err != nil || failure != nil {
		t.Fatalf("Start err=%v failure=%+v", err, failure)
	}
	if tokens.got != "lt-1" {
		t.Fatalf("loginToken 透传 = %q", tokens.got)
	}
	if res.ChallengeToken != "" {
		t.Fatalf("method 为空不应签发 challengeToken，got %q", res.ChallengeToken)
	}
	if len(res.Methods) != len(stepUpFactors) || res.ExpiresIn != 300 || res.NextStepKind != "" {
		t.Fatalf("res = %+v", res)
	}

	// 选定因子：签发挑战令牌，主体取自 loginToken 的 uid。
	res, _, err = svc.Start(context.Background(), StartInput{
		Domain: DomainSSO, BizPurpose: BizPurposeLogin, Method: "totp", Operation: "mfa_verify", LoginToken: "lt-1",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	ch, err := codec.ParseChallenge(res.ChallengeToken)
	if err != nil {
		t.Fatalf("ParseChallenge: %v", err)
	}
	if ch.BizPurpose != BizPurposeLogin || ch.Subject != (Subject{Kind: SubjectKindUID, ID: "42"}) ||
		ch.Operation != "mfa_verify" || ch.Nonce == "" {
		t.Fatalf("challenge = %+v", ch)
	}
	if res.NextStepKind != "form" {
		t.Fatalf("nextStep.kind = %q, want form", res.NextStepKind)
	}
}

func TestStartSSOLoginRequiresPassedPrimary(t *testing.T) {
	cases := []struct {
		name   string
		tokens *startLoginTokens
		code   string
	}{
		{"未过主因子", &startLoginTokens{uid: 42, passed: false}, "token_invalid"},
		{"uid 缺失", &startLoginTokens{uid: 0, passed: true}, "token_invalid"},
		{"解令牌失败", &startLoginTokens{err: errors.New("bad token")}, "token_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newStartService(t, func(d *Deps) { d.LoginTokens = tc.tokens })
			_, _, err := svc.Start(context.Background(), StartInput{
				Domain: DomainSSO, BizPurpose: BizPurposeLogin, Operation: "mfa_verify", LoginToken: "lt-1",
			})
			if got := errorCode(t, err); got != tc.code {
				t.Fatalf("code = %s, want %s", got, tc.code)
			}
		})
	}

	// 无 loginToken：拒绝匿名裸调（§3.8.1）。
	svc, _ := newStartService(t, nil)
	if _, _, err := svc.Start(context.Background(), StartInput{
		Domain: DomainSSO, BizPurpose: BizPurposeLogin, Operation: "mfa_verify",
	}); errorCode(t, err) != "invalid_request" {
		t.Fatalf("code = %s, want invalid_request", errorCode(t, err))
	}
}

func TestStartMethodEmptySkipsStarter(t *testing.T) {
	starter := &startStarter{}
	gate := passGate()
	svc, _ := newStartService(t, func(d *Deps) {
		d.Starter = starter
		d.Gate = gate
	})
	res, _, err := svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Operation: "step_up", SessionUID: "42",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.ChallengeToken != "" || starter.calls != 0 {
		t.Fatalf("method 为空不应下发：token=%q starter.calls=%d", res.ChallengeToken, starter.calls)
	}
}

func TestStartMethodSelectionUsesStarterNonceAndData(t *testing.T) {
	data, err := structpb.NewStruct(map[string]any{"challenge": "from-factor"})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	starter := &startStarter{res: FactorStartResult{Nonce: "challenge-from-factor", Kind: "form", ChallengeData: data}}
	bound := &startBound{factors: []string{"webauthn"}}
	svc, codec := newStartService(t, func(d *Deps) {
		d.Starter = starter
		d.Bound = bound
		d.Gate = passGate()
	})

	res, _, err := svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Method: "webauthn", Operation: "step_up", SessionUID: "42",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if starter.calls != 1 || starter.got.Method != "webauthn" ||
		starter.got.BizPurpose != BizPurposeMFA ||
		starter.got.Subject != (Subject{Kind: SubjectKindUID, ID: "42"}) ||
		starter.got.Nonce == "" {
		t.Fatalf("starter 入参 = %+v", starter.got)
	}
	ch, err := codec.ParseChallenge(res.ChallengeToken)
	if err != nil {
		t.Fatalf("ParseChallenge: %v", err)
	}
	if ch.Nonce != "challenge-from-factor" {
		t.Fatalf("challenge nonce = %q, want factor 生成值（options.challenge 同源）", ch.Nonce)
	}
	if res.NextStepKind != "form" || res.ChallengeData == nil ||
		res.ChallengeData.GetFields()["challenge"].GetStringValue() != "from-factor" {
		t.Fatalf("nextStep = %q challengeData = %v", res.NextStepKind, res.ChallengeData)
	}
}

func TestStartMethodUnavailable(t *testing.T) {
	bound := &startBound{factors: []string{"totp"}}
	svc, _ := newStartService(t, func(d *Deps) { d.Bound = bound })
	_, _, err := svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Method: "otp_sms", Operation: "step_up", SessionUID: "42",
	})
	if got := errorCode(t, err); got != "invalid_request" {
		t.Fatalf("code = %s, want invalid_request", got)
	}
}

func TestStartMethodDisabledWhenNoBoundFactor(t *testing.T) {
	bound := &startBound{factors: []string{}}
	svc, _ := newStartService(t, func(d *Deps) { d.Bound = bound })
	_, _, err := svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Operation: "step_up", SessionUID: "42",
	})
	if got := errorCode(t, err); got != "method_disabled" {
		t.Fatalf("code = %s, want method_disabled", got)
	}
}

func TestStartStarterFailureCode(t *testing.T) {
	starter := &startStarter{res: FactorStartResult{Code: "too_many_requests", RetryAfter: 42}}
	svc, _ := newStartService(t, func(d *Deps) {
		d.Starter = starter
		d.Gate = &startGate{}
	})
	_, _, err := svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Method: "otp_sms", Operation: "step_up", SessionUID: "42",
	})
	if got := errorCode(t, err); got != "too_many_requests" {
		t.Fatalf("code = %s, want too_many_requests", got)
	}
	var ve *Error
	if !errors.As(err, &ve) || ve.RetryAfter != 42 {
		t.Fatalf("RetryAfter = %+v, want 42", ve)
	}
}

func TestStartCaptchaFailureSurfacesConfig(t *testing.T) {
	cfg := captcha.Config{ProviderKey: "cf_turnstile", Type: "turnstile", SiteKey: "0xSITE"}
	gate := &startGate{outcome: captcha.Outcome{Required: true, Status: captcha.StatusRequired, Config: cfg}}
	svc, _ := newStartService(t, func(d *Deps) { d.Gate = gate })

	res, failure, err := svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Method: "otp_sms", Operation: "step_up", SessionUID: "42",
	})
	if err != nil || res != nil {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if failure == nil || failure.Code != captcha.StatusRequired || failure.Config != cfg {
		t.Fatalf("failure = %+v, want %s + 当前生效配置", failure, captcha.StatusRequired)
	}
	if gate.calls != 1 {
		t.Fatalf("gate.calls = %d, want 1", gate.calls)
	}

	invalid := &startGate{outcome: captcha.Outcome{Required: true, Status: captcha.StatusInvalid, Config: cfg}}
	svc, _ = newStartService(t, func(d *Deps) { d.Gate = invalid })
	if _, failure, _ := svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Method: "otp_email", Operation: "step_up", SessionUID: "42",
	}); failure == nil || failure.Code != captcha.StatusInvalid {
		t.Fatalf("failure = %+v, want %s", failure, captcha.StatusInvalid)
	}

	gateErr := &startGate{err: errors.New("gate down")}
	svc, _ = newStartService(t, func(d *Deps) { d.Gate = gateErr })
	if _, _, err := svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Method: "otp_sms", Operation: "step_up", SessionUID: "42",
	}); err == nil {
		t.Fatal("gate 基础设施错误必须上抛，不得静默放行")
	}
}

func TestStartUsesNoDispatchSceneForNonOtpMethods(t *testing.T) {
	gate := passGate()
	svc, _ := newStartService(t, func(d *Deps) { d.Gate = gate })
	if _, failure, err := svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Operation: "step_up", SessionUID: "42",
	}); err != nil || failure != nil {
		t.Fatalf("err=%v failure=%+v", err, failure)
	}
	if gate.scene != captcha.SceneNoDispatch {
		t.Fatalf("未选因子应给出无下发场景，scene = %q", gate.scene)
	}
}

func TestMethodViewCapabilities(t *testing.T) {
	svc, _ := newStartService(t, nil)
	views := map[string]MethodView{}
	for _, m := range stepUpFactors {
		views[m] = svc.methodView(m)
	}
	otp := views["otp_email"]
	if otp.CodeLength != 6 || otp.ResendAfter != 60 || otp.ExpiresIn != 300 ||
		len(otp.Steps) != 2 || otp.Steps[0] != "challenge" || otp.Steps[1] != "form" {
		t.Fatalf("otp_email view = %+v", otp)
	}
	if w := views["webauthn"]; w.Capability != "window.PublicKeyCredential" || len(w.Steps) != 2 {
		t.Fatalf("webauthn view = %+v", w)
	}
	if tp := views["totp"]; len(tp.Usage) != 1 || tp.Usage[0] != "secondary" {
		t.Fatalf("totp view = %+v", tp)
	}
}

// TestStartReadsOtpSettingsPerRequest 可证伪：挑战有效期 / 响应 expiresIn /
// OTP 方法视图的 resendAfter 与 expiresIn 均取现行 settings（§1.10.2、
// §3.8.2、§5.6 表三），改设置后后续请求跟着变；挑战令牌的 exp 同步为
// otp_ttl（§11.6.7）。返回值若仍写死 300 / 60，本用例立即失败。
func TestStartReadsOtpSettingsPerRequest(t *testing.T) {
	st := &startSettings{m: map[string]int64{
		settings.KeyOtpTtl:            600,
		settings.KeyOtpResendInterval: 90,
	}}
	gate := &startGate{}
	svc, codec := newStartService(t, func(d *Deps) {
		d.Settings = st
		d.Gate = gate
	})

	// method 为空：只回因子视图，expiresIn 同样取 otp_ttl。
	res, _, err := svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Operation: "step_up", SessionUID: "42",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.ExpiresIn != 600 {
		t.Fatalf("expiresIn = %d, want 600（跟随 otp_ttl）", res.ExpiresIn)
	}
	otpView := findMethod(t, res.Methods, "otp_sms")
	if otpView.ExpiresIn != 600 || otpView.ResendAfter != 90 {
		t.Fatalf("otp_sms view = %+v, want expiresIn=600 resendAfter=90", otpView)
	}

	// 选定 OTP 因子：响应 expiresIn 与挑战令牌 exp 同步为 600s。
	res, _, err = svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Method: "otp_sms", Operation: "step_up",
		SessionUID: "42", Captcha: &captcha.Submission{ProviderKey: "cf_turnstile", Token: "tok"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.ExpiresIn != 600 {
		t.Fatalf("expiresIn = %d, want 600", res.ExpiresIn)
	}
	base := time.Unix(1_700_000_000, 0)
	codec.now = func() time.Time { return base.Add(599 * time.Second) }
	if _, err := codec.ParseChallenge(res.ChallengeToken); err != nil {
		t.Fatalf("599s 时挑战令牌仍应有效（TTL 跟随 otp_ttl=600）: %v", err)
	}
	codec.now = func() time.Time { return base.Add(601 * time.Second) }
	if _, err := codec.ParseChallenge(res.ChallengeToken); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("601s 后应过期, err = %v", err)
	}

	// 热更新：改设置后下一次请求立即跟随。
	st.m[settings.KeyOtpTtl] = 420
	st.m[settings.KeyOtpResendInterval] = 30
	res, _, err = svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Operation: "step_up", SessionUID: "42",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if res.ExpiresIn != 420 || findMethod(t, res.Methods, "otp_email").ResendAfter != 30 {
		t.Fatalf("热更新未生效: expiresIn=%d view=%+v", res.ExpiresIn, findMethod(t, res.Methods, "otp_email"))
	}
}

// findMethod 取方法视图；缺失即失败。
func findMethod(t *testing.T, views []MethodView, method string) MethodView {
	t.Helper()
	for _, v := range views {
		if v.Method == method {
			return v
		}
	}
	t.Fatalf("methods 缺少 %s: %+v", method, views)
	return MethodView{}
}

// TestStartCaptchaSceneTable 可证伪（§2.5 触发表 / §9.3）：调用方只按所选因子
// 给出场景——OTP 类是一次性验证码下发，WebAuthn 只是取 options，TOTP 取挑战与
// 恢复码本环节无下发。若仍按「选定任意因子即强制」判定，场景断言立即失败。
func TestStartCaptchaSceneTable(t *testing.T) {
	cases := []struct {
		method string
		scene  string
	}{
		{"otp_sms", captcha.SceneOtpDispatch},
		{"otp_email", captcha.SceneOtpDispatch},
		{"webauthn", captcha.SceneWebAuthnOptions},
		{"totp", captcha.SceneNoDispatch},
		{"recovery_code", captcha.SceneNoDispatch},
		{"", captcha.SceneNoDispatch},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			gate := passGate()
			svc, _ := newStartService(t, func(d *Deps) { d.Gate = gate })
			if _, _, err := svc.Start(context.Background(), StartInput{
				Domain: DomainAccount, BizPurpose: BizPurposeMFA, Method: tc.method, Operation: "step_up", SessionUID: "42",
			}); err != nil {
				t.Fatalf("Start: %v", err)
			}
			if gate.calls != 1 || gate.scene != tc.scene {
				t.Fatalf("gate calls=%d scene=%q, want 1 / %q", gate.calls, gate.scene, tc.scene)
			}
		})
	}
}

// TestStartCaptchaRealGateOnlyOtpRequired 真实 Gate 下的行为等价：仅 OTP 下发
// 拦截，WebAuthn 取 options、TOTP 取挑战、恢复码继续放行（§2.5 触发表）。
func TestStartCaptchaRealGateOnlyOtpRequired(t *testing.T) {
	cases := []struct {
		method  string
		blocked bool
	}{
		{"otp_sms", true},
		{"otp_email", true},
		{"webauthn", false},
		{"totp", false},
		{"recovery_code", false},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			svc, _ := newStartService(t, func(d *Deps) { d.Gate = captcha.NewGate(nil, nil, nil) })
			_, failure, err := svc.Start(context.Background(), StartInput{
				Domain: DomainAccount, BizPurpose: BizPurposeMFA, Method: tc.method, Operation: "step_up", SessionUID: "42",
			})
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			if tc.blocked {
				if failure == nil || failure.Code != captcha.StatusRequired {
					t.Fatalf("failure = %+v, want %s", failure, captcha.StatusRequired)
				}
				return
			}
			if failure != nil {
				t.Fatalf("failure = %+v, want 放行", failure)
			}
		})
	}
}

// TestStartCaptchaGateMissingFailsClosed 可证伪：OTP 下发场景未注入守卫时
// 显式报错，不得静默放行（§2.5「任何一次性验证码下发 必须」）。
func TestStartCaptchaGateMissingFailsClosed(t *testing.T) {
	svc, _ := newStartService(t, nil)
	if _, _, err := svc.Start(context.Background(), StartInput{
		Domain: DomainAccount, BizPurpose: BizPurposeMFA, Method: "otp_sms", Operation: "step_up", SessionUID: "42",
	}); err == nil {
		t.Fatal("OTP 下发场景缺 guard 应显式失败，不得静默放行")
	}
}
