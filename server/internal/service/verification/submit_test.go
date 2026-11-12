package verification

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

// submitVerifier FactorVerifier 的 fake：记录入参并回放结论。
type submitVerifier struct {
	res   FactorVerifyResult
	err   error
	got   FactorVerifyInput
	calls int
}

func (v *submitVerifier) Verify(_ context.Context, in FactorVerifyInput) (FactorVerifyResult, error) {
	v.calls++
	v.got = in
	return v.res, v.err
}

// replayOnce OnceStore 的 fake：按 result 回放 SET NX 结论并记录键。
type replayOnce struct {
	result bool
	err    error
	keys   []string
	ttls   []time.Duration
}

func (o *replayOnce) SetNX(_ context.Context, key string, _ interface{}, ttl time.Duration) (bool, error) {
	o.keys = append(o.keys, key)
	o.ttls = append(o.ttls, ttl)
	if o.err != nil {
		return false, o.err
	}
	if len(o.keys) > 1 {
		return false, nil
	}
	return o.result, nil
}

// loginSessions LoginCompleter 的 fake：记录终点收尾入参并回放会话结论。
type loginSessions struct {
	session    LoginSession
	err        error
	subject    Subject
	loginToken string
	method     string
	calls      int
}

func (c *loginSessions) Complete(_ context.Context, subject Subject, loginToken, method string) (LoginSession, error) {
	c.calls++
	c.subject, c.loginToken, c.method = subject, loginToken, method
	return c.session, c.err
}

func newSubmitService(t *testing.T, configure func(*Deps)) (*Service, *AssertionCodec) {
	t.Helper()
	codec, _, _ := fixedCodec(t, time.Unix(1_700_000_000, 0))
	d := Deps{Codec: codec}
	if configure != nil {
		configure(&d)
	}
	return NewService(d), codec
}

func mustPayload(t *testing.T, code string) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(map[string]any{"code": code})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}
	return s
}

func TestSubmitAccountIssuesAssertion(t *testing.T) {
	verifier := &submitVerifier{res: FactorVerifyResult{Passed: true}}
	svc, codec := newSubmitService(t, func(d *Deps) { d.Verifier = verifier })
	chTok, err := codec.IssueChallenge(Challenge{
		BizPurpose: BizPurposeUnbindTOTP,
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce:      "nonce-1",
		Operation:  "unbind_totp",
		Methods:    []string{"totp", "otp_sms"},
	}, ChallengeTTL)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	res, err := svc.Submit(context.Background(), SubmitInput{
		Domain: DomainAccount, ChallengeToken: chTok, Method: "totp", Payload: mustPayload(t, "123456"),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Status != "" || res.ExpiresIn != 120 || len(res.AMR) != 1 || res.AMR[0] != "totp" {
		t.Fatalf("res = %+v", res)
	}
	a, err := codec.ParseAssertion(res.VerificationToken)
	if err != nil {
		t.Fatalf("ParseAssertion: %v", err)
	}
	if a.BizPurpose != BizPurposeUnbindTOTP || a.Subject != (Subject{Kind: SubjectKindUID, ID: "42"}) ||
		a.Nonce != "nonce-1" || a.Operation != "unbind_totp" ||
		len(a.AMR) != 1 || a.AMR[0] != "totp" {
		t.Fatalf("assertion = %+v", a)
	}
	if verifier.calls != 1 || verifier.got.Method != "totp" || verifier.got.ChallengeID != "nonce-1" {
		t.Fatalf("verifier 入参 = %+v", verifier.got)
	}
}

func TestSubmitSSOReturnsFlowStatus(t *testing.T) {
	verifier := &submitVerifier{res: FactorVerifyResult{Passed: true}}
	login := &loginSessions{session: LoginSession{RedirectTo: "https://rp.example/cb", SyncCookieURL: "https://sync.example"}}
	svc, codec := newSubmitService(t, func(d *Deps) { d.Verifier = verifier; d.Login = login })
	chTok, err := codec.IssueChallenge(Challenge{
		BizPurpose: BizPurposeLogin,
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce:      "nonce-2",
		Operation:  "mfa_verify",
		Methods:    []string{"totp"},
	}, ChallengeTTL)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	res, err := svc.Submit(context.Background(), SubmitInput{
		Domain: DomainSSO, ChallengeToken: chTok, Method: "totp", Payload: mustPayload(t, "123456"), LoginToken: "lt-1",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Status != "success" || len(res.AMR) != 1 || res.AMR[0] != "totp" {
		t.Fatalf("res = %+v", res)
	}
	if res.RedirectTo != "https://rp.example/cb" || res.SyncCookieURL != "https://sync.example" {
		t.Fatalf("终点字段 = %+v, want 注入的 redirect / syncCookieUrl", res)
	}
	if login.calls != 1 || login.subject != (Subject{Kind: SubjectKindUID, ID: "42"}) ||
		login.loginToken != "lt-1" || login.method != "totp" {
		t.Fatalf("终点收尾入参 = %+v", login)
	}
}

// TestSubmitSSOLoginContextMismatch：loginToken 解析失败 / uid 与挑战 subject
// 不一致由收尾适配器以 ErrLoginContext 返回，服务层映射 verification_invalid
// （§3.8.5），不静默降级、不建会话。
func TestSubmitSSOLoginContextMismatch(t *testing.T) {
	verifier := &submitVerifier{res: FactorVerifyResult{Passed: true}}
	login := &loginSessions{err: fmt.Errorf("%w: uid mismatch", ErrLoginContext)}
	svc, codec := newSubmitService(t, func(d *Deps) { d.Verifier = verifier; d.Login = login })
	chTok, err := codec.IssueChallenge(Challenge{
		BizPurpose: BizPurposeLogin,
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce:      "nonce-ctx",
		Operation:  "mfa_verify",
		Methods:    []string{"totp"},
	}, ChallengeTTL)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	_, err = svc.Submit(context.Background(), SubmitInput{
		Domain: DomainSSO, ChallengeToken: chTok, Method: "totp", LoginToken: "lt-other",
	})
	if errorCode(t, err) != "verification_invalid" {
		t.Fatalf("code = %s, want verification_invalid", errorCode(t, err))
	}
}

// TestSubmitAccountRejectsLoginToken：loginToken 仅 SsoService 组可携带
// （§3.8.2、§3.8.5）。
func TestSubmitAccountRejectsLoginToken(t *testing.T) {
	verifier := &submitVerifier{res: FactorVerifyResult{Passed: true}}
	login := &loginSessions{}
	svc, codec := newSubmitService(t, func(d *Deps) { d.Verifier = verifier; d.Login = login })
	chTok, err := codec.IssueChallenge(Challenge{
		BizPurpose: BizPurposeUnbindTOTP,
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce:      "nonce-account",
		Operation:  "unbind_totp",
		Methods:    []string{"totp"},
	}, ChallengeTTL)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	_, err = svc.Submit(context.Background(), SubmitInput{
		Domain: DomainAccount, ChallengeToken: chTok, Method: "totp", LoginToken: "lt-1",
	})
	if errorCode(t, err) != "invalid_request" {
		t.Fatalf("code = %s, want invalid_request", errorCode(t, err))
	}
	if verifier.calls != 0 || login.calls != 0 {
		t.Fatalf("拒绝应早于因子校验与收尾: verifier=%d login=%d", verifier.calls, login.calls)
	}
}

// TestSubmitSSOScanSkipsSession：扫码挑战（票据标识绑定在 nonce）由票据链路
// 收尾，Submit 不建会话，回传 ticketID 供调用方写终态 TicketResult。
func TestSubmitSSOScanSkipsSession(t *testing.T) {
	verifier := &submitVerifier{res: FactorVerifyResult{Passed: true}}
	login := &loginSessions{}
	svc, codec := newSubmitService(t, func(d *Deps) { d.Verifier = verifier; d.Login = login })
	chTok, err := codec.IssueChallenge(Challenge{
		BizPurpose: BizPurposeLogin,
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce:      scanNonce("ticket-1", "nonce-scan"),
		Operation:  "mfa_verify",
		Methods:    []string{"totp"},
	}, ChallengeTTL)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	res, err := svc.Submit(context.Background(), SubmitInput{
		Domain: DomainSSO, ChallengeToken: chTok, Method: "totp",
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if res.Status != "success" || login.calls != 0 || res.RedirectTo != "" || res.SyncCookieURL != "" {
		t.Fatalf("res = %+v login.calls = %d", res, login.calls)
	}
	if res.TicketID != "ticket-1" {
		t.Fatalf("TicketID = %q, want ticket-1", res.TicketID)
	}
	// 剥离票据前缀后交给因子校验，保证 owner / challenge 与下发阶段同源。
	if verifier.got.ChallengeID != "nonce-scan" {
		t.Fatalf("ChallengeID = %q, want nonce-scan", verifier.got.ChallengeID)
	}
}

func TestSubmitRejectsCrossDomainChallenge(t *testing.T) {
	verifier := &submitVerifier{res: FactorVerifyResult{Passed: true}}
	svc, codec := newSubmitService(t, func(d *Deps) { d.Verifier = verifier })

	loginTok, _ := codec.IssueChallenge(Challenge{
		BizPurpose: BizPurposeLogin, Subject: Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce: "n-login", Operation: "mfa_verify", Methods: []string{"totp"},
	}, ChallengeTTL)
	if _, err := svc.Submit(context.Background(), SubmitInput{
		Domain: DomainAccount, ChallengeToken: loginTok, Method: "totp",
	}); errorCode(t, err) != "verification_invalid" {
		t.Fatalf("login 挑战用于 account 域应拒绝，code = %s", errorCode(t, err))
	}

	accountTok, _ := codec.IssueChallenge(Challenge{
		BizPurpose: BizPurposeMFA, Subject: Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce: "n-account", Operation: "step_up", Methods: []string{"totp"},
	}, ChallengeTTL)
	if _, err := svc.Submit(context.Background(), SubmitInput{
		Domain: DomainSSO, ChallengeToken: accountTok, Method: "totp",
	}); errorCode(t, err) != "verification_invalid" {
		t.Fatalf("account 挑战用于 sso 域应拒绝，code = %s", errorCode(t, err))
	}
}

func TestSubmitRejectsInvalidInput(t *testing.T) {
	verifier := &submitVerifier{res: FactorVerifyResult{Passed: true}}
	svc, codec := newSubmitService(t, func(d *Deps) { d.Verifier = verifier })

	if _, err := svc.Submit(context.Background(), SubmitInput{Domain: DomainAccount}); errorCode(t, err) != "verification_invalid" {
		t.Fatalf("缺 challengeToken/method，code = %s", errorCode(t, err))
	}
	if _, err := svc.Submit(context.Background(), SubmitInput{
		Domain: DomainAccount, ChallengeToken: "garbage", Method: "totp",
	}); errorCode(t, err) != "verification_invalid" {
		t.Fatalf("篡改令牌，code = %s", errorCode(t, err))
	}

	tok, _ := codec.IssueChallenge(Challenge{
		BizPurpose: BizPurposeMFA, Subject: Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce: "n1", Operation: "step_up", Methods: []string{"totp"},
	}, ChallengeTTL)
	if _, err := svc.Submit(context.Background(), SubmitInput{
		Domain: DomainAccount, ChallengeToken: tok, Method: "otp_sms",
	}); errorCode(t, err) != "verification_invalid" {
		t.Fatalf("method 不在挑战快照，code = %s", errorCode(t, err))
	}

	// SSO uid 主体缺终点收尾依赖：不得在未建会话的情况下谎报 success。
	ssoTok, _ := codec.IssueChallenge(Challenge{
		BizPurpose: BizPurposeLogin, Subject: Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce: "n-sso", Operation: "mfa_verify", Methods: []string{"totp"},
	}, ChallengeTTL)
	if _, err := svc.Submit(context.Background(), SubmitInput{
		Domain: DomainSSO, ChallengeToken: ssoTok, Method: "totp",
	}); errorCode(t, err) != "invalid_request" {
		t.Fatalf("缺终点收尾依赖，code = %s", errorCode(t, err))
	}
}

func TestSubmitFailClosedWithoutVerifier(t *testing.T) {
	svc, codec := newSubmitService(t, nil)
	tok, _ := codec.IssueChallenge(Challenge{
		BizPurpose: BizPurposeMFA, Subject: Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce: "n1", Operation: "step_up", Methods: []string{"totp"},
	}, ChallengeTTL)
	if _, err := svc.Submit(context.Background(), SubmitInput{
		Domain: DomainAccount, ChallengeToken: tok, Method: "totp",
	}); errorCode(t, err) != "method_disabled" {
		t.Fatalf("未注入验证器必须 fail-closed，code = %s", errorCode(t, err))
	}
}

func TestSubmitMapsFactorFailure(t *testing.T) {
	cases := []struct {
		name string
		res  FactorVerifyResult
		code string
	}{
		{"默认错码", FactorVerifyResult{}, "invalid_code"},
		{"过期", FactorVerifyResult{Code: "code_expired"}, "code_expired"},
		{"尝试超限", FactorVerifyResult{Code: "too_many_attempts"}, "too_many_attempts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, codec := newSubmitService(t, func(d *Deps) { d.Verifier = &submitVerifier{res: tc.res} })
			tok, _ := codec.IssueChallenge(Challenge{
				BizPurpose: BizPurposeMFA, Subject: Subject{Kind: SubjectKindUID, ID: "42"},
				Nonce: "n1", Operation: "step_up", Methods: []string{"totp"},
			}, ChallengeTTL)
			if _, err := svc.Submit(context.Background(), SubmitInput{
				Domain: DomainAccount, ChallengeToken: tok, Method: "totp",
			}); errorCode(t, err) != tc.code {
				t.Fatalf("code = %s, want %s", errorCode(t, err), tc.code)
			}
		})
	}
}

func TestConsumeAssertionRequiresToken(t *testing.T) {
	svc, _ := newSubmitService(t, nil)
	if _, err := svc.ConsumeAssertion(context.Background(), "", Want{}); errorCode(t, err) != "verification_required" {
		t.Fatalf("code = %s, want verification_required", errorCode(t, err))
	}
	if _, err := svc.ConsumeAssertion(context.Background(), "garbage", Want{}); errorCode(t, err) != "verification_invalid" {
		t.Fatalf("篡改令牌 code = %s, want verification_invalid", errorCode(t, err))
	}
}

func TestConsumeAssertionTripleCheck(t *testing.T) {
	codec, _, _ := fixedCodec(t, time.Unix(1_700_000_000, 0))
	svc := NewService(Deps{Codec: codec})
	tok, err := codec.IssueAssertion(Assertion{
		BizPurpose: BizPurposeUnbindTOTP,
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce:      "nonce-x",
		AMR:        []string{"totp"},
		Operation:  "unbind_totp",
	}, AssertionTTL)
	if err != nil {
		t.Fatalf("IssueAssertion: %v", err)
	}
	want := Want{
		BizPurpose: BizPurposeUnbindTOTP,
		Operation:  "unbind_totp",
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
	}
	cases := []struct {
		name string
		want Want
	}{
		{"biz_purpose 不符", Want{BizPurpose: BizPurposeMFA, Operation: want.Operation, Subject: want.Subject}},
		{"operation 不符", Want{BizPurpose: want.BizPurpose, Operation: "step_up", Subject: want.Subject}},
		{"subject 不符", Want{BizPurpose: want.BizPurpose, Operation: want.Operation, Subject: Subject{Kind: SubjectKindUID, ID: "43"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.ConsumeAssertion(context.Background(), tok, tc.want); errorCode(t, err) != "verification_invalid" {
				t.Fatalf("code = %s, want verification_invalid", errorCode(t, err))
			}
		})
	}
	if _, err := svc.ConsumeAssertion(context.Background(), tok, want); err != nil {
		t.Fatalf("三重校验一致应通过: %v", err)
	}
}

func TestConsumeAssertionLowRiskSkipsOnce(t *testing.T) {
	codec, _, _ := fixedCodec(t, time.Unix(1_700_000_000, 0))
	// Once 未注入：低风险 unbind_totp 仍可消费（按 nonce + exp 放行）。
	svc := NewService(Deps{Codec: codec})
	want := Want{
		BizPurpose: BizPurposeUnbindTOTP,
		Operation:  "unbind_totp",
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
	}
	for i := 0; i < 2; i++ {
		if _, err := svc.ConsumeAssertion(context.Background(), mustAssertion(t, codec, BizPurposeUnbindTOTP, "unbind_totp", "n-low"), want); err != nil {
			t.Fatalf("第 %d 次消费低风险断言: %v", i+1, err)
		}
	}
}

func TestConsumeAssertionHighRiskReplay(t *testing.T) {
	codec, _, _ := fixedCodec(t, time.Unix(1_700_000_000, 0))
	once := &replayOnce{result: true}
	svc := NewService(Deps{Codec: codec, Once: once})
	want := Want{
		BizPurpose: BizPurposeChangePassword,
		Operation:  "pwd_change",
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
	}
	tok := mustAssertion(t, codec, BizPurposeChangePassword, "pwd_change", "n-high")

	if _, err := svc.ConsumeAssertion(context.Background(), tok, want); err != nil {
		t.Fatalf("首次消费: %v", err)
	}
	_, err := svc.ConsumeAssertion(context.Background(), tok, want)
	if errorCode(t, err) != "verification_invalid" {
		t.Fatalf("重放 code = %s, want verification_invalid", errorCode(t, err))
	}
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("重放应可追溯 ErrReplay: %v", err)
	}
	if len(once.keys) != 2 || once.keys[0] != "al:once:n-high" || once.ttls[0] != 120*time.Second {
		t.Fatalf("al:once = %v ttl = %v", once.keys, once.ttls)
	}
}

func TestConsumeAssertionHighRiskRequiresOnce(t *testing.T) {
	codec, _, _ := fixedCodec(t, time.Unix(1_700_000_000, 0))
	svc := NewService(Deps{Codec: codec})
	tok := mustAssertion(t, codec, BizPurposeAdminSensitive, "admin_write", "n-admin")
	if _, err := svc.ConsumeAssertion(context.Background(), tok, Want{
		BizPurpose: BizPurposeAdminSensitive,
		Operation:  "admin_write",
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
	}); errorCode(t, err) != "verification_invalid" {
		t.Fatalf("高风险缺 OnceStore 必须拒绝，code = %s", errorCode(t, err))
	}
}

func TestConsumeAssertionHighRiskOnceInfraError(t *testing.T) {
	codec, _, _ := fixedCodec(t, time.Unix(1_700_000_000, 0))
	once := &replayOnce{err: errors.New("redis down")}
	svc := NewService(Deps{Codec: codec, Once: once})
	tok := mustAssertion(t, codec, BizPurposeChangePassword, "pwd_change", "n-infra")
	_, err := svc.ConsumeAssertion(context.Background(), tok, Want{
		BizPurpose: BizPurposeChangePassword,
		Operation:  "pwd_change",
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
	})
	var ve *Error
	if err == nil || errors.As(err, &ve) {
		t.Fatalf("基础设施错误应原样上抛，不得伪装为业务失败: %v", err)
	}
}

func TestConsumeAssertionRejectsExpired(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	codec, _, _ := fixedCodec(t, at)
	tok, err := codec.IssueAssertion(Assertion{
		BizPurpose: BizPurposeUnbindTOTP,
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce:      "n-exp",
		AMR:        []string{"totp"},
		Operation:  "unbind_totp",
	}, AssertionTTL)
	if err != nil {
		t.Fatalf("IssueAssertion: %v", err)
	}
	codec.now = func() time.Time { return at.Add(AssertionTTL + time.Second) }
	svc := NewService(Deps{Codec: codec})
	if _, err := svc.ConsumeAssertion(context.Background(), tok, Want{
		BizPurpose: BizPurposeUnbindTOTP,
		Operation:  "unbind_totp",
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
	}); errorCode(t, err) != "verification_invalid" {
		t.Fatalf("过期断言 code = %s, want verification_invalid", errorCode(t, err))
	}
}

func mustAssertion(t *testing.T, codec *AssertionCodec, bp BizPurpose, operation, nonce string) string {
	t.Helper()
	tok, err := codec.IssueAssertion(Assertion{
		BizPurpose: bp,
		Subject:    Subject{Kind: SubjectKindUID, ID: "42"},
		Nonce:      nonce,
		AMR:        []string{"totp"},
		Operation:  operation,
	}, AssertionTTL)
	if err != nil {
		t.Fatalf("IssueAssertion: %v", err)
	}
	return tok
}
