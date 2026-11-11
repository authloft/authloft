package verification

import (
	"errors"
	"testing"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/security"
)

func testCodec(t *testing.T, seed byte) *security.Codec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed
	}
	ks, err := security.NewKeyStore(security.KeyEntry{
		ID: security.KeyID{Version: 1, Kid: 1}, Key: key,
	})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return security.NewCodec(ks)
}

// fixedCodec 返回注入固定时间的编解码器与两套底层 codec（分别用于手工
// 构造挑战 / 断言载荷，覆盖跨 purpose、非法字段等场景）。
func fixedCodec(t *testing.T, at time.Time) (*AssertionCodec, *security.Codec, *security.Codec) {
	t.Helper()
	challengeRaw := testCodec(t, 0xA1)
	verificationRaw := testCodec(t, 0xA2)
	c := NewAssertionCodec(challengeRaw, verificationRaw)
	c.now = func() time.Time { return at }
	return c, challengeRaw, verificationRaw
}

func sampleSubject() Subject { return Subject{Kind: SubjectKindUID, ID: "42"} }

func sampleChallenge() Challenge {
	return Challenge{
		BizPurpose: BizPurposeMFA,
		Subject:    sampleSubject(),
		Nonce:      "nonce-1",
		Operation:  "step_up",
		Methods:    []string{"totp", "otp_sms"},
	}
}

func sampleAssertion() Assertion {
	return Assertion{
		BizPurpose: BizPurposeChangePassword,
		Subject:    sampleSubject(),
		Nonce:      "nonce-2",
		AMR:        []string{"totp"},
		Operation:  "pwd_change",
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	c, _, _ := fixedCodec(t, at)
	want := sampleChallenge()
	tok, err := c.IssueChallenge(want, 300*time.Second)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	got, err := c.ParseChallenge(tok)
	if err != nil {
		t.Fatalf("ParseChallenge: %v", err)
	}
	if got.BizPurpose != want.BizPurpose || got.Subject != want.Subject ||
		got.Nonce != want.Nonce || got.Operation != want.Operation ||
		len(got.Methods) != 2 || got.Methods[0] != "totp" || got.Methods[1] != "otp_sms" {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

func TestAssertionRoundTrip(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	c, _, _ := fixedCodec(t, at)
	want := sampleAssertion()
	tok, err := c.IssueAssertion(want, 120*time.Second)
	if err != nil {
		t.Fatalf("IssueAssertion: %v", err)
	}
	got, err := c.ParseAssertion(tok)
	if err != nil {
		t.Fatalf("ParseAssertion: %v", err)
	}
	if got.BizPurpose != want.BizPurpose || got.Subject != want.Subject ||
		got.Nonce != want.Nonce || got.Operation != want.Operation ||
		len(got.AMR) != 1 || got.AMR[0] != "totp" {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

// TestCrossTypeIsolation 挑战与断言由 AAD purpose + 独立密钥双重隔离
// （§11.6.7）：挑战令牌不能当断言解析、断言令牌不能当挑战解析，Open
// 跨 purpose 在 GCM 认证处拒绝，无需额外的载荷消息类型校验。
func TestCrossTypeIsolation(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	c, challengeRaw, _ := fixedCodec(t, at)

	challengeTok, err := c.IssueChallenge(sampleChallenge(), 300*time.Second)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	assertionTok, err := c.IssueAssertion(sampleAssertion(), 120*time.Second)
	if err != nil {
		t.Fatalf("IssueAssertion: %v", err)
	}

	// 挑战令牌传给断言解析 → 跨 purpose + 跨密钥，必须拒绝。
	if _, err := c.ParseAssertion(challengeTok); !errors.Is(err, ErrInvalidAssertion) {
		t.Fatalf("challenge-as-assertion err = %v, want ErrInvalidAssertion", err)
	}
	// 断言令牌传给挑战解析 → 跨 purpose + 跨密钥，必须拒绝。
	if _, err := c.ParseChallenge(assertionTok); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("assertion-as-challenge err = %v, want ErrInvalidChallenge", err)
	}

	// 同一挑战载荷用 session purpose 签发 → 挑战解析拒绝。
	wrongPurpose := &token.ChallengeTokenPayload{
		BizPurpose: "mfa", SubjectKind: "uid", Subject: "42", Nonce: "n",
		Iat: at.Unix(), Exp: at.Add(300 * time.Second).Unix(),
	}
	wpTok, err := challengeRaw.Seal(security.PurposeSession, wrongPurpose)
	if err != nil {
		t.Fatalf("Seal(session): %v", err)
	}
	if _, err := c.ParseChallenge(wpTok); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("cross-purpose challenge err = %v, want ErrInvalidChallenge", err)
	}

	// 另一把密钥的两个 codec 都解不开（§11.6.7 独立密钥）。
	other := NewAssertionCodec(testCodec(t, 0xB2), testCodec(t, 0xB3))
	if _, err := other.ParseChallenge(challengeTok); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("cross-key challenge err = %v, want ErrInvalidChallenge", err)
	}
	if _, err := other.ParseAssertion(assertionTok); !errors.Is(err, ErrInvalidAssertion) {
		t.Fatalf("cross-key assertion err = %v, want ErrInvalidAssertion", err)
	}
}

func TestTamperedRejected(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	c, _, _ := fixedCodec(t, at)
	tok, err := c.IssueChallenge(sampleChallenge(), 300*time.Second)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	tampered := tok[:len(tok)-1] + "A"
	if _, err := c.ParseChallenge(tampered); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("tampered challenge err = %v, want ErrInvalidChallenge", err)
	}
	if _, err := c.ParseChallenge("not-a-token"); !errors.Is(err, ErrInvalidChallenge) {
		t.Fatalf("garbage challenge err = %v, want ErrInvalidChallenge", err)
	}
}

func TestExpiredRejected(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	c, _, _ := fixedCodec(t, at)
	challengeTok, err := c.IssueChallenge(sampleChallenge(), 300*time.Second)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	assertionTok, err := c.IssueAssertion(sampleAssertion(), 120*time.Second)
	if err != nil {
		t.Fatalf("IssueAssertion: %v", err)
	}
	c.now = func() time.Time { return at.Add(301 * time.Second) }
	if _, err := c.ParseChallenge(challengeTok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired challenge err = %v, want ErrTokenExpired", err)
	}
	if _, err := c.ParseAssertion(assertionTok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired assertion err = %v, want ErrTokenExpired", err)
	}
}

// TestInvalidPayloadRejected 解出后逐项断言封闭集合 / 三元组，不合法载荷
// 即使 GCM 认证通过也拒绝（§11.6.7）。
func TestInvalidPayloadRejected(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	c, challengeRaw, verificationRaw := fixedCodec(t, at)
	cases := []struct {
		name, bp, kind, subject, nonce string
	}{
		{"table-external biz_purpose", "register", "uid", "42", "n"},
		{"unknown biz_purpose", "admin", "uid", "42", "n"},
		{"bad subject_kind", "mfa", "sid", "42", "n"},
		{"empty subject", "mfa", "uid", "", "n"},
		{"empty nonce", "mfa", "uid", "42", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := &token.ChallengeTokenPayload{
				BizPurpose: tc.bp, SubjectKind: tc.kind, Subject: tc.subject, Nonce: tc.nonce,
				Iat: at.Unix(), Exp: at.Add(300 * time.Second).Unix(),
			}
			chTok, err := challengeRaw.Seal(security.PurposeChallenge, ch)
			if err != nil {
				t.Fatalf("Seal(challenge): %v", err)
			}
			if _, err := c.ParseChallenge(chTok); !errors.Is(err, ErrInvalidChallenge) {
				t.Fatalf("challenge err = %v, want ErrInvalidChallenge", err)
			}
			as := &token.VerificationTokenPayload{
				BizPurpose: tc.bp, SubjectKind: tc.kind, Subject: tc.subject, Nonce: tc.nonce,
				Iat: at.Unix(), Exp: at.Add(120 * time.Second).Unix(),
			}
			asTok, err := verificationRaw.Seal(security.PurposeVerification, as)
			if err != nil {
				t.Fatalf("Seal(assertion): %v", err)
			}
			if _, err := c.ParseAssertion(asTok); !errors.Is(err, ErrInvalidAssertion) {
				t.Fatalf("assertion err = %v, want ErrInvalidAssertion", err)
			}
		})
	}
}

func TestIssueInputValidation(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	c, _, _ := fixedCodec(t, at)
	valid := sampleChallenge()
	bad := []struct {
		name string
		ch   Challenge
		ttl  time.Duration
	}{
		{"empty biz_purpose", Challenge{Subject: valid.Subject, Nonce: "n"}, time.Minute},
		{"unknown biz_purpose", Challenge{BizPurpose: BizPurpose("register"), Subject: valid.Subject, Nonce: "n"}, time.Minute},
		{"invalid subject", Challenge{BizPurpose: BizPurposeMFA, Nonce: "n"}, time.Minute},
		{"empty nonce", Challenge{BizPurpose: BizPurposeMFA, Subject: valid.Subject}, time.Minute},
		{"non-positive ttl", valid, 0},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.IssueChallenge(tc.ch, tc.ttl); err == nil {
				t.Fatal("IssueChallenge must reject invalid input")
			}
		})
	}
	if _, err := c.IssueAssertion(Assertion{BizPurpose: BizPurposeMFA, Nonce: "n"}, time.Minute); err == nil {
		t.Fatal("IssueAssertion must reject invalid subject")
	}
}

func TestCodecMissing(t *testing.T) {
	c := NewAssertionCodec(nil, nil)
	if _, err := c.IssueChallenge(sampleChallenge(), time.Minute); !errors.Is(err, ErrCodecMissing) {
		t.Fatalf("IssueChallenge err = %v, want ErrCodecMissing", err)
	}
	if _, err := c.ParseChallenge("x"); !errors.Is(err, ErrCodecMissing) {
		t.Fatalf("ParseChallenge err = %v, want ErrCodecMissing", err)
	}
	if _, err := c.IssueAssertion(sampleAssertion(), time.Minute); !errors.Is(err, ErrCodecMissing) {
		t.Fatalf("IssueAssertion err = %v, want ErrCodecMissing", err)
	}
	if _, err := c.ParseAssertion("x"); !errors.Is(err, ErrCodecMissing) {
		t.Fatalf("ParseAssertion err = %v, want ErrCodecMissing", err)
	}
}
