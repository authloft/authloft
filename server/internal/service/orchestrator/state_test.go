package orchestrator

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"authloft/gen/go/token"
	"authloft/internal/security"
)

// testCodec 用固定 32B 密钥构造 Codec（不读配置）。
func testCodec(t *testing.T) *security.Codec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0xA5
	}
	ks, err := security.NewKeyStore(security.KeyEntry{
		ID:  security.KeyID{Version: 1, Kid: 1},
		Key: key,
	})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return security.NewCodec(ks)
}

// testState 构造固定时钟的 State（时钟可随测试推进）。
func testState(t *testing.T, at time.Time) *State {
	t.Helper()
	s := NewState(testCodec(t))
	s.now = func() time.Time { return at }
	return s
}

// fullPayload 覆盖 §11.6.2 的全部字段，用于 round-trip / 重签保字段断言。
func fullPayload() *token.LoginTokenPayload {
	return &token.LoginTokenPayload{
		Tid:    "tid-1",
		Flow:   "login",
		Factor: "otp_email",
		Passed: []string{"otp_email"},
		Uid:    10086,
		Ch: &token.Challenge{
			Purpose: "mfa",
			Target:  "a***@b.com",
			Nonce:   "nonce-1",
		},
		Tp: &token.ThirdParty{
			ProviderKey: "qq",
			OpenId:      "open-1",
			UnionId:     "union-1",
			Nickname:    "nick",
			AvatarUrl:   "https://example.com/a.png",
		},
		Oidc: &token.Oidc{
			ClientId:            "client-1",
			RedirectUri:         "https://example.com/cb",
			Scope:               "openid profile",
			Nonce:               "oidc-nonce",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
			State:               "state-1",
		},
		Amr: []string{"otp_email"},
	}
}

// tamperLastByte 篡改令牌解码后的最后一个字节再编码。
func tamperLastByte(t *testing.T, tok string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	return base64.RawURLEncoding.EncodeToString(raw)
}

// TestStateIssueParseRoundTrip 签发后可完整解析；exp 固定 10 分钟。
func TestStateIssueParseRoundTrip(t *testing.T) {
	at := time.Unix(1700000000, 0)
	s := testState(t, at)
	p := fullPayload()

	tok, err := s.Issue(p)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(tok); err != nil {
		t.Fatalf("token must be base64url: %v", err)
	}
	if p.GetIat() != at.Unix() {
		t.Fatalf("iat = %d, want %d", p.GetIat(), at.Unix())
	}
	if p.GetExp() != at.Add(10*time.Minute).Unix() {
		t.Fatalf("exp = %d, want %d", p.GetExp(), at.Add(10*time.Minute).Unix())
	}

	got, err := s.Parse(tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !proto.Equal(got, p) {
		t.Fatalf("round-trip payload mismatch:\n got %v\nwant %v", got, p)
	}
}

// TestStateParseTampered 篡改一律拒绝且错误可判别。
func TestStateParseTampered(t *testing.T) {
	s := testState(t, time.Unix(1700000000, 0))
	tok, err := s.Issue(fullPayload())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Parse(tamperLastByte(t, tok)); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("tampered err = %v, want ErrTokenInvalid", err)
	}
}

// TestStateParseExpired 超过 10 分钟返回 ErrTokenExpired。
func TestStateParseExpired(t *testing.T) {
	at := time.Unix(1700000000, 0)
	s := testState(t, at)
	tok, err := s.Issue(fullPayload())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	s.now = func() time.Time { return at.Add(11 * time.Minute) }
	if _, err := s.Parse(tok); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired err = %v, want ErrTokenExpired", err)
	}
}

// TestStateParseCrossPurpose 跨 purpose 解令牌一律拒绝。
func TestStateParseCrossPurpose(t *testing.T) {
	s := testState(t, time.Unix(1700000000, 0))
	p := fullPayload()
	tok, err := s.codec.Seal(security.PurposeSession, p)
	if err != nil {
		t.Fatalf("Seal session: %v", err)
	}
	if _, err := s.Parse(tok); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("cross purpose err = %v, want ErrTokenInvalid", err)
	}
}

// TestStateIssueRejectsInvalidFlow flow 不在 login|register|reset 内拒绝。
func TestStateIssueRejectsInvalidFlow(t *testing.T) {
	s := testState(t, time.Unix(1700000000, 0))
	p := fullPayload()
	p.Flow = "bogus"
	if _, err := s.Issue(p); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("invalid flow err = %v, want ErrTokenInvalid", err)
	}
}

// TestStateParseRejectsChallengePurpose bind / webauthn 不属于 login_token（§11.6.2）。
func TestStateParseRejectsChallengePurpose(t *testing.T) {
	at := time.Unix(1700000000, 0)
	s := testState(t, at)
	p := fullPayload()
	p.Ch.Purpose = "bind"
	p.Iat = at.Unix()
	p.Exp = at.Add(10 * time.Minute).Unix()
	tok, err := s.codec.Seal(security.PurposeLogin, p)
	if err != nil {
		t.Fatalf("Seal login: %v", err)
	}
	if _, err := s.Parse(tok); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("challenge purpose err = %v, want ErrTokenInvalid", err)
	}
}

// TestStateRenewPreservesFields 重签保留原载荷全部字段，只刷新 iat / exp。
func TestStateRenewPreservesFields(t *testing.T) {
	at := time.Unix(1700000000, 0)
	s := testState(t, at)
	tok, err := s.Issue(fullPayload())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	later := at.Add(2 * time.Minute)
	s.now = func() time.Time { return later }
	nextTok, next, err := s.Renew(tok, nil)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if nextTok == tok {
		t.Fatal("re-signed token must differ (fresh nonce)")
	}
	if next.GetIat() != later.Unix() || next.GetExp() != later.Add(10*time.Minute).Unix() {
		t.Fatalf("renewed iat/exp = %d/%d, want %d/%d",
			next.GetIat(), next.GetExp(), later.Unix(), later.Add(10*time.Minute).Unix())
	}

	want := fullPayload()
	want.Iat = next.GetIat()
	want.Exp = next.GetExp()
	if !proto.Equal(next, want) {
		t.Fatalf("renew must preserve all fields:\n got %v\nwant %v", next, want)
	}

	got, err := s.Parse(nextTok)
	if err != nil {
		t.Fatalf("Parse renewed: %v", err)
	}
	if !proto.Equal(got, want) {
		t.Fatalf("renewed token payload mismatch:\n got %v\nwant %v", got, want)
	}
}

// TestStateRenewAppliesMutation 重签在副本上应用变更，不丢其他字段。
func TestStateRenewAppliesMutation(t *testing.T) {
	at := time.Unix(1700000000, 0)
	s := testState(t, at)
	tok, err := s.Issue(fullPayload())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	later := at.Add(time.Minute)
	s.now = func() time.Time { return later }
	_, next, err := s.Renew(tok, func(p *token.LoginTokenPayload) {
		p.Factor = "totp"
		p.Passed = append(p.Passed, "totp")
		p.Amr = append(p.Amr, "totp")
	})
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}

	want := fullPayload()
	want.Factor = "totp"
	want.Passed = append(want.Passed, "totp")
	want.Amr = append(want.Amr, "totp")
	want.Iat = later.Unix()
	want.Exp = later.Add(10 * time.Minute).Unix()
	if !proto.Equal(next, want) {
		t.Fatalf("mutated renew mismatch:\n got %v\nwant %v", next, want)
	}
}

// TestStateRenewRejectsExpired 过期令牌不可重签。
func TestStateRenewRejectsExpired(t *testing.T) {
	at := time.Unix(1700000000, 0)
	s := testState(t, at)
	tok, err := s.Issue(fullPayload())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	s.now = func() time.Time { return at.Add(11 * time.Minute) }
	if _, _, err := s.Renew(tok, nil); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("renew expired err = %v, want ErrTokenExpired", err)
	}
}
