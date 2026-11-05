package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/gen/go/token"
	"authloft/internal/asyncqueue"
	"authloft/internal/factor"
	"authloft/internal/repo/model"
	"authloft/internal/security"
)

const (
	testRPID   = "example.org"
	testOrigin = "https://example.org"
)

var fixedNow = time.Unix(1_800_000_000, 0)

// ---- Fake 仓储 / 缓存 / 队列 ----

type fakeStore struct {
	rows map[string]*model.UserCredentialWebauthn
	err  error
}

func (s *fakeStore) FindByCredentialID(_ context.Context, id string) (*model.UserCredentialWebauthn, error) {
	if s.err != nil {
		return nil, s.err
	}
	row, ok := s.rows[id]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	return row, nil
}

type fakeQueue struct {
	tasks []asyncqueue.Task
	full  bool
}

func (q *fakeQueue) Push(task asyncqueue.Task) bool {
	if q.full {
		return false
	}
	q.tasks = append(q.tasks, task)
	return true
}

type fakeSink struct{ updates map[int64]int64 }

func (s *fakeSink) UpdateSignCount(_ context.Context, id int64, count int64) error {
	if s.updates == nil {
		s.updates = make(map[int64]int64)
	}
	s.updates[id] = count
	return nil
}

// ---- helpers ----

func testCodec(t *testing.T) *security.Codec {
	t.Helper()
	ks, err := security.NewKeyStore(security.KeyEntry{
		ID:  security.KeyID{Version: 1, Kid: 1},
		Key: bytes.Repeat([]byte{0x37}, 32),
	})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return security.NewCodec(ks)
}

func testOptions(now func() time.Time) Options {
	return Options{
		RPID:          testRPID,
		RPDisplayName: "Authloft",
		RPOrigins:     []string{testOrigin},
		ChallengeTTL:  120 * time.Second,
		Timeout:       120 * time.Second,
		Clock:         now,
	}
}

func newTestFactor(t *testing.T, codec *security.Codec, store WebauthnStore, queue SignCountPusher, now func() time.Time) *Factor {
	t.Helper()
	f, err := New(codec, store, queue, testOptions(now))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

func randomChallenge(t *testing.T) string {
	t.Helper()
	b, err := security.RandomBytes(challengeLen)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func loginCtx(nonce string) *factor.FactorContext {
	return &factor.FactorContext{
		Context: context.Background(),
		Login: &token.LoginTokenPayload{
			Tid:  "tid-1",
			Flow: "login",
			Ch:   &token.Challenge{Purpose: "login", Nonce: nonce},
		},
	}
}

func storeFor(a *testAuthenticator, signCount int64) *fakeStore {
	return &fakeStore{rows: map[string]*model.UserCredentialWebauthn{
		b64(a.credID): {
			ID: 7, UserID: 42, Kind: "webauthn",
			CredentialID: b64(a.credID), PublicKey: a.pubCOSE, SignCount: signCount,
		},
	}}
}

// ---- 形状 ----

func TestFactorShape(t *testing.T) {
	f := newTestFactor(t, testCodec(t), &fakeStore{}, &fakeQueue{}, func() time.Time { return fixedNow })
	if f.Kind() != factor.FactorWebAuthn {
		t.Fatalf("Kind = %v, want webauthn", f.Kind())
	}
	if u := f.Usages(); len(u) != 2 || u[0] != factor.UsagePrimary || u[1] != factor.UsageSecondary {
		t.Fatalf("Usages = %v, want [primary secondary]", u)
	}
	if s := f.Steps(); len(s) != 2 || s[0] != factor.StepChallenge || s[1] != factor.StepForm {
		t.Fatalf("Steps = %v, want [challenge form]", s)
	}
}

// ---- challenge（Start）----

func TestStartBindsChallengeToLoginToken(t *testing.T) {
	f := newTestFactor(t, testCodec(t), &fakeStore{}, &fakeQueue{}, func() time.Time { return fixedNow })
	ctx := loginCtx("")
	res, err := f.Start(ctx)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	nonce := ctx.Login.GetCh().GetNonce()
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(decoded) != challengeLen {
		t.Fatalf("ch.nonce = %q, want 32 random bytes (%v)", nonce, err)
	}
	// 保留 login_token 已有 challenge.purpose / target。
	if ctx.Login.GetCh().GetPurpose() != "login" || ctx.Login.GetTid() != "tid-1" {
		t.Fatalf("Start overwrote login state: %+v", ctx.Login)
	}
	if res.Method != factor.FactorWebAuthn || res.ExpiresIn != 120 {
		t.Fatalf("StepResult = %+v", res)
	}
	fields := res.ChallengeData.GetFields()
	if fields["challenge"].GetStringValue() != nonce {
		t.Fatalf("challenge_data.challenge = %q, want %q", fields["challenge"].GetStringValue(), nonce)
	}
	if fields["rpId"].GetStringValue() != testRPID {
		t.Fatalf("challenge_data.rpId = %q", fields["rpId"].GetStringValue())
	}
	// usernameless：allowCredentials 恒为空（§8.3 行 1048）。
	allow := fields["allowCredentials"].GetListValue()
	if allow == nil || len(allow.GetValues()) != 0 {
		t.Fatalf("allowCredentials = %v, want empty list", allow)
	}
}

// ---- 断言路径：成功 + 四项固定校验 ----

func TestVerifyAssertionSuccessEnqueuesSignCount(t *testing.T) {
	a := newTestAuthenticator(t)
	nonce := randomChallenge(t)
	queue := &fakeQueue{}
	f := newTestFactor(t, testCodec(t), storeFor(a, 0), queue, func() time.Time { return fixedNow })
	cred := a.assertion(t, ceremonyFixture{challenge: nonce, origin: testOrigin, rpID: testRPID, counter: 1})
	ctx := loginCtx(nonce)
	ctx.Payload = &factor.Payload{Credential: cred}

	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed || res.UID != 42 || res.Status != "" {
		t.Fatalf("Verify = %+v, want passed uid=42", res)
	}
	if len(queue.tasks) != 1 {
		t.Fatalf("queue tasks = %d, want 1", len(queue.tasks))
	}
	u := queue.tasks[0].Value.(SignCountUpdate)
	if u.ID != 7 || u.SignCount != 1 {
		t.Fatalf("sign_count update = %+v", u)
	}
	if !strings.HasPrefix(queue.tasks[0].Key, signCountKeyPrefix) {
		t.Fatalf("queue key = %q, want credential-scoped", queue.tasks[0].Key)
	}
}

func TestVerifyAssertionFourFixedChecks(t *testing.T) {
	a := newTestAuthenticator(t)
	wrong := newTestAuthenticator(t)
	nonce := randomChallenge(t)
	otherNonce := randomChallenge(t)
	base := ceremonyFixture{challenge: nonce, origin: testOrigin, rpID: testRPID, counter: 1}

	cases := []struct {
		name   string
		mutate func(f ceremonyFixture) ceremonyFixture
		passed bool
	}{
		{"valid", func(f ceremonyFixture) ceremonyFixture { return f }, true},
		{"challenge mismatch", func(f ceremonyFixture) ceremonyFixture { f.challenge = otherNonce; return f }, false},
		{"origin mismatch", func(f ceremonyFixture) ceremonyFixture { f.origin = "https://evil.example"; return f }, false},
		{"rpId hash mismatch", func(f ceremonyFixture) ceremonyFixture { f.rpID = "evil.example"; return f }, false},
		{"signature mismatch", func(f ceremonyFixture) ceremonyFixture { f.signKey = wrong.priv; return f }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			queue := &fakeQueue{}
			f := newTestFactor(t, testCodec(t), storeFor(a, 0), queue, func() time.Time { return fixedNow })
			cred := a.assertion(t, tc.mutate(base))
			ctx := loginCtx(nonce)
			ctx.Payload = &factor.Payload{Credential: cred}
			res, err := f.Verify(ctx)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.Passed != tc.passed {
				t.Fatalf("Verify = %+v, want passed=%v", res, tc.passed)
			}
			if !tc.passed {
				if res.Status != StatusInvalidCredentials {
					t.Fatalf("status = %q, want %q", res.Status, StatusInvalidCredentials)
				}
				if len(queue.tasks) != 0 {
					t.Fatalf("failed ceremony must not enqueue: %v", queue.tasks)
				}
			}
		})
	}
}

func TestVerifyAssertionSignCountMustIncrease(t *testing.T) {
	cases := []struct {
		name    string
		stored  int64
		counter uint32
		passed  bool
	}{
		{"counter advances", 5, 6, true},
		{"counter equal (clone)", 5, 5, false},
		{"counter regressed (clone)", 5, 3, false},
		{"authenticator without counter", 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAuthenticator(t)
			nonce := randomChallenge(t)
			f := newTestFactor(t, testCodec(t), storeFor(a, tc.stored), &fakeQueue{}, func() time.Time { return fixedNow })
			cred := a.assertion(t, ceremonyFixture{challenge: nonce, origin: testOrigin, rpID: testRPID, counter: tc.counter})
			ctx := loginCtx(nonce)
			ctx.Payload = &factor.Payload{Credential: cred}
			res, err := f.Verify(ctx)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.Passed != tc.passed {
				t.Fatalf("Verify = %+v, want passed=%v", res, tc.passed)
			}
		})
	}
}

func TestVerifyUnknownCredentialAndMissingInputs(t *testing.T) {
	f := newTestFactor(t, testCodec(t), &fakeStore{}, &fakeQueue{}, func() time.Time { return fixedNow })

	for _, ctx := range []*factor.FactorContext{
		nil,
		{Context: context.Background()},
		{Context: context.Background(), Login: &token.LoginTokenPayload{}},
		{Context: context.Background(), Login: &token.LoginTokenPayload{Ch: &token.Challenge{Nonce: randomChallenge(t)}}, Payload: &factor.Payload{}},
	} {
		res, err := f.Verify(ctx)
		if err != nil {
			t.Fatalf("Verify(invalid): %v", err)
		}
		if res.Status != StatusInvalidRequest {
			t.Fatalf("Verify(invalid) = %+v, want invalid_request", res)
		}
	}

	a := newTestAuthenticator(t)
	nonce := randomChallenge(t)
	cred := a.assertion(t, ceremonyFixture{challenge: nonce, origin: testOrigin, rpID: testRPID, counter: 1})
	ctx := loginCtx(nonce)
	ctx.Payload = &factor.Payload{Credential: cred}
	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify(unknown): %v", err)
	}
	if res.Passed || res.Status != StatusInvalidCredentials {
		t.Fatalf("Verify(unknown) = %+v, want invalid_credentials", res)
	}
}

func TestVerifySecondaryUIDMismatchRejected(t *testing.T) {
	a := newTestAuthenticator(t)
	nonce := randomChallenge(t)
	f := newTestFactor(t, testCodec(t), storeFor(a, 0), &fakeQueue{}, func() time.Time { return fixedNow })
	cred := a.assertion(t, ceremonyFixture{challenge: nonce, origin: testOrigin, rpID: testRPID, counter: 1})
	ctx := loginCtx(nonce)
	ctx.Login.Uid = 99
	ctx.Login.Passed = []string{"password"}
	ctx.Payload = &factor.Payload{Credential: cred}
	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Passed {
		t.Fatalf("secondary factor must not authenticate a different uid: %+v", res)
	}
}

func TestVerifyQueueFullDoesNotBlockResponse(t *testing.T) {
	a := newTestAuthenticator(t)
	nonce := randomChallenge(t)
	f := newTestFactor(t, testCodec(t), storeFor(a, 0), &fakeQueue{full: true}, func() time.Time { return fixedNow })
	cred := a.assertion(t, ceremonyFixture{challenge: nonce, origin: testOrigin, rpID: testRPID, counter: 1})
	ctx := loginCtx(nonce)
	ctx.Payload = &factor.Payload{Credential: cred}
	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed || res.UID != 42 {
		t.Fatalf("queue failure must not affect verdict: %+v", res)
	}
}

func TestVerifyPropagatesStoreError(t *testing.T) {
	want := errors.New("db down")
	f := newTestFactor(t, testCodec(t), &fakeStore{err: want}, &fakeQueue{}, func() time.Time { return fixedNow })
	a := newTestAuthenticator(t)
	nonce := randomChallenge(t)
	cred := a.assertion(t, ceremonyFixture{challenge: nonce, origin: testOrigin, rpID: testRPID, counter: 1})
	ctx := loginCtx(nonce)
	ctx.Payload = &factor.Payload{Credential: cred}
	if _, err := f.Verify(ctx); !errors.Is(err, want) {
		t.Fatalf("Verify err = %v, want %v", err, want)
	}
}

// ---- 账号域注册路径（独立原子 token + attestation）----

func TestRegistrationRoundTrip(t *testing.T) {
	a := newTestAuthenticator(t)
	codec := testCodec(t)
	f := newTestFactor(t, codec, &fakeStore{}, &fakeQueue{}, func() time.Time { return fixedNow })
	ch, err := f.BeginRegistration(42)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if ch.Token == "" || ch.ExpiresIn != 120 || ch.ChallengeData == nil {
		t.Fatalf("RegistrationChallenge = %+v", ch)
	}
	// 注册下发 PublicKeyCredentialCreationOptions（含 rp / user / challenge）。
	fields := ch.ChallengeData.GetFields()
	if fields["rp"].GetStructValue() == nil || fields["user"].GetStructValue() == nil || fields["challenge"].GetStringValue() == "" {
		t.Fatalf("creation options incomplete: %v", fields)
	}
	_, challenge, status := parseRegistrationToken(codec, ch.Token, fixedNow)
	if status != "" || challenge == "" {
		t.Fatalf("parse token = (%q, %q), want valid", challenge, status)
	}
	cred := a.attestation(t, ceremonyFixture{challenge: challenge, origin: testOrigin, rpID: testRPID, counter: 0})
	res := f.FinishRegistration(ch.Token, cred)
	if res.Status != "" || res.UID != 42 || res.CredentialID != b64(a.credID) || len(res.PublicKey) == 0 {
		t.Fatalf("FinishRegistration = %+v", res)
	}
}

func TestRegistrationTokenTamperedAndExpired(t *testing.T) {
	a := newTestAuthenticator(t)
	codec := testCodec(t)
	current := fixedNow
	f := newTestFactor(t, codec, &fakeStore{}, &fakeQueue{}, func() time.Time { return current })
	ch, err := f.BeginRegistration(42)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	_, challenge, _ := parseRegistrationToken(codec, ch.Token, fixedNow)
	valid := a.attestation(t, ceremonyFixture{challenge: challenge, origin: testOrigin, rpID: testRPID, counter: 0})

	// 篡改 / 无效 → invalid_request。
	// 不动末字符：Raw base64 末字符低位是解码丢弃位，仅替换末字符时解码字节
	// 可能不变，token 仍通过验证（flaky 根因）。改中段字符（6 位全有效）并
	// 保证与原字符不同 → 解码字节必变 → GCM 认证必败。
	idx := len(ch.Token) / 2
	replacement := "A"
	if ch.Token[idx] == 'A' {
		replacement = "B"
	}
	tampered := ch.Token[:idx] + replacement + ch.Token[idx+1:]
	if res := f.FinishRegistration(tampered, valid); res.Status != StatusInvalidRequest {
		t.Fatalf("tampered token status = %q, want invalid_request", res.Status)
	}
	if res := f.FinishRegistration("", valid); res.Status != StatusInvalidRequest {
		t.Fatalf("empty token status = %q, want invalid_request", res.Status)
	}

	// 过期 → code_expired。
	current = fixedNow.Add(121 * time.Second)
	if res := f.FinishRegistration(ch.Token, valid); res.Status != StatusCodeExpired {
		t.Fatalf("expired token status = %q, want code_expired", res.Status)
	}
}

func TestRegistrationTokenAADNotInterchangeableWithLoginToken(t *testing.T) {
	codec := testCodec(t)
	f := newTestFactor(t, codec, &fakeStore{}, &fakeQueue{}, func() time.Time { return fixedNow })
	ch, err := f.BeginRegistration(42)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if _, err := security.Open[token.LoginTokenPayload](codec, security.PurposeLogin, ch.Token); err == nil {
		t.Fatal("webauthn token must not decrypt under login purpose (AAD隔离)")
	}
}

func TestRegistrationTokenRejectsWrongPayloadPurpose(t *testing.T) {
	codec := testCodec(t)
	payload := &token.LoginTokenPayload{
		Uid: 42,
		Ch:  &token.Challenge{Purpose: "login", Nonce: randomChallenge(t)},
		Iat: fixedNow.Unix(),
		Exp: fixedNow.Add(120 * time.Second).Unix(),
	}
	tok, err := codec.Seal(security.PurposeWebAuthn, payload)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	_, _, status := parseRegistrationToken(codec, tok, fixedNow)
	if status != StatusInvalidRequest {
		t.Fatalf("status = %q, want invalid_request", status)
	}
}

func TestRegistrationAttestationChecks(t *testing.T) {
	a := newTestAuthenticator(t)
	codec := testCodec(t)
	f := newTestFactor(t, codec, &fakeStore{}, &fakeQueue{}, func() time.Time { return fixedNow })
	ch, err := f.BeginRegistration(42)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	_, challenge, _ := parseRegistrationToken(codec, ch.Token, fixedNow)
	other := randomChallenge(t)

	cases := []struct {
		name     string
		fixture  ceremonyFixture
		wantFail bool
	}{
		{"valid", ceremonyFixture{challenge: challenge, origin: testOrigin, rpID: testRPID}, false},
		{"challenge mismatch", ceremonyFixture{challenge: other, origin: testOrigin, rpID: testRPID}, true},
		{"origin mismatch", ceremonyFixture{challenge: challenge, origin: "https://evil.example", rpID: testRPID}, true},
		{"rpId hash mismatch", ceremonyFixture{challenge: challenge, origin: testOrigin, rpID: "evil.example"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred := a.attestation(t, tc.fixture)
			res := f.FinishRegistration(ch.Token, cred)
			if tc.wantFail {
				if res.Status != StatusInvalidRequest {
					t.Fatalf("status = %q, want invalid_request", res.Status)
				}
			} else if res.Status != "" {
				t.Fatalf("status = %q, want success", res.Status)
			}
		})
	}
}

// ---- 延迟队列：同键合并取最大值 ----

func TestSignCountExecutorTakesMaxPerCredential(t *testing.T) {
	sink := &fakeSink{}
	exec := NewSignCountExecutor(sink)
	exec.Execute(context.Background(), []asyncqueue.Task{
		{Key: signCountKeyPrefix + "7", Value: SignCountUpdate{ID: 7, SignCount: 3}},
		{Key: signCountKeyPrefix + "7", Value: SignCountUpdate{ID: 7, SignCount: 9}},
		{Key: signCountKeyPrefix + "7", Value: SignCountUpdate{ID: 7, SignCount: 5}},
		{Key: signCountKeyPrefix + "8", Value: SignCountUpdate{ID: 8, SignCount: 2}},
		{Key: "junk", Value: "not-an-update"},
	})
	if sink.updates[7] != 9 || sink.updates[8] != 2 {
		t.Fatalf("updates = %v, want {7:9, 8:2}", sink.updates)
	}
}
