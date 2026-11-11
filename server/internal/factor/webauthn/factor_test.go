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

// TestCreationOptionsRequireRPDisplayName 固化 rp_display_name 的根因：
// go-webauthn 只在 BeginRegistration 生成注册选项时校验 rp.name，
// libwa.New 不校验——缺 RPDisplayName 时服务正常启动、webauthn 因子
// 不降级，直到用户点「注册通行密钥」才报错。故 authloft.rp_display_name
// 必须在 config.Validate 层 fail-fast，并由安装流程保证写入。
func TestCreationOptionsRequireRPDisplayName(t *testing.T) {
	base := RPConfig{
		RPID:      testRPID,
		RPOrigins: []string{testOrigin},
		Timeout:   120 * time.Second,
	}
	challenge := bytes.Repeat([]byte{0x01}, 32)
	userID := []byte("user-1")

	// 空展示名：构造 ceremony 成功（启动期无感），生成注册选项才失败。
	empty, err := newCeremony(base)
	if err != nil {
		t.Fatalf("newCeremony without RPDisplayName: %v", err)
	}
	if _, err := empty.creationOptions(userID, "alice", challenge); err == nil ||
		!strings.Contains(err.Error(), "display name") {
		t.Errorf("empty RPDisplayName: creationOptions err = %v, want display name error", err)
	}

	// 有展示名：rp.name 原样出现在注册选项中。
	base.RPDisplayName = "Corp SSO"
	c, err := newCeremony(base)
	if err != nil {
		t.Fatalf("newCeremony: %v", err)
	}
	opts, err := c.creationOptions(userID, "alice", challenge)
	if err != nil {
		t.Fatalf("creationOptions with RPDisplayName: %v", err)
	}
	m := opts.AsMap()
	rp, ok := m["rp"].(map[string]any)
	if !ok {
		t.Fatalf("creation options missing rp: %v", m)
	}
	if rp["name"] != "Corp SSO" {
		t.Errorf("rp.name = %v, want %q", rp["name"], "Corp SSO")
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
	ch, err := f.BeginRegistration(42, "alice")
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
	// user.name / displayName 取服务端 username；user.id 仍是不透明 uid 字节串。
	user := fields["user"].GetStructValue().GetFields()
	if user["name"].GetStringValue() != "alice" || user["displayName"].GetStringValue() != "alice" {
		t.Errorf("user.name / displayName = %q / %q, want username alice",
			user["name"].GetStringValue(), user["displayName"].GetStringValue())
	}
	wantID := base64.RawURLEncoding.EncodeToString([]byte("42"))
	if user["id"].GetStringValue() != wantID {
		t.Errorf("user.id = %q, want opaque uid bytes %q", user["id"].GetStringValue(), wantID)
	}
	_, challenge, status := parseRegistrationToken(codec, ch.Token, fixedNow)
	if status != "" || challenge == "" {
		t.Fatalf("parse token = (%q, %q), want valid", challenge, status)
	}
	// 载荷字段（后端架构 §8.3 末条 / §11.6.7）：biz_purpose=webauthn_enroll、
	// operation=webauthn_register、subject_kind=uid、subject=会话 uid、
	// methods 为空、exp 与挑战有效期一致（120s）。
	payload, err := security.Open[token.ChallengeTokenPayload](codec, security.PurposeWebAuthn, ch.Token)
	if err != nil {
		t.Fatalf("open challenge payload: %v", err)
	}
	if payload.GetBizPurpose() != "webauthn_enroll" || payload.GetOperation() != "webauthn_register" ||
		payload.GetSubjectKind() != "uid" || payload.GetSubject() != "42" || len(payload.GetMethods()) != 0 {
		t.Fatalf("challenge payload fields = %+v", payload)
	}
	if payload.GetNonce() != challenge || payload.GetExp() != fixedNow.Add(120*time.Second).Unix() {
		t.Fatalf("challenge payload nonce/exp = %q / %d", payload.GetNonce(), payload.GetExp())
	}
	cred := a.attestation(t, ceremonyFixture{challenge: challenge, origin: testOrigin, rpID: testRPID, counter: 0})
	res := f.FinishRegistration(ch.Token, cred)
	if res.Status != "" || res.UID != 42 || res.CredentialID != b64(a.credID) || len(res.PublicKey) == 0 {
		t.Fatalf("FinishRegistration = %+v", res)
	}
	// 展示类投影字段（§3.6 行 914 列表项）：transports 取注册响应
	// response.transports，aaguid 取 attestationObject.authData（fixture 携带
	// 固定非零 AAGUID）。
	if len(res.Transports) != 2 || res.Transports[0] != "internal" || res.Transports[1] != "usb" {
		t.Errorf("Transports = %v, want [internal usb]", res.Transports)
	}
	if res.AAGUID != "adce0002-35bc-c60a-648b-0b25f1f05503" {
		t.Errorf("AAGUID = %q, want fixture 展示形", res.AAGUID)
	}
	if res.SignCount != 0 {
		t.Errorf("SignCount = %d, want 0（fixture counter）", res.SignCount)
	}
}

// TestFormatAAGUID AAGUID → UUID 展示形 / 边界。
func TestFormatAAGUID(t *testing.T) {
	if got := formatAAGUID(fixtureAAGUID[:]); got != "adce0002-35bc-c60a-648b-0b25f1f05503" {
		t.Errorf("formatAAGUID(非零) = %q", got)
	}
	if got := formatAAGUID(make([]byte, 16)); got != "" {
		t.Errorf("formatAAGUID(全零) = %q, want 空串", got)
	}
	if got := formatAAGUID([]byte{1, 2, 3}); got != "" {
		t.Errorf("formatAAGUID(非 16 字节) = %q, want 空串", got)
	}
}

func TestRegistrationTokenTamperedAndExpired(t *testing.T) {
	a := newTestAuthenticator(t)
	codec := testCodec(t)
	current := fixedNow
	f := newTestFactor(t, codec, &fakeStore{}, &fakeQueue{}, func() time.Time { return current })
	ch, err := f.BeginRegistration(42, "alice")
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
	ch, err := f.BeginRegistration(42, "alice")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if _, err := security.Open[token.LoginTokenPayload](codec, security.PurposeLogin, ch.Token); err == nil {
		t.Fatal("webauthn token must not decrypt under login purpose (AAD隔离)")
	}
	// 反向：login_token 也冒充不了注册挑战令牌（AAD purpose 不同）。
	loginTok, err := codec.Seal(security.PurposeLogin, &token.LoginTokenPayload{
		Tid: "tid-1", Flow: "login", Uid: 42,
		Iat: fixedNow.Unix(), Exp: fixedNow.Add(120 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatalf("Seal login token: %v", err)
	}
	if _, _, status := parseRegistrationToken(codec, loginTok, fixedNow); status != StatusInvalidRequest {
		t.Fatalf("login token as registration token status = %q, want invalid_request", status)
	}
}

// TestRegistrationTokenRejectsWrongPayloadPurpose 载荷业务字段双重校验
// （§11.6.7：消费方按 biz_purpose + operation 校验；subject_kind/subject
// 必须匹配 uid 形态）：AAD purpose 正确但载荷字段不符 → invalid_request。
func TestRegistrationTokenRejectsWrongPayloadPurpose(t *testing.T) {
	codec := testCodec(t)
	base := func() *token.ChallengeTokenPayload {
		return &token.ChallengeTokenPayload{
			BizPurpose:  "webauthn_enroll",
			SubjectKind: "uid",
			Subject:     "42",
			Nonce:       randomChallenge(t),
			Operation:   "webauthn_register",
			Iat:         fixedNow.Unix(),
			Exp:         fixedNow.Add(120 * time.Second).Unix(),
		}
	}
	cases := []struct {
		name string
		mut  func(*token.ChallengeTokenPayload)
	}{
		{"wrong biz_purpose", func(p *token.ChallengeTokenPayload) { p.BizPurpose = "mfa" }},
		{"wrong operation", func(p *token.ChallengeTokenPayload) { p.Operation = "webauthn_login" }},
		{"wrong subject_kind", func(p *token.ChallengeTokenPayload) { p.SubjectKind = "tid" }},
		{"subject not uid", func(p *token.ChallengeTokenPayload) { p.Subject = "tid-1" }},
		{"subject zero", func(p *token.ChallengeTokenPayload) { p.Subject = "0" }},
		{"empty nonce", func(p *token.ChallengeTokenPayload) { p.Nonce = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base()
			tc.mut(p)
			tok, err := codec.Seal(security.PurposeWebAuthn, p)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if _, _, status := parseRegistrationToken(codec, tok, fixedNow); status != StatusInvalidRequest {
				t.Fatalf("status = %q, want invalid_request", status)
			}
		})
	}
}

func TestRegistrationAttestationChecks(t *testing.T) {
	a := newTestAuthenticator(t)
	codec := testCodec(t)
	f := newTestFactor(t, codec, &fakeStore{}, &fakeQueue{}, func() time.Time { return fixedNow })
	ch, err := f.BeginRegistration(42, "alice")
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
