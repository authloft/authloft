package oidc

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
)

// ---- 内存 fake store：满足 oidc.Store 窄接口，不连 Redis----

type fakeStore struct {
	mu   sync.Mutex
	data map[string]string
}

func newFakeStore() *fakeStore { return &fakeStore{data: make(map[string]string)} }

func (s *fakeStore) Set(_ context.Context, code, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[code] = value
	return nil
}

// Consume 模拟 GETDEL：取到即删除，未命中返回 ok=false。
func (s *fakeStore) Consume(_ context.Context, code string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[code]
	if !ok {
		return "", false, nil
	}
	delete(s.data, code)
	return v, true, nil
}

func (s *fakeStore) put(code, value string) { _ = s.Set(context.Background(), code, value) }

// ---- 内存 KeyStore + 真实 Codec（纯本地 AES-256-GCM，不连外部服务）----

func newTestCodec(t *testing.T) *security.Codec {
	t.Helper()
	ks, err := security.NewKeyStore(security.KeyEntry{
		ID:  security.KeyID{Version: 1, Kid: 1},
		Key: []byte("0123456789abcdef0123456789abcdef"), // 32B
	})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return security.NewCodec(ks)
}

var baseTime = time.Unix(1_700_000_000, 0)

func newTestIssuer(t *testing.T) (*CodeIssuer, *fakeStore, *security.Codec) {
	t.Helper()
	store := newFakeStore()
	codec := newTestCodec(t)
	iss := NewCodeIssuer(store, codec)
	iss.Now = func() time.Time { return baseTime }
	return iss, store, codec
}

func sampleInput() orchestrator.OIDCIssue {
	return orchestrator.OIDCIssue{
		ClientID:            "client-1",
		RedirectURI:         "https://app.example/callback",
		Scope:               "openid profile email",
		Nonce:               "nonce-1",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		State:               "state-not-in-payload",
		UID:                 10086,
		AMR:                 []string{"pwd", "otp"},
		AuthTime:            baseTime.Unix() - 30,
	}
}

// TestIssueCodeConsumeRoundTrip 往返：11 字段逐一还原，iat/exp 取固定时钟，
// exp = iat + 120；OidcCodePayload 无 state 字段，in.State 天然不入载荷（§11.6.6）。
func TestIssueCodeConsumeRoundTrip(t *testing.T) {
	t.Parallel()
	iss, store, _ := newTestIssuer(t)
	in := sampleInput()

	code, err := iss.IssueCode(context.Background(), in)
	if err != nil {
		t.Fatalf("IssueCode: %v", err)
	}
	if code == "" {
		t.Fatal("empty code")
	}
	if v, ok := store.data[code]; !ok || v != code {
		t.Fatalf("store value = (%q, %v), want sealed code", v, ok)
	}

	got, err := iss.Consume(context.Background(), code)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.GetClientId() != in.ClientID ||
		got.GetRedirectUri() != in.RedirectURI ||
		got.GetUid() != in.UID ||
		got.GetScope() != in.Scope ||
		got.GetNonce() != in.Nonce ||
		got.GetCodeChallenge() != in.CodeChallenge ||
		got.GetCodeChallengeMethod() != in.CodeChallengeMethod ||
		got.GetAuthTime() != in.AuthTime ||
		got.GetIat() != baseTime.Unix() ||
		got.GetExp() != baseTime.Unix()+codeTTL {
		t.Fatalf("payload 11 字段不符: %+v", got)
	}
	if !reflect.DeepEqual(got.GetAmr(), in.AMR) {
		t.Fatalf("amr = %v, want %v", got.GetAmr(), in.AMR)
	}
}

// TestCodeIssuerSatisfiesOrchestrator 编译期 + 经接口调用验证：满足 OIDCCodeIssuer。
func TestCodeIssuerSatisfiesOrchestrator(t *testing.T) {
	t.Parallel()
	iss, _, _ := newTestIssuer(t)
	var issuer orchestrator.OIDCCodeIssuer = iss
	code, err := issuer.Issue(context.Background(), sampleInput())
	if err != nil {
		t.Fatalf("OIDCCodeIssuer.Issue: %v", err)
	}
	if _, err := iss.Consume(context.Background(), code); err != nil {
		t.Fatalf("Consume: %v", err)
	}
}

// TestConsumeExpired 过期：时间推进到 exp 之后，解封成功但 exp 校验拒绝。
func TestConsumeExpired(t *testing.T) {
	t.Parallel()
	iss, _, _ := newTestIssuer(t)
	code, err := iss.Issue(context.Background(), sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	iss.Now = func() time.Time { return baseTime.Add(121 * time.Second) }
	if _, err := iss.Consume(context.Background(), code); !errors.Is(err, ErrCodeExpired) {
		t.Fatalf("Consume 过期 = %v, want ErrCodeExpired", err)
	}
}

// TestConsumeTampered 篡改：翻转密文中间一个 base64 字符 → GCM tag 校验失败。
func TestConsumeTampered(t *testing.T) {
	t.Parallel()
	iss, store, codec := newTestIssuer(t)
	valid, err := codec.Seal(security.PurposeOidcCode, &token.OidcCodePayload{
		ClientId: "c", Iat: baseTime.Unix(), Exp: baseTime.Unix() + codeTTL,
	})
	if err != nil {
		t.Fatal(err)
	}
	i := len(valid) / 2
	repl := byte('A')
	if valid[i] == 'A' {
		repl = 'B'
	}
	tampered := valid[:i] + string([]byte{repl}) + valid[i+1:]
	store.put("tamper-code", tampered)

	if _, err := iss.Consume(context.Background(), "tamper-code"); err == nil || errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("篡改串应解封失败, got %v", err)
	}
}

// TestConsumeCrossPurpose 跨 purpose：用 login 的 AAD 封装，oidc_code 必解不开。
func TestConsumeCrossPurpose(t *testing.T) {
	t.Parallel()
	iss, store, codec := newTestIssuer(t)
	wrong, err := codec.Seal(security.PurposeLogin, &token.OidcCodePayload{
		ClientId: "c", Iat: baseTime.Unix(), Exp: baseTime.Unix() + codeTTL,
	})
	if err != nil {
		t.Fatal(err)
	}
	store.put("cross-code", wrong)
	if _, err := iss.Consume(context.Background(), "cross-code"); err == nil || errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("跨 purpose 串应解封失败, got %v", err)
	}
}

// TestConsumeOnce 重复消费：首次成功（GETDEL 删除），二次 not found。
func TestConsumeOnce(t *testing.T) {
	t.Parallel()
	iss, _, _ := newTestIssuer(t)
	code, err := iss.Issue(context.Background(), sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Consume(context.Background(), code); err != nil {
		t.Fatalf("首次 Consume: %v", err)
	}
	if _, err := iss.Consume(context.Background(), code); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("二次 Consume = %v, want ErrCodeNotFound", err)
	}
}
