package session

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"authloft/internal/security"
	sessionpkg "authloft/internal/session"
	"authloft/internal/settings"
)

// fakeEpoch 注入的 epoch reader：固定返回值或固定错误。
type fakeEpoch struct {
	epoch int64
	err   error
}

func (f fakeEpoch) Current(context.Context, int64) (int64, error) { return f.epoch, f.err }

// fakeSettings 注入的配置：仅应答 session_ttl。
type fakeSettings struct {
	ttl int64
	ok  bool
}

func (f fakeSettings) GetInt64(key string) (int64, bool) {
	if key != settings.KeySessionTtl {
		return 0, false
	}
	return f.ttl, f.ok
}

// staticProbe 登录签发侧探针 fake：固定返回 hasAny / err。
func staticProbe(hasAny bool, err error) func(context.Context, int64) (bool, error) {
	return func(context.Context, int64) (bool, error) { return hasAny, err }
}

// testTokens 构造可签发 / 解析的会话令牌入口（固定 32 字节 AES-256 密钥）。
func testTokens(t *testing.T) *sessionpkg.Tokens {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{
		ID:  security.KeyID{Version: 1, Kid: 1},
		Key: key,
	})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return sessionpkg.NewTokens(security.NewCodec(ks))
}

func fixedNow() time.Time { return time.Unix(1700000000, 0) }

func TestWriteRoundTrip(t *testing.T) {
	tokens := testTokens(t)
	w := NewSessionWriter(tokens, fakeEpoch{epoch: 7}, nil, staticProbe(false, nil))
	w.Now = fixedNow

	sid, tok, err := w.Write(context.Background(), 42, []string{"pwd", "otp"})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if sid == "" || tok == "" {
		t.Fatalf("empty result: sid=%q token=%q", sid, tok)
	}

	p, err := tokens.Parse(tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.GetId() != 42 {
		t.Errorf("id = %d, want 42", p.GetId())
	}
	if p.GetEpoch() != 7 {
		t.Errorf("epoch = %d, want 7", p.GetEpoch())
	}
	if got, want := p.GetAmr(), []string{"pwd", "otp"}; !reflect.DeepEqual(got, want) {
		t.Errorf("amr = %v, want %v", got, want)
	}
	if p.GetSid() != sid {
		t.Errorf("sid = %q, want %q", p.GetSid(), sid)
	}
	if p.GetIat() != fixedNow().Unix() {
		t.Errorf("iat = %d, want %d", p.GetIat(), fixedNow().Unix())
	}
	if want := fixedNow().Unix() + defaultSessionTTL; p.GetExp() != want {
		t.Errorf("exp = %d, want %d", p.GetExp(), want)
	}
}

func TestWriteTTLFromSettings(t *testing.T) {
	w := NewSessionWriter(testTokens(t), fakeEpoch{}, fakeSettings{ttl: 3600, ok: true}, staticProbe(false, nil))
	w.Now = fixedNow

	_, tok, err := w.Write(context.Background(), 1, nil)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	p, err := w.Tokens.Parse(tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if want := fixedNow().Unix() + 3600; p.GetExp() != want {
		t.Errorf("exp = %d, want %d", p.GetExp(), want)
	}
}

func TestWriteTTLFallback(t *testing.T) {
	cases := []struct {
		name string
		cfg  SessionSettings
	}{
		{"settings nil", nil},
		{"key missing", fakeSettings{ok: false}},
		{"zero", fakeSettings{ttl: 0, ok: true}},
		{"negative", fakeSettings{ttl: -1, ok: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := NewSessionWriter(testTokens(t), fakeEpoch{}, tc.cfg, staticProbe(false, nil))
			w.Now = fixedNow
			_, tok, err := w.Write(context.Background(), 1, nil)
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
			p, err := w.Tokens.Parse(tok)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if want := fixedNow().Unix() + defaultSessionTTL; p.GetExp() != want {
				t.Errorf("exp = %d, want %d", p.GetExp(), want)
			}
		})
	}
}

func TestWriteSIDUnique(t *testing.T) {
	w := NewSessionWriter(testTokens(t), fakeEpoch{}, nil, staticProbe(false, nil))
	w.Now = fixedNow

	sid1, _, err := w.Write(context.Background(), 1, nil)
	if err != nil {
		t.Fatalf("first Write: %v", err)
	}
	sid2, _, err := w.Write(context.Background(), 1, nil)
	if err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if sid1 == sid2 {
		t.Errorf("sid collision: %q", sid1)
	}
}

func TestWriteEpochErrorPropagates(t *testing.T) {
	sentinel := errors.New("epoch unavailable")
	w := NewSessionWriter(testTokens(t), fakeEpoch{err: sentinel}, nil, staticProbe(false, nil))

	_, _, err := w.Write(context.Background(), 1, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}
}

// TestWritePermissionProbe 登录签发侧探针的现算结果写进会话载荷（路径 A）。
func TestWritePermissionProbe(t *testing.T) {
	for _, hasAny := range []bool{false, true} {
		t.Run(fmt.Sprintf("hasAny=%v", hasAny), func(t *testing.T) {
			tokens := testTokens(t)
			w := NewSessionWriter(tokens, fakeEpoch{epoch: 7}, nil, staticProbe(hasAny, nil))
			w.Now = fixedNow
			_, tok, err := w.Write(context.Background(), 42, []string{"pwd"})
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
			p, err := tokens.Parse(tok)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if p.GetHasAnyPermission() != hasAny {
				t.Fatalf("HasAnyPermission = %v, want %v", p.GetHasAnyPermission(), hasAny)
			}
		})
	}
}

// TestWriteProbeErrorPropagates 探针故障与 epoch 读取对称：原样上抛，不签发会话。
func TestWriteProbeErrorPropagates(t *testing.T) {
	sentinel := errors.New("permission probe unavailable")
	w := NewSessionWriter(testTokens(t), fakeEpoch{}, nil, staticProbe(false, sentinel))

	_, _, err := w.Write(context.Background(), 1, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel", err)
	}
}

// TestWriteProbeUIDForward 探针收到 Write 的 uid，避免误用他人身份判定。
func TestWriteProbeUIDForward(t *testing.T) {
	var gotUID int64
	probe := func(_ context.Context, uid int64) (bool, error) { gotUID = uid; return true, nil }
	w := NewSessionWriter(testTokens(t), fakeEpoch{}, nil, probe)
	if _, _, err := w.Write(context.Background(), 99, nil); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if gotUID != 99 {
		t.Fatalf("probe uid = %d, want 99", gotUID)
	}
}
