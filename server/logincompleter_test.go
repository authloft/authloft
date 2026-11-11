package main

import (
	"context"
	"errors"
	"testing"

	"authloft/gen/go/token"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
	"authloft/internal/service/verification"
	"authloft/internal/settings"
)

// fakeSessionWriter Terminal 的会话写入 fake。
type fakeSessionWriter struct {
	uid   int64
	amr   []string
	calls int
}

func (f *fakeSessionWriter) Write(_ context.Context, uid int64, amr []string) (string, string, error) {
	f.calls++
	f.uid = uid
	f.amr = append([]string(nil), amr...)
	return "sid-1", "stok-1", nil
}

// fakeOIDCIssuer Terminal 的授权码签发 fake。
type fakeOIDCIssuer struct {
	in    orchestrator.OIDCIssue
	calls int
}

func (f *fakeOIDCIssuer) Issue(_ context.Context, in orchestrator.OIDCIssue) (string, error) {
	f.calls++
	f.in = in
	return "code-1", nil
}

// fakeLoginEvents Terminal 的登录事件投递 fake。
type fakeLoginEvents struct {
	ev    orchestrator.LoginEvent
	calls int
}

func (f *fakeLoginEvents) Record(_ context.Context, ev orchestrator.LoginEvent) error {
	f.calls++
	f.ev = ev
	return nil
}

// fakeSyncBuilder Terminal 的多域名同步链 fake。
type fakeSyncBuilder struct {
	finalURL string
	calls    int
}

func (f *fakeSyncBuilder) Build(_ context.Context, _, _, _ string, _ []string, finalURL string) (string, error) {
	f.calls++
	f.finalURL = finalURL
	return "https://sync.example/?x=1", nil
}

// fakeTerminalSettings Terminal 读取的 settings 窄接口。
type fakeTerminalSettings struct{}

func (fakeTerminalSettings) GetString(key string) (string, bool) {
	if key == settings.KeyCookieName {
		return "al_session", true
	}
	return "", false
}

func (fakeTerminalSettings) GetInt64(key string) (int64, bool) {
	if key == settings.KeySessionTtl {
		return 604800, true
	}
	return 0, false
}

func (fakeTerminalSettings) GetBool(string) (bool, bool) { return false, false }

func (fakeTerminalSettings) GetStringSlice(key string) ([]string, bool) {
	if key == settings.KeySsoDomains {
		return []string{"a.example"}, true
	}
	return nil, false
}

func newTestLoginState(t *testing.T) *orchestrator.State {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x11
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return orchestrator.NewState(security.NewCodec(ks))
}

func issueLoginToken(t *testing.T, state *orchestrator.State) string {
	t.Helper()
	tok, err := state.Issue(&token.LoginTokenPayload{
		Tid:    "tid-original",
		Flow:   "login",
		Factor: "otp_email",
		Passed: []string{"otp_email"},
		Amr:    []string{"otp_email"},
		Uid:    42,
		Oidc: &token.Oidc{
			ClientId:    "client-1",
			RedirectUri: "https://rp.example/cb",
			Scope:       "openid",
			State:       "st-1",
		},
	})
	if err != nil {
		t.Fatalf("Issue login token: %v", err)
	}
	return tok
}

func newTestLoginCompleter(t *testing.T, state *orchestrator.State, sessions *fakeSessionWriter, oidc *fakeOIDCIssuer, events *fakeLoginEvents, sync *fakeSyncBuilder) loginCompleter {
	t.Helper()
	return loginCompleter{
		terminal: orchestrator.NewTerminal(sessions, oidc, events, sync, fakeTerminalSettings{}),
		state:    state,
	}
}

// TestLoginCompleterRestoresOIDCContext：带 oidc 的 loginToken 恢复原流程
// 上下文——redirectTo 非空、syncCookieUrl 正常、会话 tid/amr 保留主因子并
// 追加二次因子。
func TestLoginCompleterRestoresOIDCContext(t *testing.T) {
	state := newTestLoginState(t)
	lt := issueLoginToken(t, state)
	sessions := &fakeSessionWriter{}
	oidc := &fakeOIDCIssuer{}
	events := &fakeLoginEvents{}
	sync := &fakeSyncBuilder{}
	completer := newTestLoginCompleter(t, state, sessions, oidc, events, sync)

	var sinkToken string
	ctx := orchestrator.WithSessionTokenSink(context.Background(), func(tok string) { sinkToken = tok })

	sess, err := completer.Complete(ctx, verification.Subject{Kind: verification.SubjectKindUID, ID: "42"}, lt, "totp")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if sess.RedirectTo != "https://rp.example/cb?code=code-1&state=st-1" {
		t.Fatalf("redirectTo = %q，OIDC 上下文未恢复", sess.RedirectTo)
	}
	if sess.SyncCookieURL != "https://sync.example/?x=1" || sync.calls != 1 {
		t.Fatalf("syncCookieUrl = %q calls = %d", sess.SyncCookieURL, sync.calls)
	}
	if sinkToken != "stok-1" {
		t.Fatalf("会话令牌写点 = %q, want stok-1", sinkToken)
	}
	wantAMR := []string{"otp_email", "totp"}
	if sessions.uid != 42 || !equalStrings(sessions.amr, wantAMR) {
		t.Fatalf("会话 uid/amr = %d/%v, want 42/%v", sessions.uid, sessions.amr, wantAMR)
	}
	if oidc.in.UID != 42 || !equalStrings(oidc.in.AMR, wantAMR) || oidc.in.ClientID != "client-1" {
		t.Fatalf("授权码入参 = %+v", oidc.in)
	}
	if events.ev.TID != "tid-original" || !equalStrings(events.ev.AMR, wantAMR) ||
		events.ev.ClientID != "client-1" || events.ev.SessionID != "sid-1" {
		t.Fatalf("登录事件 = %+v，tid/amr 失真", events.ev)
	}
}

// TestLoginCompleterRejectsContextMismatch：uid 与挑战 subject 不一致 /
// 解析失败 → ErrLoginContext（服务层据此判 verification_invalid），不建会话。
func TestLoginCompleterRejectsContextMismatch(t *testing.T) {
	state := newTestLoginState(t)
	lt := issueLoginToken(t, state)

	t.Run("uid 不一致", func(t *testing.T) {
		sessions := &fakeSessionWriter{}
		completer := newTestLoginCompleter(t, state, sessions, &fakeOIDCIssuer{}, &fakeLoginEvents{}, &fakeSyncBuilder{})
		_, err := completer.Complete(context.Background(), verification.Subject{Kind: verification.SubjectKindUID, ID: "43"}, lt, "totp")
		if !errors.Is(err, verification.ErrLoginContext) {
			t.Fatalf("err = %v, want ErrLoginContext", err)
		}
		if sessions.calls != 0 {
			t.Fatal("uid 不一致不得建会话")
		}
	})

	t.Run("解析失败", func(t *testing.T) {
		sessions := &fakeSessionWriter{}
		completer := newTestLoginCompleter(t, state, sessions, &fakeOIDCIssuer{}, &fakeLoginEvents{}, &fakeSyncBuilder{})
		_, err := completer.Complete(context.Background(), verification.Subject{Kind: verification.SubjectKindUID, ID: "42"}, "garbage", "totp")
		if !errors.Is(err, verification.ErrLoginContext) {
			t.Fatalf("err = %v, want ErrLoginContext", err)
		}
		if sessions.calls != 0 {
			t.Fatal("解析失败不得建会话")
		}
	})
}

// TestLoginCompleterWithoutLoginToken：非 OIDC / 纯直登场景仍可完成终点收尾，
// amr 只含本次二次因子。
func TestLoginCompleterWithoutLoginToken(t *testing.T) {
	state := newTestLoginState(t)
	sessions := &fakeSessionWriter{}
	oidc := &fakeOIDCIssuer{}
	events := &fakeLoginEvents{}
	sync := &fakeSyncBuilder{}
	completer := newTestLoginCompleter(t, state, sessions, oidc, events, sync)

	sess, err := completer.Complete(context.Background(), verification.Subject{Kind: verification.SubjectKindUID, ID: "42"}, "", "totp")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if sess.RedirectTo != "" || oidc.calls != 0 {
		t.Fatalf("无 OIDC 上下文不应产出 redirectTo: %q calls=%d", sess.RedirectTo, oidc.calls)
	}
	if sess.SyncCookieURL == "" || !equalStrings(sessions.amr, []string{"totp"}) || events.ev.TID != "42" {
		t.Fatalf("session=%+v amr=%v tid=%q", sess, sessions.amr, events.ev.TID)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
