// terminal_test.go 登录终点默认回跳（接口文档 §1.3 终点处理与默认落点）：
// OIDC 授权码跳转优先、不受应用快照影响；非 OIDC 流快照 default_redirect_uri
// 非空时填 redirectTo；快照缺省 / 未配置回归既有空 redirectTo 行为；
// 多域名同步链 finalURL 随 redirectTo 自动随行。
package orchestrator

import (
	"context"
	"errors"
	"testing"

	"authloft/gen/go/token"
)

// fakeConsentGranter 登录即同意授权记录写回 fake（形态 A 落点）；Grant 失败
// 由 Complete 按整体登录失败处理，不签码、不做旁路容错。
type fakeConsentGranter struct {
	err      error
	calls    int
	uid      int64
	clientID string
	scopes   string
}

func (f *fakeConsentGranter) Grant(_ context.Context, uid int64, clientID, scopes string) error {
	f.calls++
	f.uid, f.clientID, f.scopes = uid, clientID, scopes
	return f.err
}

// TestCompleteOIDCRedirectWinsOverSnapshot：OIDC 上下文在场时授权码跳转不被
// 快照默认回跳覆盖（fail-closed），同步链 finalURL 同样取 OIDC 跳转。
func TestCompleteOIDCRedirectWinsOverSnapshot(t *testing.T) {
	oidc := &lcOIDCIssuer{}
	sync := &lcSyncBuilder{}
	term := NewTerminal(&lcSessionWriter{}, oidc, &fakeLoginEvents{}, sync, fakeTerminalSettings{})
	success, err := term.Complete(context.Background(), &token.LoginTokenPayload{
		Tid: "tid-1", Uid: 42,
		Oidc: &token.Oidc{ClientId: "client-1", RedirectUri: "https://rp.example/cb", State: "st-1"},
		Sso:  &token.Sso{ClientId: "app-1", DefaultRedirectUri: "https://app.example/after"},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if success.RedirectTo != "https://rp.example/cb?code=code-1&state=st-1" {
		t.Fatalf("redirectTo = %q, want OIDC 授权码跳转", success.RedirectTo)
	}
	if oidc.calls != 1 {
		t.Fatalf("oidc issuer calls = %d, want 1", oidc.calls)
	}
	if sync.finalURL != success.RedirectTo {
		t.Fatalf("sync finalURL = %q, want 随 OIDC redirectTo", sync.finalURL)
	}
}

// TestCompleteDefaultRedirectFromSnapshot：无 OIDC + 快照 default 非空 →
// redirectTo = 应用默认回跳地址，OIDC 签发零调用；同步链 finalURL 随行
// （不改 sync 逻辑，Complete 只填 redirectTo）。
func TestCompleteDefaultRedirectFromSnapshot(t *testing.T) {
	oidc := &lcOIDCIssuer{}
	sync := &lcSyncBuilder{}
	term := NewTerminal(&lcSessionWriter{}, oidc, &fakeLoginEvents{}, sync, fakeTerminalSettings{})
	success, err := term.Complete(context.Background(), &token.LoginTokenPayload{
		Tid: "tid-1", Uid: 42,
		Sso: &token.Sso{ClientId: "app-1", DefaultRedirectUri: "https://app.example/after"},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if success.RedirectTo != "https://app.example/after" {
		t.Fatalf("redirectTo = %q, want 应用默认回跳地址", success.RedirectTo)
	}
	if oidc.calls != 0 {
		t.Fatalf("oidc issuer calls = %d, want 0", oidc.calls)
	}
	if sync.calls != 1 || sync.finalURL != "https://app.example/after" {
		t.Fatalf("sync calls = %d finalURL = %q, want finalURL 随默认回跳", sync.calls, sync.finalURL)
	}
}

// TestCompleteWithoutDefaultRedirect：无快照 / 快照在但 default 空两种形态
// 回归既有行为（redirectTo 空，前端落默认 /account#/profile）。
func TestCompleteWithoutDefaultRedirect(t *testing.T) {
	cases := map[string]*token.Sso{
		"无快照":        nil,
		"default 为空": {ClientId: "app-1"},
	}
	for name, sso := range cases {
		t.Run(name, func(t *testing.T) {
			oidc := &lcOIDCIssuer{}
			term := NewTerminal(&lcSessionWriter{}, oidc, &fakeLoginEvents{}, &lcSyncBuilder{}, fakeTerminalSettings{})
			success, err := term.Complete(context.Background(), &token.LoginTokenPayload{
				Tid: "tid-1", Uid: 42, Sso: sso,
			})
			if err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if success.RedirectTo != "" {
				t.Fatalf("redirectTo = %q, want 空（回归现状）", success.RedirectTo)
			}
			if oidc.calls != 0 {
				t.Fatalf("oidc issuer calls = %d, want 0", oidc.calls)
			}
		})
	}
}

// TestCompleteConsentGrantFailureFailsLogin 登录即同意（形态 A）Grant 写
// 授权记录失败即整体登录失败（评审裁决③：与会话写入同档硬失败）：Complete
// 返回错误、不签发授权码、不产出 redirectTo；Grant 以 uid/client_id/scope 入参
// 调用一次；成功对照 path 中 Grant 调用后照常签码。
func TestCompleteConsentGrantFailureFailsLogin(t *testing.T) {
	grantErr := errors.New("consent upsert failed")

	t.Run("Grant 失败整体登录失败", func(t *testing.T) {
		oidc := &lcOIDCIssuer{}
		granter := &fakeConsentGranter{err: grantErr}
		term := NewTerminal(&lcSessionWriter{}, oidc, &fakeLoginEvents{}, &lcSyncBuilder{}, fakeTerminalSettings{})
		term.Consents = granter
		success, err := term.Complete(context.Background(), &token.LoginTokenPayload{
			Tid: "tid-1", Uid: 42,
			Oidc: &token.Oidc{
				ClientId: "client-1", RedirectUri: "https://rp.example/cb",
				Scope: "openid profile", State: "st-1",
			},
		})
		if err == nil {
			t.Fatalf("Grant 失败应整体登录失败，got err = nil, success = %+v", success)
		}
		if success != nil {
			t.Errorf("Grant 失败不得返回 success: %+v", success)
		}
		if oidc.calls != 0 {
			t.Errorf("Grant 失败不得签码: oidc calls = %d, want 0", oidc.calls)
		}
		if granter.calls != 1 || granter.uid != 42 || granter.clientID != "client-1" || granter.scopes != "openid profile" {
			t.Errorf("Grant 入参 = calls:%d uid:%d clientID:%q scopes:%q, want 1/42/client-1/openid profile",
				granter.calls, granter.uid, granter.clientID, granter.scopes)
		}
	})

	t.Run("Grant 成功照常签码", func(t *testing.T) {
		oidc := &lcOIDCIssuer{}
		granter := &fakeConsentGranter{}
		term := NewTerminal(&lcSessionWriter{}, oidc, &fakeLoginEvents{}, &lcSyncBuilder{}, fakeTerminalSettings{})
		term.Consents = granter
		success, err := term.Complete(context.Background(), &token.LoginTokenPayload{
			Tid: "tid-1", Uid: 42,
			Oidc: &token.Oidc{
				ClientId: "client-1", RedirectUri: "https://rp.example/cb",
				Scope: "openid profile", State: "st-1",
			},
		})
		if err != nil {
			t.Fatalf("Grant 成功: %v", err)
		}
		if success == nil || success.RedirectTo != "https://rp.example/cb?code=code-1&state=st-1" {
			t.Errorf("success = %+v, want 签码跳转", success)
		}
		if granter.calls != 1 || oidc.calls != 1 {
			t.Errorf("Grant/签码 calls = %d/%d, want 1/1", granter.calls, oidc.calls)
		}
	})
}
