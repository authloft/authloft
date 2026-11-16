// terminal_test.go 登录终点默认回跳（接口文档 §1.3 终点处理与默认落点）：
// OIDC 授权码跳转优先、不受应用快照影响；非 OIDC 流快照 default_redirect_uri
// 非空时填 redirectTo；快照缺省 / 未配置回归既有空 redirectTo 行为；
// 多域名同步链 finalURL 随 redirectTo 自动随行。
package orchestrator

import (
	"context"
	"testing"

	"authloft/gen/go/token"
)

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
