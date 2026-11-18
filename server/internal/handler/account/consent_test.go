package account

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/gen/go/api/account/v1/accountv1connect"
	clientpb "authloft/gen/go/client"
	"authloft/gen/go/token"
	internalconnect "authloft/internal/connect"
	"authloft/internal/middleware"
	"authloft/internal/oidc"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	accountsvc "authloft/internal/service/account"
	"authloft/internal/service/orchestrator"
	"authloft/internal/session"
	"authloft/internal/settings"
)

// ── fakes ──────────────────────────────────────────────────────────────

type consentClients struct {
	client *model.OidcClient
	err    error
}

func (f *consentClients) FindOidcClientByClientID(_ context.Context, _ string) (*model.OidcClient, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.client == nil {
		return nil, errors.New("not found")
	}
	return f.client, nil
}

type consentGranter struct {
	calls    int
	uid      int64
	clientID string
	scopes   string
	err      error
}

func (f *consentGranter) Grant(_ context.Context, uid int64, clientID, scopes string) error {
	f.calls++
	f.uid, f.clientID, f.scopes = uid, clientID, scopes
	return f.err
}

type consentIssuer struct {
	calls int
	in    orchestrator.OIDCIssue
	code  string
}

func (f *consentIssuer) Issue(_ context.Context, in orchestrator.OIDCIssue) (string, error) {
	f.calls++
	f.in = in
	return f.code, nil
}

type consentSync struct {
	calls    int
	name     string
	value    string
	ttl      string
	domains  []string
	finalURL string
	out      string
}

func (f *consentSync) Build(_ context.Context, name, value, ttl string, domains []string, finalURL string) (string, error) {
	f.calls++
	f.name, f.value, f.ttl, f.domains, f.finalURL = name, value, ttl, domains, finalURL
	return f.out, nil
}

type consentSettings struct {
	strs   map[string]string
	slices map[string][]string
	ints   map[string]int64
}

func (f *consentSettings) GetString(k string) (string, bool) { v, ok := f.strs[k]; return v, ok }
func (f *consentSettings) GetStringSlice(k string) ([]string, bool) {
	v, ok := f.slices[k]
	return v, ok
}
func (f *consentSettings) GetInt64(k string) (int64, bool) { v, ok := f.ints[k]; return v, ok }

// ── helpers ────────────────────────────────────────────────────────────

func consentTestTokens(t *testing.T) *session.Tokens {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x20 + i)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return session.NewTokens(security.NewCodec(ks))
}

func consentTestClient(scopes string) *model.OidcClient {
	data, err := repo.MarshalClientRedirectUris(&clientpb.ClientRedirectUris{
		Uris: []string{"https://app.example.com/cb"},
	})
	if err != nil {
		panic(err)
	}
	return &model.OidcClient{
		ClientID: "app", RedirectURIs: data, Scopes: scopes, IsEnabled: 1,
	}
}

func consentCookie(t *testing.T, tokens *session.Tokens, uid int64, amr []string, iat int64) string {
	t.Helper()
	tok, err := tokens.Sign(&token.SessionTokenPayload{
		Id: uid, Epoch: 1, Amr: amr, Sid: "sid-1", Iat: iat,
		Exp: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return "al_session=" + tok
}

type consentDeps struct {
	authz    *oidc.AuthzValidator
	granter  *consentGranter
	issuer   *consentIssuer
	sync     *consentSync
	settings *consentSettings
}

func newConsentDeps(scopes string) *consentDeps {
	return &consentDeps{
		authz:    &oidc.AuthzValidator{Clients: &consentClients{client: consentTestClient(scopes)}},
		granter:  &consentGranter{},
		issuer:   &consentIssuer{code: "code-123"},
		sync:     &consentSync{out: "https://a.example.com/sso/sync_cookie?p=seal"},
		settings: &consentSettings{},
	}
}

func (d *consentDeps) service() *accountsvc.ConsentService {
	return accountsvc.NewConsentService(accountsvc.ConsentDeps{
		Authz: d.authz, Consents: d.granter, Codes: d.issuer,
		Sync: d.sync, Settings: d.settings,
	})
}

// consentEpoch 与 consentCookie 签发的 epoch 一致（见 consentCookie）。
type consentEpoch struct{}

func (consentEpoch) Current(_ context.Context, _ int64) (int64, error) { return 1, nil }

func newConsentHandler(t *testing.T, d *consentDeps) *ConsentHandler {
	t.Helper()
	tokens := consentTestTokens(t)
	verifier := session.NewVerifier(tokens, consentEpoch{})
	return NewConsentHandler(&Handler{}, d.service(), &HeaderClaimsReader{Verifier: verifier})
}

func approveRequest() *connect.Request[accountv1.ConsentApproveRequest] {
	return connect.NewRequest(&accountv1.ConsentApproveRequest{
		ClientId: "app", RedirectUri: "https://app.example.com/cb",
		Scope: "openid profile", SelectedScope: "openid profile",
		State: "xyz", Nonce: "n-1", CodeChallenge: "ch", CodeChallengeMethod: "S256",
	})
}

func assertConsentErrorInfo(t *testing.T, err error, wantCode connect.Code, wantDetail string) {
	t.Helper()
	var coded *connect.Error
	if !errors.As(err, &coded) {
		t.Fatalf("err = %v, want *connect.Error", err)
	}
	if coded.Code() != wantCode {
		t.Fatalf("connect code = %v, want %v", coded.Code(), wantCode)
	}
	info, ok := internalconnect.ErrorInfoOf(err)
	if !ok {
		t.Fatalf("no ErrorInfo detail in err: %v", err)
	}
	if info.GetCode() != wantDetail {
		t.Fatalf("ErrorInfo.code = %q, want %q", info.GetCode(), wantDetail)
	}
	if info.GetDomain() != "account" {
		t.Fatalf("ErrorInfo.domain = %q, want account", info.GetDomain())
	}
}

// ── 五类验收用例 ───────────────────────────────────────────────────────

// scope 超集：请求 scope 超出客户端注册集 / 勾选集超出请求集，均映射
// invalid_argument + ErrorInfo.code=invalid_scope，且不写记录、不签码。
func TestConsentApproveScopeSupersetInvalidScope(t *testing.T) {
	cases := []struct {
		name     string
		scope    string
		selected string
	}{
		{"请求 scope 超注册集", "openid profile email", "openid profile"},
		{"勾选集超请求 scope", "openid profile", "openid profile email"},
		{"勾选集缺 openid", "openid profile", "profile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newConsentDeps("openid,profile")
			h := newConsentHandler(t, d)
			req := approveRequest()
			req.Msg.Scope = tc.scope
			req.Msg.SelectedScope = tc.selected
			req.Header().Set("Cookie", consentCookie(t, consentTestTokens(t), 10086, []string{"pwd"}, 1700000000))

			_, err := h.ConsentApprove(context.Background(), req)
			assertConsentErrorInfo(t, err, connect.CodeInvalidArgument, "invalid_scope")
			if d.granter.calls != 0 || d.issuer.calls != 0 {
				t.Fatalf("scope 超集后仍写记录 / 签码: grant=%d issue=%d", d.granter.calls, d.issuer.calls)
			}
		})
	}
}

// 无会话：请求无有效会话 cookie / header → unauthenticated，且不触达编排。
func TestConsentApproveUnauthenticated(t *testing.T) {
	d := newConsentDeps("openid,profile")
	h := newConsentHandler(t, d)

	_, err := h.ConsentApprove(context.Background(), approveRequest())
	var coded *connect.Error
	if !errors.As(err, &coded) || coded.Code() != connect.CodeUnauthenticated {
		t.Fatalf("err = %v, want unauthenticated", err)
	}
	if d.granter.calls != 0 || d.issuer.calls != 0 || d.authz == nil {
		t.Fatalf("无会话仍触达编排: grant=%d issue=%d", d.granter.calls, d.issuer.calls)
	}
}

// 失效会话（过期 / epoch 不符）即使令牌可解也须 unauthenticated——证明走的是
// Verifier 四步校验而非仅解密，防止过期会话签码。
func TestConsentApproveStaleSessionUnauthenticated(t *testing.T) {
	d := newConsentDeps("openid,profile")
	h := newConsentHandler(t, d)
	tokens := consentTestTokens(t)

	expired, err := tokens.Sign(&token.SessionTokenPayload{
		Id: 10086, Epoch: 1, Amr: []string{"pwd"}, Sid: "sid-1",
		Iat: 1700000000, Exp: time.Now().Add(-time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("Sign expired: %v", err)
	}
	staleEpoch, err := tokens.Sign(&token.SessionTokenPayload{
		Id: 10086, Epoch: 99, Amr: []string{"pwd"}, Sid: "sid-1",
		Iat: 1700000000, Exp: time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("Sign stale: %v", err)
	}
	for name, tok := range map[string]string{"过期": expired, "epoch 不符": staleEpoch} {
		t.Run(name, func(t *testing.T) {
			req := approveRequest()
			req.Header().Set("Cookie", "al_session="+tok)
			_, err := h.ConsentApprove(context.Background(), req)
			var coded *connect.Error
			if !errors.As(err, &coded) || coded.Code() != connect.CodeUnauthenticated {
				t.Fatalf("err = %v, want unauthenticated", err)
			}
			if d.granter.calls != 0 || d.issuer.calls != 0 {
				t.Fatalf("失效会话仍触达编排: grant=%d issue=%d", d.granter.calls, d.issuer.calls)
			}
		})
	}
}

// 跨站 Origin → 403（挂载与生产同源的 HTTPOriginFunc）；同源请求不被拦截。
func TestConsentApproveCrossOriginForbidden(t *testing.T) {
	d := newConsentDeps("openid,profile")
	ch := newConsentHandler(t, d)
	_, inner := accountv1connect.NewAccountServiceHandler(ch)
	guarded := middleware.HTTPOriginFunc("https://auth.example.com", nil, inner)

	body := `{}`
	send := func(origin string) int {
		req := httptest.NewRequest(http.MethodPost, accountv1connect.AccountServiceConsentApproveProcedure, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := send("https://evil.example.com"); code != http.StatusForbidden {
		t.Fatalf("跨站 Origin 状态 = %d, want 403", code)
	}
	if code := send("https://auth.example.com"); code == http.StatusForbidden {
		t.Fatalf("同源 Origin 被误判 403")
	}
}

// deny：不写记录 / 不签码，落点拼 error=access_denied + state。
func TestConsentDenyAccessDenied(t *testing.T) {
	d := newConsentDeps("openid,profile")
	h := newConsentHandler(t, d)
	req := connect.NewRequest(&accountv1.ConsentDenyRequest{
		ClientId: "app", RedirectUri: "https://app.example.com/cb", State: "xyz",
	})
	req.Header().Set("Cookie", consentCookie(t, consentTestTokens(t), 10086, []string{"pwd"}, 1700000000))

	resp, err := h.ConsentDeny(context.Background(), req)
	if err != nil {
		t.Fatalf("ConsentDeny: %v", err)
	}
	want := "https://app.example.com/cb?error=access_denied&state=xyz"
	if got := resp.Msg.GetRedirectTo(); got != want {
		t.Fatalf("redirectTo = %q, want %q", got, want)
	}
	if resp.Msg.GetSyncCookieUrl() != "" {
		t.Fatalf("deny 不应返回 syncCookieUrl: %q", resp.Msg.GetSyncCookieUrl())
	}
	if d.granter.calls != 0 || d.issuer.calls != 0 {
		t.Fatalf("deny 不应写记录 / 签码: grant=%d issue=%d", d.granter.calls, d.issuer.calls)
	}
}

// 写记录 + 签码：断言 Grant 写勾选集、Issue 载荷取 selected scope / 会话 uid/amr/auth_time、
// 落点带 code 与 state。
func TestConsentApproveGrantAndIssue(t *testing.T) {
	d := newConsentDeps("openid,profile,email")
	h := newConsentHandler(t, d)
	req := approveRequest()
	req.Msg.Scope = "openid profile email"
	req.Msg.SelectedScope = "profile openid"
	req.Header().Set("X-Authloft-Token", strings.TrimPrefix(
		consentCookie(t, consentTestTokens(t), 10086, []string{"pwd", "otp"}, 1700000123), "al_session="))

	resp, err := h.ConsentApprove(context.Background(), req)
	if err != nil {
		t.Fatalf("ConsentApprove: %v", err)
	}
	if d.granter.calls != 1 || d.granter.uid != 10086 || d.granter.clientID != "app" || d.granter.scopes != "profile openid" {
		t.Fatalf("Grant 记录不符: calls=%d uid=%d client=%q scopes=%q", d.granter.calls, d.granter.uid, d.granter.clientID, d.granter.scopes)
	}
	if d.issuer.calls != 1 {
		t.Fatalf("Issue calls = %d, want 1", d.issuer.calls)
	}
	in := d.issuer.in
	if in.Scope != "profile openid" || in.UID != 10086 || in.AuthTime != 1700000123 ||
		len(in.AMR) != 2 || in.AMR[0] != "pwd" || in.AMR[1] != "otp" ||
		in.CodeChallenge != "ch" || in.CodeChallengeMethod != "S256" || in.Nonce != "n-1" {
		t.Fatalf("Issue 载荷不符: %+v", in)
	}
	want := "https://app.example.com/cb?code=code-123&state=xyz"
	if got := resp.Msg.GetRedirectTo(); got != want {
		t.Fatalf("redirectTo = %q, want %q", got, want)
	}
}

// 多域名同步分支：sso_domains 非空时填 syncCookieUrl 并断言 Build 入参；
// sso_domains 为空时省略同步。
func TestConsentApproveSyncCookieURLBranch(t *testing.T) {
	t.Run("多域名填首跳", func(t *testing.T) {
		d := newConsentDeps("openid,profile")
		d.settings.slices = map[string][]string{
			settings.KeySsoDomains: {"https://a.example.com", "https://b.example.com"},
		}
		d.settings.strs = map[string]string{settings.KeyCookieName: "al_session"}
		d.settings.ints = map[string]int64{settings.KeySessionTtl: 604800}
		h := newConsentHandler(t, d)
		req := approveRequest()
		tok := consentCookie(t, consentTestTokens(t), 10086, []string{"pwd"}, 1700000000)
		req.Header().Set("Cookie", tok)

		resp, err := h.ConsentApprove(context.Background(), req)
		if err != nil {
			t.Fatalf("ConsentApprove: %v", err)
		}
		if d.sync.calls != 1 {
			t.Fatalf("Sync.Build calls = %d, want 1", d.sync.calls)
		}
		if d.sync.name != "al_session" || d.sync.ttl != "604800" ||
			len(d.sync.domains) != 2 || d.sync.domains[0] != "https://a.example.com" {
			t.Fatalf("Sync.Build 入参不符: %+v", d.sync)
		}
		if d.sync.value != strings.TrimPrefix(tok, "al_session=") {
			t.Fatalf("同步会话值不符: %q", d.sync.value)
		}
		wantFinal := "https://app.example.com/cb?code=code-123&state=xyz"
		if d.sync.finalURL != wantFinal {
			t.Fatalf("finalURL = %q, want %q", d.sync.finalURL, wantFinal)
		}
		if got := resp.Msg.GetSyncCookieUrl(); got != d.sync.out {
			t.Fatalf("syncCookieUrl = %q, want %q", got, d.sync.out)
		}
	})

	t.Run("无域名省略同步", func(t *testing.T) {
		d := newConsentDeps("openid,profile")
		h := newConsentHandler(t, d)
		req := approveRequest()
		req.Header().Set("Cookie", consentCookie(t, consentTestTokens(t), 10086, []string{"pwd"}, 1700000000))
		resp, err := h.ConsentApprove(context.Background(), req)
		if err != nil {
			t.Fatalf("ConsentApprove: %v", err)
		}
		if d.sync.calls != 0 {
			t.Fatalf("无 sso_domains 仍同步: calls=%d", d.sync.calls)
		}
		if resp.Msg.GetSyncCookieUrl() != "" {
			t.Fatalf("syncCookieUrl 应为空: %q", resp.Msg.GetSyncCookieUrl())
		}
	})
}
