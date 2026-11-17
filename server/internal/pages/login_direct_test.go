// login_direct_test.go /sso/login 已登录直达单测（接口文档 §8「/sso/login
// 已登录直达」专段、§2.1「已登录不渲染空壳」口径）：有效会话按终点顺序
// 302——① returnTo 白名单内回跳（优先于应用默认回跳）② 白名单外 / 未携带
// 回落 sso 应用 default_redirect_uri（须命中本应用 redirectUris 白名单）
// ③ 默认落点 /account#/；无会话 / 校验异常 / epoch 失效一律渲染空壳
// （安全向 fail-closed）；register / reset / callback 不做直达。
package pages

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	clientpb "authloft/gen/go/client"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// ssoDirectAppRow 组装带回调白名单与默认回跳的 sso_client 行（redirect_uris
// 经 repo 唯一编解码出口序列化；patterns nil = 不设白名单列）。行默认启用
// （IsEnabled=1，终点② 仅命中已启用应用）；禁用场景由用例显式置 0。
func ssoDirectAppRow(t *testing.T, clientID string, patterns []string, defaultURI string) *model.SsoClient {
	t.Helper()
	row := ssoAppRow(t, clientID, clientID+" 应用", nil, nil, nil)
	if patterns != nil {
		uris, err := repo.MarshalClientRedirectUris(&clientpb.ClientRedirectUris{Uris: patterns})
		if err != nil {
			t.Fatalf("marshal redirect uris: %v", err)
		}
		row.RedirectURIs = uris
	}
	row.DefaultRedirectURI = defaultURI
	row.IsEnabled = 1
	return row
}

// loginWithSession 有效会话 + al_session Cookie 发 GET（直达判定读 al_session，
// 同 authorize 会话判定出口）。
func loginWithSession(t *testing.T, f *fixture, target string) *httptest.ResponseRecorder {
	t.Helper()
	f.sessions.p = validSession()
	return doGetWithCookie(t, f.engine(t), target, "al_session", "session-token")
}

// assertShell 空壳渲染断言：200 + 无 Location（未直达）+ INIT 注入在场。
func assertShell(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 空壳（body %s）", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "" {
		t.Errorf("Location = %q, want 空（不直达）", got)
	}
	if !strings.Contains(rec.Body.String(), "window.__AUTHLOFT_INIT__") {
		t.Error("body 缺 INIT 注入，未按空壳渲染")
	}
}

// assertRedirect 直达断言：302 + Location 精确命中。
func assertRedirect(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302（body %s）", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

// TestLoginDirectReturnToWhitelisted 终点①：白名单内 returnTo 原值回跳，
// 优先于应用默认回跳（①②同场时按顺序取①）。
func TestLoginDirectReturnToWhitelisted(t *testing.T) {
	f := newFixture(t)
	f.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{
		"app": ssoDirectAppRow(t, "app", []string{"https://app.example.com/cb"}, "https://app.example.com/cb"),
	}}
	rec := loginWithSession(t, f, "/sso/login?client_id=app&returnTo="+url.QueryEscape("/account#/security"))
	assertRedirect(t, rec, "/account#/security")

	rec = loginWithSession(t, f, "/sso/login?returnTo="+url.QueryEscape("/admin#/users"))
	assertRedirect(t, rec, "/admin#/users")
}

// TestLoginDirectReturnToRejectedFallsToAppDefault 白名单拒绝回落②：站外
// URL / 缺 # 的近似前缀 / 白名单外站内路径一律不放行，按顺序落 sso 应用
// default_redirect_uri。
func TestLoginDirectReturnToRejectedFallsToAppDefault(t *testing.T) {
	const appDefault = "https://app.example.com/cb"
	for _, rt := range []string{
		"https://evil.example/phish",
		"/admin",
		"/other#/page",
		"//evil.example",
	} {
		f := newFixture(t)
		f.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{
			"app": ssoDirectAppRow(t, "app", []string{appDefault}, appDefault),
		}}
		rec := loginWithSession(t, f, "/sso/login?client_id=app&returnTo="+url.QueryEscape(rt))
		assertRedirect(t, rec, appDefault)
	}
}

// TestLoginDirectDefaultLanding 终点③：直登（无 returnTo 无应用）默认落点；
// 应用命中但 default_redirect_uri 为空 / 未命中本应用 redirectUris 白名单
// （配置漂移防线）也回落默认落点。
func TestLoginDirectDefaultLanding(t *testing.T) {
	t.Run("direct no returnTo no app", func(t *testing.T) {
		rec := loginWithSession(t, newFixture(t), "/sso/login")
		assertRedirect(t, rec, loginDefaultLanding)
	})
	t.Run("app default empty", func(t *testing.T) {
		f := newFixture(t)
		f.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{
			"app": ssoDirectAppRow(t, "app", []string{"https://app.example.com/cb"}, ""),
		}}
		rec := loginWithSession(t, f, "/sso/login?client_id=app")
		assertRedirect(t, rec, loginDefaultLanding)
	})
	t.Run("app default off whitelist", func(t *testing.T) {
		f := newFixture(t)
		f.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{
			"app": ssoDirectAppRow(t, "app", []string{"https://app.example.com/cb"}, "https://other.example/cb"),
		}}
		rec := loginWithSession(t, f, "/sso/login?client_id=app")
		assertRedirect(t, rec, loginDefaultLanding)
	})
	t.Run("app disabled", func(t *testing.T) {
		f := newFixture(t)
		row := ssoDirectAppRow(t, "app", []string{"https://app.example.com/cb"}, "https://app.example.com/cb")
		row.IsEnabled = 0
		f.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{"app": row}}
		rec := loginWithSession(t, f, "/sso/login?client_id=app")
		assertRedirect(t, rec, loginDefaultLanding)
	})
	t.Run("app default redirect_uris undecodable", func(t *testing.T) {
		f := newFixture(t)
		row := ssoDirectAppRow(t, "app", []string{"https://app.example.com/cb"}, "https://app.example.com/cb")
		row.RedirectURIs = []byte("not-proto-bytes")
		f.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{"app": row}}
		rec := loginWithSession(t, f, "/sso/login?client_id=app")
		assertRedirect(t, rec, loginDefaultLanding)
	})
}

// TestLoginDirectNoSessionRendersShell 无会话渲染空壳：不 302、照常按 §2.1
// 注入（含白名单内 returnTo 同样渲染——会话无效时 returnTo 不参与判定）。
func TestLoginDirectNoSessionRendersShell(t *testing.T) {
	f := newFixture(t)
	f.sessions.p = nil
	rec := doGet(t, f.engine(t), "/sso/login?returnTo="+url.QueryEscape("/account#/security"))
	assertShell(t, rec)
	if !strings.Contains(initJSON(t, rec.Body.String()), `"methods"`) {
		t.Error("INIT 缺 methods 快照，未按 §2.1 注入")
	}
}

// TestLoginDirectVerifyErrorRendersShell 校验故障渲染空壳（安全向）：校验链
// 异常按无会话处理，不 302、不渲染错误页。
func TestLoginDirectVerifyErrorRendersShell(t *testing.T) {
	f := newFixture(t)
	f.sessions.err = errors.New("session store down")
	rec := doGetWithCookie(t, f.engine(t), "/sso/login", "al_session", "session-token")
	assertShell(t, rec)
}

// TestLoginDirectEpochInvalidRendersShell epoch 失效不直达：旧令牌属「非
// 有效」情形，按无会话处理照常渲染空壳。
func TestLoginDirectEpochInvalidRendersShell(t *testing.T) {
	f := newFixture(t)
	f.sessions.err = errors.New("session epoch stale")
	rec := doGetWithCookie(t, f.engine(t), "/sso/login", "al_session", "session-token")
	assertShell(t, rec)
}

// TestLoginDirectOnlyLoginRoute 仅本路由检测：register / reset / callback
// 有效会话仍恒渲染空壳；/sso/login 带 flow=register query 仍按路由直达
// （检测以路由为准，与快照 flow 无关）。
func TestLoginDirectOnlyLoginRoute(t *testing.T) {
	f := newFixture(t)
	f.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{
		"app": ssoDirectAppRow(t, "app", []string{"https://app.example.com/cb"}, "https://app.example.com/cb"),
	}}
	for _, target := range []string{
		"/sso/register?client_id=app",
		"/sso/reset",
		"/sso/oauth/callback/qq?client_id=app",
	} {
		rec := loginWithSession(t, f, target)
		assertShell(t, rec)
	}
	rec := loginWithSession(t, f, "/sso/login?flow=register")
	assertRedirect(t, rec, loginDefaultLanding)
}
