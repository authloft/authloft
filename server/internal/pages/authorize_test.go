// authorize_test.go GET /auth/authorize 测试（接口文档 §4.2 行
// 1059-1089）：参数错误 400 不跳转（含通配白名单 / 子域陷阱）、scope 非法
// 302 invalid_scope（state 两态）、prompt=none 无会话 302 login_required、
// 有会话 302 签码（fake 断言 UID/AMR/client_id/redirect_uri/scope/nonce/
// PKCE/auth_time）、state 缺失审计、无会话渲染登录空壳 + oidc 七键
// snake_case 注入 + URL 保持。
package pages

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	clientpb "authloft/gen/go/client"
	"authloft/gen/go/token"
	"authloft/internal/eventlog"
	"authloft/internal/oidc"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/service/orchestrator"
)

// fakeSessions SessionVerifier fake（fixture 持有指针，改 p / err 即生效）。
type fakeSessions struct {
	p   *token.SessionTokenPayload
	err error
}

func (f *fakeSessions) Verify(context.Context, string) (*token.SessionTokenPayload, error) {
	return f.p, f.err
}

// fakeCodes CodeIssuer fake：记录全部调用参数。
type fakeCodes struct {
	calls []orchestrator.OIDCIssue
	code  string
	err   error
}

func (f *fakeCodes) Issue(_ context.Context, in orchestrator.OIDCIssue) (string, error) {
	f.calls = append(f.calls, in)
	return f.code, f.err
}

// fakeAudit AuditSink fake。
type fakeAudit struct{ events []model.EventLog }

func (f *fakeAudit) PushEvent(ev model.EventLog) { f.events = append(f.events, ev) }

// multiClients 按 client_id 查行的 fake（fakeClients 忽略 clientID 参数，
// 不能表达「client 不存在」）。
type multiClients struct{ rows map[string]*model.OidcClient }

func (m multiClients) FindOidcClientByClientID(_ context.Context, id string) (*model.OidcClient, error) {
	return m.rows[id], nil
}

const (
	authzRedirect = "https://cb.example.com/cb"
	authzQ        = "/auth/authorize?client_id=demo-app&redirect_uri=" + `https%3A%2F%2Fcb.example.com%2Fcb`
)

// oidcRow 构造 oidc_client 行（redirect_uris 经 repo 唯一序列化出口）。
func oidcRow(t *testing.T, clientID string, enabled int8, patterns ...string) *model.OidcClient {
	t.Helper()
	uris, err := repo.MarshalClientRedirectUris(&clientpb.ClientRedirectUris{Uris: patterns})
	if err != nil {
		t.Fatalf("marshal redirect uris: %v", err)
	}
	return &model.OidcClient{ClientID: clientID, RedirectURIs: uris, IsEnabled: enabled}
}

// newAuthzFixture authorize 夹具：demo-app 白名单 = 精确 cb URI + app 域
// 通配一条（覆盖整段与通配两形态），默认无会话。
func newAuthzFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	row := oidcRow(t, "demo-app", 1, authzRedirect, "https://app.example.com/*")
	f.deps.Clients = multiClients{rows: map[string]*model.OidcClient{"demo-app": row}}
	return f
}

// validSession 有会话载荷（uid=42、amr=[pwd otp]、iat=1700000000）。
func validSession() *token.SessionTokenPayload {
	return &token.SessionTokenPayload{Id: 42, Epoch: 3, Amr: []string{"pwd", "otp"}, Sid: "s-1", Iat: 1700000000, Exp: 4102444800}
}

// doGetWithCookie 带 Cookie 的 GET（authorize 会话判定读 al_session）。
func doGetWithCookie(t *testing.T, r http.Handler, target, cookieName, cookieValue string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// oidcFromInit 从 INIT JSON 提取 oidc 注入体为 map（键集 + 值断言用）。
func oidcFromInit(t *testing.T, body string) map[string]string {
	t.Helper()
	var init struct {
		OIDC map[string]string `json:"oidc"`
	}
	if err := json.Unmarshal([]byte(initJSON(t, body)), &init); err != nil {
		t.Fatalf("unmarshal init: %v", err)
	}
	if init.OIDC == nil {
		t.Fatalf("init missing oidc: %s", initJSON(t, body))
	}
	return init.OIDC
}

// assertNoIssue 断言零签发、零审计（错误路径不得有副作用）。
func assertNoIssue(t *testing.T, f *fixture) {
	t.Helper()
	if len(f.codes.calls) != 0 {
		t.Errorf("codes called %d times, want 0", len(f.codes.calls))
	}
	if len(f.audit.events) != 0 {
		t.Errorf("audit pushed %d events, want 0", len(f.audit.events))
	}
}

// TestAuthorizeParamErrorsNoRedirect 参数错误全矩阵（§4.2 行 1071-1073）：
// 任一不通过都不跳转（无 Location）、400 简短错误页（无 __AUTHLOFT_INIT__、
// 无 entry.js）、no-store、零签发零审计。
func TestAuthorizeParamErrorsNoRedirect(t *testing.T) {
	f := newAuthzFixture(t)
	r := f.engine(t)

	cases := []struct {
		name   string
		target string
	}{
		{"missing client_id", "/auth/authorize?redirect_uri=" + `https%3A%2F%2Fcb.example.com%2Fcb`},
		{"missing redirect_uri", "/auth/authorize?client_id=demo-app"},
		{"client not found", "/auth/authorize?client_id=ghost&redirect_uri=" + `https%3A%2F%2Fcb.example.com%2Fcb`},
		{"redirect not whitelisted", "/auth/authorize?client_id=demo-app&redirect_uri=" + `https%3A%2F%2Fevil.example.com%2Fcb`},
		{"subdomain trap rejected", "/auth/authorize?client_id=demo-app&redirect_uri=" + `https%3A%2F%2Fcb.example.com.evil.com%2Fcb`},
	}
	for _, tc := range cases {
		rec := doGet(t, r, tc.target)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", tc.name, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("%s: Location = %q, want 空（不跳转，防开放重定向）", tc.name, loc)
		}
		body := rec.Body.String()
		if strings.Contains(body, "__AUTHLOFT_INIT__") || strings.Contains(body, "entry.js") {
			t.Errorf("%s: 错误页不得渲染 SPA 空壳:\n%s", tc.name, body)
		}
		if strings.Contains(body, "demo-app") || strings.Contains(body, "cb.example.com") {
			t.Errorf("%s: 错误页不得回显请求参数:\n%s", tc.name, body)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", tc.name, got)
		}
	}
	assertNoIssue(t, f)
}

// TestAuthorizeDisabledClientRejected client 未启用（IsEnabled=0）→ 400
// 不跳转（§4.2 行 1073「不存在 / 未启用」）。
func TestAuthorizeDisabledClientRejected(t *testing.T) {
	f := newAuthzFixture(t)
	f.deps.Clients = multiClients{rows: map[string]*model.OidcClient{
		"demo-app": oidcRow(t, "demo-app", 0, authzRedirect),
	}}
	rec := doGet(t, f.engine(t), authzQ)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want 空", loc)
	}
	assertNoIssue(t, f)
}

// TestAuthorizeInvalidScopeRedirects scope 含未支持值 → 302
// error=invalid_scope（redirect_uri 校验通过后才发生，§4.2 行 1075）；
// state 带 / 不带两态；零签发零审计。
func TestAuthorizeInvalidScopeRedirects(t *testing.T) {
	f := newAuthzFixture(t)
	r := f.engine(t)

	rec := doGet(t, r, authzQ+"&scope="+url.QueryEscape("openid read")+"&state=st1")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), authzRedirect+"?error=invalid_scope&state=st1"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}

	rec = doGet(t, r, authzQ+"&scope=read")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), authzRedirect+"?error=invalid_scope"; got != want {
		t.Errorf("Location = %q, want %q（state 缺失省略）", got, want)
	}
	assertNoIssue(t, f)
}

// TestAuthorizePromptNoneNoSession prompt=none 且无有效会话 → 302
// error=login_required、不渲染空壳（§4.2 行 1076）；state 带 / 不带两态；
// 多值 prompt（"none login"）none 生效；prompt=login 忽略 → 渲染空壳。
func TestAuthorizePromptNoneNoSession(t *testing.T) {
	f := newAuthzFixture(t)
	r := f.engine(t)

	rec := doGet(t, r, authzQ+"&prompt=none&state=st1")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), authzRedirect+"?error=login_required&state=st1"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}

	rec = doGet(t, r, authzQ+"&prompt=none")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), authzRedirect+"?error=login_required"; got != want {
		t.Errorf("Location = %q, want %q（state 缺失省略）", got, want)
	}

	rec = doGet(t, r, authzQ+"&prompt="+url.QueryEscape("none login"))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "error=login_required") {
		t.Errorf("prompt 多值含 none: status = %d Location = %q, want 302 login_required", rec.Code, rec.Header().Get("Location"))
	}
	assertNoIssue(t, f)

	// prompt=login 忽略（不支持强制重认证）→ 渲染空壳。
	rec = doGet(t, r, authzQ+"&prompt=login")
	if rec.Code != http.StatusOK {
		t.Fatalf("prompt=login: status = %d, want 200（忽略，渲染空壳）", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "entry.js") {
		t.Error("prompt=login: 应渲染登录空壳")
	}
}

// TestAuthorizeIssuesCodeWithSession 有有效会话 → 302 code=…&state=…（§4.2
// 行 1080：不渲染页面、不经过前端）；fake 断言签发参数 UID/AMR/client_id/
// redirect_uri/scope/nonce/PKCE/auth_time（amr、auth_time 取会话载荷）；
// state 存在时零审计；scope 缺省补 DefaultScope。
func TestAuthorizeIssuesCodeWithSession(t *testing.T) {
	f := newAuthzFixture(t)
	f.sessions.p = validSession()
	r := f.engine(t)

	target := authzQ +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=st1&nonce=n1&code_challenge=cc123&code_challenge_method=S256"
	rec := doGetWithCookie(t, r, target, "al_session", "session-token")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), authzRedirect+"?code=AUTHZ-CODE&state=st1"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if len(f.codes.calls) != 1 {
		t.Fatalf("codes called %d times, want 1", len(f.codes.calls))
	}
	in := f.codes.calls[0]
	if in.ClientID != "demo-app" || in.RedirectURI != authzRedirect {
		t.Errorf("client_id/redirect_uri = %q/%q", in.ClientID, in.RedirectURI)
	}
	if in.Scope != "openid profile" {
		t.Errorf("scope = %q, want %q", in.Scope, "openid profile")
	}
	if in.Nonce != "n1" {
		t.Errorf("nonce = %q, want n1", in.Nonce)
	}
	if in.CodeChallenge != "cc123" || in.CodeChallengeMethod != "S256" {
		t.Errorf("PKCE = %q/%q, want cc123/S256", in.CodeChallenge, in.CodeChallengeMethod)
	}
	if in.UID != 42 {
		t.Errorf("uid = %d, want 42", in.UID)
	}
	if len(in.AMR) != 2 || in.AMR[0] != "pwd" || in.AMR[1] != "otp" {
		t.Errorf("amr = %v, want [pwd otp]（取会话载荷）", in.AMR)
	}
	if in.AuthTime != 1700000000 {
		t.Errorf("auth_time = %d, want 1700000000（取会话 iat）", in.AuthTime)
	}
	if len(f.audit.events) != 0 {
		t.Errorf("state 存在时审计 %d 条, want 0", len(f.audit.events))
	}

	// scope 缺省 → DefaultScope（§4.2 行 1065）。
	f.codes.calls = nil
	rec = doGetWithCookie(t, r, authzQ+"&state=st2", "al_session", "session-token")
	if rec.Code != http.StatusFound {
		t.Fatalf("scope 缺省: status = %d, want 302", rec.Code)
	}
	if len(f.codes.calls) != 1 || f.codes.calls[0].Scope != oidc.DefaultScope {
		t.Errorf("scope 缺省签发 = %+v, want DefaultScope %q", f.codes.calls, oidc.DefaultScope)
	}
}

// TestAuthorizePromptNoneWithSessionIssuesCode prompt=none + 有会话 →
// 照常签发 302 code（不 login_required，§4.2 行 1069）。
func TestAuthorizePromptNoneWithSessionIssuesCode(t *testing.T) {
	f := newAuthzFixture(t)
	f.sessions.p = validSession()
	rec := doGetWithCookie(t, f.engine(t), authzQ+"&prompt=none&state=st1", "al_session", "session-token")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), authzRedirect+"?code=AUTHZ-CODE&state=st1"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if len(f.codes.calls) != 1 {
		t.Errorf("codes called %d times, want 1", len(f.codes.calls))
	}
}

// TestAuthorizeNoStateAudits state 缺失：不拒绝、跳转不带 state、改记审计
// oidc_authorize_no_state（actor_type=system，§4.2 行 1074）。有会话（直签）
// 与无会话（空壳 → Terminal 登录后签发）两路径各记一条。
func TestAuthorizeNoStateAudits(t *testing.T) {
	f := newAuthzFixture(t)
	f.sessions.p = validSession()
	r := f.engine(t)

	// 有会话直签：302 不带 state + 恰一条审计。
	rec := doGetWithCookie(t, r, authzQ, "al_session", "session-token")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302（state 缺失不拒绝）", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), authzRedirect+"?code=AUTHZ-CODE"; got != want {
		t.Errorf("Location = %q, want %q（不带 state）", got, want)
	}
	if len(f.audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(f.audit.events))
	}
	ev := f.audit.events[0]
	if ev.Event != eventlog.EventOIDCAuthorizeNoState || ev.ActorType != eventlog.ActorTypeSystem {
		t.Errorf("event/actor_type = %q/%q, want oidc_authorize_no_state/system", ev.Event, ev.ActorType)
	}
	if ev.ActorID != 0 || ev.UserID != 0 {
		t.Errorf("actor_id/user_id = %d/%d, want 0/0（system=0）", ev.ActorID, ev.UserID)
	}
	if ev.ClientID != "demo-app" {
		t.Errorf("client_id = %q, want demo-app", ev.ClientID)
	}

	// 无会话空壳（Terminal 登录后签发路径）：同样恰一条（orchestrator 无
	// 该审计写点，本端点记账不双记）。
	f.sessions.p = nil
	f.audit.events = nil
	rec = doGet(t, r, authzQ)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200（空壳）", rec.Code)
	}
	if len(f.audit.events) != 1 {
		t.Errorf("audit events = %d, want 1", len(f.audit.events))
	}
}

// TestAuthorizeShellWithoutSession 无会话 → 渲染登录空壳（login entry、
// URL 保持 /auth/authorize——200 非 302 即证）；methods 必填 + oidc 七原始
// 参数原样注入（snake_case，§4.2 行 1081 / §8 行 1479）。
func TestAuthorizeShellWithoutSession(t *testing.T) {
	f := newAuthzFixture(t)
	target := authzQ +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=st1&nonce=n1&code_challenge=cc123&code_challenge_method=S256"
	rec := doGet(t, f.engine(t), target)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200（URL 保持 /auth/authorize 渲染空壳，非 302）", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `src="/assets/login/entry.js"`) {
		t.Errorf("缺 login entry.js 引用:\n%s", body)
	}
	init := initJSON(t, body)
	if !strings.Contains(init, `"methods"`) {
		t.Errorf("缺 methods 注入（§8 login 必填）: %s", init)
	}
	oidcInit := oidcFromInit(t, body)
	want := map[string]string{
		"client_id":             "demo-app",
		"redirect_uri":          authzRedirect,
		"scope":                 "openid profile",
		"state":                 "st1",
		"nonce":                 "n1",
		"code_challenge":        "cc123",
		"code_challenge_method": "S256",
	}
	if len(oidcInit) != len(want) {
		t.Errorf("oidc 键数 = %d, want %d（%v）", len(oidcInit), len(want), oidcInit)
	}
	for k, v := range want {
		if got, ok := oidcInit[k]; !ok || got != v {
			t.Errorf("oidc[%q] = %q,%v, want %q（snake_case 原样）", k, got, ok, v)
		}
	}
	if len(f.codes.calls) != 0 {
		t.Errorf("无会话不得签发: %d calls", len(f.codes.calls))
	}
}

// TestAuthorizeVerifyErrorTreatedAnonymous 会话校验失败（含 epoch 链故障）
// 一律按无有效会话：渲染空壳，不 500、不签发（安全向，见 authorizeSession）。
func TestAuthorizeVerifyErrorTreatedAnonymous(t *testing.T) {
	f := newAuthzFixture(t)
	f.sessions.err = errors.New("epoch chain failure")
	rec := doGetWithCookie(t, f.engine(t), authzQ+"&prompt=none", "al_session", "session-token")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 login_required", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "error=login_required") {
		t.Errorf("Location = %q, want login_required（故障 ≠ 已登录，保守语义）", rec.Header().Get("Location"))
	}
}

// TestAuthorizeRedirectURIWithQuery redirect_uri 自带 query（通配命中）：
// 302 参数以 & 追加、既有 query 字面保留。
func TestAuthorizeRedirectURIWithQuery(t *testing.T) {
	f := newAuthzFixture(t)
	f.sessions.p = validSession()
	target := "/auth/authorize?client_id=demo-app&redirect_uri=" +
		url.QueryEscape("https://app.example.com/cb?foo=1") + "&state=st1"
	rec := doGetWithCookie(t, f.engine(t), target, "al_session", "session-token")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), "https://app.example.com/cb?foo=1&code=AUTHZ-CODE&state=st1"; got != want {
		t.Errorf("Location = %q, want %q（既有 query 保留 + & 追加）", got, want)
	}
	if len(f.codes.calls) != 1 {
		t.Errorf("codes called %d times, want 1", len(f.codes.calls))
	}
}
