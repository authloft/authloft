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

// consentDecideCall 记录一次 Decide 入参。
type consentDecideCall struct {
	uid                        int64
	clientID, reqScope, prompt string
}

// fakeConsents Consents fake：默认返回免同意（子集），即既有直签用例的行为；
// 新用例改 decision / err 即得形态 B / consent_required / 故障档。
type fakeConsents struct {
	decision oidc.Decision
	err      error
	calls    []consentDecideCall
}

func (f *fakeConsents) Decide(_ context.Context, uid int64, clientID, reqScope, prompt string) (oidc.Decision, error) {
	f.calls = append(f.calls, consentDecideCall{uid, clientID, reqScope, prompt})
	if f.err != nil {
		return oidc.Decision{}, f.err
	}
	base := f.decision
	if base == (oidc.Decision{}) {
		// 零值默认视作子集免同意（既有直签用例）。
		base = oidc.Decision{NeedsConsent: false}
	}
	// 与 oidc.ConsentService.Decide 同口径：prompt 精确为 consent 时强制
	// 需同意（即使 scope 为子集），pages 据返回的 NeedsConsent 渲染形态 B。
	if prompt == "consent" {
		base.NeedsConsent = true
	}
	return base, nil
}

// fakeProfiles ProfileReader fake：形态 B 账号摘要数据源。
type fakeProfiles struct {
	user *model.User
	err  error
}

func (f *fakeProfiles) FindByID(_ context.Context, _ int64) (*model.User, error) {
	return f.user, f.err
}

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
// 通配一条（覆盖整段与通配两形态），注册 scopes 为封闭集全集（既有用例
// scope 均为其子集），默认无会话；Authz 注入真实校验器（Clients 复用同一
// fake 行源，与 bootstrap 装配同构）。
func newAuthzFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	row := oidcRow(t, "demo-app", 1, authzRedirect, "https://app.example.com/*")
	row.Scopes = "openid,profile,email,phone,phone_plain,email_plain"
	f.deps.Clients = multiClients{rows: map[string]*model.OidcClient{"demo-app": row}}
	f.consents = &fakeConsents{} // 默认子集免同意（既有直签用例维持）
	f.profiles = &fakeProfiles{}
	f.deps.Consents = f.consents
	f.deps.Profiles = f.profiles
	f.deps.Authz = &oidc.AuthzValidator{Clients: f.deps.Clients}
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
	if !strings.Contains(rec.Body.String(), "window.__AUTHLOFT_INIT__") {
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
	if !strings.Contains(body, `src="/assets/`) {
		t.Errorf("缺 login 产物引用（static_base 前缀）:\n%s", body)
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
		"mode":                  "login",
		"client_name":           "",
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

// authzInit 从空壳 HTML 提取并反序列化 __AUTHLOFT_INIT__.oidc 为强类型
// （account 等嵌套对象用 oidcFromInit 的 map[string]string 无法解析）。
func authzInit(t *testing.T, body string) oidcAuthorizeInit {
	t.Helper()
	var init struct {
		OIDC oidcAuthorizeInit `json:"oidc"`
	}
	if err := json.Unmarshal([]byte(initJSON(t, body)), &init); err != nil {
		t.Fatalf("unmarshal init oidc: %v", err)
	}
	return init.OIDC
}

// TestAuthorizeConsentFormB 有会话 + 需同意 → 形态 B（§4.2 行 1452）：注入
// mode=consent + client_name + 账号摘要、不注入 methods（不 buildMethods）、
// 不签码；Decide 以有效 scope / uid / prompt 入参调用。
func TestAuthorizeConsentFormB(t *testing.T) {
	f := newAuthzFixture(t)
	f.sessions.p = validSession()
	f.consents.decision = oidc.Decision{NeedsConsent: true, PendingScopes: "profile"}
	email := "alice@example.com"
	f.profiles.user = &model.User{
		Username: "alice", Nickname: "爱丽丝", Email: &email,
		AvatarURL: "https://cdn.example/avatar.png",
	}
	row := oidcRow(t, "demo-app", 1, authzRedirect)
	row.Name = "Demo App"
	f.deps.Clients = multiClients{rows: map[string]*model.OidcClient{"demo-app": row}}

	rec := doGetWithCookie(t, f.engine(t),
		authzQ+"&scope="+url.QueryEscape("openid profile")+"&state=st1",
		"al_session", "session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200（渲染同意页空壳）", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "window.__AUTHLOFT_INIT__") {
		t.Fatal("同意页应渲染 SPA 空壳并注入 INIT")
	}
	if strings.Contains(initJSON(t, body), `"methods"`) {
		t.Error("形态 B 不得注入 methods（不 buildMethods）")
	}
	init := authzInit(t, body)
	if init.Mode != "consent" || init.ClientName != "Demo App" {
		t.Errorf("mode/client_name = %q/%q, want consent/Demo App", init.Mode, init.ClientName)
	}
	if init.Scope != "openid profile" {
		t.Errorf("scope = %q, want 有效 scope openid profile", init.Scope)
	}
	if init.Account == nil {
		t.Fatal("形态 B 缺 account 账号摘要注入")
	}
	if init.Account.Nickname != "爱丽丝" || init.Account.AvatarURL != "https://cdn.example/avatar.png" ||
		init.Account.Identifier != "a***@example.com" {
		t.Errorf("account = %+v, want 昵称/头像/掩码邮箱", init.Account)
	}
	if len(f.codes.calls) != 0 {
		t.Errorf("形态 B 不得签码: %d calls", len(f.codes.calls))
	}
	if len(f.consents.calls) != 1 {
		t.Fatalf("Decide calls = %d, want 1", len(f.consents.calls))
	}
	if got := f.consents.calls[0]; got.uid != 42 || got.clientID != "demo-app" ||
		got.reqScope != "openid profile" || got.prompt != "" {
		t.Errorf("Decide 入参 = %+v, want uid=42 clientID=demo-app scope=openid profile prompt=空", got)
	}
}

// TestAuthorizePromptNoneNonSubsetConsentRequired prompt=none + 有会话 +
// scope 非子集 → 302 consent_required、零交互不渲染（§4.2 行 1076 / 1453）。
func TestAuthorizePromptNoneNonSubsetConsentRequired(t *testing.T) {
	f := newAuthzFixture(t)
	f.sessions.p = validSession()
	f.consents.decision = oidc.Decision{NeedsConsent: true, PendingScopes: "profile"}
	r := f.engine(t)

	rec := doGetWithCookie(t, r,
		authzQ+"&scope="+url.QueryEscape("openid profile")+"&prompt=none&state=st1",
		"al_session", "session-token")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), authzRedirect+"?error=consent_required&state=st1"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if strings.Contains(rec.Body.String(), "window.__AUTHLOFT_INIT__") {
		t.Error("prompt=none 零交互：不得渲染任何页面")
	}
	if len(f.codes.calls) != 0 {
		t.Errorf("consent_required 不得签码: %d calls", len(f.codes.calls))
	}
	if len(f.consents.calls) != 1 || f.consents.calls[0].prompt != "none" {
		t.Errorf("Decide 应以 prompt=none 调用: %+v", f.consents.calls)
	}

	// state 缺失省略。
	f.consents.calls = nil
	rec = doGetWithCookie(t, r,
		authzQ+"&scope="+url.QueryEscape("openid profile")+"&prompt=none",
		"al_session", "session-token")
	if got, want := rec.Header().Get("Location"), authzRedirect+"?error=consent_required"; got != want {
		t.Errorf("Location = %q, want %q（state 缺失省略）", got, want)
	}
}

// TestAuthorizePromptConsentForcesFormB 子集（本应形态 C 直签）+ prompt=consent
// → 强制形态 B（§4.2 行 1438）：与无 prompt 的直签对照，证明强制来自 prompt。
func TestAuthorizePromptConsentForcesFormB(t *testing.T) {
	f := newAuthzFixture(t)
	f.sessions.p = validSession()
	// decision 零值 = 子集免同意；fake 按 oidc 内核口径在 prompt=consent 时强制需同意。
	r := f.engine(t)

	rec := doGetWithCookie(t, r, authzQ+"&scope=openid&prompt=consent&state=st1",
		"al_session", "session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("prompt=consent: status = %d, want 200（强制形态 B）", rec.Code)
	}
	init := authzInit(t, rec.Body.String())
	if init.Mode != "consent" {
		t.Errorf("mode = %q, want consent（子集 + prompt=consent 强制形态 B）", init.Mode)
	}
	if len(f.codes.calls) != 0 {
		t.Errorf("强制形态 B 不得签码: %d calls", len(f.codes.calls))
	}
	if len(f.consents.calls) != 1 || f.consents.calls[0].prompt != "consent" {
		t.Errorf("Decide 应以 prompt=consent 调用: %+v", f.consents.calls)
	}

	// 对照：同子集 scope 无 prompt → 形态 C 直签（证明强制来自 prompt=consent）。
	f.codes.calls = nil
	f.consents.calls = nil
	rec = doGetWithCookie(t, r, authzQ+"&scope=openid&state=st2", "al_session", "session-token")
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "code=AUTHZ-CODE") {
		t.Errorf("子集无 prompt: status = %d Location = %q, want 302 code（形态 C）",
			rec.Code, rec.Header().Get("Location"))
	}
}

// TestAuthorizeConsentSubsetDirectIssue 三态互斥正向：有会话 + 子集 scope +
// prompt≠consent → 形态 C 免同意直签（§4.2 行 1453），经 Decide 判定、
// 不渲染页面、不注入 mode=consent。
func TestAuthorizeConsentSubsetDirectIssue(t *testing.T) {
	f := newAuthzFixture(t)
	f.sessions.p = validSession()
	// 默认 fakeConsents{} 零值 = 子集免同意。
	rec := doGetWithCookie(t, f.engine(t),
		authzQ+"&scope=openid&state=st1", "al_session", "session-token")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302（形态 C 直签）", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), authzRedirect+"?code=AUTHZ-CODE&state=st1"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if strings.Contains(rec.Body.String(), "window.__AUTHLOFT_INIT__") {
		t.Error("形态 C 不渲染页面")
	}
	if len(f.codes.calls) != 1 {
		t.Fatalf("codes calls = %d, want 1", len(f.codes.calls))
	}
	if len(f.consents.calls) != 1 || f.consents.calls[0].reqScope != "openid" ||
		f.consents.calls[0].prompt != "" || f.consents.calls[0].uid != 42 {
		t.Errorf("Decide 入参 = %+v, want uid=42 scope=openid prompt=空（互斥判定经 Decide）", f.consents.calls)
	}
}

// TestAuthorizeEmptyScopeInjectsEffectiveScope 空 scope 请求 → 形态 A 空壳
// 注入缺省补值后的有效 scope（§4.2 补充口径 / 行 1457）：堵住静默扩权。
func TestAuthorizeEmptyScopeInjectsEffectiveScope(t *testing.T) {
	f := newAuthzFixture(t)
	rec := doGet(t, f.engine(t), authzQ) // 不带 scope
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200（形态 A 空壳）", rec.Code)
	}
	init := authzInit(t, rec.Body.String())
	if init.Mode != "login" {
		t.Errorf("mode = %q, want login", init.Mode)
	}
	if init.Scope != oidc.DefaultScope {
		t.Errorf("注入 scope = %q, want 有效 scope = DefaultScope %q（空请求补值）",
			init.Scope, oidc.DefaultScope)
	}
}

// TestAuthorizeFormCScopeWithoutOpenIDRejected 有会话 + 显式 scope 不含
// openid → 302 invalid_scope（§4.2：请求 scope 必含 openid，缺省补值口径
// 恒含故不命中；形态 A/B/C 入口同口径，经 internal/oidc EntryScopeValid）；
// 零签发零审计（错误路径无副作用）。
func TestAuthorizeFormCScopeWithoutOpenIDRejected(t *testing.T) {
	f := newAuthzFixture(t)
	f.sessions.p = validSession()
	rec := doGetWithCookie(t, f.engine(t),
		authzQ+"&scope="+url.QueryEscape("profile")+"&state=st1",
		"al_session", "session-token")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), authzRedirect+"?error=invalid_scope&state=st1"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	assertNoIssue(t, f)
	if len(f.consents.calls) != 0 {
		t.Errorf("入口档即拒，不得进入三态判定: %v", f.consents.calls)
	}
}

// TestAuthorizeFormCScopeExceedsRegisteredRejected 形态 C 直签前经真实
// AuthzValidator 复核（§14.2 与 Terminal 同一校验工具）：请求 scope 通过
// 入口档（封闭集 + 含 openid）、fake Decide 按已授权子集放行（模拟管理员
// 收窄客户端 scopes 后的存量授权记录漂移），但超出注册 scopes →
// 302 invalid_scope、零签发。
func TestAuthorizeFormCScopeExceedsRegisteredRejected(t *testing.T) {
	f := newAuthzFixture(t)
	f.sessions.p = validSession()
	row := oidcRow(t, "demo-app", 1, authzRedirect)
	row.Scopes = "openid,profile" // 注册集不含 email
	f.deps.Clients = multiClients{rows: map[string]*model.OidcClient{"demo-app": row}}
	f.deps.Authz = &oidc.AuthzValidator{Clients: f.deps.Clients}
	rec := doGetWithCookie(t, f.engine(t),
		authzQ+"&scope="+url.QueryEscape("openid profile email")+"&state=st1",
		"al_session", "session-token")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), authzRedirect+"?error=invalid_scope&state=st1"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if len(f.codes.calls) != 0 {
		t.Errorf("超出注册 scopes 不得直签: %d calls", len(f.codes.calls))
	}
	if len(f.consents.calls) != 1 {
		t.Errorf("Decide calls = %d, want 1（直签前复核挡在签码前）", len(f.consents.calls))
	}
}

// TestAuthorizeFormCValidScopeDirectIssue 合法 scope（含 openid 且 ⊆ 注册
// scopes）走形态 C 直签：真实 AuthzValidator 复核通过后签码，证明复核只拦
// 非法、不误伤合法路径（与 TestAuthorizeConsentSubsetDirectIssue 互补，
// 后者覆盖 scope=openid，本例覆盖多值 scope）。
func TestAuthorizeFormCValidScopeDirectIssue(t *testing.T) {
	f := newAuthzFixture(t)
	f.sessions.p = validSession()
	rec := doGetWithCookie(t, f.engine(t),
		authzQ+"&scope="+url.QueryEscape("openid profile email")+"&state=st1",
		"al_session", "session-token")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302（形态 C 直签）", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), authzRedirect+"?code=AUTHZ-CODE&state=st1"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if len(f.codes.calls) != 1 || f.codes.calls[0].Scope != "openid profile email" {
		t.Errorf("codes = %+v, want 1 次且 scope=openid profile email", f.codes.calls)
	}
}
