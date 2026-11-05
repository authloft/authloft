// shell_test.go 空壳渲染与路由注册测试（接口文档 §8）：转义 /
// no-store / CSP 基线（头形态 + nonce 注入 + strict-dynamic；
// 缺省自设与中间件两路径各测）、entry.js 引用按 static_base、三端路由
// 200 且注入零凭证键、callback 零业务。本文件同时承载 pages 包全部测试
// 夹具。
package pages

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"authloft/internal/captcha"
	"authloft/internal/factor"
	"authloft/internal/middleware"
	"authloft/internal/provider"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service"
	"authloft/internal/settings"
)

// fakeSettings SettingsReader 的 map fake（map 引用语义：持有句柄可热改值）。
type fakeSettings struct{ m map[string]any }

func (f fakeSettings) GetString(k string) (string, bool) { v, ok := f.m[k].(string); return v, ok }
func (f fakeSettings) GetInt64(k string) (int64, bool)   { v, ok := f.m[k].(int64); return v, ok }
func (f fakeSettings) GetBool(k string) (bool, bool)     { v, ok := f.m[k].(bool); return v, ok }
func (f fakeSettings) GetStringSlice(k string) ([]string, bool) {
	v, ok := f.m[k].([]string)
	return v, ok
}

// stubFactor 满足 factor.Factor 的测试桩（registry_test.go fakeFactor 同款）。
type stubFactor struct {
	kind   factor.FactorKind
	usages []factor.Usage
	steps  []factor.StepKind
}

func (s *stubFactor) Kind() factor.FactorKind  { return s.kind }
func (s *stubFactor) Usages() []factor.Usage   { return s.usages }
func (s *stubFactor) Steps() []factor.StepKind { return s.steps }
func (s *stubFactor) Start(*factor.FactorContext) (*factor.StepResult, error) {
	return nil, nil
}
func (s *stubFactor) Verify(*factor.FactorContext) (*factor.VerifyResult, error) {
	return nil, nil
}

// fakeFactors FactorSource 的 fake。
type fakeFactors struct {
	m map[factor.FactorKind]factor.Factor
}

func (f fakeFactors) Get(k factor.FactorKind) (factor.Factor, error) {
	impl, ok := f.m[k]
	if !ok {
		return nil, fmt.Errorf("factor: factor kind not registered: %q", k)
	}
	return impl, nil
}

// defaultFactors 六个已装配因子的桩（usage / steps 按 §1.10）。
func defaultFactors() fakeFactors {
	return fakeFactors{m: map[factor.FactorKind]factor.Factor{
		factor.FactorPassword: &stubFactor{kind: factor.FactorPassword,
			usages: []factor.Usage{factor.UsagePrimary}, steps: []factor.StepKind{factor.StepForm}},
		factor.FactorOTPSMS: &stubFactor{kind: factor.FactorOTPSMS,
			usages: []factor.Usage{factor.UsagePrimary, factor.UsageSecondary}, steps: []factor.StepKind{factor.StepChallenge, factor.StepForm}},
		factor.FactorOTPEmail: &stubFactor{kind: factor.FactorOTPEmail,
			usages: []factor.Usage{factor.UsagePrimary, factor.UsageSecondary}, steps: []factor.StepKind{factor.StepChallenge, factor.StepForm}},
		factor.FactorWebAuthn: &stubFactor{kind: factor.FactorWebAuthn,
			usages: []factor.Usage{factor.UsagePrimary, factor.UsageSecondary}, steps: []factor.StepKind{factor.StepChallenge, factor.StepForm}},
		factor.FactorTOTP: &stubFactor{kind: factor.FactorTOTP,
			usages: []factor.Usage{factor.UsageSecondary}, steps: []factor.StepKind{factor.StepForm}},
		factor.FactorRecovery: &stubFactor{kind: factor.FactorRecovery,
			usages: []factor.Usage{factor.UsageSecondary}, steps: []factor.StepKind{factor.StepForm}},
	}}
}

// fakeLoader ProviderLister 的 fake：按 type 回放行，调用留档。
type fakeLoader struct {
	rows  map[string][]*provider.Provider
	calls []string
}

func (f *fakeLoader) ListByType(_ context.Context, t string) ([]*provider.Provider, error) {
	f.calls = append(f.calls, t)
	return f.rows[t], nil
}

// fakeCaptcha CaptchaConfiger 的 fake。
type fakeCaptcha struct{ cfg captcha.Config }

func (f fakeCaptcha) Config(context.Context) captcha.Config { return f.cfg }

// fakeJWT JWTVerifier 的 fake。
type fakeJWT struct {
	claims jwt.MapClaims
	err    error
}

func (f *fakeJWT) Verify(string) (jwt.MapClaims, error) { return f.claims, f.err }

// fakeClients OidcClientReader 的 fake。
type fakeClients struct{ c *model.OidcClient }

func (f fakeClients) FindOidcClientByClientID(context.Context, string) (*model.OidcClient, error) {
	return f.c, nil
}

// provRow 构造 provider 实例（Row.Ext 塞入假凭证字节，供零泄漏断言）。
func provRow(key, typ string, enabled bool, signin int8, sort int32) *provider.Provider {
	isEnabled := int8(0)
	if enabled {
		isEnabled = 1
	}
	return &provider.Provider{
		Key:  key,
		Type: typ,
		Row: &model.Provider{
			ProviderKey:  key,
			DisplayName:  key + "显示名",
			Category:     "oauth",
			Type:         typ,
			EnableSignin: signin,
			IsEnabled:    isEnabled,
			UiGroup:      "social",
			SortOrder:    sort,
			IconURL:      "https://icons.example/" + key + ".png",
			Ext:          []byte("raw-secret-ext-bytes"),
		},
	}
}

// testCodec 固定 32 字节 AES-256 密钥（service/sync_cookie_test 同款）。
func testCodec(t *testing.T) *security.Codec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return security.NewCodec(ks)
}

// fixture 聚合可变夹具句柄。
type fixture struct {
	deps     Deps
	settings fakeSettings
	loader   *fakeLoader
	jwt      *fakeJWT
	clients  fakeClients
	sessions *fakeSessions
	codes    *fakeCodes
	audit    *fakeAudit
}

// newFixture 基线夹具：默认 settings（login_methods 全量 + 开关全开）、
// 空 loader、假 captcha、可注入 JWT / 客户端、真实 codec 与
// service.SyncCookieURLBuilder（链路级测试用）。
func newFixture(t *testing.T) *fixture {
	t.Helper()
	codec := testCodec(t)
	st := fakeSettings{m: map[string]any{
		settings.KeyLoginMethods:       []string{"password", "otp_sms", "otp_email", "webauthn", "thirdparty"},
		settings.KeyAllowPasswordReset: true,
		settings.KeyAllowRegistration:  true,
	}}
	loader := &fakeLoader{rows: map[string][]*provider.Provider{}}
	jw := &fakeJWT{}
	sess := &fakeSessions{} // authorize 默认无会话；测试改 p / err 生效（指针共享）
	codes := &fakeCodes{code: "AUTHZ-CODE"}
	audit := &fakeAudit{}
	f := &fixture{
		settings: st,
		loader:   loader,
		jwt:      jw,
		clients:  fakeClients{},
		sessions: sess,
		codes:    codes,
		audit:    audit,
	}
	f.deps = Deps{
		Root:       "https://auth.example.com",
		RootDomain: "auth.example.com",
		Settings:   st,
		Loader:     loader,
		Factors:    defaultFactors(),
		Gate:       fakeCaptcha{cfg: captcha.Config{ProviderKey: "cf_turnstile", Type: "turnstile", SiteKey: "0x4AAA"}},
		Sync:       service.NewSyncCookieURLBuilder(codec),
		Codec:      codec,
		JWT:        jw,
		Clients:    fakeClients{},
		Sessions:   sess,
		Codes:      codes,
		Audit:      audit,
		Metas: func() []provider.Meta {
			return []provider.Meta{
				{Type: "qq", Category: "oauth", Channel: provider.ChannelRedirect},
				{Type: "wechat_mp", Category: "oauth", Channel: provider.ChannelAPI},
				{Type: "wechat_mp_scan", Category: "oauth", Channel: provider.ChannelQRCode},
				{Type: "smtp", Category: "email"}, // 非 oauth：枚举后必须被跳过
			}
		},
	}
	return f
}

// engine 构造挂好页面路由的 gin 引擎。
func (f *fixture) engine(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r, f.deps)
	return r
}

// doGet 发 GET 请求。
func doGet(t *testing.T, r *gin.Engine, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// initJSON 从空壳 HTML 提取 window.__AUTHLOFT_INIT__ 的 JSON 文本。
func initJSON(t *testing.T, body string) string {
	t.Helper()
	const marker = "window.__AUTHLOFT_INIT__ = "
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("body missing INIT marker: %s", body)
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, "</script>")
	if j < 0 {
		t.Fatalf("body missing script close: %s", body)
	}
	return strings.TrimSuffix(rest[:j], ";")
}

// cspNonceFromHeader 断言 CSP 头为基线形态（default-src
// 'self'；script-src 'nonce-…' 'strict-dynamic'；style / font 'self'；
// img-src https:——与 middleware/csp.go 基线逐字一致）并提取 nonce。
func cspNonceFromHeader(t *testing.T, csp string) string {
	t.Helper()
	const (
		head = "default-src 'self'; script-src 'nonce-"
		tail = "' 'strict-dynamic'; style-src 'self'; font-src 'self'; img-src https:"
	)
	if !strings.HasPrefix(csp, head) || !strings.HasSuffix(csp, tail) {
		t.Fatalf("CSP = %q, want 基线形态 %q…%q（strict-dynamic 必须在）", csp, head, tail)
	}
	return strings.TrimSuffix(strings.TrimPrefix(csp, head), tail)
}

// TestShellBasics account 空壳：200、no-store、CSP 基线头 + nonce 两个
// script 一致（fixture engine 不挂 middleware.CSP，走 renderShell
// 缺省自设路径）、entry.js 引用按 static_base、INIT 仅 al_root /
// static_base 两键（零凭证键）。
func TestShellBasics(t *testing.T) {
	f := newFixture(t)
	rec := doGet(t, f.engine(t), "/account/")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200（body %s）", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	nonce := cspNonceFromHeader(t, rec.Header().Get("Content-Security-Policy"))
	body := rec.Body.String()
	if n := strings.Count(body, `nonce="`+nonce+`"`); n != 2 {
		t.Errorf("两个 script 的 nonce 出现 %d 次，want 2（inline + entry）", n)
	}
	if !strings.Contains(body, `src="/assets/account/entry.js"`) {
		t.Errorf("body 缺 entry.js 引用 /assets/account/entry.js:\n%s", body)
	}
	if got, want := initJSON(t, body), `{"al_root":"https://auth.example.com","static_base":"/assets"}`; got != want {
		t.Errorf("INIT = %s, want %s（白名单外零键）", got, want)
	}
}

// TestShellCSPConsumesMiddleware CSP 中间件路径（与
// bootstrap 页面路由组同构挂法 r.Group("", middleware.CSP())）：renderShell
// 消费 ctx 的 CSPNonceKey——body 两个 script 的 nonce 与中间件所设
// CSP 头一致（未自生成新值另设头）；头保持中间件基线（strict-dynamic 在）。
func TestShellCSPConsumesMiddleware(t *testing.T) {
	f := newFixture(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r.Group("", middleware.CSP()), f.deps)

	rec := doGet(t, r, "/account/")
	nonce := cspNonceFromHeader(t, rec.Header().Get("Content-Security-Policy"))
	if n := strings.Count(rec.Body.String(), `nonce="`+nonce+`"`); n != 2 {
		t.Errorf("两个 script 的 nonce 出现 %d 次，want 2（与 CSP 头同 nonce，即消费 ctx 而非自生成）", n)
	}
}

// TestShellStaticBaseOverrides static_base 覆盖（CDN 绝对地址 + 尾斜杠防御）
// 与 <>& 转义（JSON 编码默认 HTML 转义）。
func TestShellStaticBaseOverrides(t *testing.T) {
	f := newFixture(t)
	f.settings.m[settings.KeyStaticBase] = "https://cdn.example.com/static/"
	rec := doGet(t, f.engine(t), "/admin/")

	body := rec.Body.String()
	if !strings.Contains(body, `src="https://cdn.example.com/static/admin/entry.js"`) {
		t.Errorf("entry.js 引用未按 static_base 拼接（含尾斜杠防御）:\n%s", body)
	}

	// 转义：<>& 必须被 \u003c/\u003e/\u0026 转义，不得裸出现在 INIT 内。
	f.settings.m[settings.KeyStaticBase] = "/a<b>&c"
	body = doGet(t, f.engine(t), "/admin/").Body.String()
	init := initJSON(t, body)
	if strings.Contains(init, "<b>") || strings.Contains(init, "&c\"") {
		t.Errorf("INIT 未转义 <>&: %s", init)
	}
	if !strings.Contains(init, `\u003c`) || !strings.Contains(init, `\u0026`) {
		t.Errorf("INIT 缺 \\u003c / \\u0026 转义: %s", init)
	}
}

// TestThreeEntryRoutes 三端路由 200：login（含 methods）、account / admin
// （仅 al_root / static_base）；深路径命中同一空壳。
func TestThreeEntryRoutes(t *testing.T) {
	f := newFixture(t)
	r := f.engine(t)

	cases := []struct {
		target  string
		wantSrc string
	}{
		{"/sso/login", "/assets/login/entry.js"},
		{"/account/security/password", "/assets/account/entry.js"},
		{"/admin/users", "/assets/admin/entry.js"},
	}
	for _, tc := range cases {
		rec := doGet(t, r, tc.target)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", tc.target, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `src="`+tc.wantSrc+`"`) {
			t.Errorf("%s: 缺 entry.js %s", tc.target, tc.wantSrc)
		}
		if !strings.Contains(initJSON(t, body), `"al_root":"https://auth.example.com"`) {
			t.Errorf("%s: 缺 al_root", tc.target)
		}
	}

	// account / admin 不得带 methods（§8：methods 是 login 必填项）。
	for _, target := range []string{"/account/", "/admin/"} {
		if init := initJSON(t, doGet(t, r, target).Body.String()); strings.Contains(init, "methods") {
			t.Errorf("%s: account/admin 空壳不应注入 methods: %s", target, init)
		}
	}
	// login 空壳必须带 methods（§8 行 1436）。
	if init := initJSON(t, doGet(t, r, "/sso/login").Body.String()); !strings.Contains(init, `"methods"`) {
		t.Errorf("login 空壳缺 methods 注入: %s", init)
	}

	// 无尾斜杠形态（/account、/admin）：gin RedirectTrailingSlash 301 到
	// 尾斜杠形式，不 404。
	for _, target := range []string{"/account", "/admin"} {
		rec := doGet(t, r, target)
		if rec.Code != http.StatusMovedPermanently {
			t.Errorf("%s: status = %d, want 301（尾斜杠归一）", target, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != target+"/" {
			t.Errorf("%s: Location = %q, want %q", target, loc, target+"/")
		}
	}
}

// TestCallbackZeroBusiness callback 零业务（§2.7.3 行 604）：provider_key
// 任意值（含未注册）一律渲染 login 空壳，不 404 / 500、不校验业务。
func TestCallbackZeroBusiness(t *testing.T) {
	f := newFixture(t)
	for _, pk := range []string{"qq", "totally-unknown-provider"} {
		rec := doGet(t, f.engine(t), "/sso/oauth/callback/"+pk)
		if rec.Code != http.StatusOK {
			t.Fatalf("callback %q: status = %d, want 200", pk, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `src="/assets/login/entry.js"`) {
			t.Errorf("callback %q: 缺 login entry.js", pk)
		}
		if !strings.Contains(initJSON(t, body), `"methods"`) {
			t.Errorf("callback %q: 缺 methods", pk)
		}
	}
}
