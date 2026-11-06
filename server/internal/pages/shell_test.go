// shell_test.go 空壳渲染与路由注册测试（阶段 C，接口文档 §8）：
// 模板三占位符全量替换（nonce 出现次数 = 模板占位符数、无残留）、转义 /
// no-store / CSP 终稿（自设与中间件两路径各测 + CDN 追加）、static_base
// 尾斜杠归一、三端路由 200 且注入零凭证键、callback 零业务、四份模板
// 穷尽替换（含 setup entry，供 setup 壳同契约对账）。本文件同时承载
// pages 包全部测试夹具。
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

// fallbackCSP 未经中间件路径的自设 CSP 头（render.go cspDirectives 终稿
// 形态，static_base 同域时）。
func fallbackCSP(nonce string) string {
	return "default-src 'self'; script-src 'nonce-" + nonce + "' 'strict-dynamic'; " +
		"style-src 'nonce-" + nonce + "' 'self'; font-src 'self'; " +
		"img-src 'self' data: https:; connect-src 'self'"
}

// nonceFromCSP 从 CSP 头提取 script-src 的 nonce（script-src 在 style-src
// 之前，头两段形态固定：default-src 'self'; script-src 'nonce-…'）。
func nonceFromCSP(t *testing.T, csp string) string {
	t.Helper()
	const (
		head = "default-src 'self'; script-src 'nonce-"
		tail = "' 'strict-dynamic'"
	)
	if !strings.HasPrefix(csp, head) {
		t.Fatalf("CSP = %q, want 前缀 %q", csp, head)
	}
	rest := strings.TrimPrefix(csp, head)
	i := strings.Index(rest, tail)
	if i < 0 {
		t.Fatalf("CSP = %q, script-src 缺 'strict-dynamic' 尾", csp)
	}
	return rest[:i]
}

// tmplPlaceholderCount 模板 {entry}.html 中占位符 ph 的出现次数——
// renderTemplate 全量替换后 body 中该值的期望出现次数（硬约束 2：出现
// 几次替换几次）。
func tmplPlaceholderCount(t *testing.T, entry, ph string) int {
	t.Helper()
	tpl, err := templatesFS.ReadFile("templates/" + entry + ".html")
	if err != nil {
		t.Fatalf("read template %s: %v", entry, err)
	}
	return strings.Count(string(tpl), ph)
}

// TestShellBasics account 空壳：200、no-store、CSP 终稿头（fixture engine
// 不挂 middleware.CSP，走 RenderGinShell 缺省自设路径）+ nonce 出现次数 =
// 模板占位符数、无残留占位符、产物引用按 static_base 前缀、INIT 仅
// al_root / static_base 两键（零凭证键）。
func TestShellBasics(t *testing.T) {
	f := newFixture(t)
	rec := doGet(t, f.engine(t), "/account/")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200（body %s）", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	nonce := nonceFromCSP(t, rec.Header().Get("Content-Security-Policy"))
	if got, want := rec.Header().Get("Content-Security-Policy"), fallbackCSP(nonce); got != want {
		t.Errorf("CSP = %q, want 终稿基线 %q", got, want)
	}
	body := rec.Body.String()
	if n := strings.Count(body, `nonce="`+nonce+`"`); n != tmplPlaceholderCount(t, "account", phCSPNonce) {
		t.Errorf("nonce 出现 %d 次, want = 模板占位符 %d 次（全量替换，漏一处页面即挂）", n, tmplPlaceholderCount(t, "account", phCSPNonce))
	}
	if strings.Contains(body, "{{AUTHLOFT_") {
		t.Errorf("body 残留占位符:\n%s", body)
	}
	if !strings.Contains(body, `src="/assets/`) {
		t.Errorf("body 缺 /assets/ 前缀的产物引用:\n%s", body)
	}
	if got, want := initJSON(t, body), `{"al_root":"https://auth.example.com","static_base":"/assets"}`; got != want {
		t.Errorf("INIT = %s, want %s（白名单外零键）", got, want)
	}
}

// TestShellCSPConsumesMiddleware CSP 中间件路径（bootstrap 页面路由组同构
// 挂法 r.Group("", middleware.CSP())）：RenderGinShell 消费 ctx 的
// CSPNonceKey——body 全部 nonce 属性与中间件所设 CSP 头同 nonce（未自
// 生成新值另设头）；头保持中间件终稿基线（style-src 带 nonce、
// strict-dynamic 在、connect-src 'self'）。
func TestShellCSPConsumesMiddleware(t *testing.T) {
	f := newFixture(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r.Group("", middleware.CSP()), f.deps)

	rec := doGet(t, r, "/account/")
	csp := rec.Header().Get("Content-Security-Policy")
	nonce := nonceFromCSP(t, csp)
	for _, want := range []string{
		"style-src 'nonce-" + nonce + "' 'self'",
		"font-src 'self'",
		"img-src 'self' data: https:",
		"connect-src 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP 头缺终稿指令 %q：%s", want, csp)
		}
	}
	if n := strings.Count(rec.Body.String(), `nonce="`+nonce+`"`); n != tmplPlaceholderCount(t, "account", phCSPNonce) {
		t.Errorf("nonce 出现 %d 次, want %d（与 CSP 头同 nonce，即消费 ctx 而非自生成）", n, tmplPlaceholderCount(t, "account", phCSPNonce))
	}
}

// TestShellCSPSupporterCDN 生产装配路径（bootstrap registerPages 同构）：
// middleware.CSP 挂 pages.StaticBaseCSPSupporter——static_base 为 CDN
// 绝对地址时头追加 script / style / font 三段 CDN 源；同域 /assets 时
// 不追加。同名指令多次出现取并集（csp.go 注）。
func TestShellCSPSupporterCDN(t *testing.T) {
	f := newFixture(t)
	gin.SetMode(gin.TestMode)
	r := gin.New()
	Register(r.Group("", middleware.CSP(StaticBaseCSPSupporter(f.settings))), f.deps)

	// 同域默认：无追加段。
	rec := doGet(t, r, "/admin/")
	csp := rec.Header().Get("Content-Security-Policy")
	nonce := nonceFromCSP(t, csp)
	if got, want := csp, strings.Join([]string{
		"default-src 'self'",
		"script-src 'nonce-" + nonce + "' 'strict-dynamic'",
		"style-src 'nonce-" + nonce + "' 'self'",
		"font-src 'self'",
		"img-src 'self' data: https:",
		"connect-src 'self'",
	}, "; "); got != want {
		t.Errorf("同域 CSP = %q, want 基线 %q", got, want)
	}

	// CDN 绝对地址：追加三段 CDN 源（script-src CDN 源仅为 CSP2 回退）。
	f.settings.m[settings.KeyStaticBase] = "https://cdn.example.com/static/"
	rec = doGet(t, r, "/admin/")
	csp = rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{
		"script-src https://cdn.example.com",
		"style-src https://cdn.example.com",
		"font-src https://cdn.example.com",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CDN CSP 头缺追加段 %q：%s", want, csp)
		}
	}
	// img / connect / default 不追加（§8 表：https: 已覆盖 CDN、API 恒同源）。
	if strings.Contains(csp, "img-src https://cdn") || strings.Contains(csp, "connect-src https://") {
		t.Errorf("img-src / connect-src 不追加 CDN 源：%s", csp)
	}
	// 每请求现算：改回同域后新请求无追加段。
	f.settings.m[settings.KeyStaticBase] = "/assets"
	if csp := doGet(t, r, "/admin/").Header().Get("Content-Security-Policy"); strings.Contains(csp, "cdn.example.com") {
		t.Errorf("static_base 热更回同域后仍带 CDN 段：%s", csp)
	}
}

// TestShellStaticBaseOverrides static_base 覆盖（CDN 绝对地址 + 尾斜杠
// 归一）与 <>& 转义（JSON 编码默认 HTML 转义）。
func TestShellStaticBaseOverrides(t *testing.T) {
	f := newFixture(t)
	f.settings.m[settings.KeyStaticBase] = "https://cdn.example.com/static/"
	rec := doGet(t, f.engine(t), "/admin/")

	body := rec.Body.String()
	if !strings.Contains(body, `src="https://cdn.example.com/static/`) {
		t.Errorf("产物引用未按 static_base 拼接:\n%s", body)
	}
	if strings.Contains(body, "https://cdn.example.com/static//") {
		t.Errorf("尾斜杠未归一（出现 //）:\n%s", body)
	}
	if got := initJSON(t, body); !strings.Contains(got, `"static_base":"https://cdn.example.com/static/"`) {
		t.Errorf("INIT static_base 应为原值（归一只作用占位符替换）: %s", got)
	}
	// 自设头（无中间件路径）同需追加 CDN 源（cspDirectives）。
	csp := rec.Header().Get("Content-Security-Policy")
	nonce := nonceFromCSP(t, csp)
	for _, want := range []string{
		"script-src 'nonce-" + nonce + "' 'strict-dynamic' https://cdn.example.com",
		"style-src 'nonce-" + nonce + "' 'self' https://cdn.example.com",
		"font-src 'self' https://cdn.example.com",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("自设 CSP 头缺 CDN 追加 %q：%s", want, csp)
		}
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
		target string
		entry  string
	}{
		{"/sso/login", "login"},
		{"/account/security/password", "account"},
		{"/admin/users", "admin"},
	}
	for _, tc := range cases {
		rec := doGet(t, r, tc.target)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", tc.target, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `src="/assets/`) {
			t.Errorf("%s: 缺 /assets/ 前缀产物引用", tc.target)
		}
		if n := strings.Count(body, "{{AUTHLOFT_"); n != 0 {
			t.Errorf("%s: 残留占位符 %d 处", tc.target, n)
		}
		nonce := nonceFromCSP(t, rec.Header().Get("Content-Security-Policy"))
		if n := strings.Count(body, `nonce="`+nonce+`"`); n != tmplPlaceholderCount(t, tc.entry, phCSPNonce) {
			t.Errorf("%s: nonce 出现 %d 次, want = 模板 %d 次", tc.target, n, tmplPlaceholderCount(t, tc.entry, phCSPNonce))
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
	// login 空壳必须带 methods（§8 行 1540）。
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
		if !strings.Contains(body, `src="/assets/`) {
			t.Errorf("callback %q: 缺 login 产物引用", pk)
		}
		if !strings.Contains(initJSON(t, body), `"methods"`) {
			t.Errorf("callback %q: 缺 methods", pk)
		}
	}
}

// TestRenderTemplatePlaceholderExhaustive 四份模板占位符穷尽替换（阶段 C
// 验收锚点：含 setup entry——setup 壳同契约由本测试对账，setup 包侧仅测
// gin 链接线）：固定 nonce + INIT 直接调 renderTemplate，断言 ① 无残留
// `{{AUTHLOFT_`；② nonce 出现次数 = 模板占位符出现次数（login/account/
// admin/setup 各异，随前端构建产物伸缩）；③ static_base 占位符全量替换
// 且尾斜杠归一；④ INIT 注入原样落位、\u2028/\u2029 转义（json.Marshal）。
func TestRenderTemplatePlaceholderExhaustive(t *testing.T) {
	const nonce = "fixed-test-nonce"
	type init4 struct {
		ALRoot     string `json:"al_root"`
		StaticBase string `json:"static_base"`
		S2028      string `json:"s2028"`
	}
	init := init4{ALRoot: "https://uc.example.com", StaticBase: "/init-assets", S2028: "a\u2028b\u2029c"}
	for _, entry := range []string{"login", "account", "admin", "setup"} {
		// static_base 传带尾斜杠值：占位符替换须归一为 /assets（INIT 内原值
		// 用不同字符串，避免干扰 /assets/ 计数）。
		body, err := renderTemplate(entry, init, "/assets/", nonce)
		if err != nil {
			t.Fatalf("%s: renderTemplate: %v", entry, err)
		}
		got := string(body)
		if strings.Contains(got, "{{AUTHLOFT_") {
			t.Errorf("%s: 残留占位符:\n%s", entry, got)
		}
		if n := strings.Count(got, nonce); n != tmplPlaceholderCount(t, entry, phCSPNonce) {
			t.Errorf("%s: nonce 出现 %d 次, want = 模板占位符 %d 次", entry, n, tmplPlaceholderCount(t, entry, phCSPNonce))
		}
		if n := strings.Count(got, "/assets/"); n != tmplPlaceholderCount(t, entry, phStaticBase) {
			t.Errorf("%s: static_base 出现 %d 次, want = 模板占位符 %d 次（尾斜杠已归一）", entry, n, tmplPlaceholderCount(t, entry, phStaticBase))
		}
		if strings.Contains(got, "/assets//") {
			t.Errorf("%s: 尾斜杠未归一（出现 /assets//）:\n%s", entry, got)
		}
		if !strings.Contains(got, `window.__AUTHLOFT_INIT__ = {"al_root":"https://uc.example.com","static_base":"/init-assets","s2028":"a`+`\u2028`+`b`+`\u2029`+`c"};`) {
			t.Errorf("%s: INIT 注入或 \\u2028/\\u2029 转义不正确:\n%s", entry, got)
		}
	}
}
