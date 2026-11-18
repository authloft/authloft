// template_render_test.go 客户端自定义模板渲染链路单测（接口文档 §8.1）：
// 四占位符全量替换、模板变量 JSON 按 INIT_JSON 同口径转义、回落各分支、
// 回落文件壳与改动前逐字一致。可证伪断言均以真实嵌入文件 / 固定 nonce 驱动。
package pages

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"authloft/internal/middleware"
	"authloft/internal/repo/model"
)

// fakeTplResolver TemplateResolver 的 fake：按 key 回放内容，可注入 Resolve
// 错误（模拟 miss / 故障）。
type fakeTplResolver struct {
	content map[string]string
	err     error
	calls   []string
}

func (f *fakeTplResolver) Resolve(_ context.Context, key string) (string, error) {
	f.calls = append(f.calls, key)
	if f.err != nil {
		return "", f.err
	}
	c, ok := f.content[key]
	if !ok {
		return "", errors.New("template not found")
	}
	return c, nil
}

// fakeSsoClients SsoClientReader 的 fake：按 client_id 回放 sso_client 行。
type fakeSsoClients struct {
	rows map[string]*model.SsoClient
}

func (f *fakeSsoClients) FindSsoClientByClientID(_ context.Context, id string) (*model.SsoClient, error) {
	c, ok := f.rows[id]
	if !ok {
		return nil, errors.New("sso client not found")
	}
	return c, nil
}

// legacyRender 改动前的 renderTemplate 三步替换（去掉模板变量 / 站点名这两
// 新增步），作为「回落文件壳逐字一致」的独立 oracle。site_name 与实现同口径
// 转义注入，保证第五占位符在场时两路输出仍逐字相等。
func legacyRender(htmlText string, init any, staticBase, nonce, siteName string) string {
	initJSON, _ := json.Marshal(init)
	if siteName == "" {
		siteName = "Authloft"
	}
	h := strings.ReplaceAll(htmlText, phCSPNonce, nonce)
	h = strings.ReplaceAll(h, phStaticBase, strings.TrimRight(staticBase, "/"))
	h = strings.ReplaceAll(h, phInitJSON, string(initJSON))
	h = strings.ReplaceAll(h, phSiteName, html.EscapeString(siteName))
	return h
}

// fixedNonceEngine 构造把 CSP nonce 钉死的引擎，令两请求 body 可逐字比较
// （生产 nonce 每请求随机，不可直接比 body）。
func fixedNonceEngine(t *testing.T, d Deps) *echo.Echo {
	t.Helper()
	r := echo.NewWithConfig(echo.Config{NoGroupAutoRegister404Routes: true})
	r.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			c.Set(middleware.CSPNonceKey, "FIXED-NONCE")
			return next(c)
		}
	})
	Register(r.Group(""), d)
	return r
}

// TestRenderHTMLFivePlaceholders 自定义模板含五占位符 + 非保留 {{…}}：
// 五占位符全量替换（非保留按字面输出、不报错），模板变量 JSON 原文注入、
// 不被重组；站点名替换到 <title>；static_base 尾斜杠归一；init JSON 正常替换。
func TestRenderHTMLFivePlaceholders(t *testing.T) {
	const custom = `<html><head><title>` + phSiteName + `</title><script nonce="` + phCSPNonce + `">` +
		`window.__AUTHLOFT_INIT__=` + phInitJSON + `;` +
		`window.TV=` + TemplateVarsPlaceholder + `;</script>` +
		`<link href="` + phStaticBase + `/x.css"><p>{{brand}}</p></head></html>`
	init := struct {
		Foo string `json:"foo"`
	}{Foo: "bar"}
	varsJSON := `{"color":"blue","lt":"<>&"}`

	got, err := renderHTML(custom, init, "https://cdn.example.com/assets/", "NONCE123", varsJSON, "My Site")
	if err != nil {
		t.Fatalf("renderHTML: %v", err)
	}
	body := string(got)
	for _, ph := range []string{phCSPNonce, phStaticBase, phInitJSON, phSiteName, TemplateVarsPlaceholder} {
		if strings.Contains(body, ph) {
			t.Errorf("残留占位符 %q:\n%s", ph, body)
		}
	}
	for _, want := range []string{
		`<title>My Site</title>`,
		`nonce="NONCE123"`,
		`https://cdn.example.com/assets/x.css`,
		`window.__AUTHLOFT_INIT__={"foo":"bar"}`,
		`window.TV={"color":"blue","lt":"<>&"}`,
		`{{brand}}`, // 未命中变量键按字面输出、不报错（§8.1 第 4 步）
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body 缺 %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "/assets//x.css") {
		t.Errorf("尾斜杠未归一:\n%s", body)
	}
}

// TestRenderHTMLVarsEmpty 模板变量未配置（resolve 层归一为 {}）：占位符以
// {} 替换；空值归一由 templateVarsInject 负责（另测）。
func TestRenderHTMLVarsEmpty(t *testing.T) {
	const custom = `<script>window.TV=` + TemplateVarsPlaceholder + `;</script>`
	got, err := renderHTML(custom, struct{}{}, "/assets", "N", "{}", "Authloft")
	if err != nil {
		t.Fatalf("renderHTML: %v", err)
	}
	if !strings.Contains(string(got), "window.TV={};") {
		t.Errorf("body = %s, want TV={}", got)
	}
}

// TestRenderHTMLBuiltinShellPlaceholders 内置文件壳：无模板变量占位符（第五
// 占位符注入对其为空操作），但含站点名占位符需被替换；renderHTML 输出与
// legacyRender 逐字一致。
func TestRenderHTMLBuiltinShellPlaceholders(t *testing.T) {
	init := &initPayload{ALRoot: "https://uc.example.com", StaticBase: "/assets"}
	for _, entry := range []string{"login", "account", "admin", "setup"} {
		tpl, err := templatesFS.ReadFile("templates/" + entry + ".html")
		if err != nil {
			t.Fatalf("read %s: %v", entry, err)
		}
		if strings.Contains(string(tpl), TemplateVarsPlaceholder) {
			t.Fatalf("%s 内置壳不应含模板变量占位符", entry)
		}
		if !strings.Contains(string(tpl), phSiteName) {
			t.Fatalf("%s 内置壳应含站点名占位符（构建期注入 <title>）", entry)
		}
		got, err := renderHTML(string(tpl), init, "/assets/", "FIXED", `{"x":"<>&"}`, "Authloft")
		if err != nil {
			t.Fatalf("%s renderHTML: %v", entry, err)
		}
		want := legacyRender(string(tpl), init, "/assets/", "FIXED", "Authloft")
		if string(got) != want {
			t.Errorf("%s 回落文件壳与 legacyRender 不一致（长度 got=%d want=%d）", entry, len(got), len(want))
		}
	}
}

// TestRenderHTMLSiteNameEscapeAndFallback 第五占位符的注入值安全口径（§8.1：
// 转义在构造注入值时完成）：HTML 文本上下文转义防 </title><script> 注入；
// 空串 / 缺失回落 settings.DefaultSiteName。
func TestRenderHTMLSiteNameEscapeAndFallback(t *testing.T) {
	const custom = `<html><head><title>` + phSiteName + `</title></head></html>`
	cases := []struct {
		name     string
		siteName string
		want     string
	}{
		{"normal", "My Site", "<title>My Site</title>"},
		{"ampersand", "A & B", "<title>A &amp; B</title>"},
		{"injection", "</title><script>alert(1)</script>", "<title>&lt;/title&gt;&lt;script&gt;alert(1)&lt;/script&gt;</title>"},
		{"empty falls back", "", "<title>Authloft</title>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderHTML(custom, struct{}{}, "/assets", "N", "{}", tc.siteName)
			if err != nil {
				t.Fatalf("renderHTML: %v", err)
			}
			if !strings.Contains(string(got), tc.want) {
				t.Errorf("body = %s, want 含 %q", got, tc.want)
			}
			if strings.Contains(string(got), phSiteName) {
				t.Errorf("残留站点名占位符: %s", got)
			}
		})
	}
	// 注入攻击串不得原样出现在输出中。
	got, err := renderHTML(custom, struct{}{}, "/assets", "N", "{}", "</title><script>alert(1)</script>")
	if err != nil {
		t.Fatalf("renderHTML: %v", err)
	}
	if strings.Contains(string(got), "</title><script>") {
		t.Errorf("注入串未转义:\n%s", got)
	}
}

// TestTemplateVarsInjectEscape 注入值转义实证：< > & 与真实 U+2028/U+2029
// 一律转义为 \uXXXX，防 </script> 提前闭合与 JS 字符串换行注入；空 / 空白
// 为 {}；已是字面 \u2028 序列的原文不被二次改写（只改字符编码表示）。
func TestTemplateVarsInjectEscape(t *testing.T) {
	raw := `{"brand":"<script>&a` + "\u2028\u2029" + `","lit":"\u2028"}`
	got := templateVarsInject(raw)
	want := `{"brand":"\u003cscript\u003e\u0026a\u2028\u2029","lit":"\u2028"}`
	if got != want {
		t.Errorf("templateVarsInject = %s, want %s", got, want)
	}
	for _, ch := range []string{"<", ">", "&", "\u2028", "\u2029"} {
		if strings.Contains(got, ch) {
			t.Errorf("转义后仍含裸字符 %q: %s", ch, got)
		}
	}
	for _, empty := range []string{"", "  ", "\t\n"} {
		if g := templateVarsInject(empty); g != "{}" {
			t.Errorf("templateVarsInject(%q) = %q, want {}", empty, g)
		}
	}
}

// TestResolveClientTemplateFallback 回落各分支：无 client_id / Templates nil
// （setup 模式）/ SsoClients nil / 查无行 / SSO 行命中但应用被禁用 / template
// _key 空 / Resolve miss 一律 ok=false、varsJSON 为空、err 为 nil；命中时
// html 与转义后 varsJSON 正确返回。sso_client 行命中且已启用即随返回（ssoRow
// 非 nil）且不受模板回落影响（§2.1 sso 注入与 methods 过滤以行命中且已启用
// 为条件）；查无行 / 禁用应用 / 授权入口 ssoRow 为 nil。
func TestResolveClientTemplateFallback(t *testing.T) {
	const custom = `<html>{{AUTHLOFT_TEMPLATE_VARS}}</html>`
	resolver := &fakeTplResolver{content: map[string]string{"k": custom}}
	sso := &fakeSsoClients{rows: map[string]*model.SsoClient{
		"app":    {ClientID: "app", TemplateKey: "k", TemplateVars: `{"a":"<x>"}`, IsEnabled: 1},
		"nokey":  {ClientID: "nokey", TemplateKey: "", TemplateVars: "", IsEnabled: 1},
		"disapp": {ClientID: "disapp", TemplateKey: "k", TemplateVars: `{"a":"<x>"}`, IsEnabled: 0},
	}}
	cases := []struct {
		name     string
		deps     Deps
		clientID string
		wantOK   bool
		wantRow  bool
	}{
		{"no client id", Deps{Templates: resolver, SsoClients: sso}, "", false, false},
		{"templates nil setup", Deps{SsoClients: sso}, "app", false, true},
		{"sso clients nil", Deps{Templates: resolver}, "app", false, false},
		{"row not found", Deps{Templates: resolver, SsoClients: sso}, "missing", false, false},
		{"app disabled", Deps{Templates: resolver, SsoClients: sso}, "disapp", false, false},
		{"template key empty", Deps{Templates: resolver, SsoClients: sso}, "nokey", false, true},
		{"resolve miss", Deps{Templates: &fakeTplResolver{content: map[string]string{}}, SsoClients: sso}, "app", false, true},
		{"sso hit", Deps{Templates: resolver, SsoClients: sso}, "app", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			html, vars, row, ok, err := resolveClientTemplate(context.Background(), tc.deps, tc.clientID, false)
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (html=%q vars=%q)", ok, tc.wantOK, html, vars)
			}
			if (row != nil) != tc.wantRow {
				t.Fatalf("ssoRow = %v, wantRow = %v（行命中不受模板回落影响）", row, tc.wantRow)
			}
			if tc.wantOK {
				if html != custom {
					t.Errorf("html = %q, want %q", html, custom)
				}
				if vars != `{"a":"\u003cx\u003e"}` {
					t.Errorf("vars = %s, want escaped JSON", vars)
				}
			} else if html != "" || vars != "" {
				t.Errorf("回落应返回空 html/vars, got html=%q vars=%q", html, vars)
			}
		})
	}
}

// TestResolveClientTemplateOIDC 授权入口用 oidc_client（Deps.Clients）：即使
// SsoClients 未装配也能命中，验证两族分流与 oidc 客户端 template_vars 转义；
// 授权入口 ssoRow 恒 nil（§2.1 authorize 不注入 sso）。
func TestResolveClientTemplateOIDC(t *testing.T) {
	const custom = `<html>{{AUTHLOFT_TEMPLATE_VARS}}</html>`
	d := Deps{
		Templates: &fakeTplResolver{content: map[string]string{"oidc-k": custom}},
		Clients:   &fakeClients{c: &model.OidcClient{TemplateKey: "oidc-k", TemplateVars: `{"b":"&"}`}},
	}
	html, vars, row, ok, err := resolveClientTemplate(context.Background(), d, "oidc-app", true)
	if err != nil || !ok {
		t.Fatalf("resolveClientTemplate(oidc): ok=%v err=%v", ok, err)
	}
	if html != custom || vars != `{"b":"\u0026"}` {
		t.Errorf("oidc html=%q vars=%q", html, vars)
	}
	if row != nil {
		t.Errorf("oidc 入口 ssoRow = %v, want nil", row)
	}
	// oidc=false 时 SsoClients 未装配必须回落（不会误用 Clients）。
	if _, _, _, ok, _ := resolveClientTemplate(context.Background(), d, "oidc-app", false); ok {
		t.Error("sso 分支在无 SsoClients 时不应命中")
	}
}

// TestLoginShellCustomTemplate 端到端：sso_client 指定 template_key 且模板含
// 模板变量占位符 → 自定义模板生效（变量转义后注入、四占位符全替换）；
// 行命中时 INIT 同时追加 sso 键（§2.1）。
func TestLoginShellCustomTemplate(t *testing.T) {
	f := newFixture(t)
	const custom = `<html><head><script nonce="` + phCSPNonce + `">` +
		`window.__AUTHLOFT_INIT__=` + phInitJSON + `;` +
		`window.__AUTHLOFT_TEMPLATE_VARS__=` + TemplateVarsPlaceholder + `;</script>` +
		`<link href="` + phStaticBase + `/x.css"></head><body id="root">custom</body></html>`
	f.deps.Templates = &fakeTplResolver{content: map[string]string{"tpl-login": custom}}
	f.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{
		"app-1": {ClientID: "app-1", Name: "示例应用", TemplateKey: "tpl-login", TemplateVars: `{"brand":"<b>&` + "\u2028" + `"}`, IsEnabled: 1},
	}}

	rec := doGet(t, fixedNonceEngine(t, f.deps), "/sso/login?client_id=app-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`nonce="FIXED-NONCE"`,
		`href="/assets/x.css"`,
		`window.__AUTHLOFT_INIT__={"al_root"`,
		`"sso":{"clientId":"app-1","name":"示例应用"}`,
		`window.__AUTHLOFT_TEMPLATE_VARS__={"brand":"\u003cb\u003e\u0026\u2028"}`,
		`id="root">custom`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body 缺 %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "{{AUTHLOFT_") {
		t.Errorf("残留占位符:\n%s", body)
	}
}

// TestLoginShellDisabledAppDefaultShape 禁用应用（IsEnabled=0）按未传入
// client_id 的默认形态渲染（§2.1）：200 空壳、不套自定义模板、不注入 sso
// 上下文、methods 不被应用交集过滤（全局口径）；与已启用形态
// （TestLoginShellCustomTemplate）互为对照。
func TestLoginShellDisabledAppDefaultShape(t *testing.T) {
	f := newFixture(t)
	const custom = `<html><body id="root">disabled-app-tpl-marker</body></html>`
	f.deps.Templates = &fakeTplResolver{content: map[string]string{"tpl-login": custom}}
	row := ssoAppRow(t, "disapp", "禁用应用", []string{"password"}, nil,
		func(r *model.SsoClient) { r.TemplateKey = "tpl-login" })
	row.IsEnabled = 0
	f.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{"disapp": row}}

	rec := doGet(t, fixedNonceEngine(t, f.deps), "/sso/login?client_id=disapp")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 空壳（body %s）", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "disabled-app-tpl-marker") || strings.Contains(body, "AUTHLOFT_TEMPLATE_VARS") {
		t.Error("禁用应用不应套用自定义模板，应回落默认文件壳")
	}
	init := parseInit(t, body)
	if sso, ok := init["sso"]; ok {
		t.Errorf("禁用应用不应注入 sso 上下文: %v", sso)
	}
	got := methodNames(loginMethodsFromInit(t, init))
	want := []string{"password", "otp_sms", "otp_email", "webauthn"} // 全局口径（应用 login_methods 仅 password，过滤未生效）
	if !reflect.DeepEqual(got, want) {
		t.Errorf("methods = %v, want 全局口径 %v（禁用应用不参与应用级过滤）", got, want)
	}
}

// TestLoginShellFallbackByteIdentical 端到端逐字一致：未指定 client_id 与
// client_id 查无行两种回落，body 与基线（无 client_id 文件壳）逐字相同——
// 查无行回落壳不注入 sso（§2.1）、不含模板变量注入痕迹；行命中但模板回落
// （Resolve miss / setup Templates nil）时文件壳本体不变、仅 INIT JSON 追加
// sso 键（行命中与模板解析正交，§2.1）。
func TestLoginShellFallbackByteIdentical(t *testing.T) {
	baseline := newFixture(t)
	baselineBody := doGet(t, fixedNonceEngine(t, baseline.deps), "/sso/login").Body.String()

	// 查无行回落：与基线逐字一致（回落壳不注入 sso）。
	ghost := newFixture(t)
	ghost.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{}}
	ghostBody := doGet(t, fixedNonceEngine(t, ghost.deps), "/sso/login?client_id=ghost").Body.String()

	// Resolve miss：行命中 + template_key，但 Resolve 未命中 → sso 照注入。
	miss := newFixture(t)
	miss.deps.Templates = &fakeTplResolver{content: map[string]string{}}
	miss.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{
		"app": {ClientID: "app", TemplateKey: "absent", IsEnabled: 1},
	}}
	missBody := doGet(t, fixedNonceEngine(t, miss.deps), "/sso/login?client_id=app").Body.String()

	// setup 模式：Templates 为 nil（Deps 未装配模板解析源）→ sso 照注入。
	setup := newFixture(t)
	setup.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{
		"app": {ClientID: "app", TemplateKey: "k", IsEnabled: 1},
	}}
	setupBody := doGet(t, fixedNonceEngine(t, setup.deps), "/sso/login?client_id=app").Body.String()

	if ghostBody != baselineBody {
		t.Errorf("查无行回落 body 与基线不一致（长度 got=%d baseline=%d）", len(ghostBody), len(baselineBody))
	}
	if strings.Contains(ghostBody, `"_TV_`) || strings.Contains(ghostBody, "AUTHLOFT_TEMPLATE_VARS") {
		t.Errorf("查无行回落 body 含模板变量注入痕迹")
	}
	for name, body := range map[string]string{"resolve miss": missBody, "setup nil": setupBody} {
		if !strings.Contains(body, `"sso":{"clientId":"app","name":""}`) {
			t.Errorf("%s 行命中回落应注入 sso 键:\n%s", name, body)
		}
		if strings.Contains(body, `"_TV_`) || strings.Contains(body, "AUTHLOFT_TEMPLATE_VARS") {
			t.Errorf("%s 回落 body 含模板变量注入痕迹", name)
		}
		if body == baselineBody {
			t.Errorf("%s 行命中回落 body 不应与基线逐字一致（INIT 应多 sso 键）", name)
		}
	}
}
