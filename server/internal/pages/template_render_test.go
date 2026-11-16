// template_render_test.go 客户端自定义模板渲染链路单测（接口文档 §8.1）：
// 四占位符全量替换、模板变量 JSON 按 INIT_JSON 同口径转义、回落各分支、
// 回落文件壳与改动前逐字一致。可证伪断言均以真实嵌入文件 / 固定 nonce 驱动。
package pages

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

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

// legacyRender 改动前的 renderTemplate 三步替换（去掉模板变量占位符这一
// 新增步），作为「回落文件壳逐字一致」的独立 oracle。
func legacyRender(htmlText string, init any, staticBase, nonce string) string {
	initJSON, _ := json.Marshal(init)
	h := strings.ReplaceAll(htmlText, phCSPNonce, nonce)
	h = strings.ReplaceAll(h, phStaticBase, strings.TrimRight(staticBase, "/"))
	h = strings.ReplaceAll(h, phInitJSON, string(initJSON))
	return h
}

// fixedNonceEngine 构造把 CSP nonce 钉死的引擎，令两请求 body 可逐字比较
// （生产 nonce 每请求随机，不可直接比 body）。
func fixedNonceEngine(t *testing.T, d Deps) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(middleware.CSPNonceKey, "FIXED-NONCE")
		c.Next()
	})
	Register(r, d)
	return r
}

// TestRenderHTMLFourPlaceholders 自定义模板含四占位符 + 非保留 {{…}}：
// 四占位符全量替换（非保留按字面输出、不报错），模板变量 JSON 原文注入、
// 不被重组；static_base 尾斜杠归一；init JSON 正常替换。
func TestRenderHTMLFourPlaceholders(t *testing.T) {
	const custom = `<html><script nonce="` + phCSPNonce + `">` +
		`window.__AUTHLOFT_INIT__=` + phInitJSON + `;` +
		`window.TV=` + TemplateVarsPlaceholder + `;</script>` +
		`<link href="` + phStaticBase + `/x.css"><p>{{brand}}</p></html>`
	init := struct {
		Foo string `json:"foo"`
	}{Foo: "bar"}
	varsJSON := `{"color":"blue","lt":"<>&"}`

	got, err := renderHTML(custom, init, "https://cdn.example.com/assets/", "NONCE123", varsJSON)
	if err != nil {
		t.Fatalf("renderHTML: %v", err)
	}
	body := string(got)
	for _, ph := range []string{phCSPNonce, phStaticBase, phInitJSON, TemplateVarsPlaceholder} {
		if strings.Contains(body, ph) {
			t.Errorf("残留占位符 %q:\n%s", ph, body)
		}
	}
	for _, want := range []string{
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
	got, err := renderHTML(custom, struct{}{}, "/assets", "N", "{}")
	if err != nil {
		t.Fatalf("renderHTML: %v", err)
	}
	if !strings.Contains(string(got), "window.TV={};") {
		t.Errorf("body = %s, want TV={}", got)
	}
}

// TestRenderHTMLBuiltinShellNoop 内置文件壳无模板变量占位符：新增的第四
// 占位符替换必须是空操作，renderHTML 输出与改动前 legacyRender 逐字一致。
func TestRenderHTMLBuiltinShellNoop(t *testing.T) {
	init := &initPayload{ALRoot: "https://uc.example.com", StaticBase: "/assets"}
	for _, entry := range []string{"login", "account", "admin", "setup"} {
		tpl, err := templatesFS.ReadFile("templates/" + entry + ".html")
		if err != nil {
			t.Fatalf("read %s: %v", entry, err)
		}
		if strings.Contains(string(tpl), TemplateVarsPlaceholder) {
			t.Fatalf("%s 内置壳不应含模板变量占位符", entry)
		}
		got, err := renderHTML(string(tpl), init, "/assets/", "FIXED", `{"x":"<>&"}`)
		if err != nil {
			t.Fatalf("%s renderHTML: %v", entry, err)
		}
		want := legacyRender(string(tpl), init, "/assets/", "FIXED")
		if string(got) != want {
			t.Errorf("%s 回落文件壳与改动前不一致（长度 got=%d want=%d）", entry, len(got), len(want))
		}
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
// （setup 模式）/ SsoClients nil / 查无行 / template_key 空 / Resolve miss
// 一律 ok=false、varsJSON 为空、err 为 nil；命中时 html 与转义后 varsJSON
// 正确返回。
func TestResolveClientTemplateFallback(t *testing.T) {
	const custom = `<html>{{AUTHLOFT_TEMPLATE_VARS}}</html>`
	resolver := &fakeTplResolver{content: map[string]string{"k": custom}}
	sso := &fakeSsoClients{rows: map[string]*model.SsoClient{
		"app":   {TemplateKey: "k", TemplateVars: `{"a":"<x>"}`},
		"nokey": {TemplateKey: "", TemplateVars: ""},
	}}
	cases := []struct {
		name     string
		deps     Deps
		clientID string
		wantOK   bool
	}{
		{"no client id", Deps{Templates: resolver, SsoClients: sso}, "", false},
		{"templates nil setup", Deps{SsoClients: sso}, "app", false},
		{"sso clients nil", Deps{Templates: resolver}, "app", false},
		{"row not found", Deps{Templates: resolver, SsoClients: sso}, "missing", false},
		{"template key empty", Deps{Templates: resolver, SsoClients: sso}, "nokey", false},
		{"resolve miss", Deps{Templates: &fakeTplResolver{content: map[string]string{}}, SsoClients: sso}, "app", false},
		{"sso hit", Deps{Templates: resolver, SsoClients: sso}, "app", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			html, vars, ok, err := resolveClientTemplate(context.Background(), tc.deps, tc.clientID, false)
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (html=%q vars=%q)", ok, tc.wantOK, html, vars)
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
// SsoClients 未装配也能命中，验证两族分流与 oidc 客户端 template_vars 转义。
func TestResolveClientTemplateOIDC(t *testing.T) {
	const custom = `<html>{{AUTHLOFT_TEMPLATE_VARS}}</html>`
	d := Deps{
		Templates: &fakeTplResolver{content: map[string]string{"oidc-k": custom}},
		Clients:   &fakeClients{c: &model.OidcClient{TemplateKey: "oidc-k", TemplateVars: `{"b":"&"}`}},
	}
	html, vars, ok, err := resolveClientTemplate(context.Background(), d, "oidc-app", true)
	if err != nil || !ok {
		t.Fatalf("resolveClientTemplate(oidc): ok=%v err=%v", ok, err)
	}
	if html != custom || vars != `{"b":"\u0026"}` {
		t.Errorf("oidc html=%q vars=%q", html, vars)
	}
	// oidc=false 时 SsoClients 未装配必须回落（不会误用 Clients）。
	if _, _, ok, _ := resolveClientTemplate(context.Background(), d, "oidc-app", false); ok {
		t.Error("sso 分支在无 SsoClients 时不应命中")
	}
}

// TestLoginShellCustomTemplate 端到端：sso_client 指定 template_key 且模板含
// 模板变量占位符 → 自定义模板生效（变量转义后注入、四占位符全替换）。
func TestLoginShellCustomTemplate(t *testing.T) {
	f := newFixture(t)
	const custom = `<html><head><script nonce="` + phCSPNonce + `">` +
		`window.__AUTHLOFT_INIT__=` + phInitJSON + `;` +
		`window.__AUTHLOFT_TEMPLATE_VARS__=` + TemplateVarsPlaceholder + `;</script>` +
		`<link href="` + phStaticBase + `/x.css"></head><body id="root">custom</body></html>`
	f.deps.Templates = &fakeTplResolver{content: map[string]string{"tpl-login": custom}}
	f.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{
		"app-1": {TemplateKey: "tpl-login", TemplateVars: `{"brand":"<b>&` + "\u2028" + `"}`},
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

// TestLoginShellFallbackByteIdentical 端到端逐字一致：未指定 client_id、
// Resolve miss、setup（Templates nil）三种回落，body 与不带 client_id 的
// 文件壳逐字相同，且不含模板变量注入痕迹。
func TestLoginShellFallbackByteIdentical(t *testing.T) {
	baseline := newFixture(t)
	baselineBody := doGet(t, fixedNonceEngine(t, baseline.deps), "/sso/login").Body.String()

	// Resolve miss：有 client_id + template_key，但 Resolve 未命中。
	miss := newFixture(t)
	miss.deps.Templates = &fakeTplResolver{content: map[string]string{}}
	miss.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{
		"app": {TemplateKey: "absent"},
	}}
	missBody := doGet(t, fixedNonceEngine(t, miss.deps), "/sso/login?client_id=app").Body.String()

	// setup 模式：Templates 为 nil（Deps 未装配模板解析源）。
	setup := newFixture(t)
	setup.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{
		"app": {TemplateKey: "k"},
	}}
	setupBody := doGet(t, fixedNonceEngine(t, setup.deps), "/sso/login?client_id=app").Body.String()

	for name, body := range map[string]string{"resolve miss": missBody, "setup nil": setupBody} {
		if body != baselineBody {
			t.Errorf("%s 回落 body 与基线不一致（长度 got=%d baseline=%d）", name, len(body), len(baselineBody))
		}
		if strings.Contains(body, `"_TV_`) || strings.Contains(body, "AUTHLOFT_TEMPLATE_VARS") {
			t.Errorf("%s 回落 body 含模板变量注入痕迹", name)
		}
	}
}
