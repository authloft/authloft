// sso_init_test.go __AUTHLOFT_INIT__.sso 注入与 methods 应用级交集过滤单测
// （接口文档 §2.1 应用级过滤、§8 注入白名单 sso 键）：命中行注入
// clientId / name（INIT_JSON 既有转义，不含过滤结果）、行配置关闭的因子
// 不出现、thirdparty 按 auth_providers 白名单过滤、过滤后零 provider 不
// 注入条目、register / reset 不读应用配置、查无行回落壳不注入、列解码
// 失败 500、authorize 入口不注入。
package pages

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	clientpb "authloft/gen/go/client"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// ssoAppRow 组装 sso_client 行：login_methods / auth_providers 列经 repo
// 唯一编解码出口序列化（§12.0）；methods / providers 传 nil = 列空 = 未
// 配置 = 跟随全局（§2.1）。行默认启用（IsEnabled=1，§2.1 行命中需已启用；
// 禁用场景经 mutate 显式置 0）。mutate 供破坏列字节等特殊场景。
func ssoAppRow(t *testing.T, clientID, name string, methods, providers []string, mutate func(*model.SsoClient)) *model.SsoClient {
	t.Helper()
	lm, err := repo.MarshalClientLoginMethods(&clientpb.ClientLoginMethods{Methods: methods})
	if err != nil {
		t.Fatalf("marshal login_methods: %v", err)
	}
	op, err := repo.MarshalClientAuthProviders(&clientpb.ClientAuthProviders{Providers: providers})
	if err != nil {
		t.Fatalf("marshal auth_providers: %v", err)
	}
	row := &model.SsoClient{ClientID: clientID, Name: name, LoginMethods: lm, AuthProviders: op, IsEnabled: 1}
	if mutate != nil {
		mutate(row)
	}
	return row
}

// ssoFixture 基线夹具 + sso_client 行源。
func ssoFixture(t *testing.T, rows map[string]*model.SsoClient) *fixture {
	t.Helper()
	f := newFixture(t)
	f.deps.SsoClients = &fakeSsoClients{rows: rows}
	return f
}

// ssoFromInit 取 INIT.sso 注入体（map 形态；缺失返回 nil）。
func ssoFromInit(t *testing.T, body string) map[string]any {
	t.Helper()
	m, _ := parseInit(t, body)["sso"].(map[string]any)
	return m
}

// TestSsoInitInjectedRowHit 行命中注入 sso（§2.1 注入结构）：clientId / name
// 两键封闭集合、不含过滤结果；转义走 INIT_JSON 既有 json.Marshal 口径
// （<>& 与 U+2028，无新增转义面）；模板回落（无自定义模板的常态）仍注入
// ——行命中与模板解析正交；三个 flow 页与 callback 同为登录 entry、同注入
// （注册首签回传 ssoClientId 依赖此键，前端架构 §1.5）。
func TestSsoInitInjectedRowHit(t *testing.T) {
	const name = `<b>&应用` + "\u2028"
	f := ssoFixture(t, map[string]*model.SsoClient{
		"app": ssoAppRow(t, "app", name, nil, nil, nil),
	})
	for _, target := range []string{
		"/sso/login?client_id=app",
		"/sso/register?client_id=app",
		"/sso/reset?client_id=app",
		"/sso/oauth/callback/qq?client_id=app",
	} {
		rec := doGet(t, f.engine(t), target)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200（body %s）", target, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		init := parseInit(t, body)
		sso, ok := init["sso"].(map[string]any)
		if !ok {
			t.Fatalf("%s: INIT.sso 缺失:\n%s", target, body)
		}
		if len(sso) != 2 {
			t.Errorf("%s: sso 键集 = %v, want 仅 clientId/name（不含过滤结果，§2.1）", target, sso)
		}
		if sso["clientId"] != "app" || sso["name"] != name {
			t.Errorf("%s: sso = %v, want clientId=app name=%q", target, sso, name)
		}
		if !strings.Contains(body, `\u003cb\u003e\u0026`+"应用"+`\u2028`) {
			t.Errorf("%s: INIT_JSON 未按既有口径转义 <>& 与 U+2028:\n%s", target, body)
		}
		if strings.Contains(body, "<b>&") {
			t.Errorf("%s: 注入值未转义（裸 <b>& 出现，防 </script> 提前闭合）", target)
		}
		if len(init) != 5 {
			t.Errorf("%s: INIT 键数 = %d, want 5（al_root/static_base/methods/sso/passwordPolicy）", target, len(init))
		}
	}
}

// TestSsoMethodsIntersection 应用级交集（§2.1 第一行）：应用 login_methods
// 配置 [otp_sms password]，全局还含 otp_email / webauthn / thirdparty——
// 行配置关闭的因子不出现，且顺序仍随全局序（与应用配置顺序无关）。
func TestSsoMethodsIntersection(t *testing.T) {
	f := ssoFixture(t, map[string]*model.SsoClient{
		"app": ssoAppRow(t, "app", "应用", []string{"otp_sms", "password"}, []string{"qq"}, nil),
	})
	got := methodNames(loginMethodsFrom(t, "/sso/login?client_id=app", f))
	want := []string{"password", "otp_sms"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("methods = %v, want %v（应用交集 + 全局序）", got, want)
	}
}

// TestSsoThirdpartyAllowedProviders thirdparty 条目按应用 auth_providers
// 白名单过滤（§2.1 第三行）：应用放行 thirdparty 且白名单 [qq]，全局两个
// 可登 Provider（qq + scan）——快照只余 qq。
func TestSsoThirdpartyAllowedProviders(t *testing.T) {
	f := ssoFixture(t, map[string]*model.SsoClient{
		"app": ssoAppRow(t, "app", "应用", []string{"thirdparty"}, []string{"qq"}, nil),
	})
	f.loader.rows = map[string][]*provider.Provider{
		"qq":             {provRow("qq", "qq", true, 1, 10)},
		"wechat_mp_scan": {provRow("scan", "wechat_mp_scan", true, 1, 20)},
	}
	var tp map[string]any
	for _, m := range loginMethodsFrom(t, "/sso/login?client_id=app", f) {
		if m["method"] == "thirdparty" {
			tp = m
		}
	}
	if tp == nil {
		t.Fatalf("thirdparty 条目缺失")
	}
	provs, _ := tp["providers"].([]any)
	if len(provs) != 1 {
		t.Fatalf("providers = %v, want 1（白名单外 scan 被过滤）", provs)
	}
	p, _ := provs[0].(map[string]any)
	if p["providerKey"] != "qq" {
		t.Errorf("providerKey = %v, want qq", p["providerKey"])
	}
}

// TestSsoThirdpartyZeroProvidersOmitted 白名单过滤后零 provider → thirdparty
// 条目不注入（§2.1：过滤后可用 Provider 非空才成立）；应用未放行其余因子
// → methods 为空数组。
func TestSsoThirdpartyZeroProvidersOmitted(t *testing.T) {
	f := ssoFixture(t, map[string]*model.SsoClient{
		"app": ssoAppRow(t, "app", "应用", []string{"thirdparty"}, []string{"ghost"}, nil),
	})
	f.loader.rows = map[string][]*provider.Provider{
		"qq": {provRow("qq", "qq", true, 1, 10)},
	}
	got := methodNames(loginMethodsFrom(t, "/sso/login?client_id=app", f))
	for _, m := range got {
		if m == "thirdparty" {
			t.Errorf("过滤后零 provider 仍注入 thirdparty: %v", got)
		}
	}
	if len(got) != 0 {
		t.Errorf("methods = %v, want 空", got)
	}
}

// TestSsoUnconfiguredFollowsGlobal 行命中但两列均未配置（空 = 跟随全局，
// §2.1）：methods 与全局基线一致，sso 键仍注入（行命中即注入，§2.1 只以
// 查无行为不注入条件）。
func TestSsoUnconfiguredFollowsGlobal(t *testing.T) {
	f := ssoFixture(t, map[string]*model.SsoClient{
		"app": ssoAppRow(t, "app", "应用", nil, nil, nil),
	})
	got := methodNames(loginMethodsFrom(t, "/sso/login?client_id=app", f))
	want := []string{"password", "otp_sms", "otp_email", "webauthn"} // 全局集（thirdparty 零可用 provider 不注入）
	if !reflect.DeepEqual(got, want) {
		t.Errorf("methods = %v, want %v（未配置跟随全局）", got, want)
	}
	rec := doGet(t, f.engine(t), "/sso/login?client_id=app")
	if sso := ssoFromInit(t, rec.Body.String()); sso == nil {
		t.Errorf("行命中未配置仍应注入 sso:\n%s", rec.Body.String())
	}
}

// TestSsoRegisterResetNoAppConfig register / reset 不读应用配置（§2.1：仅
// flow=login 消费交集）：应用仅放行 password / thirdparty，注册 / 重置快照
// 仍镜像全局口径；sso 键照注入（注册首签回传依赖，前端架构 §1.5）。
func TestSsoRegisterResetNoAppConfig(t *testing.T) {
	f := ssoFixture(t, map[string]*model.SsoClient{
		"app": ssoAppRow(t, "app", "应用", []string{"password", "thirdparty"}, []string{"qq"}, nil),
	})
	if got := methodNames(loginMethodsFrom(t, "/sso/register?client_id=app", f)); !reflect.DeepEqual(got, []string{"password", "otp_sms", "otp_email"}) {
		t.Errorf("register methods = %v, want 全局口径 [password otp_sms otp_email]", got)
	}
	if got := methodNames(loginMethodsFrom(t, "/sso/reset?client_id=app", f)); !reflect.DeepEqual(got, []string{"otp_sms", "otp_email"}) {
		t.Errorf("reset methods = %v, want 全局口径 [otp_sms otp_email]", got)
	}
	for _, target := range []string{"/sso/register?client_id=app", "/sso/reset?client_id=app"} {
		rec := doGet(t, f.engine(t), target)
		if sso := ssoFromInit(t, rec.Body.String()); sso == nil {
			t.Errorf("%s: INIT.sso 缺失（注册首签回传依赖此键）", target)
		}
	}
}

// TestSsoRowMissFallbackNoInit client_id 查无行：回落默认壳、不注入 sso、
// methods 走全局（§2.1 查无行不注入本键）。
func TestSsoRowMissFallbackNoInit(t *testing.T) {
	f := ssoFixture(t, map[string]*model.SsoClient{})
	rec := doGet(t, f.engine(t), "/sso/login?client_id=ghost")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	init := parseInit(t, rec.Body.String())
	if _, ok := init["sso"]; ok {
		t.Errorf("查无行回落壳不应注入 sso: %v", init)
	}
	if len(init) != 4 {
		t.Errorf("INIT 键数 = %d, want 4（al_root/static_base/methods/passwordPolicy）", len(init))
	}
}

// TestSsoConfigParseFailure 应用配置列解码失败 → 500（服务端故障，与
// login_methods 缺键同口径；不静默降级为跟随全局）。
func TestSsoConfigParseFailure(t *testing.T) {
	row := ssoAppRow(t, "app", "应用", nil, nil, func(r *model.SsoClient) {
		r.LoginMethods = []byte{0xff, 0xff, 0xff} // 非法 wire format
	})
	f := ssoFixture(t, map[string]*model.SsoClient{"app": row})
	rec := doGet(t, f.engine(t), "/sso/login?client_id=app")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500（body %s）", rec.Code, rec.Body.String())
	}
}

// TestAuthorizeNoSsoInjection authorize 入口不注入 sso（§2.1 / §8 白名单）：
// 即便同一 client_id 存在 sso_client 行（两族分列，authorize 只消费
// oidc_client），INIT 有 oidc 键而无 sso 键，methods 亦不被应用交集过滤。
func TestAuthorizeNoSsoInjection(t *testing.T) {
	f := newAuthzFixture(t)
	f.deps.SsoClients = &fakeSsoClients{rows: map[string]*model.SsoClient{
		"demo-app": ssoAppRow(t, "demo-app", "应用", []string{"password"}, []string{"qq"}, nil),
	}}
	rec := doGet(t, f.engine(t), authzQ)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200（body %s）", rec.Code, rec.Body.String())
	}
	init := parseInit(t, rec.Body.String())
	if _, ok := init["sso"]; ok {
		t.Errorf("authorize 入口不应注入 sso: %v", init)
	}
	if _, ok := init["oidc"]; !ok {
		t.Errorf("authorize 入口应注入 oidc 键: %v", init)
	}
	got := methodNames(loginMethodsFromInit(t, init))
	want := []string{"password", "otp_sms", "otp_email", "webauthn"} // 全局基线（thirdparty 零可用 provider 不注入）
	if !reflect.DeepEqual(got, want) {
		t.Errorf("authorize methods = %v, want %v（不被应用交集过滤）", got, want)
	}
}

// loginMethodsFromInit 从已解析的 INIT map 提取 methods 数组（authorize
// 路径复用 parseInit 结果，不再发请求）。
func loginMethodsFromInit(t *testing.T, init map[string]any) []map[string]any {
	t.Helper()
	snap, ok := init["methods"].(map[string]any)
	if !ok {
		t.Fatalf("INIT.methods 缺失: %v", init)
	}
	list, _ := snap["methods"].([]any)
	out := make([]map[string]any, len(list))
	for i, v := range list {
		out[i], _ = v.(map[string]any)
	}
	return out
}
