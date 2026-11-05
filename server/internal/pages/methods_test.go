// methods_test.go methods 快照组装测试（§2.1 行 359-413、§12.3）：
// provider 过滤 is_enabled+enable_signin、凭证零泄漏、login_methods 过滤、
// steps 序列对 §1.10、login_methods 缺失 500、register / reset 流过滤、
// 数值字段十进制字符串（§1.12）。
package pages

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"authloft/internal/provider"
	"authloft/internal/settings"
)

// parseInit INIT JSON → map。
func parseInit(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(initJSON(t, body)), &m); err != nil {
		t.Fatalf("parse INIT: %v (%s)", err, initJSON(t, body))
	}
	return m
}

// loginMethodsFrom GET target 后取 INIT.methods.methods 数组。
func loginMethodsFrom(t *testing.T, target string, f *fixture) []map[string]any {
	t.Helper()
	rec := doGet(t, f.engine(t), target)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status = %d, want 200（body %s）", target, rec.Code, rec.Body.String())
	}
	init := parseInit(t, rec.Body.String())
	snap, ok := init["methods"].(map[string]any)
	if !ok {
		t.Fatalf("INIT.methods 缺失: %s", initJSON(t, rec.Body.String()))
	}
	list, _ := snap["methods"].([]any)
	out := make([]map[string]any, len(list))
	for i, v := range list {
		out[i], _ = v.(map[string]any)
	}
	return out
}

// methodNames 提取 method 名序列。
func methodNames(ms []map[string]any) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i], _ = m["method"].(string)
	}
	return out
}

// strSlice 提取 []string 字段。
func strSlice(v any) []string {
	list, _ := v.([]any)
	out := make([]string, len(list))
	for i, e := range list {
		out[i], _ = e.(string)
	}
	return out
}

// TestLoginMethodsFilter login_methods 过滤（§2.1 行 406）：白名单外、
// device、未注册方式不注入；顺序保持 settings 序。
func TestLoginMethodsFilter(t *testing.T) {
	f := newFixture(t)
	f.settings.m[settings.KeyLoginMethods] = []string{
		"otp_sms", "password", "totp", "device", "no_such_method", "recovery_code",
	}
	got := methodNames(loginMethodsFrom(t, "/sso/login", f))
	want := []string{"otp_sms", "password", "totp", "recovery_code"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("methods = %v, want %v（login_methods 过滤 + device 不出现）", got, want)
	}
}

// TestStepsSequences steps 序列对 §1.10 行 305-310：password=[form]、
// otp_sms/otp_email/webauthn=[challenge,form]、totp/recovery_code=[form]。
func TestStepsSequences(t *testing.T) {
	f := newFixture(t)
	f.settings.m[settings.KeyLoginMethods] = []string{
		"password", "otp_sms", "otp_email", "webauthn", "totp", "recovery_code",
	}
	ms := loginMethodsFrom(t, "/sso/login", f)
	want := map[string][]string{
		"password":      {"form"},
		"otp_sms":       {"challenge", "form"},
		"otp_email":     {"challenge", "form"},
		"webauthn":      {"challenge", "form"},
		"totp":          {"form"},
		"recovery_code": {"form"},
	}
	for _, m := range ms {
		name, _ := m["method"].(string)
		if !reflect.DeepEqual(strSlice(m["steps"]), want[name]) {
			t.Errorf("%s steps = %v, want %v", name, strSlice(m["steps"]), want[name])
		}
	}
}

// TestFactorExtras 各因子渲染补充字段（§2.1 行 383-397）：password fields、
// otp challengeFields + codeLength/resendAfter/expiresIn（settings 镜像 +
// §1.12 十进制字符串）、webauthn capability、totp codeLength。
func TestFactorExtras(t *testing.T) {
	f := newFixture(t)
	f.settings.m[settings.KeyOtpResendInterval] = int64(90)
	f.settings.m[settings.KeyOtpTtl] = int64(600)
	f.settings.m[settings.KeyLoginMethods] = []string{"password", "otp_sms", "otp_email", "webauthn", "totp"}
	ms := loginMethodsFrom(t, "/sso/login", f)
	byName := map[string]map[string]any{}
	for _, m := range ms {
		byName[m["method"].(string)] = m
	}

	pw := byName["password"]
	fields, _ := pw["fields"].([]any)
	if len(fields) != 3 {
		t.Fatalf("password fields = %v, want 3（username/password/captcha）", pw["fields"])
	}
	first, _ := fields[0].(map[string]any)
	if first["name"] != "username" || first["type"] != "text" || first["required"] != true {
		t.Errorf("password fields[0] = %v", first)
	}

	sms := byName["otp_sms"]
	if cf, _ := sms["challengeFields"].([]any); len(cf) != 1 {
		t.Errorf("otp_sms challengeFields = %v, want [phone]", sms["challengeFields"])
	} else if m, _ := cf[0].(map[string]any); m["name"] != "phone" || m["type"] != "phone" {
		t.Errorf("otp_sms challengeFields[0] = %v", m)
	}
	if sms["codeLength"] != "6" || sms["resendAfter"] != "90" || sms["expiresIn"] != "600" {
		t.Errorf("otp_sms 数值字段 = %v/%v/%v, want \"6\"/\"90\"/\"600\"（§1.12 字符串）",
			sms["codeLength"], sms["resendAfter"], sms["expiresIn"])
	}
	if wa := byName["webauthn"]; wa["capability"] != "window.PublicKeyCredential" {
		t.Errorf("webauthn capability = %v", wa["capability"])
	}
	if tp := byName["totp"]; tp["codeLength"] != "6" {
		t.Errorf("totp codeLength = %v, want \"6\"", tp["codeLength"])
	}
}

// TestThirdpartyProviders thirdparty.providers 组装（§12.3 行 1462-1466）：
// 只含 is_enabled=1 且 enable_signin=1；凭证零泄漏（ext 字节不进注入）；
// steps 为所辖渠道首 kind 并集（§2.7.1 行 576）；sort_order 排序；
// 非 oauth 渠道 type 不参与。
func TestThirdpartyProviders(t *testing.T) {
	f := newFixture(t)
	f.loader.rows = map[string][]*provider.Provider{
		"qq": {
			provRow("qq", "qq", true, 1, 10),
			provRow("qq_disabled", "qq", false, 1, 11), // is_enabled=0 → 排除
		},
		"wechat_mp": {
			provRow("wxmp", "wechat_mp", true, 0, 30), // enable_signin=0 → 排除
		},
		"wechat_mp_scan": {
			provRow("scan", "wechat_mp_scan", true, 1, 20),
		},
	}

	rec := doGet(t, f.engine(t), "/sso/login")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "raw-secret-ext-bytes") {
		t.Errorf("注入泄漏 ext 凭证字节")
	}
	if strings.Contains(body, "wxmp") || strings.Contains(body, "qq_disabled") {
		t.Errorf("注入含未启用 / 禁登 Provider")
	}

	var tp map[string]any
	for _, m := range loginMethodsFrom(t, "/sso/login", f) {
		if m["method"] == "thirdparty" {
			tp = m
		}
	}
	if tp == nil {
		t.Fatalf("thirdparty 条目缺失")
	}
	if !reflect.DeepEqual(strSlice(tp["usage"]), []string{"primary"}) {
		t.Errorf("thirdparty usage = %v, want [primary]", tp["usage"])
	}
	// 渠道并集：redirect（qq）+ qrcode（scan）；api 渠道被过滤 → 无 external。
	if !reflect.DeepEqual(strSlice(tp["steps"]), []string{"redirect", "qrcode"}) {
		t.Errorf("thirdparty steps = %v, want [redirect qrcode]", tp["steps"])
	}
	provs, _ := tp["providers"].([]any)
	if len(provs) != 2 {
		t.Fatalf("providers = %v, want 2（qq + scan）", provs)
	}
	wantKeys := []string{"qq", "scan"} // sort_order 10 < 20
	for i, want := range wantKeys {
		p, _ := provs[i].(map[string]any)
		if p["providerKey"] != want {
			t.Errorf("providers[%d].providerKey = %v, want %q（sort_order 序）", i, p["providerKey"], want)
		}
		// 公开视图字段封闭集合（§12.3：不得返回任何凭证字段）
		for k := range p {
			switch k {
			case "providerKey", "displayName", "type", "channel", "icon", "uiGroup", "sortOrder":
			default:
				t.Errorf("providers[%d] 越界键 %q", i, k)
			}
		}
	}
	qq, _ := provs[0].(map[string]any)
	if qq["channel"] != "redirect" || qq["sortOrder"] != "10" || qq["icon"] != "https://icons.example/qq.png" {
		t.Errorf("qq 公开字段 = %v", qq)
	}

	// 非 oauth 渠道（smtp）不进 Loader 查询。
	for _, call := range f.loader.calls {
		if call == "smtp" {
			t.Errorf("Loader 查询了非 oauth 渠道 %q", call)
		}
	}
}

// TestThirdpartyAllChannelsSteps 全渠道启用时 steps 并集按 §1.10 表序
// [redirect external qrcode]（§2.7.1 行 563 示例）。
func TestThirdpartyAllChannelsSteps(t *testing.T) {
	f := newFixture(t)
	f.loader.rows = map[string][]*provider.Provider{
		"qq":             {provRow("qq", "qq", true, 1, 10)},
		"wechat_mp":      {provRow("wxmp", "wechat_mp", true, 1, 30)},
		"wechat_mp_scan": {provRow("scan", "wechat_mp_scan", true, 1, 20)},
	}
	for _, m := range loginMethodsFrom(t, "/sso/login", f) {
		if m["method"] == "thirdparty" {
			if !reflect.DeepEqual(strSlice(m["steps"]), []string{"redirect", "external", "qrcode"}) {
				t.Errorf("steps = %v, want [redirect external qrcode]", m["steps"])
			}
			return
		}
	}
	t.Fatalf("thirdparty 条目缺失")
}

// TestThirdpartyEmptyOmitted login_methods 含 thirdparty 但零可用 Provider
// 时不注入该条目（未启用口径，默认行为）。
func TestThirdpartyEmptyOmitted(t *testing.T) {
	f := newFixture(t)
	f.loader.rows = map[string][]*provider.Provider{
		"qq": {provRow("qq", "qq", false, 1, 10)},
	}
	got := methodNames(loginMethodsFrom(t, "/sso/login", f))
	for _, m := range got {
		if m == "thirdparty" {
			t.Errorf("零可用 Provider 时仍注入 thirdparty: %v", got)
		}
	}
}

// TestLoginMethodsMissing login_methods 缺键 → 500（§8 行 1436 缺失即
// 服务端故障；无回退接口）。
func TestLoginMethodsMissing(t *testing.T) {
	f := newFixture(t)
	delete(f.settings.m, settings.KeyLoginMethods)
	rec := doGet(t, f.engine(t), "/sso/login")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestFlagsAndCaptcha flags 镜像 settings 两开关（§2.1 行 374-377）、
// captcha 取 Gate 现算配置（§2.5 同结构）。
func TestFlagsAndCaptcha(t *testing.T) {
	f := newFixture(t)
	f.settings.m[settings.KeyAllowPasswordReset] = false
	f.settings.m[settings.KeyAllowRegistration] = true

	rec := doGet(t, f.engine(t), "/sso/login")
	init := parseInit(t, rec.Body.String())
	snap := init["methods"].(map[string]any)
	flags := snap["flags"].(map[string]any)
	if flags["passwordReset"] != false || flags["registration"] != true {
		t.Errorf("flags = %v, want passwordReset=false registration=true", flags)
	}
	cap := snap["captcha"].(map[string]any)
	if cap["providerKey"] != "cf_turnstile" || cap["type"] != "turnstile" || cap["siteKey"] != "0x4AAA" {
		t.Errorf("captcha = %v", cap)
	}
}

// TestRegisterFlow flow=register（§2.1 行 411）：按注册开关过滤、不读
// login_methods；allow_registration=false → 空数组。
func TestRegisterFlow(t *testing.T) {
	f := newFixture(t)
	f.settings.m[settings.KeyAllowSignupPhone] = false
	f.settings.m[settings.KeyAllowRegistration] = true
	delete(f.settings.m, settings.KeyLoginMethods) // 不读 login_methods

	got := methodNames(loginMethodsFrom(t, "/sso/register", f))
	want := []string{"password", "otp_email"} // phone 关 → 无 otp_sms；thirdparty 不在注册开关集合
	if !reflect.DeepEqual(got, want) {
		t.Errorf("register methods = %v, want %v", got, want)
	}

	f.settings.m[settings.KeyAllowRegistration] = false
	if got := methodNames(loginMethodsFrom(t, "/sso/register", f)); len(got) != 0 {
		t.Errorf("allow_registration=false 时 methods = %v, want 空", got)
	}
}

// TestResetFlow flow=reset（§2.1 行 412）：只保留 otp_sms / otp_email、
// usage=[primary]、steps=[challenge form]；allow_password_reset=false →
// 空数组且 flags.passwordReset=false 两者一致。
func TestResetFlow(t *testing.T) {
	f := newFixture(t)
	delete(f.settings.m, settings.KeyLoginMethods) // 不读 login_methods

	ms := loginMethodsFrom(t, "/sso/reset", f)
	if !reflect.DeepEqual(methodNames(ms), []string{"otp_sms", "otp_email"}) {
		t.Fatalf("reset methods = %v, want [otp_sms otp_email]", methodNames(ms))
	}
	for _, m := range ms {
		if !reflect.DeepEqual(strSlice(m["usage"]), []string{"primary"}) {
			t.Errorf("%s usage = %v, want [primary]", m["method"], m["usage"])
		}
		if !reflect.DeepEqual(strSlice(m["steps"]), []string{"challenge", "form"}) {
			t.Errorf("%s steps = %v, want [challenge form]", m["method"], m["steps"])
		}
	}

	f.settings.m[settings.KeyAllowPasswordReset] = false
	rec := doGet(t, f.engine(t), "/sso/reset")
	init := parseInit(t, rec.Body.String())
	snap := init["methods"].(map[string]any)
	if ms, _ := snap["methods"].([]any); len(ms) != 0 {
		t.Errorf("allow_password_reset=false 时 methods = %v, want 空数组", ms)
	}
	if snap["flags"].(map[string]any)["passwordReset"] != false {
		t.Errorf("flags.passwordReset 与空数组不一致（§2.1 行 407）")
	}
}

// TestFlowQueryOverride flow 取页面 URL query（§2.1 行 363-368），
// 非法值回落页面缺省。
func TestFlowQueryOverride(t *testing.T) {
	f := newFixture(t)
	f.settings.m[settings.KeyAllowRegistration] = false
	f.settings.m[settings.KeyLoginMethods] = []string{"password"}

	// /sso/login?flow=register → 注册快照（空，因 allow_registration=false）。
	if got := loginMethodsFrom(t, "/sso/login?flow=register", f); len(got) != 0 {
		t.Errorf("flow=register 覆盖失败: %v", methodNames(got))
	}
	// /sso/register?flow=bogus → 非法值回落页面缺省 register。
	if got := methodNames(loginMethodsFrom(t, "/sso/register?flow=bogus", f)); len(got) != 0 {
		t.Errorf("非法 flow 应回落 register 缺省: %v", got)
	}
	// /sso/login 无 query → login 快照（password 在）。
	if got := methodNames(loginMethodsFrom(t, "/sso/login", f)); !reflect.DeepEqual(got, []string{"password"}) {
		t.Errorf("login 缺省快照 = %v", got)
	}
}

// TestMethodsZeroCredentialKeys 注入键封闭集合（§8 行 1430-1437）：login
// INIT 仅 al_root / static_base / methods 三键，无任何凭证类键。
func TestMethodsZeroCredentialKeys(t *testing.T) {
	f := newFixture(t)
	rec := doGet(t, f.engine(t), "/sso/login")
	init := parseInit(t, rec.Body.String())
	allowed := map[string]bool{"al_root": true, "static_base": true, "methods": true}
	for k := range init {
		if !allowed[k] {
			t.Errorf("INIT 越界键 %q（白名单外）", k)
		}
	}
	if len(init) != 3 {
		t.Errorf("INIT 键数 = %d, want 3", len(init))
	}
	// 数值字段全字符串（§1.12：JSON 不出现裸数字）。
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for _, vv := range x {
				walk(vv)
			}
		case []any:
			for _, vv := range x {
				walk(vv)
			}
		case float64:
			t.Errorf("注入出现裸数字 %v（§1.12 应为十进制字符串）", x)
		}
	}
	walk(init)
}
