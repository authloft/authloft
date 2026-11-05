// cookie_test.go 会话 Cookie 三态驱动测试（接口文档 §1.9 行
// 286-310 / §5.6 行 1354 / SDK-init §4.4 逐字对齐）：
//  1. 三态 × HTTP/HTTPS 信号组合矩阵（true/false 恒定；auto 随信号）；
//  2. 默认值与未注入三态源（旧默认恒 HTTPS，既有调用方零破坏）；
//  3. X-Forwarded-Proto 首值 / 缺省 / TLS 三路推断 + 头优先于 TLS；
//  4. SameSite 联动降级断言（HTTPS → None；明文 → Lax + 省 Secure）；
//  5. 三态源每请求读取（后台改值立即生效，沿 cookie_name 热更口径）；
//  6. Clear 属性与 Set 同判定 + 删除语义（MaxAge=-1）；
//  7. RequestSignal ctx 载体 roundtrip；NewCookie variadic 兼容。
package session

import (
	"context"
	"net/http"
	"testing"
	"time"

	"authloft/internal/settings"
)

// modeOf 固定三态源。
func modeOf(v string) func() string { return func() string { return v } }

// sigHeader 仅 X-Forwarded-Proto 头信号（connect 链形态：TLS 不可得）。
func sigHeader(v string) RequestSignal {
	return RequestSignal{Header: http.Header{"X-Forwarded-Proto": []string{v}}}
}

// wantCookie 断言 Secure / SameSite 联动（§1.9 行 288 / 292）。
func wantCookie(t *testing.T, ck *http.Cookie, secure bool, name string) {
	t.Helper()
	if secure {
		if !ck.Secure || ck.SameSite != http.SameSiteNoneMode {
			t.Errorf("%s: HTTPS 判定应 Secure+SameSite=None, got Secure=%v SameSite=%v", name, ck.Secure, ck.SameSite)
		}
	} else {
		if ck.Secure || ck.SameSite != http.SameSiteLaxMode {
			t.Errorf("%s: 明文判定应省略 Secure+SameSite=Lax, got Secure=%v SameSite=%v", name, ck.Secure, ck.SameSite)
		}
	}
	if !ck.HttpOnly || ck.Path != "/" {
		t.Errorf("%s: HttpOnly/Path 应恒定 true+/, got %v/%q", name, ck.HttpOnly, ck.Path)
	}
}

// TestSetTriStateMatrix 三态 × HTTP/HTTPS 信号组合矩阵（§1.9 行 299-310）：
// true/false 恒定覆盖推断；auto 逐请求按信号判定。
func TestSetTriStateMatrix(t *testing.T) {
	cases := []struct {
		mode    string
		sig     RequestSignal
		secure  bool
		comment string
	}{
		// true：恒 HTTPS，无视信号（明文环境浏览器不保存，§5.6 行 1356 文案）。
		{settings.HTTPSDeploymentTrue, RequestSignal{}, true, "true+无信号"},
		{settings.HTTPSDeploymentTrue, sigHeader("http"), true, "true+头http"},
		{settings.HTTPSDeploymentTrue, RequestSignal{TLS: true}, true, "true+TLS"},
		// false：恒明文，无视信号。
		{settings.HTTPSDeploymentFalse, RequestSignal{}, false, "false+无信号"},
		{settings.HTTPSDeploymentFalse, sigHeader("https"), false, "false+头https"},
		{settings.HTTPSDeploymentFalse, RequestSignal{TLS: true}, false, "false+TLS"},
		// auto：随信号三路（头首值 → TLS → 兜底明文）。
		{settings.HTTPSDeploymentAuto, RequestSignal{}, false, "auto+无信号=兜底明文"},
		{settings.HTTPSDeploymentAuto, sigHeader("https"), true, "auto+头https"},
		{settings.HTTPSDeploymentAuto, sigHeader("http"), false, "auto+头http"},
		{settings.HTTPSDeploymentAuto, sigHeader("https, http"), true, "auto+头逗号首值https"},
		{settings.HTTPSDeploymentAuto, sigHeader("http, https"), false, "auto+头逗号首值http"},
		{settings.HTTPSDeploymentAuto, RequestSignal{TLS: true}, true, "auto+TLS直连"},
		{settings.HTTPSDeploymentAuto, sigHeader("HTTPS"), true, "auto+头大小写不敏感"},
		{settings.HTTPSDeploymentAuto, sigHeader("wss"), false, "auto+头其他任意值=明文"},
	}
	for _, tc := range cases {
		c := NewCookie("al_session", "example.com", 7*24*time.Hour, WithHTTPSMode(modeOf(tc.mode)))
		wantCookie(t, c.Set("tok", tc.sig), tc.secure, tc.comment)
	}
}

// TestSetDefaultModeHTTPSDefaults 未注入三态源（3 参旧调用）沿旧默认恒
// HTTPS——既有调用方（connect 拦截器 / sso 测试直构 / pages 临时构造）
// 零破坏；默认档（settings.Defaults）https_deployment = auto（§5.6
// 行 1354）。
func TestSetDefaultModeHTTPSDefaults(t *testing.T) {
	c := NewCookie("", "", time.Hour)
	if c.name != "al_session" {
		t.Fatalf("空名应回落 al_session, got %q", c.name)
	}
	// 无三态源：即使信号全明文也沿旧默认 Secure+None。
	wantCookie(t, c.Set("tok"), true, "未注入mode+无信号")
	wantCookie(t, c.Set("tok", RequestSignal{}), true, "未注入mode+无信号(显式)")
	def := settings.Defaults()
	if got := def[settings.KeyHttpsDeployment]; got != settings.HTTPSDeploymentAuto {
		t.Errorf("Defaults()[https_deployment] = %v, want auto（§5.6 行 1354 默认值）", got)
	}
}

// TestSetAutoInferenceThreePaths auto 三路推断逐字断言（§1.9 行 306-309
// / SDK-init §4.4 规则 1-3）：头首值、头缺省看 TLS、头与 TLS 矛盾以头
// 为准（头优先于 TLS）。
func TestSetAutoInferenceThreePaths(t *testing.T) {
	c := NewCookie("al_session", "", time.Hour, WithHTTPSMode(modeOf(settings.HTTPSDeploymentAuto)))
	// 路一：头存在按头（HTTP 头 + TLS 直连矛盾 → 明文，头优先）。
	if got := ResolveHTTPS(c.mode, sigHeader("http")); got {
		t.Errorf("头=http+TLS 矛盾应以头为准判明文（规则 3）")
	}
	// 路一反向：头=https + 无 TLS（反代 TLS 终止典型形态）→ HTTPS。
	if !ResolveHTTPS(c.mode, sigHeader("https")) {
		t.Errorf("头=https 应判 HTTPS（反代场景唯一可靠来源）")
	}
	// 路二：头缺省看 TLS。
	if !ResolveHTTPS(c.mode, RequestSignal{TLS: true}) {
		t.Errorf("头缺省+TLS 直连应判 HTTPS（规则 2）")
	}
	// 路二兜底：头缺省无 TLS → 明文。
	if ResolveHTTPS(c.mode, RequestSignal{}) {
		t.Errorf("头缺省无 TLS 应兜底明文（规则 2 兜底）")
	}
	// 未传信号（variadic 空）≡ 无信号兜底。
	if ResolveHTTPS(c.mode, RequestSignal{}) {
		t.Errorf("无信号应兜底明文")
	}
}

// TestSetModeHotReload 三态源每请求读取（§1.9「逐请求判定」+ 沿
// cookie_name 热更口径）：后台改值 → 同一构造器下一判定立即生效，无
// 进程内缓存死值。
func TestSetModeHotReload(t *testing.T) {
	current := settings.HTTPSDeploymentAuto
	c := NewCookie("al_session", "", time.Hour, WithHTTPSMode(func() string { return current }))
	sig := sigHeader("http") // 明文信号
	wantCookie(t, c.Set("tok", sig), false, "auto+明文信号")
	current = settings.HTTPSDeploymentTrue
	wantCookie(t, c.Set("tok", sig), true, "后台改 true 后同信号翻转为 HTTPS")
	current = settings.HTTPSDeploymentFalse
	wantCookie(t, c.Set("tok", sigHeader("https")), false, "后台改 false 后无视信号恒明文")
}

// TestClearAttributes Clear 属性与 Set 同判定 + 删除语义（MaxAge=-1、
// 同名同 Path；HttpOnly 恒定）。
func TestClearAttributes(t *testing.T) {
	c := NewCookie("al_session", "example.com", time.Hour, WithHTTPSMode(modeOf(settings.HTTPSDeploymentFalse)))
	ck := c.Clear()
	if ck.MaxAge != -1 {
		t.Errorf("Clear MaxAge = %d, want -1（浏览器立即删除）", ck.MaxAge)
	}
	if ck.Name != "al_session" || ck.Path != "/" || ck.Domain != "example.com" {
		t.Errorf("Clear 应同名同 Path/Domain: %q/%q/%q", ck.Name, ck.Path, ck.Domain)
	}
	wantCookie(t, ck, false, "Clear 明文判定")
	// HTTPS 判定的 Clear 同步带 Secure+None。
	c2 := NewCookie("al_session", "", time.Hour, WithHTTPSMode(modeOf(settings.HTTPSDeploymentTrue)))
	wantCookie(t, c2.Clear(), true, "Clear HTTPS 判定")
}

// TestRequestSignalContext RequestSignal ctx 载体 roundtrip：connect
// 链拦截器注入 → 下游（写点 / thirdparty）读取；未注入返回零值。
func TestRequestSignalContext(t *testing.T) {
	if got := RequestSignalFromContext(context.Background()); got.Header != nil || got.TLS {
		t.Errorf("未注入 ctx 应返回零值信号, got %+v", got)
	}
	sig := RequestSignal{Header: http.Header{"X-Forwarded-Proto": []string{"https"}}}
	ctx := WithRequestSignal(context.Background(), sig)
	if got := RequestSignalFromContext(ctx); !deriveAutoHTTPS(got) {
		t.Errorf("ctx 注入后应可推断 HTTPS, got %+v", got)
	}
	// RequestSignalFromContext(nil ctx) 防御。
	if got := RequestSignalFromContext(nil); got.Header != nil || got.TLS {
		t.Errorf("nil ctx 应返回零值信号, got %+v", got)
	}
}
