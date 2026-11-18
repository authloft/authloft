// turnstile_test.go 三家各走自身 factory 的 type 侧用例（docs/后端架构.md
// §9.1 阶段三）：init 自注册后经 provider.NewVerifier 分派到本包实现并携带
// Ext 口径（site_key=client_id、secret=client_secret、endpoint 覆盖默认端点）；
// meta 驱动 admin /schema（引用键呈现、oauth 专属键不下发）。
package turnstile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	captchacore "authloft/internal/provider/captcha/captcha-core"
)

// TestTypeRegisteredAndDispatched 注册表分派到本包实现（blank import 完整性
// 由 bootstrap 门禁与本用例共同兜底）。
func TestTypeRegisteredAndDispatched(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok {
		t.Fatalf("type %q 未注册（_ import 缺失）", Type)
	}
	if meta.Category != provider.CategoryCaptcha || meta.DisplayName != "Cloudflare Turnstile" {
		t.Fatalf("meta = %+v", meta)
	}
	if meta.Schema == nil || len(meta.Schema()) == 0 {
		t.Fatal("meta.Schema() 为空（admin /schema 数据源缺失）")
	}
	// CSP 源声明随实现走（§9.4 工厂化收口）：本包登记源 = 接口文档 §8
	// 参考源清单表，防注册声明漂移。
	wantCSP := map[string][]string{
		"frame-src": {"https://challenges.cloudflare.com"},
	}
	if !reflect.DeepEqual(meta.CSPSources, wantCSP) {
		t.Fatalf("meta.CSPSources = %v, want %v（接口文档 §8 参考源清单）", meta.CSPSources, wantCSP)
	}
}

// TestNewVerifierViaRegistry provider.NewVerifier 按本包 type 构造并使用
// Ext 配置（httptest 假端点，不打真实厂商）：请求恰含 secret/response 两
// 字段、endpoint 取 ext.endpoint。
func TestNewVerifierViaRegistry(t *testing.T) {
	var method, ctype string
	form := map[string]string{}
	rec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		ctype = r.Header.Get("Content-Type")
		_ = r.ParseForm()
		for k, vs := range r.PostForm {
			form[k] = vs[0]
		}
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer rec.Close()

	p := &provider.Provider{
		Key:  "cf_turnstile",
		Type: Type,
		Ext:  &providerpb.Ext{ClientId: "0xSITE", ClientSecret: "sec-1", Endpoint: rec.URL},
	}
	v, err := provider.NewVerifier(p)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, ok := v.(*captchacore.Verifier); !ok {
		t.Fatalf("NewVerifier 返回 %T, want *captchacore.Verifier（三家共用实现）", v)
	}
	if err := v.Verify(context.Background(), "cf_turnstile", provider.Submission{Token: "tok"}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if method != http.MethodPost || ctype != "application/x-www-form-urlencoded" {
		t.Fatalf("request = (%q, %q), want POST form-urlencoded", method, ctype)
	}
	if len(form) != 2 || form["secret"] != "sec-1" || form["response"] != "tok" {
		t.Fatalf("form = %v, want {secret:sec-1, response:tok}", form)
	}
}

// TestDefaultEndpoint 厂商默认端点常量（Cloudflare Turnstile siteverify）。
func TestDefaultEndpoint(t *testing.T) {
	if defaultVerifyURL != "https://challenges.cloudflare.com/turnstile/v0/siteverify" {
		t.Fatalf("defaultVerifyURL = %q", defaultVerifyURL)
	}
}
