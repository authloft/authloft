// hcaptcha_test.go 三家各走自身 factory 的 type 侧用例（docs/后端架构.md
// §9.1 阶段三）：init 自注册后经 provider.NewVerifier 分派到本包实现并携带
// Ext 口径（site_key=client_id、secret=client_secret、endpoint 覆盖默认端点）。
package hcaptcha

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
	if meta.Category != provider.CategoryCaptcha || meta.DisplayName != "hCaptcha" {
		t.Fatalf("meta = %+v", meta)
	}
	if meta.Schema == nil || len(meta.Schema()) == 0 {
		t.Fatal("meta.Schema() 为空（admin /schema 数据源缺失）")
	}
	// CSP 源声明随实现走（§9.4 工厂化收口）：本包登记源 = 接口文档 §8
	// 参考源清单表，防注册声明漂移。
	wantCSP := map[string][]string{
		"frame-src": {"https://hcaptcha.com", "https://*.hcaptcha.com"},
		"style-src": {"https://hcaptcha.com", "https://*.hcaptcha.com"},
	}
	if !reflect.DeepEqual(meta.CSPSources, wantCSP) {
		t.Fatalf("meta.CSPSources = %v, want %v（接口文档 §8 参考源清单）", meta.CSPSources, wantCSP)
	}
}

// TestNewVerifierViaRegistry provider.NewVerifier 按本包 type 构造并使用
// Ext 配置（httptest 假端点，不打真实厂商）。
func TestNewVerifierViaRegistry(t *testing.T) {
	var method string
	form := map[string]string{}
	rec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		_ = r.ParseForm()
		for k, vs := range r.PostForm {
			form[k] = vs[0]
		}
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer rec.Close()

	p := &provider.Provider{
		Key:  "hc",
		Type: Type,
		Ext:  &providerpb.Ext{ClientId: "0xSITE", ClientSecret: "sec-h", Endpoint: rec.URL},
	}
	v, err := provider.NewVerifier(p)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, ok := v.(*captchacore.Verifier); !ok {
		t.Fatalf("NewVerifier 返回 %T, want *captchacore.Verifier（三家共用实现）", v)
	}
	if err := v.Verify(context.Background(), "hc", provider.Submission{Token: "tok"}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if method != http.MethodPost {
		t.Fatalf("method = %q, want POST", method)
	}
	if len(form) != 2 || form["secret"] != "sec-h" || form["response"] != "tok" {
		t.Fatalf("form = %v, want {secret:sec-h, response:tok}", form)
	}
}

// TestDefaultEndpoint 厂商默认端点常量（hCaptcha siteverify）。
func TestDefaultEndpoint(t *testing.T) {
	if defaultVerifyURL != "https://api.hcaptcha.com/siteverify" {
		t.Fatalf("defaultVerifyURL = %q", defaultVerifyURL)
	}
}
