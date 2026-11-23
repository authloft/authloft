// csp_test.go 覆盖 Catalog.CSP()（docs/后端架构.md §9.4 / docs/接口文档.md
// §8「provider 贡献源」）：降级各态一律贡献空串（未配置不写入任何域名）、
// 各家第三方各 type 的登记片段逐字、每请求现算（与 Current 同源，热更新
// 语义一致）、白名单过滤与逐行生效隔离。
package captcha

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"authloft/internal/provider"
	"authloft/internal/settings"

	// 三家新 type 的注册触发（同 factory_chain_test.go 先例：本测试二进制
	// 内 Lookup 可命中；package main 的装配门禁另以 bootstrap.go 的 import
	// 取证，两个测试二进制互不影响）。
	_ "authloft/internal/provider/captcha/aliyun_captcha"
	_ "authloft/internal/provider/captcha/capjs"
	_ "authloft/internal/provider/captcha/geetest_v4"
)

// TestCatalogCSPNoContribution 无贡献各态（§8「未配置的 Provider 不写入
// 任何域名」；§9.4 Current 同源判定）：键空串 / 键未设置 / 行不存在 /
// 查询 error / 未登记 type（image / 未知值）→ 空串；查询 error 不
// panic、不阻塞。
func TestCatalogCSPNoContribution(t *testing.T) {
	cases := []struct {
		name string
		keys KeyReader
		rows map[string]*provider.Provider
		err  error
	}{
		{"键空串", mapKeys{settings.KeyCaptchaProviderKey: ""}, nil, nil},
		{"键未设置", mapKeys{}, nil, nil},
		{"行不存在", mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}, nil, nil},
		{"查询 error 基础设施故障", mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}, nil, errors.New("db down")},
		{"image 自绘不贡献源", mapKeys{settings.KeyCaptchaProviderKey: "img"}, map[string]*provider.Provider{
			"img": {Key: "img", Type: TypeImage, Row: captchaRow("img", TypeImage, 1, "")},
		}, nil},
		{"未知 type 未登记", mapKeys{settings.KeyCaptchaProviderKey: "weird"}, map[string]*provider.Provider{
			"weird": {Key: "weird", Type: "geetest", Row: captchaRow("weird", "geetest", 1, "")},
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCatalog(tc.keys, &fakeSource{rows: tc.rows, err: tc.err})
			if got := c.CSP(); got != "" {
				t.Fatalf("CSP() = %q, want 空串（无贡献不写入任何域名）", got)
			}
		})
	}
}

// TestCatalogCSPProviders 各第三方 type 的登记片段逐字（接口文档 §8 参考源
// 清单表；指令序 = 白名单文档序 frame/style/worker）。
func TestCatalogCSPProviders(t *testing.T) {
	cases := []struct {
		name  string
		pkey  string
		ptype string
		want  string
	}{
		{"turnstile", "cf_turnstile", TypeTurnstile,
			"frame-src https://challenges.cloudflare.com"},
		{"recaptcha", "goog", TypeRecaptcha,
			"frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/"},
		{"hcaptcha", "hc", TypeHcaptcha,
			"frame-src https://hcaptcha.com https://*.hcaptcha.com; style-src https://hcaptcha.com https://*.hcaptcha.com"},
		{"geetest_v4", "geo", TypeGeetestV4,
			"frame-src https://gcaptcha4.geetest.com"},
		{"aliyun_captcha", "aly", TypeAliyunCaptcha, ""},
		{"capjs", "cap", TypeCapjs,
			"worker-src blob:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCatalog(
				mapKeys{settings.KeyCaptchaProviderKey: tc.pkey},
				&fakeSource{rows: map[string]*provider.Provider{
					tc.pkey: {Key: tc.pkey, Type: tc.ptype, Row: captchaRow(tc.pkey, tc.ptype, 1, "site")},
				}},
			)
			if got := c.CSP(); got != tc.want {
				t.Fatalf("CSP() = %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestCatalogCSPNotCached 每请求现算（§9.4 与 Gate 下发配置同源、热更新
// 语义一致）：settings 键热更后 CSP 片段立即跟随，不缓存。
func TestCatalogCSPNotCached(t *testing.T) {
	keys := mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}
	rows := map[string]*provider.Provider{
		"cf_turnstile": {Key: "cf_turnstile", Type: TypeTurnstile, Row: captchaRow("cf_turnstile", TypeTurnstile, 1, "k")},
		"hc":           {Key: "hc", Type: TypeHcaptcha, Row: captchaRow("hc", TypeHcaptcha, 1, "h")},
	}
	c := NewCatalog(keys, &fakeSource{rows: rows})

	if got, want := c.CSP(), "frame-src https://challenges.cloudflare.com"; got != want {
		t.Fatalf("首次 CSP() = %q, want %q", got, want)
	}
	keys[settings.KeyCaptchaProviderKey] = "hc"
	want := "frame-src https://hcaptcha.com https://*.hcaptcha.com; style-src https://hcaptcha.com https://*.hcaptcha.com"
	if got := c.CSP(); got != want {
		t.Fatalf("换键后 CSP() = %q\nwant %q", got, want)
	}
	keys[settings.KeyCaptchaProviderKey] = ""
	if got := c.CSP(); got != "" {
		t.Fatalf("清空后 CSP() = %q, want 空串", got)
	}
}

// TestCatalogCSPNilReceiver nil Catalog 不 panic（装配缺依赖时贡献空串，
// §9.4 不阻塞响应头）。
func TestCatalogCSPNilReceiver(t *testing.T) {
	var c *Catalog
	if got := c.CSP(); got != "" {
		t.Fatalf("nil Catalog CSP() = %q, want 空串", got)
	}
}

// TestCatalogCSPPerRowOnlyCurrentProvider 按行贡献（§8：按「当前生效且已
// 配置的 captcha Provider」动态追加，未配置行不写入任何域名）：多行并存时
// CSP 头仅含当前生效行的源——逐字断言即证 A 行不含 B 行源，切键即换源。
func TestCatalogCSPPerRowOnlyCurrentProvider(t *testing.T) {
	rows := map[string]*provider.Provider{
		"geo": {Key: "geo", Type: TypeGeetestV4, Row: captchaRow("geo", TypeGeetestV4, 1, "id")},
		"aly": {Key: "aly", Type: TypeAliyunCaptcha, Row: captchaRow("aly", TypeAliyunCaptcha, 1, "scene")},
		"cap": {Key: "cap", Type: TypeCapjs, Row: captchaRow("cap", TypeCapjs, 1, "site")},
	}
	want := map[string]string{
		"geo": "frame-src https://gcaptcha4.geetest.com",
		"aly": "",
		"cap": "worker-src blob:",
	}
	keys := mapKeys{settings.KeyCaptchaProviderKey: "geo"}
	c := NewCatalog(keys, &fakeSource{rows: rows})
	for _, k := range []string{"geo", "aly", "cap", "geo"} {
		keys[settings.KeyCaptchaProviderKey] = k
		if got := c.CSP(); got != want[k] {
			t.Fatalf("生效行 %s: CSP() = %q\nwant %q（CSP 头仅含当前生效行的源）", k, got, want[k])
		}
	}
}

// cspProbeOnce 白名单探针只注册一次（防 -count 重复注册 panic）。
var cspProbeOnce sync.Once

// TestCatalogCSPWhitelistClosesDirectives 白名单封闭语义（§8：可扩展指令
// 白名单仅三项，白名单外指令的声明一律不生效）：探针 type 同时声明白名单内
// frame-src 与白名单外 script-src，输出含 frame-src、不含 script-src——
// 聚合只遍历白名单指令序，多出的声明静默丢弃。
func TestCatalogCSPWhitelistClosesDirectives(t *testing.T) {
	cspProbeOnce.Do(func() {
		provider.RegisterVerifier("csp_whitelist_probe", provider.Meta{
			DisplayName: "CSP 白名单探针",
			Category:    provider.CategoryCaptcha,
			CSPSources: map[string][]string{
				"script-src": {"https://evil.example"},
				"frame-src":  {"https://ok.example"},
			},
		}, func(*provider.Provider) (provider.Verifier, error) { return nil, nil })
	})
	c := NewCatalog(
		mapKeys{settings.KeyCaptchaProviderKey: "probe"},
		&fakeSource{rows: map[string]*provider.Provider{
			"probe": {Key: "probe", Type: "csp_whitelist_probe", Row: captchaRow("probe", "csp_whitelist_probe", 1, "")},
		}},
	)
	got := c.CSP()
	if want := "frame-src https://ok.example"; got != want {
		t.Fatalf("CSP() = %q, want %q（白名单外 script-src 声明不生效）", got, want)
	}
	if strings.Contains(got, "evil.example") || strings.Contains(got, "script-src") {
		t.Fatalf("CSP() = %q, 白名单外指令与源泄漏进输出", got)
	}
}
