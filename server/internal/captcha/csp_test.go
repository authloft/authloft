// csp_test.go 覆盖 Catalog.CSP()（docs/后端架构.md §9.4 行
// 1129-1137 / docs/接口文档.md §8 行 1534-1548）：降级各态一律贡献空串
//（未启用 / 未配置不写入任何域名）、三家第三方各 type 的登记片段逐字、
// 每请求现算（与 Current 同源，热更新语义一致）。
package captcha

import (
	"errors"
	"testing"

	"authloft/internal/settings"
)

// TestCatalogCSPNoContribution 无贡献各态（§8 行 1534「未启用 / 未配置
// 的 Provider 不写入任何域名」；§9.4 行 1134 Current 同源判定）：键空串 /
// 键未设置 / 行不存在 / 未启用 / 查询 error / 未登记 type（image / 未知
// 值）→ 空串；查询 error 不 panic、不阻塞。
func TestCatalogCSPNoContribution(t *testing.T) {
	cases := []struct {
		name string
		keys KeyReader
		rows map[string]*ProviderRecord
		err  error
	}{
		{"键空串", mapKeys{settings.KeyCaptchaProviderKey: ""}, nil, nil},
		{"键未设置", mapKeys{}, nil, nil},
		{"行不存在", mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}, nil, nil},
		{"未启用 is_enabled=0", mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}, map[string]*ProviderRecord{
			"cf_turnstile": {ProviderKey: "cf_turnstile", Category: CategoryCaptcha, Type: TypeTurnstile},
		}, nil},
		{"查询 error 基础设施故障", mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}, nil, errors.New("db down")},
		{"image 自绘不贡献源", mapKeys{settings.KeyCaptchaProviderKey: "img"}, map[string]*ProviderRecord{
			"img": {ProviderKey: "img", Category: CategoryCaptcha, Type: TypeImage, Enabled: true},
		}, nil},
		{"未知 type 未登记", mapKeys{settings.KeyCaptchaProviderKey: "weird"}, map[string]*ProviderRecord{
			"weird": {ProviderKey: "weird", Category: CategoryCaptcha, Type: "geetest", Enabled: true},
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCatalog(tc.keys, mapSource{rows: tc.rows, err: tc.err})
			if got := c.CSP(); got != "" {
				t.Fatalf("CSP() = %q, want 空串（无贡献不写入任何域名）", got)
			}
		})
	}
}

// TestCatalogCSPProviders 三家第三方各 type 的登记片段逐字（接口文档
// §8 行 1542-1546 参考源清单表；指令序 = 白名单文档序 frame/connect/style）。
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
			"frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/recaptcha/; connect-src https://www.google.com/recaptcha/"},
		{"hcaptcha", "hc", TypeHcaptcha,
			"frame-src https://hcaptcha.com https://*.hcaptcha.com; connect-src https://hcaptcha.com https://*.hcaptcha.com; style-src https://hcaptcha.com https://*.hcaptcha.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCatalog(
				mapKeys{settings.KeyCaptchaProviderKey: tc.pkey},
				mapSource{rows: map[string]*ProviderRecord{
					tc.pkey: {ProviderKey: tc.pkey, Category: CategoryCaptcha, Type: tc.ptype, Enabled: true, SiteKey: "site"},
				}},
			)
			if got := c.CSP(); got != tc.want {
				t.Fatalf("CSP() = %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestCatalogCSPNotCached 每请求现算（§9.4 行 1134 与 Gate 下发配置同源、
// 热更新语义一致）：settings 键热更后 CSP 片段立即跟随，不缓存。
func TestCatalogCSPNotCached(t *testing.T) {
	keys := mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}
	rows := map[string]*ProviderRecord{
		"cf_turnstile": {ProviderKey: "cf_turnstile", Category: CategoryCaptcha, Type: TypeTurnstile, Enabled: true, SiteKey: "k"},
		"hc":           {ProviderKey: "hc", Category: CategoryCaptcha, Type: TypeHcaptcha, Enabled: true, SiteKey: "h"},
	}
	c := NewCatalog(keys, mapSource{rows: rows})

	if got, want := c.CSP(), "frame-src https://challenges.cloudflare.com"; got != want {
		t.Fatalf("首次 CSP() = %q, want %q", got, want)
	}
	keys[settings.KeyCaptchaProviderKey] = "hc"
	want := "frame-src https://hcaptcha.com https://*.hcaptcha.com; connect-src https://hcaptcha.com https://*.hcaptcha.com; style-src https://hcaptcha.com https://*.hcaptcha.com"
	if got := c.CSP(); got != want {
		t.Fatalf("换键后 CSP() = %q\nwant %q", got, want)
	}
	keys[settings.KeyCaptchaProviderKey] = ""
	if got := c.CSP(); got != "" {
		t.Fatalf("清空后 CSP() = %q, want 空串", got)
	}
}

// TestCatalogCSPNilReceiver nil Catalog 不 panic（装配缺依赖时贡献空串，
// §9.4 行 1134 不阻塞响应头）。
func TestCatalogCSPNilReceiver(t *testing.T) {
	var c *Catalog
	if got := c.CSP(); got != "" {
		t.Fatalf("nil Catalog CSP() = %q, want 空串", got)
	}
}
