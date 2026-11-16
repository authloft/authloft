// provider_source_test.go 覆盖 provider 表行 → captcha 窄投影，重点验证
// Ext.proxy_url 投影到 ProviderRecord.ProxyURL（§15.4，出站代理在构造期
// 固化）。纯函数用例本地可跑、不依赖 DB。
package captcha

import (
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/repo/model"
)

// TestProjectProviderRecordProxyURL 投影把 Ext.proxy_url 完整带到
// ProviderRecord.ProxyURL；其余字段一并断言防止投影遗漏。
func TestProjectProviderRecordProxyURL(t *testing.T) {
	const proxyURL = "socks5://alice:pw@proxy.example:1080"
	row := &model.Provider{
		ProviderKey: "cf_turnstile",
		Category:    CategoryCaptcha,
		Type:        TypeTurnstile,
		IsEnabled:   1,
	}
	ext := &providerpb.Ext{
		ClientId:     "0x4AAA",
		ClientSecret: "sec-1",
		Endpoint:     "https://verify.example",
		ProxyUrl:     proxyURL,
	}
	got := projectProviderRecord(row, ext)
	if got.ProxyURL != proxyURL {
		t.Fatalf("ProxyURL = %q, want %q", got.ProxyURL, proxyURL)
	}
	if got.ProviderKey != "cf_turnstile" || got.Category != CategoryCaptcha ||
		got.Type != TypeTurnstile || !got.Enabled ||
		got.SiteKey != "0x4AAA" || got.Secret != "sec-1" || got.VerifyURL != "https://verify.example" {
		t.Fatalf("投影字段不完整: %+v", got)
	}
}

// TestProjectProviderRecordEmptyProxy 空 proxy_url 投影为空串（空串直连，
// §15.4），不得凭空生成默认代理值。
func TestProjectProviderRecordEmptyProxy(t *testing.T) {
	got := projectProviderRecord(&model.Provider{}, &providerpb.Ext{})
	if got.ProxyURL != "" {
		t.Fatalf("空 proxy_url 投影 = %q, want 空串", got.ProxyURL)
	}
}
