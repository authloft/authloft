// provider_source_test.go 覆盖 provider 表行 → captcha 窄投影的纯函数部分；
// 出站代理池由 Find 经 provider.ResolveOutbound 解析补齐（§15.4，装配期
// 固化），其 fail-closed 语义由 provider 包共享解析助手的单测覆盖，本文件
// 只锁投影本身。纯函数用例本地可跑、不依赖 DB。
package captcha

import (
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/repo/model"
)

// TestProjectProviderRecordFields 投影完整带出行与 Ext 字段；出站代理池不在
// 纯投影内（恒 nil，由 Find 解析补齐）。
func TestProjectProviderRecordFields(t *testing.T) {
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
	}
	got := projectProviderRecord(row, ext)
	if got.ProviderKey != "cf_turnstile" || got.Category != CategoryCaptcha ||
		got.Type != TypeTurnstile || !got.Enabled ||
		got.SiteKey != "0x4AAA" || got.Secret != "sec-1" || got.VerifyURL != "https://verify.example" {
		t.Fatalf("投影字段不完整: %+v", got)
	}
	if got.Proxy != nil {
		t.Fatalf("纯投影不应携带出站代理池, got %+v", got.Proxy)
	}
}

// TestProjectProviderRecordZero 零值行 / 零 Ext 投影为全零值，不得凭空生成
// 默认值。
func TestProjectProviderRecordZero(t *testing.T) {
	got := projectProviderRecord(&model.Provider{}, &providerpb.Ext{})
	if got.ProviderKey != "" || got.Category != "" || got.Type != "" || got.Enabled ||
		got.SiteKey != "" || got.Secret != "" || got.VerifyURL != "" || got.Proxy != nil {
		t.Fatalf("零值投影 = %+v, want 全零值", got)
	}
}
