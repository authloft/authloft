// 服务型 Provider 静态 meta 单测：captcha / storage 类型并入 LookupTypeMeta
// 与 TypeMetas（admin 下拉 / schema / 写路径数据源），category 与 Schema 字段
// 声明正确；它们不进两张带 factory 的注册表，NewAdapter / NewSender 仍查不到。
package provider_test

import (
	"errors"
	"testing"

	"authloft/internal/captcha"
	"authloft/internal/provider"
)

// TestServiceTypeConstantsMatchRuntime 静态表 type 字面量与运行时实现同源：
// captcha 三家与 captcha 包导出常量必须相等，防止单侧改动导致「下拉能建、
// 运行时不认」的漂移。storage 的 local 在 Resolver 内是内联字面量、无导出
// 常量可对照，靠 servicetype.go 的注释说明保持同步。
func TestServiceTypeConstantsMatchRuntime(t *testing.T) {
	if provider.CaptchaTypeTurnstile != captcha.TypeTurnstile ||
		provider.CaptchaTypeRecaptcha != captcha.TypeRecaptcha ||
		provider.CaptchaTypeHcaptcha != captcha.TypeHcaptcha {
		t.Errorf("captcha type 常量与运行时实现漂移: provider=(%q,%q,%q) captcha=(%q,%q,%q)",
			provider.CaptchaTypeTurnstile, provider.CaptchaTypeRecaptcha, provider.CaptchaTypeHcaptcha,
			captcha.TypeTurnstile, captcha.TypeRecaptcha, captcha.TypeHcaptcha)
	}
}

// TestLookupTypeMetaServiceTypes 第四源：三家 captcha 与 storage/local 命中，
// category 正确、Ext 字段经 Schema() 完整声明；两张 factory 注册表均查不到。
func TestLookupTypeMetaServiceTypes(t *testing.T) {
	for _, tc := range []struct {
		typ         string
		category    string
		fieldKeys   []string
		displayName string
		wantProxy   bool // captcha 类别呈现 proxy_url，local 不呈现
	}{
		{provider.CaptchaTypeTurnstile, provider.CategoryCaptcha, []string{"client_id", "client_secret", "endpoint"}, "Cloudflare Turnstile", true},
		{provider.CaptchaTypeRecaptcha, provider.CategoryCaptcha, []string{"client_id", "client_secret", "endpoint"}, "Google reCAPTCHA", true},
		{provider.CaptchaTypeHcaptcha, provider.CategoryCaptcha, []string{"client_id", "client_secret", "endpoint"}, "hCaptcha", true},
		{provider.StorageTypeLocal, provider.CategoryStorage, []string{"bucket", "domain", "path_prefix"}, "本地存储（local）", false},
	} {
		meta, ok := provider.LookupTypeMeta(tc.typ)
		if !ok {
			t.Errorf("LookupTypeMeta(%q) 未命中", tc.typ)
			continue
		}
		if meta.Type != tc.typ || meta.Category != tc.category || meta.DisplayName != tc.displayName {
			t.Errorf("%q meta = %+v", tc.typ, meta)
		}
		// Schema = 完整声明形态：基础两列 + Ext + display 四项 + is_enabled，
		// proxy_url 按 type 有无；oauth 专属键在两类别均不下发。
		extKeys := map[string]bool{}
		for _, k := range tc.fieldKeys {
			extKeys[k] = true
		}
		wantKeys := map[string]bool{
			"provider_key": true, "display_name": true, "icon_url": true,
			"ui_group": true, "sort_order": true, "remark": true,
			"is_enabled": true, "proxy_url": tc.wantProxy,
		}
		for _, k := range tc.fieldKeys {
			wantKeys[k] = true
		}
		oauthOnly := map[string]bool{
			"union_provider": true, "enable_signin": true, "enable_signup": true,
			"auto_bind": true, "auto_bind_fields": true,
		}
		schema := meta.Schema()
		if len(schema) == 0 {
			t.Errorf("%q meta.Schema() 为空", tc.typ)
			continue
		}
		got := map[string]bool{}
		for _, f := range schema {
			got[f.Key] = true
			if oauthOnly[f.Key] {
				t.Errorf("%q Schema() 不应含 oauth 专属键 %q", tc.typ, f.Key)
			}
			if !wantKeys[f.Key] {
				t.Errorf("%q Schema() 出现意外字段 %q", tc.typ, f.Key)
			}
			if extKeys[f.Key] && f.Storage != provider.StorageExt {
				t.Errorf("%q Ext 字段 %q Storage = %q, want ext", tc.typ, f.Key, f.Storage)
			}
			if f.Key == "is_enabled" {
				if f.Default != "true" || f.Storage != provider.StorageColumn {
					t.Errorf("%q is_enabled 属性漂移: %+v", tc.typ, f)
				}
			}
			if f.Key == "proxy_url" {
				if !tc.wantProxy {
					t.Errorf("%q Schema() 不应含 proxy_url", tc.typ)
				} else if f.Section != "endpoint" || !f.Advanced || f.Storage != provider.StorageExt {
					t.Errorf("%q proxy_url 属性漂移: %+v", tc.typ, f)
				}
			}
		}
		for k, want := range wantKeys {
			if want && !got[k] {
				t.Errorf("%q Schema() 缺少 %q", tc.typ, k)
			}
		}
		// 每次调用返回独立切片，调用方改动不得污染后续调用。
		mutated := meta.Schema()
		mutated[0].Key = "mutated"
		if meta.Schema()[0].Key == "mutated" {
			t.Errorf("%q Schema() 返回共享切片", tc.typ)
		}
		if _, ok := provider.Lookup(tc.typ); ok {
			t.Errorf("%q 不应进 oauth 适配器注册表", tc.typ)
		}
		if _, ok := provider.LookupSenderMeta(tc.typ); ok {
			t.Errorf("%q 不应进消息域注册表", tc.typ)
		}
	}
}

// TestTypeMetasIncludesServiceTypes 下拉数据源：TypeMetas 含 captcha / storage
// 四类，且整体仍按 Type 稳定升序。
func TestTypeMetasIncludesServiceTypes(t *testing.T) {
	want := map[string]string{
		provider.CaptchaTypeTurnstile: provider.CategoryCaptcha,
		provider.CaptchaTypeRecaptcha: provider.CategoryCaptcha,
		provider.CaptchaTypeHcaptcha:  provider.CategoryCaptcha,
		provider.StorageTypeLocal:     provider.CategoryStorage,
	}
	seen := map[string]bool{}
	metas := provider.TypeMetas()
	for i, meta := range metas {
		if i > 0 && metas[i-1].Type >= meta.Type {
			t.Errorf("TypeMetas 未稳定排序: %q >= %q", metas[i-1].Type, meta.Type)
		}
		if cat, ok := want[meta.Type]; ok {
			seen[meta.Type] = true
			if meta.Category != cat {
				t.Errorf("%q category = %q, want %q", meta.Type, meta.Category, cat)
			}
		}
	}
	for typ := range want {
		if !seen[typ] {
			t.Errorf("TypeMetas 缺少 %q", typ)
		}
	}
}

// TestServiceTypesHaveNoProviderFactory 服务型类型不经 provider 工厂解析：
// 误当普通行构造时 NewAdapter / NewSender 一律失败，不会拿到假适配器。
func TestServiceTypesHaveNoProviderFactory(t *testing.T) {
	for _, typ := range []string{
		provider.CaptchaTypeTurnstile, provider.CaptchaTypeRecaptcha,
		provider.CaptchaTypeHcaptcha, provider.StorageTypeLocal,
	} {
		p := &provider.Provider{Key: "svc", Type: typ}
		if _, err := provider.NewAdapter(p); !errors.Is(err, provider.ErrUnknownType) {
			t.Errorf("NewAdapter(%q) = %v, want ErrUnknownType", typ, err)
		}
		if _, err := provider.NewSender(p, "captcha"); !errors.Is(err, provider.ErrChannelNotConfigured) {
			t.Errorf("NewSender(%q) = %v, want ErrChannelNotConfigured", typ, err)
		}
	}
}
