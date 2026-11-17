// 服务型 Provider 静态 meta 单测：captcha / storage / proxy 类型以 meta-only
// 并入统一注册表的 LookupTypeMeta 与 TypeMetas（admin 下拉 / schema / 写路径
// 数据源），category 与 Schema 字段声明正确；它们不进登录快照 AdapterTypes，
// NewAdapter / NewSender 仍查不到。
package provider_test

import (
	"errors"
	"reflect"
	"testing"

	"authloft/internal/captcha"
	"authloft/internal/provider"
	"authloft/internal/provider/schemafield"
	// 渠道漏斗（引用键单一来源漂移测试）：oauth 经 SchemaFor、smtp / aliyun_sms
	// 经各自 Schema 汇入同一份 ProxyRef 声明；storage/local 经本包 _ import
	// 触发 init 自注册（meta 已随工厂化迁入实现子包，§15.3）。
	_ "authloft/internal/provider/email/smtp"
	_ "authloft/internal/provider/oauth/wechat_mp"
	_ "authloft/internal/provider/sms/aliyun_sms"
	_ "authloft/internal/provider/storage/local"
)

// TestServiceTypeConstantsMatchRuntime 静态表 type 字面量与运行时实现同源：
// captcha 三家与 captcha 包导出常量必须相等，防止单侧改动导致「下拉能建、
// 运行时不认」的漂移。storage 的 local 由 provider/storage/local 以
// provider.StorageTypeLocal 注册，字面量单一来源在本包。
func TestServiceTypeConstantsMatchRuntime(t *testing.T) {
	if provider.CaptchaTypeTurnstile != captcha.TypeTurnstile ||
		provider.CaptchaTypeRecaptcha != captcha.TypeRecaptcha ||
		provider.CaptchaTypeHcaptcha != captcha.TypeHcaptcha {
		t.Errorf("captcha type 常量与运行时实现漂移: provider=(%q,%q,%q) captcha=(%q,%q,%q)",
			provider.CaptchaTypeTurnstile, provider.CaptchaTypeRecaptcha, provider.CaptchaTypeHcaptcha,
			captcha.TypeTurnstile, captcha.TypeRecaptcha, captcha.TypeHcaptcha)
	}
}

// TestLookupTypeMetaServiceTypes 服务型源：三家 captcha、storage/local 与 proxy
// 命中，category 正确、Ext 字段经 Schema() 完整声明；不进登录快照
// AdapterTypes，消息域视图亦查不到。引用键呈现范围：captcha 声明（出站外呼）、
// local（本地磁盘）与 proxy 行自身（不自引）不声明。
func TestLookupTypeMetaServiceTypes(t *testing.T) {
	for _, tc := range []struct {
		typ         string
		category    string
		fieldKeys   []string
		displayName string
		wantRef     bool // captcha 类别呈现 proxy_provider_key 引用键
	}{
		{provider.CaptchaTypeTurnstile, provider.CategoryCaptcha, []string{"client_id", "client_secret", "endpoint"}, "Cloudflare Turnstile", true},
		{provider.CaptchaTypeRecaptcha, provider.CategoryCaptcha, []string{"client_id", "client_secret", "endpoint"}, "Google reCAPTCHA", true},
		{provider.CaptchaTypeHcaptcha, provider.CategoryCaptcha, []string{"client_id", "client_secret", "endpoint"}, "hCaptcha", true},
		{provider.StorageTypeLocal, provider.CategoryStorage, []string{"bucket", "domain", "path_prefix"}, "本地存储", false},
		{provider.ProxyType, provider.CategoryProxy, []string{"scheme", "host", "port", "user", "password"}, "基础代理", false},
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
		// 引用键按 type 有无；oauth 专属键在各类别均不下发。
		extKeys := map[string]bool{}
		for _, k := range tc.fieldKeys {
			extKeys[k] = true
		}
		wantKeys := map[string]bool{
			"provider_key": true, "display_name": true, "icon_url": true,
			"ui_group": true, "sort_order": true, "remark": true,
			"is_enabled": true, provider.ProxyRefKey: tc.wantRef,
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
			if f.Key == provider.ProxyRefKey {
				if !tc.wantRef {
					t.Errorf("%q Schema() 不应含引用键 %q", tc.typ, provider.ProxyRefKey)
				} else if !reflect.DeepEqual(f, schemafield.ProxyRef()) {
					t.Errorf("%q 引用键声明漂移: %+v, want %v", tc.typ, f, schemafield.ProxyRef())
				}
			}
		}
		for k, want := range wantKeys {
			if want && !got[k] {
				t.Errorf("%q Schema() 缺少 %q", tc.typ, k)
			}
		}
		// proxy 行五字段逐项对齐 §5.3 声明口径（scheme 封闭集、host 禁字符集、
		// port number、user/password 撤 advanced、五行 section=endpoint）。
		if tc.typ == provider.ProxyType {
			assertProxyRowFields(t, schema)
		}
		// 每次调用返回独立切片，调用方改动不得污染后续调用。
		mutated := meta.Schema()
		mutated[0].Key = "mutated"
		if meta.Schema()[0].Key == "mutated" {
			t.Errorf("%q Schema() 返回共享切片", tc.typ)
		}
		// meta-only：不进登录快照（无 auth 槽），消息域视图亦不含。
		for _, atyp := range provider.AdapterTypes() {
			if atyp == tc.typ {
				t.Errorf("%q 不应出现在 AdapterTypes()（登录快照数据源）", tc.typ)
			}
		}
		if _, ok := provider.LookupSenderMeta(tc.typ); ok {
			t.Errorf("%q 不应进消息域视图", tc.typ)
		}
	}
}

// assertProxyRowFields proxy 行五真实字段声明逐项断言（§5.3 代理提供商与出站
// 代理引用约定表）：必填口径 scheme/host、组合校验单一来源在 proxyclient.
// NewConfig（声明侧不重复、port 不标 required——number 字段 required 走
// GetStringValue 无法判数）。
func assertProxyRowFields(t *testing.T, schema []provider.FieldMeta) {
	t.Helper()
	byKey := map[string]provider.FieldMeta{}
	for _, f := range schema {
		byKey[f.Key] = f
	}
	f, ok := byKey["scheme"]
	if !ok || f.Type != "select" || !f.Required || !reflect.DeepEqual(f.Options, []string{"socks5", "http", "https"}) {
		t.Errorf("scheme 声明漂移: %+v (ok=%v)", f, ok)
	}
	f, ok = byKey["host"]
	if !ok || f.Type != "text" || !f.Required || f.Pattern == "" {
		t.Errorf("host 声明漂移: %+v (ok=%v)", f, ok)
	}
	f, ok = byKey["port"]
	if !ok || f.Type != "number" || !f.Required {
		t.Errorf("port 声明漂移（必填 number，§5.3 五字段表）: %+v (ok=%v)", f, ok)
	}
	f, ok = byKey["user"]
	if !ok || f.Type != "text" || f.Required || f.Advanced {
		t.Errorf("user 声明漂移: %+v (ok=%v)", f, ok)
	}
	f, ok = byKey["password"]
	if !ok || f.Type != "secret" || f.Required || f.Advanced {
		t.Errorf("password 声明漂移: %+v (ok=%v)", f, ok)
	}
	for _, key := range []string{"scheme", "host", "port", "user", "password"} {
		if g := byKey[key]; g.Section != "endpoint" || g.Storage != provider.StorageExt {
			t.Errorf("%s section/storage = (%q, %q), want (endpoint, ext)", key, g.Section, g.Storage)
		}
	}
}

// TestProxyRefDeclarationSingleSource 引用键声明单一来源（§5.3：呈现范围由各
// provider 的 Schema() 是否声明决定）：oauth 全渠道（SchemaFor 漏斗）、smtp、
// aliyun_sms、captcha 三家声明的引用键逐字段等于 schemafield.ProxyRef()；
// union / storage/local / proxy 行自身不声明。
func TestProxyRefDeclarationSingleSource(t *testing.T) {
	ref := schemafield.ProxyRef()
	lookup := func(typ string, schema func() []provider.FieldMeta) {
		t.Helper()
		for _, f := range schema() {
			if f.Key == provider.ProxyRefKey {
				if !reflect.DeepEqual(f, ref) {
					t.Errorf("%s 引用键声明漂移: %+v, want %+v", typ, f, ref)
				}
				return
			}
		}
		t.Errorf("%s Schema() 缺少引用键 %q", typ, provider.ProxyRefKey)
	}
	if meta, ok := provider.Lookup("wechat_mp"); ok {
		lookup("wechat_mp", meta.Schema)
	} else {
		t.Fatal("wechat_mp 未注册（_ import 缺失）")
	}
	if meta, ok := provider.LookupSenderMeta("smtp"); ok {
		lookup("smtp", meta.Schema)
	} else {
		t.Fatal("smtp 未注册（_ import 缺失）")
	}
	if meta, ok := provider.LookupSenderMeta("aliyun_sms"); ok {
		lookup("aliyun_sms", meta.Schema)
	} else {
		t.Fatal("aliyun_sms 未注册（_ import 缺失）")
	}
	for _, typ := range []string{
		provider.CaptchaTypeTurnstile, provider.CaptchaTypeRecaptcha, provider.CaptchaTypeHcaptcha,
	} {
		meta, _ := provider.LookupTypeMeta(typ)
		lookup(typ, meta.Schema)
	}
	for _, typ := range []string{provider.UnionProviderType, provider.StorageTypeLocal, provider.ProxyType} {
		meta, _ := provider.LookupTypeMeta(typ)
		for _, f := range meta.Schema() {
			if f.Key == provider.ProxyRefKey {
				t.Errorf("%s Schema() 不应声明引用键", typ)
			}
		}
	}
}

// TestTypeMetasIncludesServiceTypes 下拉数据源：TypeMetas 含 captcha / storage /
// proxy 五类，且整体仍按 Type 稳定升序。
func TestTypeMetasIncludesServiceTypes(t *testing.T) {
	want := map[string]string{
		provider.CaptchaTypeTurnstile: provider.CategoryCaptcha,
		provider.CaptchaTypeRecaptcha: provider.CategoryCaptcha,
		provider.CaptchaTypeHcaptcha:  provider.CategoryCaptcha,
		provider.StorageTypeLocal:     provider.CategoryStorage,
		provider.ProxyType:            provider.CategoryProxy,
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
		provider.CaptchaTypeHcaptcha, provider.StorageTypeLocal, provider.ProxyType,
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
