package schemafield

import (
	"testing"

	"authloft/internal/provider"
)

// TestConstructorsReturnIndependentSlices 调用方就地改 label / 默认不污染他人。
func TestConstructorsReturnIndependentSlices(t *testing.T) {
	a := EnableFlags()
	b := EnableFlags()
	a[0].Label = "mutated"
	if b[0].Label != "admin.schemaField.isEnabledLabel" {
		t.Fatalf("EnableFlags 返回切片不独立: %q", b[0].Label)
	}
	p := ProviderKey()
	p.Label = "mutated"
	if ProviderKey().Label != "admin.schemaField.providerKeyLabel" {
		t.Fatal("ProviderKey 返回值不独立")
	}
}

// TestAttributeAlignment 关键字段的 Key / Storage / Pattern / Default / Kind 对齐基线。
func TestAttributeAlignment(t *testing.T) {
	cases := []struct {
		name    string
		field   provider.FieldMeta
		key     string
		storage provider.FieldStorage
		pattern string
	}{
		{"ProviderKey", ProviderKey(), "provider_key", provider.StorageColumn, "^[a-z0-9_]+$"},
		{"IconURL", IconURL(), "icon_url", provider.StorageColumn, "^https?://"},
		{"ProxyRef", ProxyRef(), provider.ProxyRefKey, provider.StorageExt, ""},
	}
	for _, tc := range cases {
		if tc.field.Key != tc.key || tc.field.Storage != tc.storage || tc.field.Pattern != tc.pattern {
			t.Errorf("%s 属性错位: %+v", tc.name, tc.field)
		}
	}

	u := UnionProvider()
	if u.Kind != provider.FieldDynamicOptions || u.DynamicKey != "union_provider_keys" || u.Storage != provider.StorageColumn {
		t.Errorf("UnionProvider 动态属性错位: %+v", u)
	}
	if u.Options != nil {
		t.Errorf("UnionProvider 不应内置 options: %v", u.Options)
	}

	// ProxyRef 引用声明形态同 UnionProvider 先例：Kind=FieldDynamicOptions +
	// DynamicKey 查库注入（键名引声明侧常量），构造器不下发候选值。
	r := ProxyRef()
	if r.Kind != provider.FieldDynamicOptions || r.DynamicKey != provider.ProxyRefDynamicKey ||
		r.Storage != provider.StorageExt || r.Section != "endpoint" || r.Type != "select" || r.Required {
		t.Errorf("ProxyRef 动态属性错位: %+v", r)
	}
	if r.Options != nil {
		t.Errorf("ProxyRef 不应内置 options: %v", r.Options)
	}

	if got := SortOrder(); got.Default != "0" {
		t.Errorf("SortOrder 默认值错位: %+v", got)
	}
	flags := EnableFlags()
	if len(flags) != 5 || flags[0].Default != "true" || flags[3].Default != "false" {
		t.Errorf("EnableFlags 默认值错位: %+v", flags)
	}

	if got := Metadata("credential").Section; got != "credential" {
		t.Errorf("Metadata section 参数未生效: %q", got)
	}
	if got := Metadata("").Section; got != "basic" {
		t.Errorf("Metadata 默认 section 应 basic, got %q", got)
	}
	if got := OAuthCredentials(); len(got) != 11 || got[10].Key != "metadata" {
		t.Errorf("OAuthCredentials 应 11 项且末项 metadata: %+v", got)
	}
	if got := SMSFields(); len(got) != 6 {
		t.Errorf("SMSFields 应 6 项, got %d", len(got))
	}
	if got := CaptchaFields(); len(got) != 3 {
		t.Errorf("CaptchaFields 应 3 项, got %d", len(got))
	}
	if got := StorageLocalFields(); len(got) != 3 {
		t.Errorf("StorageLocalFields 应 3 项, got %d", len(got))
	}
}
