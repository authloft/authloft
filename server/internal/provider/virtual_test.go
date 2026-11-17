// 虚拟 Provider 类型元数据单测：统一注册表查询能命中 unionid（meta-only），
// 但它没有任何 factory 槽——不进登录链 metas() 的数据源 AdapterTypes，
// NewAdapter / NewSender 对它一律失败。
package provider_test

import (
	"errors"
	"testing"

	"authloft/internal/provider"
)

// TestLookupTypeMetaUnion 虚拟类型：LookupTypeMeta 命中 union meta，
// 类别为 union、Schema 为完整表列声明（虚拟类型无 Ext 字段）；
// 消息域视图查不到它（无 sender 槽）。
func TestLookupTypeMetaUnion(t *testing.T) {
	meta, ok := provider.LookupTypeMeta(provider.UnionProviderType)
	if !ok {
		t.Fatalf("LookupTypeMeta(%q) 未命中", provider.UnionProviderType)
	}
	if meta.Type != provider.UnionProviderType || meta.Category != provider.CategoryUnion ||
		meta.DisplayName == "" {
		t.Errorf("union meta = %+v", meta)
	}
	schema := meta.Schema()
	if len(schema) == 0 {
		t.Fatal("union meta.Schema() 为空，应为完整表列声明")
	}
	want := map[string]bool{
		"provider_key": true, "display_name": true, "icon_url": true,
		"ui_group": true, "sort_order": true, "remark": true,
	}
	// union_provider / 登录建号开关 / is_enabled / 引用键在 union 类别整体裁剪
	//（虚拟类型无外呼，§5.3 引用键呈现范围不含 union）。
	banned := map[string]bool{
		"union_provider": true, "enable_signin": true, "enable_signup": true,
		"auto_bind": true, "auto_bind_fields": true, "is_enabled": true, provider.ProxyRefKey: true,
	}
	for _, f := range schema {
		if banned[f.Key] {
			t.Errorf("union Schema() 不应含字段 %q", f.Key)
			continue
		}
		if !want[f.Key] {
			t.Errorf("union Schema() 出现意外字段 %q", f.Key)
		}
		if (f.Key == "provider_key" || f.Key == "display_name") && f.Storage != provider.StorageColumn {
			t.Errorf("union %q Storage = %q, want column", f.Key, f.Storage)
		}
	}
	if _, ok := provider.LookupSenderMeta(provider.UnionProviderType); ok {
		t.Error("unionid 不应进消息域视图（无 sender 槽）")
	}
	for _, typ := range provider.AdapterTypes() {
		if typ == provider.UnionProviderType {
			t.Error("unionid 不应出现在 AdapterTypes()（登录快照数据源）")
		}
	}
}

// TestTypeMetasIncludesUnion 下拉数据源：TypeMetas 含 unionid 且按 Type
// 稳定升序；oauth / 消息域注册项仍在（新文件不 blank import 具体渠道包，
// 故只断言虚拟项自身与排序，不假定其他包已注册）。
func TestTypeMetasIncludesUnion(t *testing.T) {
	metas := provider.TypeMetas()
	found := false
	for i, meta := range metas {
		if i > 0 && metas[i-1].Type >= meta.Type {
			t.Errorf("TypeMetas 未稳定排序: %q >= %q", metas[i-1].Type, meta.Type)
		}
		if meta.Type == provider.UnionProviderType {
			found = true
			if meta.Category != provider.CategoryUnion {
				t.Errorf("union category = %q", meta.Category)
			}
		}
	}
	if !found {
		t.Fatalf("TypeMetas 缺少 %q: %+v", provider.UnionProviderType, metas)
	}
}

// TestUnionTypeHasNoRuntimeFactory 虚拟 Provider 无登录入口、无消息发送：
// NewAdapter / NewSender 对它一律失败，即便误把它当普通行解析也不会构造出
// 假的适配器或 Sender。
func TestUnionTypeHasNoRuntimeFactory(t *testing.T) {
	p := &provider.Provider{Key: "wechat_union", Type: provider.UnionProviderType}
	if _, err := provider.NewAdapter(p); !errors.Is(err, provider.ErrUnknownType) {
		t.Errorf("NewAdapter(unionid) = %v, want ErrUnknownType", err)
	}
	if _, err := provider.NewSender(p, provider.CategoryUnion); !errors.Is(err, provider.ErrChannelNotConfigured) {
		t.Errorf("NewSender(unionid) = %v, want ErrChannelNotConfigured", err)
	}
}
