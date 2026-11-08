// 虚拟 Provider 类型元数据单测：三源统一查询能命中 unionid，但它不进任何
// 带 factory 的注册表，也不出现在登录链 metas() 的数据源 provider.Types()。
package provider_test

import (
	"errors"
	"testing"

	"authloft/internal/provider"
)

// TestLookupTypeMetaUnion 第三源：LookupTypeMeta 命中虚拟 Union meta，
// 类别为 union、无 Ext 字段；两张带 factory 的注册表都查不到它。
func TestLookupTypeMetaUnion(t *testing.T) {
	meta, ok := provider.LookupTypeMeta(provider.UnionProviderType)
	if !ok {
		t.Fatalf("LookupTypeMeta(%q) 未命中", provider.UnionProviderType)
	}
	if meta.Type != provider.UnionProviderType || meta.Category != provider.CategoryUnion ||
		meta.DisplayName == "" || len(meta.Fields) != 0 {
		t.Errorf("union meta = %+v", meta)
	}
	if _, ok := provider.Lookup(provider.UnionProviderType); ok {
		t.Error("unionid 不应进 oauth 适配器注册表")
	}
	if _, ok := provider.LookupSenderMeta(provider.UnionProviderType); ok {
		t.Error("unionid 不应进消息域注册表")
	}
	for _, typ := range provider.Types() {
		if typ == provider.UnionProviderType {
			t.Error("unionid 不应出现在 provider.Types()（登录快照数据源）")
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
