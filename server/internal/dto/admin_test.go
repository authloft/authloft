package dto

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	adminv1 "authloft/gen/go/api/admin/v1"
	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/repo/model"
	// 注册表数据源（§15.3）：与 bootstrap 同款 _ import 触发自注册，测试
	// 断言「schema 与注册表 meta 逐项一致」需两域真实 meta。
	_ "authloft/internal/provider/email/smtp"
	_ "authloft/internal/provider/oauth/wechat_mp"
	_ "authloft/internal/provider/sms/aliyun_sms"
)

// wantProviderRow §5.2 列表 / 详情用例的 provider 行样例。
func wantProviderRow() *model.Provider {
	return &model.Provider{
		ID: 7, ProviderKey: "wechat_official", UnionProvider: "wechat_union",
		DisplayName: "微信扫码", Category: "oauth", Type: "wechat_mp",
		EnableSignin: 1, EnableSignup: 0, AutoBind: 1, AutoBindFields: "email,phone",
		IsEnabled: 1, UiGroup: "social", SortOrder: 30,
		IconURL: "https://cdn.example.com/wechat.png", Remark: "生产渠道",
		CreatedAt: time.Unix(1761700000, 0).UTC(), UpdatedAt: time.Unix(1761800000, 0).UTC(),
	}
}

// schemaFieldByKey 从 schema 响应中取指定 key 的字段（重复 key 直接报错）。
func schemaFieldByKey(t *testing.T, resp *adminv1.SchemaResponse, key string) *adminv1.SchemaField {
	t.Helper()
	var found *adminv1.SchemaField
	for _, f := range resp.GetFields() {
		if f.GetKey() == key {
			if found != nil {
				t.Fatalf("schema 字段 %q 重复出现", key)
			}
			found = f
		}
	}
	if found == nil {
		t.Fatalf("schema 缺少字段 %q（fields 数量 %d）", key, len(resp.GetFields()))
	}
	return found
}

// TestAdminProviderListEntry 列表项逐项对 §5.2 行 1168（列：显示名 /
// providerKey / 类别 / 类型 / 状态 / 策略标签 / 排序；int8 0/1 → bool）。
func TestAdminProviderListEntry(t *testing.T) {
	got := AdminProviderListEntry(wantProviderRow())
	if got.GetProviderKey() != "wechat_official" || got.GetDisplayName() != "微信扫码" ||
		got.GetCategory() != "oauth" || got.GetType() != "wechat_mp" {
		t.Errorf("列表基础列 = %+v", got)
	}
	if !got.GetIsEnabled() || !got.GetEnableSignin() || got.GetEnableSignup() || !got.GetAutoBind() {
		t.Errorf("状态 / 策略标签 = (isEnabled=%v signin=%v signup=%v bind=%v), want (true,true,false,true)",
			got.GetIsEnabled(), got.GetEnableSignin(), got.GetEnableSignup(), got.GetAutoBind())
	}
	if got.GetSortOrder() != 30 {
		t.Errorf("sortOrder = %d, want 30", got.GetSortOrder())
	}
	if AdminProviderListEntry(nil) == nil {
		t.Error("nil 行应输出空消息而非 nil")
	}
}

// TestAdminProviderDetailPlaintextExt 详情逐项对 §5.2 行 1170 + §12.9 行 1776：
// 表列 typed 透出；ext Struct 明文（不脱敏，§5.2 行 1170 管理员明文口径）、
// 键 = Ext 字段名（与 §5.3 schema key 同源）、int64 十进制字符串（§1.12）。
func TestAdminProviderDetailPlaintextExt(t *testing.T) {
	ext := &providerpb.Ext{
		ClientId:     "wx-123",
		ClientSecret: "secret-456",
		Host:         "smtp.example.com",
		Port:         587,
		DisableSsl:   true,
		UserMapping:  map[string]string{"nickname": "$.name"},
		Metadata:     map[string]string{"username": "u1"},
		MaxSize:      2097152,
	}
	got := AdminProviderDetail(wantProviderRow(), ext)
	if got.GetProviderKey() != "wechat_official" || got.GetUnionProvider() != "wechat_union" ||
		got.GetDisplayName() != "微信扫码" || got.GetCategory() != "oauth" || got.GetType() != "wechat_mp" {
		t.Errorf("详情基础列 = %+v", got)
	}
	if !got.GetEnableSignin() || got.GetEnableSignup() || !got.GetAutoBind() || !got.GetIsEnabled() {
		t.Errorf("开关列 = (signin=%v signup=%v bind=%v enabled=%v), want (true,false,true,true)",
			got.GetEnableSignin(), got.GetEnableSignup(), got.GetAutoBind(), got.GetIsEnabled())
	}
	if got.GetAutoBindFields() != "email,phone" || got.GetUiGroup() != "social" ||
		got.GetIconUrl() != "https://cdn.example.com/wechat.png" || got.GetRemark() != "生产渠道" {
		t.Errorf("展示列 = %+v", got)
	}
	if got.GetCreatedAt() != 1761700000 || got.GetUpdatedAt() != 1761800000 {
		t.Errorf("timestamps = (%d, %d), want (1761700000, 1761800000)", got.GetCreatedAt(), got.GetUpdatedAt())
	}
	if got.GetSortOrder() != 30 {
		t.Errorf("sortOrder = %d, want 30", got.GetSortOrder())
	}
	// ext Struct：键 snake_case（Ext 字段名）、值明文、类型正确。
	fields := got.GetExt().GetFields()
	if v := fields["client_id"].GetStringValue(); v != "wx-123" {
		t.Errorf("ext.client_id = %q, want wx-123（明文，不脱敏）", v)
	}
	if v := fields["client_secret"].GetStringValue(); v != "secret-456" {
		t.Errorf("ext.client_secret = %q, want secret-456（全站唯一明文出口，§12.1 行 1719）", v)
	}
	if v := fields["host"].GetStringValue(); v != "smtp.example.com" {
		t.Errorf("ext.host = %q", v)
	}
	if v := fields["port"].GetNumberValue(); v != 587 {
		t.Errorf("ext.port = %v, want 587（int32 → JSON number）", v)
	}
	if v := fields["disable_ssl"].GetBoolValue(); !v {
		t.Errorf("ext.disable_ssl = %v, want true", v)
	}
	if v := fields["max_size"].GetStringValue(); v != "2097152" {
		t.Errorf("ext.max_size = %q, want 2097152（int64 → 十进制字符串，§1.12）", v)
	}
	if v := fields["user_mapping"].GetStructValue().GetFields()["nickname"].GetStringValue(); v != "$.name" {
		t.Errorf("ext.user_mapping.nickname = %q", v)
	}
	if v := fields["metadata"].GetStructValue().GetFields()["username"].GetStringValue(); v != "u1" {
		t.Errorf("ext.metadata.username = %q", v)
	}
}

// TestAdminProviderDetailEmptyInputs 空输入防御分支：nil 行 → 空消息（口径同
// AccountProfile 的不可达防御分支）；真实行 + nil Ext → 空 Struct（protojson
// 视图 {}，ext 字段恒在便于管理表单绑定）。
func TestAdminProviderDetailEmptyInputs(t *testing.T) {
	if got := AdminProviderDetail(nil, nil); got == nil {
		t.Error("nil 行应输出空消息而非 nil")
	}
	got := AdminProviderDetail(wantProviderRow(), nil)
	if got.GetExt() == nil || len(got.GetExt().GetFields()) != 0 {
		t.Errorf("nil ext 应输出空 Struct, got %v", got.GetExt())
	}
}

// TestAdminSchemaOauthBaseline oauth 类型（wechat_mp，注册表 meta 无 Ext 字段
// 声明）：schema 仅含 13 个表列基线字段（§5.3 示例的表列部分），逐项对行
// 1192-1225；category / union_provider 的 options 由调用方注入。
func TestAdminSchemaOauthBaseline(t *testing.T) {
	meta, ok := provider.Lookup("wechat_mp")
	if !ok || meta.Category != "oauth" {
		t.Fatalf("Lookup(wechat_mp) = (%+v, %v), want category=oauth", meta, ok)
	}
	resp := AdminSchema("wechat_mp", meta.Category, nil, []string{"union_a"})
	if resp.GetType() != "wechat_mp" || resp.GetCategory() != "oauth" {
		t.Errorf("type/category = (%q, %q)", resp.GetType(), resp.GetCategory())
	}
	if len(resp.GetFields()) != 13 {
		t.Fatalf("基线字段数 = %d, want 13（表列基线，oauth meta 无字段声明）", len(resp.GetFields()))
	}
	// 顺序即 §5.3 示例排列。
	wantOrder := []string{"provider_key", "display_name", "category", "union_provider",
		"icon_url", "ui_group", "sort_order", "remark",
		"is_enabled", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields"}
	for i, key := range wantOrder {
		if resp.GetFields()[i].GetKey() != key {
			t.Fatalf("fields[%d].key = %q, want %q", i, resp.GetFields()[i].GetKey(), key)
		}
	}
	// 逐项对 §5.3 行 1192-1225。
	f := schemaFieldByKey(t, resp, "provider_key")
	if f.GetLabel() != "唯一标识" || f.GetType() != "text" || f.GetSection() != "basic" ||
		!f.GetRequired() || f.GetPattern() != "^[a-z0-9_]+$" || f.GetHelp() == "" {
		t.Errorf("provider_key = %+v", f)
	}
	f = schemaFieldByKey(t, resp, "category")
	if f.GetType() != "select" || !f.GetRequired() || len(f.GetOptions()) != 1 || f.GetOptions()[0] != "oauth" {
		t.Errorf("category = %+v（options 应为注册表类别）", f)
	}
	f = schemaFieldByKey(t, resp, "union_provider")
	if f.GetType() != "select" || len(f.GetOptions()) != 1 || f.GetOptions()[0] != "union_a" {
		t.Errorf("union_provider = %+v（options 应为 union Provider 键列表）", f)
	}
	f = schemaFieldByKey(t, resp, "icon_url")
	if f.GetPattern() != "^https?://" || f.GetSection() != "display" {
		t.Errorf("icon_url = %+v", f)
	}
	f = schemaFieldByKey(t, resp, "ui_group")
	if f.GetType() != "select" || f.GetDefault().GetStringValue() != "social" {
		t.Errorf("ui_group = %+v（default social）", f)
	}
	if got := []string{"social", "enterprise", "dev", "other"}; len(f.GetOptions()) != 4 {
		t.Errorf("ui_group options = %v, want %v", f.GetOptions(), got)
	}
	f = schemaFieldByKey(t, resp, "sort_order")
	if f.GetType() != "number" || f.GetDefault().GetNumberValue() != 0 {
		t.Errorf("sort_order = %+v（default 0）", f)
	}
	if f := schemaFieldByKey(t, resp, "remark"); !f.GetAdvanced() {
		t.Errorf("remark = %+v（advanced 折叠）", f)
	}
	for _, key := range []string{"is_enabled", "enable_signin", "enable_signup"} {
		if f := schemaFieldByKey(t, resp, key); !f.GetDefault().GetBoolValue() {
			t.Errorf("%s default = %v, want true", key, f.GetDefault())
		}
	}
	if f := schemaFieldByKey(t, resp, "enable_signup"); f.GetHelp() == "" {
		t.Errorf("enable_signup = %+v（help 应含关闭后语义，行 1222）", f)
	}
	if f := schemaFieldByKey(t, resp, "auto_bind"); f.GetDefault().GetBoolValue() {
		t.Errorf("auto_bind default = %v, want false", f.GetDefault())
	}
	f = schemaFieldByKey(t, resp, "auto_bind_fields")
	if f.GetDefault().GetStringValue() != "email,phone" || f.GetHelp() != "auto_bind 开启时生效" {
		t.Errorf("auto_bind_fields = %+v", f)
	}
}

// TestAdminSchemaSenderMetaFields 消息域（smtp）类型：Ext 字段与注册表
// SenderMeta.Fields 逐项一致（§15.3：meta 是 /schema 唯一数据源），基线 13 +
// meta 5 共 18 个字段；meta 字段顺序保持声明序。
func TestAdminSchemaSenderMetaFields(t *testing.T) {
	meta, ok := provider.LookupSenderMeta("smtp")
	if !ok || meta.Category != provider.CategoryEmail {
		t.Fatalf("LookupSenderMeta(smtp) = (%+v, %v)", meta, ok)
	}
	resp := AdminSchema("smtp", meta.Category, meta.Fields, nil)
	if resp.GetCategory() != "email" {
		t.Errorf("category = %q, want email（注册表 meta 决定）", resp.GetCategory())
	}
	if len(resp.GetFields()) != 13+len(meta.Fields) {
		t.Fatalf("字段数 = %d, want 13 基线 + %d meta 声明", len(resp.GetFields()), len(meta.Fields))
	}
	// Ext 字段逐项对注册表 meta（key/label/type/section/required/advanced/help）。
	for _, mf := range meta.Fields {
		got := schemaFieldByKey(t, resp, mf.Key)
		if got.GetLabel() != mf.Label || got.GetType() != mf.Type || got.GetSection() != mf.Section ||
			got.GetRequired() != mf.Required || got.GetAdvanced() != mf.Advanced || got.GetHelp() != mf.Help {
			t.Errorf("%s 与注册表 meta 不一致: schema=%+v meta=%+v", mf.Key, got, mf)
		}
		switch mf.Key {
		case "port":
			if got.GetDefault().GetNumberValue() != 587 {
				t.Errorf("port default = %v, want 587（meta Default 587 → JSON number）", got.GetDefault())
			}
		case "host":
			if !got.GetRequired() || got.GetSection() != "endpoint" {
				t.Errorf("host = %+v", got)
			}
		case "from":
			if got.GetSection() != "basic" {
				t.Errorf("from section = %q, want basic（meta 声明）", got.GetSection())
			}
		case "disable_ssl":
			if got.GetSection() != "policy" || got.GetType() != "checkbox" {
				t.Errorf("disable_ssl = %+v", got)
			}
		case "metadata":
			if got.GetSection() != "credential" || got.GetType() != "json" {
				t.Errorf("metadata = %+v", got)
			}
		}
	}
	// 顺序：basic 基线 4 项后即 meta 声明序（§5.3 行 1185 区块内沿用数组序）。
	if resp.GetFields()[4].GetKey() != meta.Fields[0].Key {
		t.Errorf("fields[4].key = %q, want %q（meta 首个声明字段）", resp.GetFields()[4].GetKey(), meta.Fields[0].Key)
	}
	// 基线在 meta 字段之后仍在（display / policy 区块）。
	for _, key := range []string{"icon_url", "ui_group", "sort_order", "remark", "is_enabled", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields"} {
		schemaFieldByKey(t, resp, key)
	}
}

// TestSchemaDefaultValue FieldMeta.Default → JSON 默认值转换边界：JSON 标量按
// 原类型（number / bool），解析失败按字符串，空串无默认值。
func TestSchemaDefaultValue(t *testing.T) {
	cases := []struct {
		in   string
		want *structpb.Value
	}{
		{"", nil},
		{"social", structpb.NewStringValue("social")},
		{"email,phone", structpb.NewStringValue("email,phone")},
		{"587", structpb.NewNumberValue(587)},
		{"0", structpb.NewNumberValue(0)},
		{"true", structpb.NewBoolValue(true)},
		{"false", structpb.NewBoolValue(false)},
	}
	for _, tc := range cases {
		got := schemaDefaultValue(tc.in)
		switch {
		case tc.want == nil && got != nil:
			t.Errorf("schemaDefaultValue(%q) = %+v, want nil", tc.in, got)
		case tc.want != nil && !proto.Equal(got, tc.want):
			t.Errorf("schemaDefaultValue(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}
