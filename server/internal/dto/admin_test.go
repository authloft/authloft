package dto

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	adminv1 "authloft/gen/go/api/admin/v1"
	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
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

// schemaFieldsOf nil 安全地取 meta.Schema()（Schema 为 func 字段，未迁移类型为 nil）。
func schemaFieldsOf(schema func() []provider.FieldMeta) []provider.FieldMeta {
	if schema == nil {
		return nil
	}
	return schema()
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

// TestAdminSchemaOauthBaseline oauth 类型（wechat_mp）以完整 Schema 声明转换为
// wire：3 个 basic 表列 + 11 个 Ext + 4 个 display + 5 个 policy + proxy_url = 24 项，
// 顺序即 §5.3 区块声明序；union_provider 的 options 由 dynamicOptions 按 DynamicKey 注入。
// 这是对"表列基线 + Ext + proxy_url"旧 wire 的逐字段保真回归。
func TestAdminSchemaOauthBaseline(t *testing.T) {
	meta, ok := provider.Lookup("wechat_mp")
	if !ok || meta.Category != "oauth" {
		t.Fatalf("Lookup(wechat_mp) = (%+v, %v), want category=oauth", meta, ok)
	}
	resp := AdminSchema("wechat_mp", meta.Category, schemaFieldsOf(meta.Schema),
		map[string][]string{"union_provider_keys": {"union_a"}})
	if resp.GetType() != "wechat_mp" || resp.GetCategory() != "oauth" {
		t.Errorf("type/category = (%q, %q)", resp.GetType(), resp.GetCategory())
	}
	if len(resp.GetFields()) != 24 {
		t.Fatalf("字段数 = %d, want 24（3 basic + 11 Ext + 4 display + 5 policy + proxy_url）", len(resp.GetFields()))
	}
	// 顺序即 §5.3 示例排列（表列基线 → Ext 声明序 → display / policy → proxy_url）。
	wantOrder := []string{"provider_key", "display_name", "union_provider",
		"client_id", "client_secret", "app_id", "cert", "scopes", "provider_url",
		"custom_auth_url", "custom_token_url", "custom_user_info_url", "user_mapping", "metadata",
		"icon_url", "ui_group", "sort_order", "remark",
		"is_enabled", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields",
		ProxyURLFieldKey}
	for i, key := range wantOrder {
		if resp.GetFields()[i].GetKey() != key {
			t.Fatalf("fields[%d].key = %q, want %q", i, resp.GetFields()[i].GetKey(), key)
		}
	}
	// 逐项对 §5.3 行 1192-1225；label / help 是前端 i18n 键，不是展示文案。
	f := schemaFieldByKey(t, resp, "provider_key")
	if f.GetLabel() != "admin.schemaField.providerKeyLabel" || f.GetType() != "text" || f.GetSection() != "basic" ||
		!f.GetRequired() || f.GetPattern() != "^[a-z0-9_]+$" ||
		f.GetHelp() != "admin.schemaField.providerKeyHelp" {
		t.Errorf("provider_key = %+v", f)
	}
	if f := schemaFieldByKey(t, resp, "display_name"); f.GetLabel() != "admin.schemaField.displayNameLabel" {
		t.Errorf("display_name label = %q, want i18n key", f.GetLabel())
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
	if f := schemaFieldByKey(t, resp, "enable_signup"); f.GetHelp() != "admin.schemaField.enableSignupHelp" {
		t.Errorf("enable_signup help = %q, want i18n key（关闭后语义，行 1222）", f.GetHelp())
	}
	if f := schemaFieldByKey(t, resp, "auto_bind"); f.GetDefault().GetBoolValue() {
		t.Errorf("auto_bind default = %v, want false", f.GetDefault())
	}
	f = schemaFieldByKey(t, resp, "auto_bind_fields")
	if f.GetDefault().GetStringValue() != "email,phone" || f.GetHelp() != "admin.schemaField.autoBindFieldsHelp" {
		t.Errorf("auto_bind_fields = %+v", f)
	}
	// 通用 Ext 基线 proxy_url 随 schema 统一下发（endpoint / advanced / text）。
	f = schemaFieldByKey(t, resp, ProxyURLFieldKey)
	if f.GetSection() != "endpoint" || !f.GetAdvanced() || f.GetType() != "text" ||
		f.GetLabel() != "admin.schemaField.proxyUrlLabel" || f.GetHelp() != "admin.schemaField.proxyUrlHelp" {
		t.Errorf("proxy_url = %+v", f)
	}
}

// TestAdminSchemaSenderMetaFields 消息域（smtp）以完整 Schema 声明逐字段转换为
// wire（§15.3：meta 是 /schema 唯一数据源）：属性与 schema 声明逐项一致，顺序保持
// 声明序；仅 oauth 的 5 列不在此声明里、自然不出现。
func TestAdminSchemaSenderMetaFields(t *testing.T) {
	meta, ok := provider.LookupSenderMeta("smtp")
	if !ok || meta.Category != provider.CategoryEmail {
		t.Fatalf("LookupSenderMeta(smtp) = (%+v, %v)", meta, ok)
	}
	schemaFields := schemaFieldsOf(meta.Schema)
	resp := AdminSchema("smtp", meta.Category, schemaFields, nil)
	if resp.GetCategory() != "email" {
		t.Errorf("category = %q, want email（注册表 meta 决定）", resp.GetCategory())
	}
	if len(resp.GetFields()) != len(schemaFields) {
		t.Fatalf("字段数 = %d, want %d（完整 Schema 声明逐项转换）", len(resp.GetFields()), len(schemaFields))
	}
	schemaFieldByKey(t, resp, ProxyURLFieldKey) // 完整 Schema 声明含 proxy_url（email 呈现）
	// 每个字段逐项对齐声明（key/label/type/section/required/advanced/help/default/options/pattern）。
	for i, mf := range schemaFields {
		got := resp.GetFields()[i] // 转换保真：wire 顺序 = 声明顺序
		if got.GetKey() != mf.Key || got.GetLabel() != mf.Label || got.GetType() != mf.Type ||
			got.GetSection() != mf.Section || got.GetRequired() != mf.Required ||
			got.GetAdvanced() != mf.Advanced || got.GetHelp() != mf.Help ||
			got.GetPattern() != mf.Pattern {
			t.Errorf("fields[%d] 与 Schema 声明不一致: wire=%+v meta=%+v", i, got, mf)
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
	// 表列基线 + display + is_enabled 由完整 Schema 声明覆盖，顺序即声明序。
	for _, key := range []string{"provider_key", "display_name", "icon_url", "ui_group", "sort_order", "remark", "is_enabled"} {
		schemaFieldByKey(t, resp, key)
	}
	// 仅 oauth 的 5 列不在 smtp 声明里，wire 不得出现。
	for _, key := range oauthOnlyTestKeys {
		if f, ok := schemaFieldMaybe(resp, key); ok {
			t.Errorf("email schema 不应含 %q: %+v", key, f)
		}
	}
}

// oauthOnlyTestKeys 仅 oauth 类别可读写的 5 个表列（dto 侧断言与
// oauthOnlyProviderColumns 同源口径）。
var oauthOnlyTestKeys = []string{
	"union_provider", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields",
}

// schemaFieldMaybe schemaFieldByKey 的非致命版本（用于断言字段不存在）。
func schemaFieldMaybe(resp *adminv1.SchemaResponse, key string) (*adminv1.SchemaField, bool) {
	for _, f := range resp.GetFields() {
		if f.GetKey() == key {
			return f, true
		}
	}
	return nil, false
}

// TestAdminProviderColumnKeysForCategory 三个类别的可写表列键集：oauth 全量
// 11 键；sms / email / unknown 裁掉 5 个 oauth 专属键、剩 6 个通用键；union
// （虚拟）再裁掉 is_enabled，只剩 5 键（无启用开关可关）。此函数是 schema /
// 写入 / 校验三处共用的唯一真相。
func TestAdminProviderColumnKeysForCategory(t *testing.T) {
	oauth := AdminProviderColumnKeysFor(provider.CategoryOAuth)
	if len(oauth) != len(AdminProviderColumnKeys) {
		t.Fatalf("oauth 键数 = %d, want %d（全量）", len(oauth), len(AdminProviderColumnKeys))
	}
	for _, category := range []string{provider.CategorySMS, provider.CategoryEmail, "unknown"} {
		got := AdminProviderColumnKeysFor(category)
		if len(got) != 6 {
			t.Errorf("category=%q 键数 = %d, want 6: %v", category, len(got), got)
		}
		for _, key := range oauthOnlyTestKeys {
			for _, k := range got {
				if k == key {
					t.Errorf("category=%q 不应含 oauth 专属键 %q", category, key)
				}
			}
		}
	}
	// union（虚拟）：通用列里再少 is_enabled——虚拟 Provider 无 adapter /
	// 无登录入口，启用开关无可开关的行为。
	union := AdminProviderColumnKeysFor(provider.CategoryUnion)
	if len(union) != 5 {
		t.Errorf("category=union 键数 = %d, want 5（虚拟类别无 is_enabled）: %v", len(union), union)
	}
	for _, k := range union {
		if k == "is_enabled" {
			t.Errorf("category=union 不应含 is_enabled: %v", union)
		}
	}
	// 返回值是副本，调用方改动不得污染全量常量。
	got := AdminProviderColumnKeysFor(provider.CategoryOAuth)
	got[0] = "tampered"
	if AdminProviderColumnKeys[0] == "tampered" {
		t.Fatal("AdminProviderColumnKeysFor 应返回副本")
	}
	// 完整 Schema 转换：oauth 全量声明（含 union_provider / 5 开关 / proxy_url）；
	// union 声明不含 is_enabled 与 proxy_url；storage/local 声明不含 proxy_url。
	// 键集裁剪已下沉到各 provider.Schema()，AdminSchema 只做纯转换。
	oauthMeta, _ := provider.LookupTypeMeta("wechat_mp")
	oauthSchema := AdminSchema("wechat_mp", provider.CategoryOAuth, schemaFieldsOf(oauthMeta.Schema), nil)
	if len(oauthSchema.GetFields()) != len(schemaFieldsOf(oauthMeta.Schema)) {
		t.Errorf("oauth schema 字段数 = %d, want %d（完整 Schema 声明）",
			len(oauthSchema.GetFields()), len(schemaFieldsOf(oauthMeta.Schema)))
	}
	unionMeta, _ := provider.LookupTypeMeta(provider.UnionProviderType)
	unionSchema := AdminSchema(provider.UnionProviderType, provider.CategoryUnion, schemaFieldsOf(unionMeta.Schema), nil)
	if len(unionSchema.GetFields()) != len(schemaFieldsOf(unionMeta.Schema)) {
		t.Errorf("union schema 字段数 = %d, want %d（完整 Schema 声明）",
			len(unionSchema.GetFields()), len(schemaFieldsOf(unionMeta.Schema)))
	}
	if f, ok := schemaFieldMaybe(unionSchema, "is_enabled"); ok {
		t.Errorf("union schema 不应含启用开关: %+v", f)
	}
	if f, ok := schemaFieldMaybe(unionSchema, ProxyURLFieldKey); ok {
		t.Errorf("union（无外呼）schema 不应含 proxy_url: %+v", f)
	}
	// storage/local 声明不含 proxy_url（无网络外呼）。
	localMeta, _ := provider.LookupTypeMeta("local")
	localSchema := AdminSchema("local", "storage", schemaFieldsOf(localMeta.Schema), nil)
	if f, ok := schemaFieldMaybe(localSchema, ProxyURLFieldKey); ok {
		t.Errorf("storage/local schema 不应含 proxy_url: %+v", f)
	}
}

// TestProxyURLSchemaField proxy_url 的完整契约：由 AdminSchema 从 Schema 声明转换
// 出的 proxy_url 字段形态（endpoint / advanced / text / i18n 键 / 无默认值 / 非必填）。
// 另钉 ProxyURLFieldEnabled 的裁剪判定：union 与 storage/local 不呈现，其余呈现。
func TestProxyURLSchemaField(t *testing.T) {
	meta, ok := provider.LookupTypeMeta("wechat_mp")
	if !ok {
		t.Fatal("wechat_mp meta 缺失")
	}
	resp := AdminSchema("wechat_mp", provider.CategoryOAuth, schemaFieldsOf(meta.Schema), nil)
	f := schemaFieldByKey(t, resp, ProxyURLFieldKey)
	if f.GetLabel() != "admin.schemaField.proxyUrlLabel" || f.GetHelp() != "admin.schemaField.proxyUrlHelp" ||
		f.GetType() != "text" || f.GetSection() != "endpoint" || !f.GetAdvanced() || f.GetRequired() ||
		f.GetDefault() != nil {
		t.Errorf("proxy_url 字段契约 = %+v", f)
	}
	for _, tc := range []struct {
		category, typ string
		want          bool
	}{
		{provider.CategoryOAuth, "wechat_mp", true},
		{provider.CategorySMS, "aliyun_sms", true},
		{provider.CategoryEmail, "smtp", true},
		{"captcha", "turnstile", true},
		{provider.CategoryUnion, provider.UnionProviderType, false},
		{"storage", "local", false},
		{"storage", "s3", true}, // 有网络外呼的未来存储实现按 §15.4 纳入
	} {
		if got := ProxyURLFieldEnabled(tc.category, tc.typ); got != tc.want {
			t.Errorf("ProxyURLFieldEnabled(%q,%q) = %v, want %v", tc.category, tc.typ, got, tc.want)
		}
	}
}

// TestAdminSchemaConversionFidelity 纯转换保真：给定混合字段声明（表列 / Ext /
// dynamic / pattern / default / options / i18n 键），wire 逐字段、逐属性对齐声明；
// 顺序即声明序；dynamic 字段 options 来自 dynamicOptions[DynamicKey]（未命中为空），
// 普通字段 options 来自自身 Options；Storage / Kind / DynamicKey 不进 wire。
func TestAdminSchemaConversionFidelity(t *testing.T) {
	fields := []provider.FieldMeta{
		{Key: "provider_key", Label: "admin.schemaField.providerKeyLabel", Type: "text", Section: "basic",
			Required: true, Pattern: "^[a-z0-9_]+$", Help: "admin.schemaField.providerKeyHelp",
			Storage: provider.StorageColumn},
		{Key: "union_provider", Label: "admin.schemaField.unionProviderLabel", Type: "select", Section: "basic",
			Help: "admin.schemaField.unionProviderHelp", Storage: provider.StorageColumn,
			Kind: provider.FieldDynamicOptions, DynamicKey: "union_provider_keys"},
		{Key: "ui_group", Label: "admin.schemaField.uiGroupLabel", Type: "select", Section: "display",
			Options: []string{"social", "enterprise"}, Default: "social", Storage: provider.StorageColumn},
		{Key: "is_enabled", Label: "admin.schemaField.isEnabledLabel", Type: "checkbox", Section: "policy",
			Default: "true", Storage: provider.StorageColumn},
		{Key: "client_secret", Label: "admin.schemaField.clientSecretLabel", Type: "secret", Section: "credential",
			Required: true, Help: "admin.schemaField.clientSecretHelp", Storage: provider.StorageExt},
		{Key: "missing_dyn", Label: "admin.schemaField.missingDynLabel", Type: "select", Section: "basic",
			Storage: provider.StorageExt, Kind: provider.FieldDynamicOptions, DynamicKey: "not_provided"},
	}
	resp := AdminSchema("wechat_mp", provider.CategoryOAuth, fields,
		map[string][]string{"union_provider_keys": {"union_a", "union_b"}})
	if resp.GetType() != "wechat_mp" || resp.GetCategory() != provider.CategoryOAuth {
		t.Errorf("type/category = (%q,%q)", resp.GetType(), resp.GetCategory())
	}
	if len(resp.GetFields()) != len(fields) {
		t.Fatalf("字段数 = %d, want %d", len(resp.GetFields()), len(fields))
	}
	for i, mf := range fields {
		got := resp.GetFields()[i]
		if got.GetKey() != mf.Key {
			t.Errorf("fields[%d].key = %q, want %q（顺序即声明序）", i, got.GetKey(), mf.Key)
		}
		if got.GetLabel() != mf.Label || got.GetType() != mf.Type || got.GetSection() != mf.Section ||
			got.GetRequired() != mf.Required || got.GetAdvanced() != mf.Advanced ||
			got.GetHelp() != mf.Help || got.GetPattern() != mf.Pattern {
			t.Errorf("fields[%d](%s) 属性与声明不一致: wire=%+v meta=%+v", i, mf.Key, got, mf)
		}
		if !proto.Equal(got.GetDefault(), schemaDefaultValue(mf.Default)) {
			t.Errorf("fields[%d](%s) default = %v, want %v", i, mf.Key, got.GetDefault(), schemaDefaultValue(mf.Default))
		}
	}
	// dynamic 字段 options 来自 map；未命中为空。普通字段 options 来自自身 Options。
	if opts := resp.GetFields()[1].GetOptions(); len(opts) != 2 || opts[0] != "union_a" || opts[1] != "union_b" {
		t.Errorf("union_provider options = %v, want [union_a union_b]（dynamic 注入）", opts)
	}
	if opts := resp.GetFields()[5].GetOptions(); len(opts) != 0 {
		t.Errorf("missing_dyn options = %v, want 空（dynamic key 未命中）", opts)
	}
	if opts := resp.GetFields()[2].GetOptions(); len(opts) != 2 || opts[0] != "social" || opts[1] != "enterprise" {
		t.Errorf("ui_group options = %v, want [social enterprise]（自身声明）", opts)
	}
	// Storage / Kind / DynamicKey 无 wire 对应字段：protojson 视图不得出现这些键。
	raw, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"\"storage\"", "\"kind\"", "\"dynamicKey\"", "\"dynamic_key\""} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("wire 不应含 %s: %s", forbidden, raw)
		}
	}
}

// TestMergeProviderExtProxyURL extKeys 含 proxy_url 时落库、PATCH 缺省保留原值。
func TestMergeProviderExtProxyURL(t *testing.T) {
	fields := map[string]*structpb.Value{
		ProxyURLFieldKey: structpb.NewStringValue("socks5://alice:pw@127.0.0.1:1080"),
	}
	ext, err := MergeProviderExt(&providerpb.Ext{}, fields, []string{ProxyURLFieldKey})
	if err != nil {
		t.Fatal(err)
	}
	if got := ext.GetProxyUrl(); got != "socks5://alice:pw@127.0.0.1:1080" {
		t.Errorf("ext.proxy_url = %q", got)
	}
	// PATCH：原值保留、未提交的 Ext 键不动。
	orig := &providerpb.Ext{ProxyUrl: "http://old:8080", ClientId: "id"}
	merged, err := MergeProviderExt(orig, map[string]*structpb.Value{}, []string{ProxyURLFieldKey})
	if err != nil {
		t.Fatal(err)
	}
	if merged.GetProxyUrl() != "http://old:8080" || merged.GetClientId() != "id" {
		t.Errorf("PATCH 结果 = %+v", merged)
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

// TestAdminSettingsSiteName AdminSettings 全键投影含 site_name（第 37 键）：
// 快照有值原样投影；缺失 / 非 string 按零值投影（protojson 省略）。
func TestAdminSettingsSiteName(t *testing.T) {
	snap := settings.Defaults()
	snap[settings.KeySiteName] = "Authloft Docs"
	if got := AdminSettings(snap).GetSiteName(); got != "Authloft Docs" {
		t.Errorf("SiteName = %q, want Authloft Docs", got)
	}

	snap[settings.KeySiteName] = "Authloft"
	if got := AdminSettings(snap).GetSiteName(); got != "Authloft" {
		t.Errorf("SiteName = %q, want Authloft（默认值）", got)
	}

	delete(snap, settings.KeySiteName)
	if got := AdminSettings(snap).GetSiteName(); got != "" {
		t.Errorf("缺失键 SiteName = %q, want 空串（零值投影）", got)
	}
}
