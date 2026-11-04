// admin 域的内部模型 → proto 报文转换（docs/接口文档.md §5.2 行 1168/1170、
// §5.3 行 1181-1244）：Provider 行 → 列表项 / 管理详情视图、provider.Ext →
// google.protobuf.Struct 明文透出、注册表 meta → SchemaField 的映射均以本文件
// 为唯一出口（docs/后端架构.md §3.5：本层只做转换与裁剪，不定义新的跨端结构）。
//
// 明文口径（§5.2 行 1170、§12.1 行 1719）：AdminProvider.ext 是全站唯一明文
// 凭证出口，仅管理员会话可见（鉴权由 admin 拦截器保证）；本层不做二次脱敏，
// 也不落任何日志。列表项 Provider 消息没有 ext 字段——凭证只存在于 Admin 视图
// 消息，泄露靠类型系统拦住（§3.5 view.go 口径）。
package dto

import (
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	adminv1 "authloft/gen/go/api/admin/v1"
	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/repo/model"
)

// extJSON Ext → Struct 的中间 JSON 编码（§12.9 行 1779：AdminProvider.ext 用
// Struct 承载 provider.Ext 明文透出）：UseProtoNames 使键与 §5.3 schema 的
// key 同源（Ext 字段名，snake_case——提交体即 {"<key>": <value>}，§5.3 行 1183），
// 与 internal/oidc 的 oidcJSON 同口径；零值标量按 §12.9 行 1775 省略。
var extJSON = protojson.MarshalOptions{UseProtoNames: true}

// AdminProviderListEntry 把 provider 行组装为 §5.2 行 1168 的列表项
// （列：显示名 / provider_key / 类别 / 类型 / 状态 / 策略标签 / 排序）。
// 列表消息没有 ext 字段（provider.proto），不触碰任何凭证。
func AdminProviderListEntry(row *model.Provider) *adminv1.Provider {
	if row == nil {
		return &adminv1.Provider{}
	}
	return &adminv1.Provider{
		ProviderKey:  row.ProviderKey,
		DisplayName:  row.DisplayName,
		Category:     row.Category,
		Type:         row.Type,
		IsEnabled:    row.IsEnabled == 1,
		EnableSignin: row.EnableSignin == 1,
		EnableSignup: row.EnableSignup == 1,
		AutoBind:     row.AutoBind == 1,
		SortOrder:    int64(row.SortOrder),
	}
}

// AdminProviderDetail 把 provider 行 + 解析后的 Ext 组装为 §5.2 行 1170 的
// 管理详情（返回明文凭证，需管理员会话）：provider 表列 typed 透出，ext 按
// §12.9 行 1779 用 Struct 明文透出（键 = Ext 字段名）。行缺失的防御分支输出
// 空消息（调用方契约下不可达，口径同 AccountProfile）。
func AdminProviderDetail(row *model.Provider, ext *providerpb.Ext) *adminv1.AdminProvider {
	if row == nil {
		return &adminv1.AdminProvider{}
	}
	return &adminv1.AdminProvider{
		ProviderKey:    row.ProviderKey,
		UnionProvider:  row.UnionProvider,
		DisplayName:    row.DisplayName,
		Category:       row.Category,
		Type:           row.Type,
		EnableSignin:   row.EnableSignin == 1,
		EnableSignup:   row.EnableSignup == 1,
		AutoBind:       row.AutoBind == 1,
		AutoBindFields: row.AutoBindFields,
		IsEnabled:      row.IsEnabled == 1,
		UiGroup:        row.UiGroup,
		SortOrder:      int64(row.SortOrder),
		IconUrl:        row.IconURL,
		Remark:         row.Remark,
		Ext:            AdminProviderExt(ext),
		CreatedAt:      row.CreatedAt.Unix(),
		UpdatedAt:      row.UpdatedAt.Unix(),
	}
}

// AdminProviderExt provider.Ext → Struct 明文透出（§12.9 行 1779）：经 protojson
// （UseProtoNames，snake_case 键）往返保持 Ext 字段名与 §5.3 schema key 逐字一致；
// int64 按 §1.12 输出十进制字符串、int32 为数字。nil / 空 Ext 输出空 Struct
// （protojson 视图 {}，字段恒存在便于管理表单绑定）。两条错误分支均只回空值、
// 不落日志——本函数输出是明文凭证，任何路径都不得进日志。
func AdminProviderExt(ext *providerpb.Ext) *structpb.Struct {
	if ext == nil {
		ext = &providerpb.Ext{}
	}
	raw, err := extJSON.Marshal(ext)
	if err != nil {
		return &structpb.Struct{}
	}
	out := &structpb.Struct{}
	if err := protojson.Unmarshal(raw, out); err != nil {
		return &structpb.Struct{}
	}
	return out
}

// §5.3 行 1185 的五区块取值（封闭集合）。
const (
	sectionBasic      = "basic"
	sectionCredential = "credential"
	sectionEndpoint   = "endpoint"
	sectionDisplay    = "display"
	sectionPolicy     = "policy"
)

// AdminSchema 组装 §5.3 行 1181-1227 的动态表单 schema：
//
//   - type / category：由注册表按 type 决定（行 1190、1192，《后端架构》§15.3
//     行 1731：注册表 meta 是 /schema 唯一数据源）；
//   - fields[]：provider 表列基线（全类型共有的封闭集，§5.3 示例即契约——
//     行 1192-1225 逐字：key / label / type / section / required / default /
//     options / pattern / advanced / help）+ Ext 字段逐项来自 meta 声明
//     （§15.3 行 1731「动态 schema 由适配器声明（provider.Ext 字段的标签、
//     渲染类型与默认值）」，不硬编码）；
//   - 顺序：basic 基线 → meta 声明的 Ext 字段（声明序）→ display / policy
//     基线，即 §5.3 示例的区块排列；前端按 section 分组、区块内沿用 fields[]
//     数组顺序（行 1185），不做二次排序。
//
// unionProviderKeys 是 union_provider 字段的 options 数据源（行 1197：仅列
// category=union 的 Provider），由调用方（handler）查库注入。
func AdminSchema(providerType, category string, extFields []provider.FieldMeta, unionProviderKeys []string) *adminv1.SchemaResponse {
	resp := &adminv1.SchemaResponse{Type: providerType, Category: category}
	resp.Fields = append(resp.Fields, schemaBaselineBasic(category, unionProviderKeys)...)
	resp.Fields = append(resp.Fields, schemaFieldsFromMeta(extFields)...)
	resp.Fields = append(resp.Fields, schemaBaselineDisplay()...)
	resp.Fields = append(resp.Fields, schemaBaselinePolicy()...)
	return resp
}

// schemaBaselineBasic §5.3 基础信息区块基线（行 1192-1198）：category 的
// options 由注册表 meta 决定（单值只读，行 1196），union_provider 的 options
// 为 union 类 Provider 的 provider_key 列表（行 1197）。
func schemaBaselineBasic(category string, unionProviderKeys []string) []*adminv1.SchemaField {
	return []*adminv1.SchemaField{
		{Key: "provider_key", Label: "唯一标识", Type: "text", Section: sectionBasic, Required: true,
			Pattern: "^[a-z0-9_]+$",
			Help:    "创建后不可修改，将出现在回调地址 /sso/oauth/callback/{provider_key} 中"},
		{Key: "display_name", Label: "显示名称", Type: "text", Section: sectionBasic, Required: true},
		{Key: "category", Label: "类别", Type: "select", Section: sectionBasic, Required: true,
			Options: []string{category},
			Help:    "由注册表按 type 决定，只读"},
		{Key: "union_provider", Label: "联合登录归属", Type: "select", Section: sectionBasic,
			Options: unionProviderKeys,
			Help:    "仅列 category=union 的 Provider；留空表示不参与 Union ID 归并"},
	}
}

// schemaBaselineDisplay §5.3 展示与排序区块基线（行 1213-1217）。
func schemaBaselineDisplay() []*adminv1.SchemaField {
	return []*adminv1.SchemaField{
		{Key: "icon_url", Label: "图标 URL", Type: "text", Section: sectionDisplay,
			Pattern: "^https?://",
			Help:    "绝对 URL，由管理员自行上传到任意可访问位置后填写（Authloft 不提供上传）；留空时前端渲染通用占位图标"},
		{Key: "ui_group", Label: "展示分组", Type: "select", Section: sectionDisplay,
			Options: []string{"social", "enterprise", "dev", "other"},
			Default: structpb.NewStringValue("social")},
		{Key: "sort_order", Label: "排序", Type: "number", Section: sectionDisplay,
			Default: structpb.NewNumberValue(0)},
		{Key: "remark", Label: "备注", Type: "text", Section: sectionDisplay, Advanced: true},
	}
}

// schemaBaselinePolicy §5.3 策略开关区块基线（行 1219-1225）。
func schemaBaselinePolicy() []*adminv1.SchemaField {
	return []*adminv1.SchemaField{
		{Key: "is_enabled", Label: "启用", Type: "checkbox", Section: sectionPolicy,
			Default: structpb.NewBoolValue(true)},
		{Key: "enable_signin", Label: "允许用于登录", Type: "checkbox", Section: sectionPolicy,
			Default: structpb.NewBoolValue(true)},
		{Key: "enable_signup", Label: "允许用于注册", Type: "checkbox", Section: sectionPolicy,
			Default: structpb.NewBoolValue(true),
			Help:    "关闭后该渠道不得用于建号：登录时「创建新账号」入口置灰，仅保留「退出并使用其他账号登录」，并提示该渠道未开放注册（已由信封 binding.allowSignup=false 反映）；如需把该三方身份绑到已有账号，由用户先正常登录再从安全中心发起绑定（§3.7）"},
		{Key: "auto_bind", Label: "按联系方式自动绑定", Type: "checkbox", Section: sectionPolicy,
			Default: structpb.NewBoolValue(false)},
		{Key: "auto_bind_fields", Label: "自动绑定字段", Type: "text", Section: sectionPolicy,
			Default: structpb.NewStringValue("email,phone"),
			Help:    "auto_bind 开启时生效"},
	}
}

// schemaFieldsFromMeta 注册表 meta 声明的 Ext 字段 → SchemaField（§15.3 行
// 1731：标签 / 渲染类型 / 默认值由适配器声明；§5.3 行 1243：section 亦由 meta
// 声明），保持声明顺序（区块内顺序沿用 fields[] 数组顺序，§5.3 行 1185）。
// FieldMeta 无 options / pattern（当前 Ext 字段渲染类型只有 text / secret /
// checkbox / number / json 声明集），对应字段保持零值。
func schemaFieldsFromMeta(fields []provider.FieldMeta) []*adminv1.SchemaField {
	out := make([]*adminv1.SchemaField, 0, len(fields))
	for _, f := range fields {
		out = append(out, &adminv1.SchemaField{
			Key:      f.Key,
			Label:    f.Label,
			Type:     f.Type,
			Section:  f.Section,
			Required: f.Required,
			Default:  schemaDefaultValue(f.Default),
			Advanced: f.Advanced,
			Help:     f.Help,
		})
	}
	return out
}

// schemaDefaultValue FieldMeta.Default（string）→ 任意 JSON 默认值（§5.3 行
// 1190：default 取值如 "social" / 0 / true）：先按 JSON 标量解析（number /
// bool / string / null 及对象数组），解析失败按原文作字符串默认值；空串无
// 默认值（nil，protojson 省略，§12.9 行 1775）。
func schemaDefaultValue(s string) *structpb.Value {
	if s == "" {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err == nil {
		if pv, perr := structpb.NewValue(v); perr == nil {
			return pv
		}
	}
	return structpb.NewStringValue(s)
}
