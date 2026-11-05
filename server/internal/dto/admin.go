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
	"fmt"
	"math"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	accountv1 "authloft/gen/go/api/account/v1"
	adminv1 "authloft/gen/go/api/admin/v1"
	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/repo"
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

// extUnmarshal 提交体 → provider.Ext 的 protojson 解析选项（protojson 解析
// 同时接受 proto 字段名与 lowerCamelCase 两种键形，§5.3 行 1183 的提交体键
// 即 Ext 字段名 snake_case，无需选项切换）；DiscardUnknown 保险——合法键集
// 已在 service 校验，此处仅防御注册表未声明却与 Ext 字段同名的残余键。类型
// 不符（bool 列收到字符串等）由 protojson 报错，service 映射 invalid_request。
var extUnmarshal = protojson.UnmarshalOptions{DiscardUnknown: true}

// AdminProviderColumnKeys provider 表列中可经提交体写入的基线键集（§5.3 行
// 1192-1225 示例即契约：display / policy 区块 + basic 区块的 display_name /
// union_provider）。不含 provider_key（service 单独校验「创建后不可改」）、
// category 与 type（由注册表按 type 决定，只读）。
var AdminProviderColumnKeys = []string{
	"display_name", "union_provider", "icon_url", "ui_group", "sort_order", "remark",
	"is_enabled", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields",
}

// ApplyProviderColumns 把提交体中的表列基线键（AdminProviderColumnKeys）应
// 用到 row（写路径：Create 从零值行起、Update 从 FindByKey 读回的完整
// 行上——未提交的键不动即「缺省键保留原值」，PATCH over schema 键集。该
// 缺省语义 docs 未明说，按默认口径处理）。provider_key /
// category / type 不经本函数（service 层按 §5.2 行 1171「创建后不可改」与
// 注册表只读口径单独校验）。值类型不符返回错误（service 映射 invalid_request）；
// 显式 null 按清零语义落列默认值。
func ApplyProviderColumns(row *model.Provider, fields map[string]*structpb.Value) error {
	if row == nil {
		return fmt.Errorf("dto: apply provider columns: nil row")
	}
	for _, key := range AdminProviderColumnKeys {
		v, ok := fields[key]
		if !ok {
			continue // 缺省保留原值（PATCH）
		}
		var err error
		switch key {
		case "display_name":
			row.DisplayName, err = columnString(v)
		case "union_provider":
			row.UnionProvider, err = columnString(v)
		case "icon_url":
			row.IconURL, err = columnString(v)
		case "ui_group":
			row.UiGroup, err = columnString(v)
		case "remark":
			row.Remark, err = columnString(v)
		case "auto_bind_fields":
			row.AutoBindFields, err = columnString(v)
		case "sort_order":
			row.SortOrder, err = columnInt32(v)
		case "is_enabled":
			row.IsEnabled, err = columnInt8Bool(v)
		case "enable_signin":
			row.EnableSignin, err = columnInt8Bool(v)
		case "enable_signup":
			row.EnableSignup, err = columnInt8Bool(v)
		case "auto_bind":
			row.AutoBind, err = columnInt8Bool(v)
		}
		if err != nil {
			return fmt.Errorf("dto: apply provider columns: key %q: %w", key, err)
		}
	}
	return nil
}

// MergeProviderExt 把提交体中属于 Ext 键集（extKeys，注册表 meta.Fields 声明
// 的字段名集合）的值合并进原 Ext（protojson 往返：原 Ext 按 UseProtoNames 序
// 列化为键值 map，提交值覆盖同名键，再整体解析回 provider.Ext——未提交的
// Ext 字段保留原值，PATCH 语义同 ApplyProviderColumns）。Create 传空 Ext 起
// 点即可。类型不符由 protojson 报错（service 映射 invalid_request）。orig 为
// nil 时按空 Ext 起点（与 ParseProviderExt 的非 nil 语义一致）。
func MergeProviderExt(orig *providerpb.Ext, fields map[string]*structpb.Value, extKeys []string) (*providerpb.Ext, error) {
	if orig == nil {
		orig = &providerpb.Ext{}
	}
	raw, err := extJSON.Marshal(orig)
	if err != nil {
		return nil, fmt.Errorf("dto: merge provider ext: %w", err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("dto: merge provider ext: %w", err)
	}
	for _, key := range extKeys {
		v, ok := fields[key]
		if !ok {
			continue // 缺省保留原值（PATCH）
		}
		m[key] = v.AsInterface()
	}
	merged, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("dto: merge provider ext: %w", err)
	}
	out := &providerpb.Ext{}
	if err := extUnmarshal.Unmarshal(merged, out); err != nil {
		return nil, fmt.Errorf("dto: merge provider ext: %w", err)
	}
	return out, nil
}

// columnString 表列 string 值（§1.11 text 渲染）；null 清零、非 string 报错。
func columnString(v *structpb.Value) (string, error) {
	if v == nil {
		return "", nil
	}
	switch v := v.GetKind().(type) {
	case *structpb.Value_NullValue:
		return "", nil
	case *structpb.Value_StringValue:
		return v.StringValue, nil
	default:
		return "", fmt.Errorf("want string value, got %T", v)
	}
}

// columnInt32 表列 int32 值（§1.11 number 渲染）；null 清零、非 number 报错。
func columnInt32(v *structpb.Value) (int32, error) {
	if v == nil {
		return 0, nil
	}
	switch v := v.GetKind().(type) {
	case *structpb.Value_NullValue:
		return 0, nil
	case *structpb.Value_NumberValue:
		n := v.NumberValue
		if n != math.Trunc(n) {
			return 0, fmt.Errorf("want integer, got %v", n)
		}
		return int32(n), nil
	default:
		return 0, fmt.Errorf("want number value, got %T", v)
	}
}

// columnInt8Bool 表列 tinyint 开关（§1.11 checkbox 渲染，§12.9 行 1749 用 bool
// 承载）；null 清零、非 bool 报错。
func columnInt8Bool(v *structpb.Value) (int8, error) {
	if v == nil {
		return 0, nil
	}
	switch v := v.GetKind().(type) {
	case *structpb.Value_NullValue:
		return 0, nil
	case *structpb.Value_BoolValue:
		if v.BoolValue {
			return 1, nil
		}
		return 0, nil
	default:
		return 0, fmt.Errorf("want bool value, got %T", v)
	}
}

// —— 用户管理族（§5.1 行 1162、§5.4 行 1249-1255）——

// adminStr 可空列读值（nil / 空串归一空串；admin 域 phone / email 明文——
// §5.4 未要求掩码且管理端需真实值，掩码仅 account 域自助视图，§3.1 行 806）。
func adminStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// AdminMe 当前管理员视图（§5.1 行 1162）：{id, username, nickname,
// avatarUrl, isAdmin:true}——isAdmin 恒 true（非管理员在 admin 拦截器即被
// 拦下，不会走到 handler）。
func AdminMe(row *model.User) *adminv1.MeResponse {
	if row == nil {
		return &adminv1.MeResponse{}
	}
	return &adminv1.MeResponse{
		Id:        row.ID,
		Username:  row.Username,
		Nickname:  row.Nickname,
		AvatarUrl: row.AvatarURL,
		IsAdmin:   true,
	}
}

// AdminUser user 行 → AdminUser 视图（§5.4 行 1249 列表 / 行 1250 详情内
// 嵌套共用；字段集为 user 表列投影，user.proto 注释）。
func AdminUser(row *model.User) *adminv1.AdminUser {
	if row == nil {
		return &adminv1.AdminUser{}
	}
	u := &adminv1.AdminUser{
		Id:            row.ID,
		Username:      row.Username,
		Nickname:      row.Nickname,
		AvatarUrl:     row.AvatarURL,
		Phone:         adminStr(row.Phone),
		Email:         adminStr(row.Email),
		PhoneVerified: int64(row.PhoneVerified),
		EmailVerified: int64(row.EmailVerified),
		UserStatus:    int64(row.UserStatus),
		MfaRequired:   int64(row.MfaRequired),
		Epoch:         int64(row.Epoch),
		CreatedAt:     row.CreatedAt.Unix(),
		UpdatedAt:     row.UpdatedAt.Unix(),
	}
	if row.LastLoginAt != nil {
		u.LastLoginAt = row.LastLoginAt.Unix()
	}
	return u
}

// AdminCredentialSummary user_credential 行 → 凭证概览条目（§5.4 行 1250
//「凭证概览」：kind / is_enabled；secret 不透出，UserCredentialSummary 无该
// 字段）。含全部 kind（mfa_setting 行即「MFA 已开启」的行存在性投影）。
func AdminCredentialSummary(row *model.UserCredential) *adminv1.UserCredentialSummary {
	if row == nil {
		return &adminv1.UserCredentialSummary{}
	}
	s := &adminv1.UserCredentialSummary{
		Id:        row.ID,
		Kind:      row.Kind,
		Label:     row.Label,
		IsEnabled: row.IsEnabled == 1,
		CreatedAt: row.CreatedAt.Unix(),
	}
	if row.LastUsedAt != nil {
		s.LastUsedAt = row.LastUsedAt.Unix()
	}
	return s
}

// AdminThirdpartyBinding user_thirdparty_bind 行 → 绑定条目（§5.4 行 1250
//「绑定」）。union_id 恒零值（protojson 省略）：§12.7 行 1543 普通行不存
// unionid，Union 行的 unionid 即其 open_id 已在列表可见——union_id 字段
// 留给未来跨行归并视图，不在本投影内拼装（默认口径，待定）。
func AdminThirdpartyBinding(row *model.UserThirdpartyBind) *adminv1.UserThirdpartyBinding {
	if row == nil {
		return &adminv1.UserThirdpartyBinding{}
	}
	return &adminv1.UserThirdpartyBinding{
		Id:          row.ID,
		ProviderKey: row.ProviderKey,
		OpenId:      row.OpenID,
		Nickname:    row.Nickname,
		AvatarUrl:   row.AvatarURL,
		CreatedAt:   row.CreatedAt.Unix(),
	}
}

// AdminUserDetail GetUser 详情组装（§5.4 行 1250 详情含凭证概览、绑定、
// MFA 状态）：user 投影（含 mfa_required 列）+ 凭证概览（含 mfa_setting
// 行存在性）+ 绑定列表 + mfa 五因子绑定明细（§3.5 行 887-898 既有视图，
// AdminUserMfa）。
func AdminUserDetail(user *model.User, creds []model.UserCredential, binds []model.UserThirdpartyBind) *adminv1.UserDetailResponse {
	items := make([]*adminv1.UserCredentialSummary, len(creds))
	for i := range creds {
		items[i] = AdminCredentialSummary(&creds[i])
	}
	bindings := make([]*adminv1.UserThirdpartyBinding, len(binds))
	for i := range binds {
		bindings[i] = AdminThirdpartyBinding(&binds[i])
	}
	return &adminv1.UserDetailResponse{
		User:        AdminUser(user),
		Credentials: items,
		Bindings:    bindings,
		Mfa:         AdminUserMfa(user, creds),
	}
}

// AdminUserMfa 用户详情的 MFA 绑定明细（§5.4 行 1250「MFA 状态」的数据
// 面，§3.5 行 887-898 跨包既有视图）：五因子序同 mfaFactorOrder；bound
// 判定与 account handler mfaBound 同口径（totp / webauthn / recovery_code
// 走 user_credential 行存在且 is_enabled=1，recovery_code 另需 meta 余量
// 非空；otp_sms / otp_email 走 phone / email 非空，target 掩码）；MFA
// 开关（mfa_setting 行存在性）与强制（user.mfa_required 列）不在此重复
//（§3.5 行 885：摘要走 §3.2 mfaPolicy——admin 侧由凭证概览的 mfa_setting
// 行与 user.mfa_required 承载，默认口径）。webauthn 的 credentials
// 计数需 user_credential_webauthn 表（WebauthnRepo，不在本实现依赖面），
// 置零由 protojson 省略（§12.9 行 1752），待定。
func AdminUserMfa(user *model.User, creds []model.UserCredential) *accountv1.MfaResponse {
	rows := map[string]*model.UserCredential{}
	for i := range creds {
		rows[creds[i].Kind] = &creds[i] // webauthn 多行取首行（mfaBound 同款口径）
	}
	factors := make([]*accountv1.MfaFactor, 0, len(mfaFactorOrder))
	for _, name := range mfaFactorOrder {
		f := &accountv1.MfaFactor{Factor: name}
		switch name {
		case "totp", "webauthn":
			if row := rows[name]; row != nil && row.IsEnabled == 1 {
				f.Bound = true
				f.BoundAt = row.CreatedAt.Unix()
				if row.LastUsedAt != nil {
					f.LastUsedAt = row.LastUsedAt.Unix()
				}
			}
		case "recovery_code":
			if row := rows[name]; row != nil && row.IsEnabled == 1 {
				if meta, err := repo.UnmarshalCredentialMeta(row.Meta); err == nil {
					f.Remaining = int64(len(meta.GetRecoveryCodes()))
					f.Bound = f.Remaining > 0
				}
				if f.Bound {
					f.BoundAt = row.CreatedAt.Unix()
				}
			}
		case "otp_sms":
			if user != nil && adminStr(user.Phone) != "" {
				f.Bound = true
				f.Target = maskPhone(*user.Phone)
			}
		case "otp_email":
			if user != nil && adminStr(user.Email) != "" {
				f.Bound = true
				f.Target = maskEmail(*user.Email)
			}
		}
		factors = append(factors, f)
	}
	resp := &accountv1.MfaResponse{Factors: factors}
	if row := rows["recovery_code"]; row != nil {
		resp.RecoveryIssuedAt = row.CreatedAt.Unix()
	}
	return resp
}

// AdminEventItem event_log 行 → 事件条目（§5.4 行 1255 用户登录记录 /
// §5.6 行 1272 统一事件视图共用，EventItem 注释）：detail 为 msgpack 字节
// → JSON 对象透出（§12.1 行 1629），解码失败按 nil 处理（附加信息缺失
// 不影响主字段，复用 account.go decodeProfileExtra 同款口径——同为
// msgpack map 透传，§3.1 extra 与 §12.0 detail 同源约定）。
func AdminEventItem(row *model.EventLog) *adminv1.EventItem {
	if row == nil {
		return &adminv1.EventItem{}
	}
	return &adminv1.EventItem{
		Id:        row.ID,
		Event:     row.Event,
		ActorType: row.ActorType,
		ActorId:   row.ActorID,
		UserId:    row.UserID,
		ClientId:  row.ClientID,
		Amr:       row.AMR,
		Ip:        row.IP,
		Ua:        row.UA,
		Target:    row.Target,
		Detail:    decodeProfileExtra(row.Detail),
		CreatedAt: row.CreatedAt.Unix(),
	}
}
