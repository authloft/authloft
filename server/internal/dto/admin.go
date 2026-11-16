// admin 域内部模型 → proto 报文转换的唯一出口：本层只做转换与裁剪，不定义跨端结构。
// AdminProvider.ext 是全站唯一明文凭证出口，仅管理员会话可见（鉴权由 admin 拦截器保证）；
// 本层不做二次脱敏、不落日志；列表消息不含 ext 字段，凭证泄露靠类型系统拦住。
package dto

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	accountv1 "authloft/gen/go/api/account/v1"
	adminv1 "authloft/gen/go/api/admin/v1"
	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

// extJSON Ext → Struct 中间编码：UseProtoNames 使键与 schema key 同源（Ext 字段名
// snake_case），与 internal/oidc 的 oidcJSON 同口径；零值标量省略。
var extJSON = protojson.MarshalOptions{UseProtoNames: true}

// AdminProviderListEntry provider 行 → 列表项；列表消息没有 ext 字段，不触碰凭证。
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

// AdminProviderDetail provider 行 + Ext → 管理详情（返回明文凭证，需管理员会话）：
// ext 用 Struct 明文透出；行缺失防御分支输出空消息（调用方契约下不可达）。
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

// AdminProviderExt provider.Ext → Struct 明文透出：nil / 空 Ext 输出空 Struct，
// 字段恒存在便于表单绑定。两条错误分支只回空值并记一条 Warn；输出是明文
// 凭证，日志只记错误类别、不记 err 文本或任何字段内容。
func AdminProviderExt(ext *providerpb.Ext) *structpb.Struct {
	if ext == nil {
		ext = &providerpb.Ext{}
	}
	raw, err := extJSON.Marshal(ext)
	if err != nil {
		slog.Warn("dto: encode admin provider ext failed", "step", "marshal_ext")
		return &structpb.Struct{}
	}
	out := &structpb.Struct{}
	if err := protojson.Unmarshal(raw, out); err != nil {
		slog.Warn("dto: decode admin provider ext failed", "step", "unmarshal_ext")
		return &structpb.Struct{}
	}
	return out
}

// AdminSchema 把类型 meta 声明的完整 []FieldMeta 按序转换为 wire SchemaField：
// 每个字段的 key/label/type/section/required/default/advanced/help/pattern 逐项透传；
// Kind=FieldDynamicOptions 的字段从 dynamicOptions[DynamicKey] 注入 options，其余
// 字段用自身 Options；Storage / Kind / DynamicKey 不进 wire（proto 无对应字段）。
// label / help 是前端 i18n 键，本层不持有文案；type / category 仅作顶层响应字段。
// 字段裁剪（哪些表列 / Ext / 引用键出现）完全由调用方传入的 fields 决定。
func AdminSchema(providerType, category string, fields []provider.FieldMeta, dynamicOptions map[string][]string) *adminv1.SchemaResponse {
	resp := &adminv1.SchemaResponse{Type: providerType, Category: category}
	for _, f := range fields {
		sf := &adminv1.SchemaField{
			Key:      f.Key,
			Label:    f.Label,
			Type:     f.Type,
			Section:  f.Section,
			Required: f.Required,
			Default:  schemaDefaultValue(f.Default),
			Advanced: f.Advanced,
			Help:     f.Help,
			Pattern:  f.Pattern,
		}
		if f.Kind == provider.FieldDynamicOptions {
			sf.Options = dynamicOptions[f.DynamicKey]
		} else {
			sf.Options = f.Options
		}
		resp.Fields = append(resp.Fields, sf)
	}
	return resp
}

// schemaDefaultValue FieldMeta.Default（string）→ JSON 默认值：先按 JSON 标量解析，
// 失败按原文作字符串；空串无默认值（nil，protojson 省略）。
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

// extUnmarshal 提交体 → provider.Ext 解析选项：DiscardUnknown 保险——合法键集已在
// service 校验，此处仅防御未声明却与 Ext 同名的残余键；类型不符由 protojson 报错。
var extUnmarshal = protojson.UnmarshalOptions{DiscardUnknown: true}

// ProviderColumnKeys 从完整 Schema 声明派生可写表列键集：Storage == StorageColumn
// 且排除 provider_key（仅创建时写、更新时作定位键，不得进 ApplyProviderColumns，
// 否则 Update 可能改动主键）。返回值是独立切片，供写入侧经 ApplyProviderColumns
// 逐键赋值（§4.4）。
func ProviderColumnKeys(fields []provider.FieldMeta) []string {
	keys := make([]string, 0, len(fields))
	for _, f := range fields {
		if f.Storage == provider.StorageColumn && f.Key != "provider_key" {
			keys = append(keys, f.Key)
		}
	}
	return keys
}

// ApplyProviderColumns 把 columnKeys 指定的表列键应用到 row：未提交的键不动即缺省
// 保留原值（PATCH over schema 键集）。columnKeys 由写入侧经 ProviderColumnKeys 从
// Schema 派生，已排除 provider_key / category / type（创建后不可改、只读）；值类型
// 不符返回错误，显式 null 按清零落列默认值。
func ApplyProviderColumns(row *model.Provider, fields map[string]*structpb.Value, columnKeys []string) error {
	if row == nil {
		return fmt.Errorf("dto: apply provider columns: nil row")
	}
	for _, key := range columnKeys {
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

// MergeProviderExt 把 Ext 键集的值合并进原 Ext（protojson 往返：未提交字段保留原值，
// PATCH 语义同 ApplyProviderColumns）。Create 传空 Ext 起点，orig 为 nil 时按空 Ext；
// 类型不符由 protojson 报错。extKeys 须由写入侧从 Schema 的 Ext 字段派生
// （service.metaFieldKeys）——proxy_provider_key 引用键按 Schema 声明是否含该字段
// 自动纳入，与 schema 下发键集一致。
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

// columnString 表列 string 值；null 清零、非 string 报错。
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

// columnInt32 表列 int32 值；null 清零、非 number 报错。
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

// columnInt8Bool 表列 tinyint 开关（用 bool 承载）；null 清零、非 bool 报错。
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

// —— 用户管理族 ——

// adminStr 可空列读值（nil / 空串归一空串；admin 域 phone / email 明文，掩码仅 account 自助视图）。
func adminStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// AdminMe 当前管理员视图；isAdmin 恒 true（非管理员在 admin 拦截器即被拦下）。
func AdminMe(row *model.User, permissions []string) *adminv1.MeResponse {
	if row == nil {
		return &adminv1.MeResponse{}
	}
	return &adminv1.MeResponse{
		Id:          row.ID,
		Username:    row.Username,
		Nickname:    row.Nickname,
		AvatarUrl:   row.AvatarURL,
		IsAdmin:     true,
		Permissions: permissions,
	}
}

// AdminUser user 行 → AdminUser 视图（列表 / 详情嵌套共用，字段集为表列投影）。
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

// AdminCredentialSummary 凭证概览条目（secret 不透出）；含全部 kind（行存在的
// 凭证类型），两步验证开关由 user.mfa_required 承载。
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

// AdminThirdpartyBinding 绑定条目；union_id 恒零值（protojson 省略）：普通行不存
// unionid、Union 行的 unionid 即 open_id 已可见，该字段留给未来跨行归并视图。
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

// AdminUserDetail GetUser 详情组装：user 投影 + 凭证概览 + 绑定列表 + MFA 五因子明细。
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

// adminMfaFactorOrder 管理员详情五因子序（与 account GetMfa 明细同序：
// totp → otp_sms → otp_email → webauthn → recovery_code）。
var adminMfaFactorOrder = [...]string{"totp", "otp_sms", "otp_email", "webauthn", "recovery_code"}

// AdminUserMfa 用户详情的 MFA 绑定明细：五因子序同 adminMfaFactorOrder；
// bound 判定与 account handler mfaBound 同口径（凭证行 / phone / email
// 非空，target 掩码）。两步验证开关不在此重复投影（由 AdminUser.MfaRequired
// 承载），此处只出各因子绑定态。webauthn credentials 计数需独立表（不在本
// 实现依赖面），置零省略、待定。
func AdminUserMfa(user *model.User, creds []model.UserCredential) *accountv1.MfaResponse {
	rows := map[string]*model.UserCredential{}
	for i := range creds {
		rows[creds[i].Kind] = &creds[i] // webauthn 多行取首行（mfaBound 同款口径）
	}
	factors := make([]*accountv1.MfaFactor, 0, len(adminMfaFactorOrder))
	for _, name := range adminMfaFactorOrder {
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

// AdminEventItem event_log 行 → 事件条目；detail 为 msgpack → JSON 对象，解码失败
// 按 nil 处理（附加信息缺失不影响主字段，同 account.go decodeProfileExtra 口径）。
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

// AdminSsoClient sso_client 行 → SsoClient 消息（列表 / 详情两用）；client_secret
// 明文透出，仅 admin 会话可达，本文件不做二次脱敏也不落日志。redirect_uris /
// login_methods / oauth_providers 由 service 经 §12.3 编解码唯一出口解析后
// 传入；default_redirect_uri 直取行值（空串 = 未配置）；nil / 空切片按 proto3
// 空 repeated 省略。
func AdminSsoClient(row *model.SsoClient, uris, loginMethods, oauthProviders []string) *adminv1.SsoClient {
	if row == nil {
		return &adminv1.SsoClient{}
	}
	return &adminv1.SsoClient{
		Id:                 row.ID,
		ClientId:           row.ClientID,
		ClientSecret:       row.ClientSecret,
		Name:               row.Name,
		RedirectUris:       uris,
		LoginMethods:       loginMethods,
		OauthProviders:     oauthProviders,
		DefaultRedirectUri: row.DefaultRedirectURI,
		TemplateKey:        row.TemplateKey,
		TemplateVars:       row.TemplateVars,
		CreatedAt:          row.CreatedAt.Unix(),
		UpdatedAt:          row.UpdatedAt.Unix(),
	}
}

// AdminOidcClient oidc_client 行 → OidcClient 消息（列表 / 详情两用）；uris / scopes 由 service 解码后传入。
func AdminOidcClient(row *model.OidcClient, uris, scopes []string) *adminv1.OidcClient {
	if row == nil {
		return &adminv1.OidcClient{}
	}
	return &adminv1.OidcClient{
		Id:              row.ID,
		ClientId:        row.ClientID,
		ClientSecret:    row.ClientSecret,
		Name:            row.Name,
		RedirectUris:    uris,
		Scopes:          scopes,
		AccessTokenTtl:  int64(row.AccessTokenTTL),
		RefreshTokenTtl: int64(row.RefreshTokenTTL),
		TemplateKey:     row.TemplateKey,
		TemplateVars:    row.TemplateVars,
		CreatedAt:       row.CreatedAt.Unix(),
		UpdatedAt:       row.UpdatedAt.Unix(),
	}
}

// AdminSettings settings 快照 → SettingsResponse 全键投影；键名经 settings 常量逐键
// 对齐、零自造。类型断言失败按零值投影；线上 JSON 零值省略是标准 protojson 行为，
// 前端以 GET 结果 + 默认底稿合并后整体回写（服务端按 has 位做部分更新）。
func AdminSettings(snap map[string]any) *adminv1.SettingsResponse {
	toInt := func(k string) int64 { v, _ := snap[k].(int64); return v }
	toBool := func(k string) bool { v, _ := snap[k].(bool); return v }
	toStr := func(k string) string { v, _ := snap[k].(string); return v }
	return &adminv1.SettingsResponse{
		PwdMinLength:          toInt(settings.KeyPwdMinLength),
		PwdMaxLength:          toInt(settings.KeyPwdMaxLength),
		PwdRequireClasses:     toInt(settings.KeyPwdRequireClasses),
		PwdDisallowUsername:   toBool(settings.KeyPwdDisallowUsername),
		PwdDisallowCommon:     toBool(settings.KeyPwdDisallowCommon),
		AllowPasswordReset:    toBool(settings.KeyAllowPasswordReset),
		OtpResendInterval:     toInt(settings.KeyOtpResendInterval),
		OtpTtl:                toInt(settings.KeyOtpTtl),
		OtpMaxAttempts:        toInt(settings.KeyOtpMaxAttempts),
		OtpDailyLimitTarget:   toInt(settings.KeyOtpDailyLimitTarget),
		OtpDailyLimitIp:       toInt(settings.KeyOtpDailyLimitIP),
		LoginMethods:          toSlice(settings.KeyLoginMethods, snap),
		AllowRegistration:     toBool(settings.KeyAllowRegistration),
		AllowSignupPassword:   toBool(settings.KeyAllowSignupPassword),
		AllowSignupPhone:      toBool(settings.KeyAllowSignupPhone),
		AllowSignupEmail:      toBool(settings.KeyAllowSignupEmail),
		MfaEnabled:            toBool(settings.KeyMfaEnabled),
		MfaMethods:            toSlice(settings.KeyMfaMethods, snap),
		PwdFailCapture:        toInt(settings.KeyPwdFailCapture),
		PwdFailBan:            toInt(settings.KeyPwdFailBan),
		PwdBanTtl:             toInt(settings.KeyPwdBanTtl),
		SessionTtl:            toInt(settings.KeySessionTtl),
		CookieName:            toStr(settings.KeyCookieName),
		SsoDomains:            toSlice(settings.KeySsoDomains, snap),
		QueueWorkers:          toInt(settings.KeyQueueWorkers),
		QueueCapacity:         toInt(settings.KeyQueueCapacity),
		QueueBatch:            toInt(settings.KeyQueueBatch),
		QueueFlushMs:          toInt(settings.KeyQueueFlushMs),
		CaptchaProviderKey:    toStr(settings.KeyCaptchaProviderKey),
		SmsProviderKey:        toStr(settings.KeySmsProviderKey),
		EmailProviderKey:      toStr(settings.KeyEmailProviderKey),
		AvatarStorageProvider: toStr(settings.KeyAvatarStorageProvider),
		GatewayTokens:         toSlice(settings.KeyGatewayTokens, snap),
		EventlogRetentionDays: toInt(settings.KeyEventlogRetentionDays),
		StaticBase:            toStr(settings.KeyStaticBase),
		HttpsDeployment:       toStr(settings.KeyHttpsDeployment),
		SiteName:              toStr(settings.KeySiteName),
	}
}

// toSlice 快照 []string 键取值（断言失败即 nil，proto3 空 repeated 省略）。
func toSlice(k string, snap map[string]any) []string {
	v, _ := snap[k].([]string)
	return v
}

// decodePayloadJSON DecodeToken 载荷 → Struct 编码：EmitUnpopulated 使零值字段恒
// 可见（排障视图需要完整字段集）；int64 按 protojson 编码为十进制字符串。
var decodePayloadJSON = protojson.MarshalOptions{EmitUnpopulated: true}

// AdminDecodePayload 内部载荷 → Struct 原样透传（前端不解析）。载荷含敏感内容，
// 本函数只做转换、不落日志；编码失败（不可达）按错误上抛由调用方消毒为 internal。
func AdminDecodePayload(msg proto.Message) (*structpb.Struct, error) {
	b, err := decodePayloadJSON.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("admin dto: decode payload: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("admin dto: decode payload json: %w", err)
	}
	return structpb.NewStruct(m)
}
