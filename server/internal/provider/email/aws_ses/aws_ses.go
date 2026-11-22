// aws_ses 邮件 Sender 薄封装（docs/后端架构.md §15.5 薄封装总则）：一期走
// SES SMTP 接口，整条发送链路复用 email/smtp 基座导出构造器 New（AUTH PLAIN
// + STARTTLS / 隐式 TLS / socks5 代理口径与基座完全一致），本包不重写发送
// 逻辑，只做 Schema 收窄与凭证语义声明。API v2 方案（SigV4，需 region /
// session_token / role_arn）仅记录为二期，字段编号不预留。
//
// 与通用 smtp 行的差异（其余取值口径同基座）：
//   - host = SES 区域 SMTP 端点，形态 email-smtp.{region}.amazonaws.com。
//     随部署地域变化，由管理员填写——不固化不派生（无 region 字段）
//   - user / password = SES 控制台 "Create SMTP Credentials" 单独生成的
//     SMTP 凭证，非 IAM AccessKey（直接填 IAM AccessKey 会认证失败）
//   - from 必填 = 已验证的发件地址：SES SMTP 凭证用户名不是邮箱地址，
//     基座 from 留空回落认证 user 的语义对 SES 不成立，schema 侧拦缺项
//   - port / disable_ssl 为固化项：不进 Schema、不在表单透出（未声明字段
//     提交即 invalid_request，接口文档 §5.3），构造期由基座默认承载
//     （port 0 → 587 STARTTLS、disable_ssl false 正常协商）
package awsses

import (
	"authloft/internal/provider"
	"authloft/internal/provider/email/smtp"
	"authloft/internal/provider/schemafield"
)

// Type 渠道类型（§15.5 内置清单：aws_ses）。
const Type = "aws_ses"

func init() {
	provider.RegisterSender(Type, provider.SenderMeta{
		Type:        Type,
		DisplayName: "Amazon SES",
		Category:    provider.CategoryEmail,
		// Schema 是 /schema 的唯一数据源（表列 + Ext，接口文档 §5.3）。Label
		// 复用既有 smtp 键（语义一致）。SES 专属 help（端点形态 email-smtp.
		// {region}.amazonaws.com、凭证=SES SMTP 凭证非 IAM AccessKey）需专用
		// i18n 键，而字段文案门禁要求键与 zh/en 文案同批落地（跨端契约见
		// internal/pages/field_i18n_test.go）——web 侧不在本卡范围，help 键
		// 待 web 卡补文案后随行声明。
		Schema: schema,
	}, newSender)
}

// schema /schema 唯一数据源：完整字段声明（表列 + Ext），按方案 A 字段表
// 收窄：port / disable_ssl 固化项不声明，from 必填，其余同 smtp 行。
func schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 13)
	fields = append(fields, schemafield.ProviderKey(), schemafield.DisplayName())
	fields = append(fields,
		provider.FieldMeta{Key: "host", Label: "admin.schemaField.smtpHostLabel", Type: "text", Section: "endpoint", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "user", Label: "admin.schemaField.smtpUserLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "password", Label: "admin.schemaField.smtpPasswordLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "sign_name", Label: "admin.schemaField.smtpSignNameLabel", Type: "text", Section: "credential", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "from", Label: "admin.schemaField.smtpFromLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "metadata", Label: "admin.schemaField.metadataLabel", Type: "json", Section: "credential", Advanced: true,
			Help: "admin.schemaField.smtpMetadataHelp", Storage: provider.StorageExt},
	)
	fields = append(fields, schemafield.IconURL(), schemafield.SortOrder(), schemafield.Remark())
	// is_enabled / 登录建号开关是 auth 专属：email 行不声明也不消费
	// （渠道生效实例判定只看 settings 键 → 行命中，provider/sender.go）。
	fields = append(fields, schemafield.ProxyRef())
	return fields
}

// newSender 注册表工厂：构造与发送整体委托 smtp 基座，fail-closed 与取值
// 口径完全一致（凭证装配期取自 Provider 实例，运行期不回读）。
func newSender(p *provider.Provider) (provider.Sender, error) {
	return smtp.New(p)
}
