// Package factor 认证因子统一接口与注册表（docs/后端架构.md §6、§3.8 行 381-387）。
// 因子只增不改：新增认证方式 = internal/factor/<name>/ 一个包 + 一行注册（§1.3）。
// 本包不依赖 HTTP / Gin，也不实现任何具体因子。
package factor

// FactorKind 认证因子（凭证类型）枚举，取值与后端架构 §6.1 行 903-914 逐条一致。
type FactorKind string

const (
	FactorPassword   FactorKind = "password"
	FactorOTPSMS     FactorKind = "otp_sms"
	FactorOTPEmail   FactorKind = "otp_email"
	FactorWebAuthn   FactorKind = "webauthn"
	FactorTOTP       FactorKind = "totp"
	FactorRecovery   FactorKind = "recovery_code"
	FactorThirdParty FactorKind = "thirdparty"
	FactorDevice     FactorKind = "device" // 已登录设备，内部实现，不对外暴露
)

// allKinds 全部合法 FactorKind（启动期完整性断言用）。
var allKinds = []FactorKind{
	FactorPassword,
	FactorOTPSMS,
	FactorOTPEmail,
	FactorWebAuthn,
	FactorTOTP,
	FactorRecovery,
	FactorThirdParty,
	FactorDevice,
}

// validKind 是否为已知 FactorKind。
func validKind(kind FactorKind) bool {
	for _, k := range allKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Usage 因子用途（主因子 / 二次因子），取值与后端架构 §6.1 行 916-921 一致。
type Usage string

const (
	UsagePrimary   Usage = "primary"
	UsageSecondary Usage = "secondary"
)

// StepKind 步骤形态（前端怎么渲染这一步），取值与接口文档 §1.4 行 167-176
// 的 kind 枚举逐条一致。
type StepKind string

const (
	StepForm      StepKind = "form"      // 渲染输入框并提交
	StepChallenge StepKind = "challenge" // 无输入，向后端要挑战数据
	StepRedirect  StepKind = "redirect"  // 浏览器跳转（第三方）
	StepExternal  StepKind = "external"  // 调宿主能力取 code（wx.login）
	StepQRCode    StepKind = "qrcode"    // 展示码图
	StepPoll      StepKind = "poll"      // 长轮询等待
)

// Factor 认证因子统一接口（后端架构 §6.3 行 945-955）。
// 所有因子（含单步 password）实现同一接口，编排层只有一份状态机。
type Factor interface {
	Kind() FactorKind
	Usages() []Usage
	Steps() []StepKind

	// Start 处理 challenge 步：下发验证码 / 生成 WebAuthn options / 产出跳转 URL。
	Start(ctx *FactorContext) (*StepResult, error)
	// Verify 校验提交结果，返回通过 / 失败 / 需要重试。
	Verify(ctx *FactorContext) (*VerifyResult, error)
}
