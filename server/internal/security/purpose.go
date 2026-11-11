// Package security 令牌加密、密码哈希与策略校验的公共基础件
// （docs/后端架构.md §3.11）。叶子包：密钥与策略参数一律由调用方注入，
// 不 import config、不读任何存储。
package security

// AAD purpose 常量（后端架构 §11.6.1，取值封闭为本文件八个常量）。
// purpose 是存储加密的 AAD 前缀，只标记「哪个场景 / 哪把密钥」、不进载荷；
// 载荷内业务用途字段统一叫 biz_purpose（挑战 / 验证令牌取值见 §11.6.7，
// 登录过程态内取 login/register/reset/mfa），两套命名空间各自封闭、互不约束。
// 跨 purpose 解令牌由 token.go 的 AAD 构造天然拒绝（token_test.go 验证）。
const (
	// PurposeSession session_token。
	PurposeSession = "session"
	// PurposeLogin 登录过程态 login_token（接口文档 §1.8）。
	PurposeLogin = "login"
	// PurposeTicket ticket 与 al:ticket 存储值加密（§11.6.5）。
	PurposeTicket = "ticket"
	// PurposeVerification 二次验证通过后的断言令牌（VerificationTokenPayload，§11.6.7）。
	PurposeVerification = "verification"
	// PurposeChallenge 挑战令牌（webauthn_enroll 与 step-up 统一，§11.6.7、接口文档 §3.6）。
	PurposeChallenge = "challenge"
	// PurposeCookie al_login_state（接口文档 §2.7.2）。
	PurposeCookie = "cookie"
	// PurposeSyncPayload 多域名同步载荷（§11.2）。
	PurposeSyncPayload = "sync_payload"
	// PurposeOidcCode OIDC 授权码值（§11.6.6，接口文档 §4.2）。
	PurposeOidcCode = "oidc_code"
)

// purposes 封闭集合：Seal/Open 均拒绝表外值，防调用方自造 purpose
// 绕过隔离。新增取值需先改文档（§11.6.1）再改此表。
var purposes = map[string]bool{
	PurposeSession:      true,
	PurposeLogin:        true,
	PurposeTicket:       true,
	PurposeVerification: true,
	PurposeChallenge:    true,
	PurposeCookie:       true,
	PurposeSyncPayload:  true,
	PurposeOidcCode:     true,
}

// validPurpose purpose 是否属于 §11.6.1 封闭集合。
func validPurpose(purpose string) bool { return purposes[purpose] }
