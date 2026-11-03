// Package security 令牌加密、密码哈希与策略校验的公共基础件
// （docs/后端架构.md §3.11）。叶子包：密钥与策略参数一律由调用方注入，
// 不 import config、不读任何存储。
package security

// AAD purpose 常量（后端架构 §11.6.1，取值封闭为本文件七个常量）。
// purpose 是存储加密的 AAD 前缀，与载荷内的 challenge.purpose
//（login/register/reset/mfa 业务枚举）是两套概念、互不约束。
// 跨 purpose 解令牌由 token.go 的 AAD 构造天然拒绝（token_test.go 验证）。
const (
	// PurposeSession session_token。
	PurposeSession = "session"
	// PurposeLogin 登录过程态 login_token（接口文档 §1.8）。
	PurposeLogin = "login"
	// PurposeTicket ticket 与 al:ticket 存储值加密（§11.6.5）。
	PurposeTicket = "ticket"
	// PurposeBind 账号域绑定一次性 token（接口文档 §3.4）。
	PurposeBind = "bind"
	// PurposeWebAuthn 通行密钥注册一次性 token（接口文档 §3.6）。
	PurposeWebAuthn = "webauthn"
	// PurposeCookie al_login_state（接口文档 §2.7.2）。
	PurposeCookie = "cookie"
	// PurposeSyncPayload 多域名同步载荷（§11.2）。
	PurposeSyncPayload = "sync_payload"
)

// purposes 封闭集合：Seal/Open 均拒绝表外值，防调用方自造 purpose
// 绕过隔离。新增取值需先改文档（§11.6.1）再改此表。
var purposes = map[string]bool{
	PurposeSession:     true,
	PurposeLogin:       true,
	PurposeTicket:      true,
	PurposeBind:        true,
	PurposeWebAuthn:    true,
	PurposeCookie:      true,
	PurposeSyncPayload: true,
}

// validPurpose purpose 是否属于 §11.6.1 封闭集合。
func validPurpose(purpose string) bool { return purposes[purpose] }
