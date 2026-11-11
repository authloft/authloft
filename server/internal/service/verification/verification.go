// Package verification 验证内核（docs/后端架构.md §3.7、§6.1、§6.3、
// §11.6.7）：biz_purpose 策略、主体标识与断言令牌。策略判定唯一入口，
// 登录编排只保留调用边界，不在 handler / 因子 / 编排内另写 biz_purpose 分支。
package verification

// BizPurpose 载荷内业务用途，封闭集合（§11.6.7；接口文档 §1.10.2）。
// 与 AAD purpose（security.PurposeChallenge / PurposeVerification）是两套
// 命名空间：AAD purpose 只标记场景与密钥、不进载荷；解出令牌后两者分别
// 断言，互不要求相等。
type BizPurpose string

const (
	BizPurposeLogin            BizPurpose = "login"
	BizPurposeMFA              BizPurpose = "mfa"
	BizPurposeBindContact      BizPurpose = "bind_contact"
	BizPurposeChangePassword   BizPurpose = "change_password"
	BizPurposeUnbindTOTP       BizPurpose = "unbind_totp"
	BizPurposeUnbindThirdParty BizPurpose = "unbind_thirdparty"
	BizPurposeAdminSensitive   BizPurpose = "admin_sensitive"
	BizPurposeWebAuthnEnroll   BizPurpose = "webauthn_enroll"
)

// bizPurposes 封闭集合（§11.6.7）：解出令牌后先断言，防表外用途进入策略判定。
var bizPurposes = map[BizPurpose]bool{
	BizPurposeLogin:            true,
	BizPurposeMFA:              true,
	BizPurposeBindContact:      true,
	BizPurposeChangePassword:   true,
	BizPurposeUnbindTOTP:       true,
	BizPurposeUnbindThirdParty: true,
	BizPurposeAdminSensitive:   true,
	BizPurposeWebAuthnEnroll:   true,
}

// Valid 是否属于 §11.6.7 封闭集合。
func (p BizPurpose) Valid() bool { return bizPurposes[p] }

// SubjectKind 主体类型（§11.6.7）：tid = 登录过程态 id，uid = 会话用户 id。
type SubjectKind string

const (
	SubjectKindTID SubjectKind = "tid"
	SubjectKindUID SubjectKind = "uid"
)

// Valid 是否属于 §11.6.7 封闭集合。
func (k SubjectKind) Valid() bool {
	return k == SubjectKindTID || k == SubjectKindUID
}

// Subject 主体标识：Kind 与 ID 搭配，与 challengeId 共同构成 al:code owner
// 三元组 biz_purpose:subject:challengeId（§10.1）。
type Subject struct {
	Kind SubjectKind
	ID   string
}

// Valid 主体是否完整（类型封闭、ID 非空）。
func (s Subject) Valid() bool { return s.Kind.Valid() && s.ID != "" }

// Owner 构造 al:code 的归属标识三元组（§10.1）：
// biz_purpose:subject:challengeId。跨场景串码由三元组逐项比对阻断。
func Owner(bp BizPurpose, subject, challengeID string) string {
	return string(bp) + ":" + subject + ":" + challengeID
}

// stepUpFactors 接口文档 §1.10.2 的允许因子集合（上限）：除 webauthn_enroll
// 外各 biz_purpose 一致。表为「上限」，运行期还须与主体已绑定 / 已启用因子
// 取交集（§1.10.2 约束 1、§6.3）。
var stepUpFactors = []string{"otp_sms", "otp_email", "webauthn", "totp", "recovery_code"}

var enrollFactors = []string{"webauthn"}

// Policy 验证策略：biz_purpose → 允许因子集合 / 高风险判定的唯一判定点
// （§3.7、§6.1）。纯表驱动，不读存储、不读配置、不感知登录信封。
type Policy struct{}

// DefaultPolicy 内置静态策略表（§1.10.2）；装配方可注入自定义实现替换。
func DefaultPolicy() *Policy { return &Policy{} }

// Factors 返回该 biz_purpose 允许的因子集合（副本，调用方改写不污染表）。
// 未知 / 表外 biz_purpose 返回 nil，fail-closed（§1.10.2 约束 3）。
func (p *Policy) Factors(bp BizPurpose) []string {
	switch bp {
	case BizPurposeWebAuthnEnroll:
		return append([]string(nil), enrollFactors...)
	case BizPurposeLogin, BizPurposeMFA, BizPurposeBindContact,
		BizPurposeChangePassword, BizPurposeUnbindTOTP,
		BizPurposeUnbindThirdParty, BizPurposeAdminSensitive:
		return append([]string(nil), stepUpFactors...)
	default:
		return nil
	}
}

// Allows 判定某因子在该 biz_purpose 下是否被放行（§6.3 放行判定唯一入口）。
// 只判定策略表上限；与主体已绑定因子的交集由消费方按 §1.10.2 约束 1 取。
func (p *Policy) Allows(bp BizPurpose, method string) bool {
	for _, m := range p.Factors(bp) {
		if m == method {
			return true
		}
	}
	return false
}

// HighRisk 高风险 biz_purpose（§11.6.7）：断言消费时须做 1 次
// SET NX al:once:{nonce} 去重；低风险仅按 nonce + exp 放行、不读 Redis。
// 本包只提供判定，去重落点由消费方按文档口径实现。
func (p *Policy) HighRisk(bp BizPurpose) bool {
	return bp == BizPurposeChangePassword || bp == BizPurposeAdminSensitive
}
