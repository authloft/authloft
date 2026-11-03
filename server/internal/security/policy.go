package security

import (
	"fmt"
	"strings"
	"unicode"
)

// 密码强度策略（接口文档 §5.6 pwd_* 键语义；后端架构 §3.11：注册、
// 重置、改密三处唯一入口）。settings 模块落地前由调用方以参数结构传入，
// 本包不读任何存储。

// PasswordPolicy 可配策略参数，字段与 §5.6 键一一对应（越界值按默认处理）。
type PasswordPolicy struct {
	MinLength        int  // pwd_min_length 默认 8
	MaxLength        int  // pwd_max_length 默认 64；只可调低不可调高（>64 截为 64）
	RequireClasses   int  // pwd_require_classes 默认 3；1-3，字符类 = 大写/小写/数字，符号不计入
	DisallowUsername bool // pwd_disallow_username 默认 true；禁止包含用户名
	DisallowCommon   bool // pwd_disallow_common 默认 true；禁止命中弱口令字典
}

// DefaultPasswordPolicy §5.6 默认值（setup 模式无 settings，即用此档）。
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:        8,
		MaxLength:        64,
		RequireClasses:   3,
		DisallowUsername: true,
		DisallowCommon:   true,
	}
}

// PasswordRule 违规规则标识（调用方据此映射错误码）。
type PasswordRule string

// 规则标识：前五个对应 §5.6 pwd_* 可配键；后三个为固定规则
//（§5.6 固定不可配，写死在代码内，不进 settings）。
const (
	RuleMinLength        PasswordRule = "pwd_min_length"
	RuleMaxLength        PasswordRule = "pwd_max_length"
	RuleHardMaxLength    PasswordRule = "pwd_hard_max_length" // 长度 >64 一律拒绝（防 DoS）
	RuleRequireClasses   PasswordRule = "pwd_require_classes"
	RuleEqualsIdentity   PasswordRule = "pwd_equals_identity" // 与用户名或邮箱完全相同
	RuleDisallowUsername PasswordRule = "pwd_disallow_username"
	RuleWhitespace       PasswordRule = "pwd_whitespace" // 含空白字符
	RuleDisallowCommon   PasswordRule = "pwd_disallow_common"
)

// PasswordViolation 一条违规：Rule 供调用方映射错误码，Reason 为可拼接的
// 简短原因短语（风格沿用 setup 既有文案，调用方可直接拼进提示语）。
type PasswordViolation struct {
	Rule   PasswordRule
	Reason string
}

// ValidatePassword 按策略校验，返回全部命中的违规（nil = 通过）。
// 固定规则不受参数控制：>64、与用户名或邮箱完全相同、含空白，一律拒绝；
// username / email 为空串时跳过对应比较。检查顺序稳定（长度 → 字符类 →
// 身份 → 空白 → 字典），调用方取首条即得稳定文案。
func ValidatePassword(p PasswordPolicy, username, email, password string) []PasswordViolation {
	if p.MinLength <= 0 {
		p.MinLength = 8
	}
	if p.MaxLength <= 0 || p.MaxLength > 64 {
		p.MaxLength = 64
	}
	if p.RequireClasses < 1 || p.RequireClasses > 3 {
		p.RequireClasses = 3
	}

	var vs []PasswordViolation
	if len(password) < p.MinLength {
		vs = append(vs, PasswordViolation{RuleMinLength, fmt.Sprintf("minimum length is %d", p.MinLength)})
	}
	switch {
	case len(password) > 64:
		vs = append(vs, PasswordViolation{RuleHardMaxLength, "length exceeds the hard limit of 64"})
	case len(password) > p.MaxLength:
		vs = append(vs, PasswordViolation{RuleMaxLength, fmt.Sprintf("maximum length is %d", p.MaxLength)})
	}
	if passwordClasses(password) < p.RequireClasses {
		vs = append(vs, PasswordViolation{RuleRequireClasses, classReason(p.RequireClasses)})
	}
	switch {
	case username != "" && password == username:
		vs = append(vs, PasswordViolation{RuleEqualsIdentity, "must not equal the username"})
	case email != "" && password == email:
		vs = append(vs, PasswordViolation{RuleEqualsIdentity, "must not equal the email"})
	}
	if p.DisallowUsername && username != "" && strings.Contains(password, username) {
		vs = append(vs, PasswordViolation{RuleDisallowUsername, "must not contain the username"})
	}
	for _, r := range password {
		if unicode.IsSpace(r) {
			vs = append(vs, PasswordViolation{RuleWhitespace, "must not contain whitespace"})
			break
		}
	}
	if p.DisallowCommon {
		if _, hit := commonPasswords[password]; hit {
			vs = append(vs, PasswordViolation{RuleDisallowCommon, "too common"})
		}
	}
	return vs
}

// passwordClasses 已满足的字符类数（大写/小写/数字；符号不计入，§5.6）。
func passwordClasses(password string) int {
	var upper, lower, digit bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		}
	}
	n := 0
	for _, ok := range [...]bool{upper, lower, digit} {
		if ok {
			n++
		}
	}
	return n
}

// classReason 字符类不足的文案：默认三档沿用既有措辞，其余给通用描述。
func classReason(require int) string {
	if require >= 3 {
		return "must contain uppercase, lowercase and digit"
	}
	return fmt.Sprintf("must satisfy at least %d character classes (uppercase, lowercase, digit)", require)
}

// commonPasswords 内置弱口令字典（pwd_disallow_common 的数据源，精确
// 匹配）。首十二项为 setup 安装期过渡表原样并入，其余为常见弱口令扩充。
var commonPasswords = map[string]struct{}{
	// setup 过渡表（保留，勿删）
	"password1": {}, "password12": {}, "passwd123": {},
	"123456789": {}, "12345678a": {}, "qwerty123": {},
	"admin1234": {}, "admin12345": {}, "letmein123": {},
	"iloveyou123": {}, "welcome123": {}, "abc123456": {},
	// 常见弱口令扩充
	"123456": {}, "1234567": {}, "12345678": {}, "1234567890": {},
	"password": {}, "password123": {}, "password1234": {},
	"passw0rd": {}, "p@ssw0rd": {}, "qwerty": {}, "qwertyuiop": {},
	"abc123": {}, "admin123": {}, "admin123456": {}, "root123": {},
	"welcome1": {}, "letmein1": {}, "letmein1234": {}, "iloveyou1": {},
	"monkey123": {}, "dragon123": {}, "sunshine123": {}, "princess123": {},
	"football123": {}, "shadow123": {}, "master123": {}, "secret123": {},
	"superman123": {}, "batman123": {}, "trustno123": {}, "starwars123": {},
	"changeme123": {}, "qazwsx123": {}, "zaq12wsx": {}, "1q2w3e4r": {},
	"1qaz2wsx": {}, "whatever123": {}, "computer123": {},
	// 大写开头的常见变体（三类齐全，覆盖“只补数字/大小写”的绕法）
	"Admin12345": {}, "Qwerty123": {}, "Passw0rd123": {},
}
