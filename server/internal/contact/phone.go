// Package contact 联系方式格式校验的单一真相源（接口文档 §1.11）。
// 位于 infra 层，factor / service / admin 各层均可引用，不产生反向依赖。
package contact

import "regexp"

// PhoneE164Pattern 手机号 E.164 格式：+ 开头、国家码首位非 0、总长不超过 15 位数字。
// 裸号一律拒绝（系统未上线，无存量兼容需要）。
var PhoneE164Pattern = regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

// IsValidPhoneE164 是否合法 E.164 手机号。
func IsValidPhoneE164(v string) bool {
	return PhoneE164Pattern.MatchString(v)
}
