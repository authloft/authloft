package contact

import "testing"

// TestIsValidPhoneE164 手机号 E.164 口径（§1.11）单一真相源：裸号与非法
// 形态一律拒绝，合法国际号码放行。account / admin / factor / orchestrator
// 共用本函数，用例覆盖各入口关心的边界。
func TestIsValidPhoneE164(t *testing.T) {
	valid := []string{
		"+8613800138000",
		"+85291234567",
		"+12025550100",
		"+85512345678",     // 未列入前端区号表，但仍是合法 E.164
		"+123456789012345", // 1 位国家码 + 14 位本地号 = 15 位数字上限
	}
	for _, v := range valid {
		if !IsValidPhoneE164(v) {
			t.Errorf("IsValidPhoneE164(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"13800138000",       // 裸号
		"+",                 // 仅 + 无数字
		"+0123456789",       // 首位 0（非合法国家码）
		"+1234567890123456", // 超过 15 位数字
		" +8613800138000 ",  // 带空白（调用方须先 TrimSpace）
		"+86-13800138000",   // 含分隔符
		"",
	}
	for _, v := range invalid {
		if IsValidPhoneE164(v) {
			t.Errorf("IsValidPhoneE164(%q) = true, want false", v)
		}
	}
}
