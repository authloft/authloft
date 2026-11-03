package security

import (
	"strings"
	"testing"
)

// TestValidatePasswordDefaultPolicyValid 默认策略（§5.6 默认值）下合法
//（与 setup 弱口介试例同源，不得误杀）。
func TestValidatePasswordDefaultPolicyValid(t *testing.T) {
	for _, p := range []string{"Str0ngPassw0rd", "Abcdef12", "xY9zzzzzzz"} {
		if vs := ValidatePassword(DefaultPasswordPolicy(), "someone", "", p); len(vs) != 0 {
			t.Errorf("password %q should be valid, got %v", p, vs)
		}
	}
}

// TestValidatePasswordRules 逐条规则分支（默认策略，首条违规规则断言）。
func TestValidatePasswordRules(t *testing.T) {
	policy := DefaultPasswordPolicy()
	cases := []struct {
		name     string
		username string
		email    string
		password string
		want     PasswordRule
	}{
		{"too short", "someone", "", "Sh0rt!", RuleMinLength},
		{"65 chars hard limit", "someone", "", "A" + strings.Repeat("b", 31) + "0" + strings.Repeat("c", 31) + "1", RuleHardMaxLength},
		{"missing digit", "someone", "", "aaaaaaaa", RuleRequireClasses},
		{"missing lowercase", "someone", "", "AAAAAAAA", RuleRequireClasses},
		{"missing letters", "someone", "", "12345678", RuleRequireClasses},
		{"equals username", "Someone123", "", "Someone123", RuleEqualsIdentity},
		{"equals email", "someone", "User1@Example.com", "User1@Example.com", RuleEqualsIdentity},
		{"contains username", "someone", "", "someone01A", RuleDisallowUsername},
		{"whitespace space", "someone", "", "admin0 1A", RuleWhitespace},
		{"whitespace tab", "someone", "", "adm\tin01A", RuleWhitespace},
		{"whitespace unicode", "someone", "", "admin01A\u00a0", RuleWhitespace},
		{"common full class", "someone", "", "Admin12345", RuleDisallowCommon},
	}
	for _, tc := range cases {
		vs := ValidatePassword(policy, tc.username, tc.email, tc.password)
		if len(vs) == 0 {
			t.Errorf("%s: expected violation, got none", tc.name)
			continue
		}
		if vs[0].Rule != tc.want {
			t.Errorf("%s: first rule = %s, want %s (all: %v)", tc.name, vs[0].Rule, tc.want, vs)
		}
	}
}

// TestValidatePassword64Boundary 64 长度边界：恰好 64 合法（三类齐全）、
// 65 一律拒绝（固定硬上限，无视 MaxLength 配置调高）。
func TestValidatePassword64Boundary(t *testing.T) {
	policy := DefaultPasswordPolicy()
	ok64 := "A" + strings.Repeat("b", 30) + "0" + strings.Repeat("c", 31) + "1"
	if len(ok64) != 64 {
		t.Fatalf("fixture length = %d, want 64", len(ok64))
	}
	if vs := ValidatePassword(policy, "someone", "", ok64); len(vs) != 0 {
		t.Errorf("64-char mixed password should be valid, got %v", vs)
	}
	bad65 := "A" + strings.Repeat("b", 31) + "0" + strings.Repeat("c", 31) + "1"
	if len(bad65) != 65 {
		t.Fatalf("fixture length = %d, want 65", len(bad65))
	}
	for _, p := range []PasswordPolicy{policy, {MinLength: 8, MaxLength: 99, RequireClasses: 3}} {
		vs := ValidatePassword(p, "someone", "", bad65)
		if len(vs) == 0 || vs[0].Rule != RuleHardMaxLength {
			t.Fatalf("65-char password must hit hard limit, got %v", vs)
		}
	}
}

// TestValidatePasswordMultipleViolations 组合违规全部报出且顺序稳定
//（password1：缺字符类 + 字典命中）。
func TestValidatePasswordMultipleViolations(t *testing.T) {
	vs := ValidatePassword(DefaultPasswordPolicy(), "someone", "", "password1")
	if len(vs) != 2 {
		t.Fatalf("expect 2 violations, got %v", vs)
	}
	if vs[0].Rule != RuleRequireClasses || vs[1].Rule != RuleDisallowCommon {
		t.Fatalf("order = [%s, %s], want [pwd_require_classes, pwd_disallow_common]", vs[0].Rule, vs[1].Rule)
	}
}

// TestValidatePasswordReasonStyle 文案风格沿用 setup 既有短语
//（调用方拼接 "admin password does not meet the policy: " 后语义不变）。
func TestValidatePasswordReasonStyle(t *testing.T) {
	cases := []struct{ username, password, want string }{
		{"someone", "Sh0rt!", "minimum length is 8"},
		{"someone", strings.Repeat("A", 64) + "a0", "length exceeds the hard limit of 64"},
		{"someone", "aaaaaaaa", "must contain uppercase, lowercase and digit"},
		{"Someone123", "Someone123", "must not equal the username"},
		{"someone", "someone01A", "must not contain the username"},
		{"someone", "admin0 1A", "must not contain whitespace"},
	}
	for _, tc := range cases {
		vs := ValidatePassword(DefaultPasswordPolicy(), tc.username, "", tc.password)
		if len(vs) == 0 {
			t.Errorf("password %q: no violation", tc.password)
			continue
		}
		if vs[0].Reason != tc.want {
			t.Errorf("password %q: reason = %q, want %q", tc.password, vs[0].Reason, tc.want)
		}
	}
}

// TestValidatePasswordCustomPolicy 可配参数生效（§5.6 pwd_* 键语义）。
func TestValidatePasswordCustomPolicy(t *testing.T) {
	// MinLength 12：8 位混合密码过默认、过不了自定义。
	base := DefaultPasswordPolicy()
	base.MinLength = 12
	if vs := ValidatePassword(base, "someone", "", "Abcdef12"); len(vs) == 0 || vs[0].Rule != RuleMinLength {
		t.Fatalf("min length 12 must reject 8-char, got %v", vs)
	}
	// RequireClasses 2：小写 + 数字即可过。
	base = DefaultPasswordPolicy()
	base.RequireClasses = 2
	if vs := ValidatePassword(base, "someone", "", "abcdefg1"); len(vs) != 0 {
		t.Fatalf("2 classes (lowercase+digit) should pass, got %v", vs)
	}
	// RequireClasses 越界按默认 3。
	base = DefaultPasswordPolicy()
	base.RequireClasses = 0
	if vs := ValidatePassword(base, "someone", "", "abcdefg1"); len(vs) == 0 || vs[0].Rule != RuleRequireClasses {
		t.Fatalf("require classes 0 must normalize to 3, got %v", vs)
	}
	// DisallowUsername false：包含用户名不再违规。
	base = DefaultPasswordPolicy()
	base.DisallowUsername = false
	if vs := ValidatePassword(base, "someone", "", "someone01A"); len(vs) != 0 {
		t.Fatalf("disallow_username=false should allow containing username, got %v", vs)
	}
	// 固定规则不受开关影响：与用户名完全相同仍拒绝。
	if vs := ValidatePassword(base, "Someone1", "", "Someone1"); len(vs) == 0 || vs[0].Rule != RuleEqualsIdentity {
		t.Fatalf("equals-username fixed rule must apply, got %v", vs)
	}
	// DisallowCommon false：字典口令按其余规则判定。
	base = DefaultPasswordPolicy()
	base.DisallowCommon = false
	if vs := ValidatePassword(base, "someone", "", "Admin12345"); len(vs) != 0 {
		t.Fatalf("disallow_common=false should allow dictionary password, got %v", vs)
	}
	// MaxLength 只可调低：17 字符被 MaxLength=16 拒。
	base = DefaultPasswordPolicy()
	base.MaxLength = 16
	long17 := "Abcdef0" + strings.Repeat("x", 8) + "1Y"
	if len(long17) != 17 {
		t.Fatalf("fixture length = %d, want 17", len(long17))
	}
	if vs := ValidatePassword(base, "someone", "", long17); len(vs) == 0 || vs[0].Rule != RuleMaxLength {
		t.Fatalf("max length 16 must reject 17-char, got %v", vs)
	}
}

// TestValidatePasswordEmptyIdentity 空 username/email 跳过比较，不误伤、
// 空密码不 panic（长度违规兜底）。
func TestValidatePasswordEmptyIdentity(t *testing.T) {
	if vs := ValidatePassword(DefaultPasswordPolicy(), "", "", "Abcdef12"); len(vs) != 0 {
		t.Fatalf("empty identity should not trigger rules, got %v", vs)
	}
	if vs := ValidatePassword(DefaultPasswordPolicy(), "", "", ""); len(vs) == 0 {
		t.Fatal("empty password must violate min length")
	}
}

// TestCommonPasswordsDictionary 字典 spot check：setup 过渡表全在、
// 合法测试密码不在。
func TestCommonPasswordsDictionary(t *testing.T) {
	for _, p := range []string{
		"password1", "password12", "passwd123", "123456789", "12345678a",
		"qwerty123", "admin1234", "admin12345", "letmein123", "iloveyou123",
		"welcome123", "abc123456", "123456", "password", "Admin12345",
	} {
		if _, hit := commonPasswords[p]; !hit {
			t.Errorf("dictionary must contain %q", p)
		}
	}
	for _, p := range []string{"Str0ngPassw0rd", "Abcdef12", "xY9zzzzzzz", "SecondStr0ng9"} {
		if _, hit := commonPasswords[p]; hit {
			t.Errorf("valid fixture %q must not be in dictionary", p)
		}
	}
}
