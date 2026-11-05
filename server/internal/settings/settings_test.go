// settings 包纯逻辑测试（无 DB / Redis，本地可跑）：
//  1. 36 键白名单逐键对照接口文档 §5.6 四张表硬编码断言（键名 / 类型 /
//     默认值，缺一多一都算 FAIL）；
//  2. pwd_* 五键与 security.PasswordRule 规则标识同名（§5.6 行 1275）；
//  3. Validate 白名单 + 类型校验（含 int→int64 归一化、交叉约束不做、
//     https_deployment 三态值域）；
//  4. 编解码 roundtrip 与错误形态。
package settings

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"authloft/internal/security"
)

// spec06 §5.6 四张表硬编码副本（行 1279-1336）：键 / 类型 / 默认值。
// 与实现故意两份：实现若漂移（改名 / 改默认 / 增删键），此处必红。
var spec56 = []struct {
	key string
	typ ValueType
	def any
}{
	// 表一：密码策略（行 1279-1283）
	{"pwd_min_length", TypeInt64, int64(8)},
	{"pwd_max_length", TypeInt64, int64(64)},
	{"pwd_require_classes", TypeInt64, int64(3)},
	{"pwd_disallow_username", TypeBool, true},
	{"pwd_disallow_common", TypeBool, true},
	// 表二：账号策略（行 1297）
	{"allow_password_reset", TypeBool, true},
	// 表三：验证码限流（行 1303-1307）
	{"otp_resend_interval", TypeInt64, int64(60)},
	{"otp_ttl", TypeInt64, int64(300)},
	{"otp_max_attempts", TypeInt64, int64(5)},
	{"otp_daily_limit_target", TypeInt64, int64(10)},
	{"otp_daily_limit_ip", TypeInt64, int64(50)},
	// 表四：其余（行 1313-1336）
	{"login_methods", TypeStringSlice, []string{"password", "otp_sms", "otp_email", "webauthn", "thirdparty"}},
	{"allow_registration", TypeBool, true},
	{"allow_signup_password", TypeBool, true},
	{"allow_signup_phone", TypeBool, true},
	{"allow_signup_email", TypeBool, true},
	{"mfa_enabled", TypeBool, true},
	{"mfa_methods", TypeStringSlice, []string{"totp", "otp_sms", "otp_email", "webauthn"}},
	{"pwd_fail_capture", TypeInt64, int64(3)},
	{"pwd_fail_ban", TypeInt64, int64(6)},
	{"pwd_ban_ttl", TypeInt64, int64(21600)},
	{"session_ttl", TypeInt64, int64(604800)},
	{"cookie_name", TypeString, "al_session"},
	{"sso_domains", TypeStringSlice, []string{}},
	{"queue_workers", TypeInt64, int64(4)},
	{"queue_capacity", TypeInt64, int64(8192)},
	{"queue_batch", TypeInt64, int64(200)},
	{"queue_flush_ms", TypeInt64, int64(2000)},
	{"captcha_provider_key", TypeString, ""},
	{"sms_provider_key", TypeString, ""},
	{"email_provider_key", TypeString, ""},
	{"avatar_storage_provider", TypeString, ""},
	{"gateway_tokens", TypeStringSlice, []string{}},
	{"eventlog_retention_days", TypeInt64, int64(180)},
	{"static_base", TypeString, "/assets"},
	{"https_deployment", TypeString, "auto"},
}

// TestRegistryMatchesSpec：白名单 = §5.6 四张表之和，逐键断言键名 /
// 类型 / 默认值；总数 36（5+1+5+25）双向无多无缺、无重复。
func TestRegistryMatchesSpec(t *testing.T) {
	if len(spec56) != 36 {
		t.Fatalf("§5.6 硬编码副本应 36 键，实际 %d", len(spec56))
	}
	got := Defs()
	if len(got) != 36 {
		t.Errorf("白名单应 36 键，实际 %d", len(got))
	}
	seen := make(map[string]bool, len(got))
	for _, d := range got {
		if seen[d.Key] {
			t.Errorf("白名单重复键 %q", d.Key)
		}
		seen[d.Key] = true
	}
	for _, s := range spec56 {
		d, ok := Lookup(s.key)
		if !ok {
			t.Errorf("§5.6 键 %q 不在白名单（缺）", s.key)
			continue
		}
		if d.Type != s.typ {
			t.Errorf("键 %q 类型 = %v，§5.6 应 %v", s.key, d.Type, s.typ)
		}
		if !reflect.DeepEqual(d.Default, s.def) {
			t.Errorf("键 %q 默认值 = %#v，§5.6 应 %#v", s.key, d.Default, s.def)
		}
	}
	if len(seen) != len(spec56) {
		t.Errorf("白名单 %d 键 ≠ §5.6 %d 键（多出表外键）", len(seen), len(spec56))
	}
}

// TestPwdKeysMatchSecurityRules：pwd_* 五个可配键与 security/policy.go 的
// PasswordRule 规则标识逐字同名（§5.6 行 1275：三处完全同名）。
func TestPwdKeysMatchSecurityRules(t *testing.T) {
	pairs := []struct {
		rule security.PasswordRule
		key  string
	}{
		{security.RuleMinLength, KeyPwdMinLength},
		{security.RuleMaxLength, KeyPwdMaxLength},
		{security.RuleRequireClasses, KeyPwdRequireClasses},
		{security.RuleDisallowUsername, KeyPwdDisallowUsername},
		{security.RuleDisallowCommon, KeyPwdDisallowCommon},
	}
	for _, p := range pairs {
		if string(p.rule) != p.key {
			t.Errorf("security 规则 %q 与 settings 键 %q 不同名", p.rule, p.key)
		}
	}
}

// TestValidate：白名单外拒绝、类型不符拒绝、int/int64 归一化、
// 切片防御性拷贝、交叉约束不做（§5.6 行 1338：仅校验键名与值类型）。
func TestValidate(t *testing.T) {
	if _, err := Validate("no_such_key", "x"); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("白名单外键应拒绝，err = %v", err)
	} else if !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("白名单外键拒绝错误应包 ErrInvalidValue, err = %v", err)
	}
	bad := []struct {
		key string
		val any
	}{
		{KeyPwdMinLength, "8"}, // string 不是 int64
		{KeyPwdMinLength, 8.5}, // 浮点不接受
		{KeyPwdMinLength, nil},
		{KeyCookieName, 8},                   // int 不是 string
		{KeyMfaEnabled, "true"},              // string 不是 bool
		{KeyLoginMethods, []any{"password"}}, // []any 不是 []string
		{KeyLoginMethods, "password"},
		{KeyHttpsDeployment, "yes"},      // 三态值域外（§5.6 行 1354）
		{KeyHttpsDeployment, ""},        // 空串不在三态
		{KeyHttpsDeployment, "TRUE"},     // 大小写敏感，仅小写三态
		{KeyHttpsDeployment, 8},          // 非 string
	}
	for _, c := range bad {
		_, err := Validate(c.key, c.val)
		if err == nil {
			t.Errorf("Validate(%q, %T) 应拒绝", c.key, c.val)
			continue
		}
		// 全部拒绝路径（既有键类型不符 / https_deployment 值域外）
		// 均须包裹哨兵，供 service 层 errors.Is 判定转译 invalid_request。
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("Validate(%q, %T) 拒绝错误应包 ErrInvalidValue, got %v", c.key, c.val, err)
		}
	}
	if v, err := Validate(KeyPwdMinLength, 12); err != nil || v != int64(12) {
		t.Errorf("int 12 应归一为 int64(12)，得 %#v, err %v", v, err)
	}
	// https_deployment 三态值域：true / false / auto 通过（§5.6 行 1354）。
	for _, ok := range []string{HTTPSDeploymentTrue, HTTPSDeploymentFalse, HTTPSDeploymentAuto} {
		if v, err := Validate(KeyHttpsDeployment, ok); err != nil || v != ok {
			t.Errorf("Validate(https_deployment, %q) 应通过，得 %#v, err %v", ok, v, err)
		}
	}
	if v, err := Validate(KeyPwdMinLength, int64(12)); err != nil || v != int64(12) {
		t.Errorf("int64(12) 应原样通过，得 %#v, err %v", v, err)
	}
	in := []string{"password", "otp_sms"}
	v, err := Validate(KeyLoginMethods, in)
	if err != nil {
		t.Fatalf("[]string 应通过: %v", err)
	}
	in[0] = "mutated"
	if got := v.([]string); got[0] != "password" {
		t.Errorf("归一化值应是输入副本，输入被改后不应联动：%v", got)
	}
	// 交叉约束不做：pwd_max_length=100（> 硬上限 64）也放行，由前端/管理员自律
	if _, err := Validate(KeyPwdMaxLength, int64(100)); err != nil {
		t.Errorf("交叉约束不做，pwd_max_length=100 不应在 Validate 拒绝: %v", err)
	}
}

// TestValidateNormalizesEmptySlice（纯逻辑）：空 / nil 切片必须
// 归一为**非 nil 空切片**——append([]string(nil), v...) 会返回 nil，
// EncodeValue 落库 JSON "null"，DecodeValue 对 null fail-fast →
// watcher reload 持续失败 + 重启 Preload 起不来（SetSettings 全量替换下
// sso_domains/gateway_tokens 清空必现）。断言：归一值非 nil、EncodeValue
// 落 "[]"、DecodeValue 回读闭环。
func TestValidateNormalizesEmptySlice(t *testing.T) {
	for _, in := range [][]string{{}, nil} {
		v, err := Validate(KeySsoDomains, in)
		if err != nil {
			t.Fatalf("Validate(sso_domains, %#v) 不应报错: %v", in, err)
		}
		got, ok := v.([]string)
		if !ok {
			t.Fatalf("归一值应为 []string, got %T", v)
		}
		if got == nil {
			t.Fatalf("Validate(%#v) 归一值不得为 nil（落库变 JSON null → DecodeValue fail-fast）", in)
		}
		if len(got) != 0 {
			t.Errorf("归一值应为空切片, got %v", got)
		}
		raw, err := EncodeValue(v)
		if err != nil || raw != "[]" {
			t.Errorf("EncodeValue(%#v) = %q, err %v；want \"[]\"", v, raw, err)
		}
		back, err := DecodeValue(KeySsoDomains, raw)
		if err != nil {
			t.Errorf("DecodeValue(\"[]\") 不应报错: %v", err)
		}
		if b, ok := back.([]string); !ok || len(b) != 0 {
			t.Errorf("DecodeValue(\"[]\") 回读 = %#v", back)
		}
	}
	// 非空切片不回归：值原样、编码为数组。
	v, err := Validate(KeyGatewayTokens, []string{"tok"})
	if err != nil {
		t.Fatalf("Validate(gateway_tokens, [tok]): %v", err)
	}
	if raw, err := EncodeValue(v); err != nil || raw != `["tok"]` {
		t.Errorf("EncodeValue([tok]) = %q, err %v", raw, err)
	}
}

// TestEncodeValue：§4.7 行 830「标量也按 JSON 存」。
func TestEncodeValue(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{int64(8), "8"},
		{true, "true"},
		{false, "false"},
		{"al_session", `"al_session"`},
		{[]string{"a", "b"}, `["a","b"]`},
		{[]string{}, "[]"},
		{"", `""`},
	}
	for _, c := range cases {
		got, err := EncodeValue(c.in)
		if err != nil || got != c.want {
			t.Errorf("EncodeValue(%#v) = %q, err %v；want %q", c.in, got, err, c.want)
		}
	}
}

// TestDecodeValue：按注册类型解码 + 错误形态（null / 浮点 / 裸标量 /
// 类型错位 / 白名单外）。
func TestDecodeValue(t *testing.T) {
	if v, err := DecodeValue("pwd_min_length", "8"); err != nil || v != int64(8) {
		t.Errorf("decode int64: %v, %v", v, err)
	}
	if v, err := DecodeValue("pwd_disallow_username", "true"); err != nil || v != true {
		t.Errorf("decode bool: %v, %v", v, err)
	}
	if v, err := DecodeValue("cookie_name", `"al_session"`); err != nil || v != "al_session" {
		t.Errorf("decode string: %v, %v", v, err)
	}
	if v, err := DecodeValue("login_methods", `["password","otp_sms"]`); err != nil ||
		!reflect.DeepEqual(v, []string{"password", "otp_sms"}) {
		t.Errorf("decode []string: %#v, %v", v, err)
	}
	if v, err := DecodeValue("sso_domains", "[]"); err != nil || v.([]string) == nil {
		t.Errorf("decode 空 []string 应得非 nil 空切片: %#v, %v", v, err)
	}
	bad := []struct{ key, raw string }{
		{"pwd_min_length", "null"},    // JSON null
		{"pwd_min_length", "8.5"},     // 小数进 int64
		{"pwd_min_length", `"8"`},     // 字符串进 int64
		{"cookie_name", "al_session"}, // 裸标量（非 JSON）
		{"cookie_name", "null"},
		{"mfa_enabled", "1"},            // 数字进 bool
		{"login_methods", `["a",1]`},    // 混型数组
		{"login_methods", `"password"`}, // 标量进 []string
		{"no_such_key", "8"},            // 白名单外
	}
	for _, c := range bad {
		if _, err := DecodeValue(c.key, c.raw); err == nil {
			t.Errorf("DecodeValue(%q, %q) 应报错", c.key, c.raw)
		}
	}
}

// TestDefaultsSnapshotCopies：Defaults / Snapshot / GetStringSlice 的切片
// 值互不共享，调用方修改不污染注册表默认值。
func TestDefaultsSnapshotCopies(t *testing.T) {
	d1 := Defaults()
	d1[KeyLoginMethods].([]string)[0] = "mutated"
	d2 := Defaults()
	if got := d2[KeyLoginMethods].([]string); got[0] != "password" {
		t.Errorf("Defaults() 应每次深拷贝：got %v", got)
	}
}
