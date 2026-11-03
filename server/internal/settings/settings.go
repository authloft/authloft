// Package settings 系统配置模块（后端架构 §3.12 行 463）：35 键白名单 /
// 默认值 / 值类型、启动全量预热、本地缓存快照、写入口径、al:settings:chg
// 热更新。键名与默认值的唯一真相 = 接口文档 §5.6 四张表（行 1275-1336），
// 本包逐键一致、不另起别名；白名单外的写入一律拒绝（§4.7 行 838）。
package settings

import (
	"encoding/json"
	"fmt"
)

// ValueType 值类型（§5.6 全部 35 键归入四类：string / int64 / bool / []string）。
type ValueType int

const (
	TypeString ValueType = iota
	TypeInt64
	TypeBool
	TypeStringSlice
)

// String 供错误信息与日志使用。
func (t ValueType) String() string {
	switch t {
	case TypeString:
		return "string"
	case TypeInt64:
		return "int64"
	case TypeBool:
		return "bool"
	case TypeStringSlice:
		return "[]string"
	default:
		return fmt.Sprintf("ValueType(%d)", int(t))
	}
}

// 键常量（§5.6 逐字一致）。消费方引用常量，禁止裸字符串防漂移；
// 密码策略五键与 security.PasswordRule 规则标识同名（§5.6 行 1275：
// 键名在前端 admin 设置页、后端三处完全同名）。
const (
	// 密码策略 5 键（§5.6 表一，行 1279-1283）
	KeyPwdMinLength        = "pwd_min_length"        // int64，默认 8
	KeyPwdMaxLength        = "pwd_max_length"        // int64，默认 64（只可调低）
	KeyPwdRequireClasses   = "pwd_require_classes"   // int64，默认 3（1-3）
	KeyPwdDisallowUsername = "pwd_disallow_username" // bool，默认 true
	KeyPwdDisallowCommon   = "pwd_disallow_common"   // bool，默认 true

	// 账号策略 1 键（§5.6 表二，行 1297）
	KeyAllowPasswordReset = "allow_password_reset" // bool，默认 true

	// 验证码限流 5 键（§5.6 表三，行 1303-1307）
	KeyOtpResendInterval   = "otp_resend_interval"    // int64，默认 60 秒
	KeyOtpTtl              = "otp_ttl"                // int64，默认 300 秒
	KeyOtpMaxAttempts      = "otp_max_attempts"       // int64，默认 5 次
	KeyOtpDailyLimitTarget = "otp_daily_limit_target" // int64，默认 10 次/日
	KeyOtpDailyLimitIP     = "otp_daily_limit_ip"     // int64，默认 50 次/日

	// 其余 24 键（§5.6 表四，行 1313-1336）
	KeyLoginMethods          = "login_methods"           // []string
	KeyAllowRegistration     = "allow_registration"      // bool，默认 true
	KeyAllowSignupPassword   = "allow_signup_password"   // bool，默认 true
	KeyAllowSignupPhone      = "allow_signup_phone"      // bool，默认 true
	KeyAllowSignupEmail      = "allow_signup_email"      // bool，默认 true
	KeyMfaEnabled            = "mfa_enabled"             // bool，默认 true
	KeyMfaMethods            = "mfa_methods"             // []string
	KeyPwdFailCapture        = "pwd_fail_capture"        // int64，默认 3 次
	KeyPwdFailBan            = "pwd_fail_ban"            // int64，默认 6 次
	KeyPwdBanTtl             = "pwd_ban_ttl"             // int64，默认 21600 秒
	KeySessionTtl            = "session_ttl"             // int64，默认 604800 秒
	KeyCookieName            = "cookie_name"             // string，默认 al_session
	KeySsoDomains            = "sso_domains"             // []string，默认 []
	KeyQueueWorkers          = "queue_workers"           // int64，默认 4
	KeyQueueCapacity         = "queue_capacity"          // int64，默认 8192
	KeyQueueBatch            = "queue_batch"             // int64，默认 200
	KeyQueueFlushMs          = "queue_flush_ms"          // int64，默认 2000 毫秒
	KeyCaptchaProviderKey    = "captcha_provider_key"    // string，默认 ""
	KeySmsProviderKey        = "sms_provider_key"        // string，默认 ""
	KeyEmailProviderKey      = "email_provider_key"      // string，默认 ""
	KeyAvatarStorageProvider = "avatar_storage_provider" // string，默认 ""
	KeyGatewayTokens         = "gateway_tokens"          // []string，默认 []
	KeyEventlogRetentionDays = "eventlog_retention_days" // int64，默认 180 天
	KeyStaticBase            = "static_base"             // string，默认 /assets
)

// Def 单键定义：值类型 + 默认值（Default 取 string / int64 / bool / []string
// 之一，与 Type 匹配）。
type Def struct {
	Key     string
	Type    ValueType
	Default any
}

// defs 35 键有序定义（§5.6 四张表之和：5 + 1 + 5 + 24）。顺序 = 表序。
var defs = []Def{
	// 密码策略（§5.6 表一）
	{KeyPwdMinLength, TypeInt64, int64(8)},
	{KeyPwdMaxLength, TypeInt64, int64(64)},
	{KeyPwdRequireClasses, TypeInt64, int64(3)},
	{KeyPwdDisallowUsername, TypeBool, true},
	{KeyPwdDisallowCommon, TypeBool, true},
	// 账号策略（§5.6 表二）
	{KeyAllowPasswordReset, TypeBool, true},
	// 验证码限流（§5.6 表三）
	{KeyOtpResendInterval, TypeInt64, int64(60)},
	{KeyOtpTtl, TypeInt64, int64(300)},
	{KeyOtpMaxAttempts, TypeInt64, int64(5)},
	{KeyOtpDailyLimitTarget, TypeInt64, int64(10)},
	{KeyOtpDailyLimitIP, TypeInt64, int64(50)},
	// 其余（§5.6 表四）
	{KeyLoginMethods, TypeStringSlice, []string{"password", "otp_sms", "otp_email", "webauthn", "thirdparty"}},
	{KeyAllowRegistration, TypeBool, true},
	{KeyAllowSignupPassword, TypeBool, true},
	{KeyAllowSignupPhone, TypeBool, true},
	{KeyAllowSignupEmail, TypeBool, true},
	{KeyMfaEnabled, TypeBool, true},
	{KeyMfaMethods, TypeStringSlice, []string{"totp", "otp_sms", "otp_email", "webauthn"}},
	{KeyPwdFailCapture, TypeInt64, int64(3)},
	{KeyPwdFailBan, TypeInt64, int64(6)},
	{KeyPwdBanTtl, TypeInt64, int64(21600)},
	{KeySessionTtl, TypeInt64, int64(604800)},
	{KeyCookieName, TypeString, "al_session"},
	{KeySsoDomains, TypeStringSlice, []string{}},
	{KeyQueueWorkers, TypeInt64, int64(4)},
	{KeyQueueCapacity, TypeInt64, int64(8192)},
	{KeyQueueBatch, TypeInt64, int64(200)},
	{KeyQueueFlushMs, TypeInt64, int64(2000)},
	{KeyCaptchaProviderKey, TypeString, ""},
	{KeySmsProviderKey, TypeString, ""},
	{KeyEmailProviderKey, TypeString, ""},
	{KeyAvatarStorageProvider, TypeString, ""},
	{KeyGatewayTokens, TypeStringSlice, []string{}},
	{KeyEventlogRetentionDays, TypeInt64, int64(180)},
	{KeyStaticBase, TypeString, "/assets"},
}

// byKey 键 → 定义索引（启动时建一次，只读）。
var byKey = func() map[string]Def {
	m := make(map[string]Def, len(defs))
	for _, d := range defs {
		m[d.Key] = d
	}
	return m
}()

// Defs 返回全部键定义的副本（admin GET /settings 响应、前端设置页遍历用）。
func Defs() []Def {
	out := make([]Def, len(defs))
	copy(out, defs)
	return out
}

// Lookup 查单键定义；第二返回值 false = 不在白名单。
func Lookup(key string) (Def, bool) {
	d, ok := byKey[key]
	return d, ok
}

// Defaults 返回全量默认快照（切片值深拷贝，调用方可安全持有）。
// setup 模式无 settings 表时即用本档（§5.6 行 1275 与 policy.go 同口径）。
func Defaults() map[string]any {
	m := make(map[string]any, len(defs))
	for _, d := range defs {
		m[d.Key] = cloneValue(d.Default)
	}
	return m
}

// Validate 写入校验（§4.7 行 837-838 / §5.6 行 1338）：键名 ∈ 白名单 +
// 值类型与注册类型一致；交叉约束（如 pwd_min_length ≤ pwd_max_length）
// 不做——由前端设置页与管理员自律保证。返回归一化后的值（int 统一收敛
// 为 int64）；错误前缀 "settings: "。
func Validate(key string, value any) (any, error) {
	d, ok := byKey[key]
	if !ok {
		return nil, fmt.Errorf("settings: unknown key %q", key)
	}
	switch d.Type {
	case TypeString:
		if v, ok := value.(string); ok {
			return v, nil
		}
	case TypeInt64:
		// int / int64 均接受（Go 字面量默认 int），统一归一为 int64。
		switch v := value.(type) {
		case int:
			return int64(v), nil
		case int64:
			return v, nil
		}
	case TypeBool:
		if v, ok := value.(bool); ok {
			return v, nil
		}
	case TypeStringSlice:
		if v, ok := value.([]string); ok {
			return append([]string(nil), v...), nil
		}
	}
	return nil, fmt.Errorf("settings: key %q expects %s, got %T", key, d.Type, value)
}

// EncodeValue 按 §4.7 行 830「JSON 编码值（标量也按 JSON 存）」编码：
// int64(8) → "8"、true → "true"、"al_session" → "\"al_session\""。
// 调用方须先经 Validate 归一化。
func EncodeValue(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("settings: encode: %w", err)
	}
	return string(b), nil
}

// DecodeValue 按键注册类型解码 JSON 存储值，返回具体类型
// （string / int64 / bool / []string）。JSON null 与类型不符（含
// 浮点残值、裸标量）均报错——预热 fail-fast，见 store.Preload。
func DecodeValue(key string, raw string) (any, error) {
	d, ok := byKey[key]
	if !ok {
		return nil, fmt.Errorf("settings: unknown key %q", key)
	}
	if raw == "null" {
		return nil, fmt.Errorf("settings: decode %s: null value", key)
	}
	switch d.Type {
	case TypeString:
		var v string
		if err := json.Unmarshal([]byte(raw), &v); err == nil {
			return v, nil
		}
	case TypeInt64:
		var v int64
		if err := json.Unmarshal([]byte(raw), &v); err == nil {
			return v, nil
		}
	case TypeBool:
		var v bool
		if err := json.Unmarshal([]byte(raw), &v); err == nil {
			return v, nil
		}
	case TypeStringSlice:
		var v []string
		if err := json.Unmarshal([]byte(raw), &v); err == nil {
			if v == nil {
				v = []string{}
			}
			return v, nil
		}
	}
	return nil, fmt.Errorf("settings: decode %s: value %q is not %s", key, raw, d.Type)
}

// cloneValue 深拷贝快照值（仅 []string 需要复制，标量不可变）。
func cloneValue(v any) any {
	if s, ok := v.([]string); ok {
		return append([]string(nil), s...)
	}
	return v
}
