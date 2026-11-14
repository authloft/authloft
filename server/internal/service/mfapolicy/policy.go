// policy.go 两步验证运行期判定唯一入口（docs/后端架构.md §3.7、
// docs/接口文档.md §3.2 / §3.5）。
//
// 判定式（§3.2 / §3.5）：
//
//	系统已开放   = settings.mfa_enabled == true
//	白名单       = settings.mfa_methods（去重，保持配置顺序）
//	可用因子     = 白名单 ∩ 用户已绑定（recovery_code 随 totp 生效）
//	实际要求MFA  = 系统已开放 && user.mfa_required == 1 && len(可用因子) > 0
//
// 依赖以窄接口注入（用户读 / 凭证读 / settings 读）。本包不 import
// service/account、service/verification、service/orchestrator，供登录编排、
// 扫码写票、三方登录、SetMfa 前置校验与验证内核共用，避免各判定点复制口径
// 或形成反向依赖。
//
// 错误口径：依赖读取故障原样上抛，调用方按 fail-closed 处理——判定失败不得
// 降级成「无需二次验证」。判定依赖（用户 / 凭证 / settings 读取器）未注入即
// 装配缺陷，Required / UsableFactors 一律返回 ErrDepsUnavailable，不得静默
// 回退成「无需二次验证」。
package mfapolicy

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

// UserReader 用户行读取窄接口：*repo.UserRepo 天然满足。
type UserReader interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
}

// CredentialReader 凭证行读取窄接口：*repo.CredentialRepo 天然满足，
// 亦与 factor.CredentialRepo 同构，登录侧可直接注入。
type CredentialReader interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
}

// SettingsReader settings 热更新读取窄接口：*settings.Store 天然满足。
type SettingsReader interface {
	GetBool(key string) (bool, bool)
	GetStringSlice(key string) ([]string, bool)
}

// Deps 判定依赖（装配层构造）。
type Deps struct {
	// Users user 表读取（mfa_required 列与手机号 / 邮箱绑定态）。
	Users UserReader
	// Creds user_credential 行读取（totp / webauthn 绑定态）。
	Creds CredentialReader
	// Settings 热更新键读取（mfa_enabled 系统开关、mfa_methods 白名单）。
	Settings SettingsReader
}

// ErrDepsUnavailable 判定依赖未注入（装配缺陷）。调用方须按 fail-closed
// 上抛，不得据此跳过二次验证。
var ErrDepsUnavailable = errors.New("mfapolicy: deps not wired")

// 已绑定判定涉及的凭证 kind 与因子名。
const (
	kindTotp           = "totp"
	kindWebauthn       = "webauthn"
	factorOtpSms       = "otp_sms"
	factorOtpEmail     = "otp_email"
	factorRecoveryCode = "recovery_code"
)

// mfaWhitelistFactors 白名单值域（封闭四因子）。recovery_code 随 totp 生效、
// 不单列（接口文档 §3.2），故不属白名单值域；管理员写入的未知值在
// AllowedMethods 中丢弃，避免脏配置把全站两步验证打挂。
var mfaWhitelistFactors = [...]string{kindTotp, factorOtpSms, factorOtpEmail, kindWebauthn}

// SystemEnabled 系统是否开放两步验证：settings.mfa_enabled，缺省 true
// （§5.6）。纯读 helper，读取器为 nil 时按默认值处理；判定入口 Required
// 已先校验依赖完整性。
func SystemEnabled(s SettingsReader) bool {
	if s == nil {
		return true
	}
	if v, ok := s.GetBool(settings.KeyMfaEnabled); ok {
		return v
	}
	return true
}

// AllowedMethods 管理员配置的可用因子白名单（§3.2）：去重、保持 settings
// 顺序，并按封闭四因子值域过滤——recovery_code 随 totp 生效不单列，未知值
// 丢弃而非报错（管理员写入脏值时不应打挂全站两步验证）；未配置时为 nil。
// 纯读 helper，判定入口 Required 已先校验依赖完整性。
func AllowedMethods(s SettingsReader) []string {
	if s == nil {
		return nil
	}
	raw, _ := s.GetStringSlice(settings.KeyMfaMethods)
	if len(raw) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, m := range raw {
		if m == "" || seen[m] || !whitelistFactor(m) {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}

// whitelistFactor 是否属于白名单封闭值域（§3.2）。
func whitelistFactor(m string) bool {
	for _, f := range mfaWhitelistFactors {
		if f == m {
			return true
		}
	}
	return false
}

// UsableFactors 当前可用因子：白名单 ∩ 用户已绑定（§3.2）。
// recovery_code 不依赖白名单单列，totp 可用时随之一并计入，供二次验证
// 候选集与「是否允许开启」判定使用；投影层仍按白名单输出。
// uid<=0 表示无主体，返回 (nil, nil)；依赖未注入返回 ErrDepsUnavailable，
// 读取故障原样上抛——两者均不得降级为「无可用因子」。
func UsableFactors(ctx context.Context, d Deps, uid int64) ([]string, error) {
	if uid <= 0 {
		return nil, nil
	}
	if err := checkDeps(d); err != nil {
		return nil, err
	}
	user, err := d.Users.FindByID(ctx, uid)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}
	return usableWithUser(ctx, d, uid, user)
}

// Required 是否实际要求二次验证：系统已开放 && user.mfa_required==1 &&
// 存在可用因子（§3.2 / §3.5）。无可用因子按未开启处理，不锁死登录。
// uid<=0 表示无主体，返回 (false, nil)；依赖未注入返回 ErrDepsUnavailable，
// 读取故障原样上抛（fail-closed），调用方不得解释为「无需二次验证」。
func Required(ctx context.Context, d Deps, uid int64) (bool, error) {
	if uid <= 0 {
		return false, nil
	}
	if err := checkDeps(d); err != nil {
		return false, err
	}
	if !SystemEnabled(d.Settings) {
		return false, nil
	}
	user, err := d.Users.FindByID(ctx, uid)
	if err != nil {
		return false, err
	}
	if user == nil || user.MfaRequired != 1 {
		return false, nil
	}
	factors, err := usableWithUser(ctx, d, uid, user)
	if err != nil {
		return false, err
	}
	return len(factors) > 0, nil
}

// checkDeps 判定依赖完整性校验：三者缺一即装配缺陷，调用方按 fail-closed
// 上抛（不得静默关闭二次验证）。
func checkDeps(d Deps) error {
	if d.Users == nil || d.Creds == nil || d.Settings == nil {
		return ErrDepsUnavailable
	}
	return nil
}

// usableWithUser 已加载用户行后的可用因子计算，避免 Required 重复读 user。
func usableWithUser(ctx context.Context, d Deps, uid int64, user *model.User) ([]string, error) {
	allowed := AllowedMethods(d.Settings)
	if len(allowed) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(allowed))
	for _, f := range allowed {
		ok, err := bound(ctx, d, uid, user, f)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, f)
		}
	}
	if contains(out, kindTotp) && !contains(out, factorRecoveryCode) {
		out = append(out, factorRecoveryCode)
	}
	return out, nil
}

// bound 单因子绑定态（§3.2「已绑定」口径，与 account handler mfaBound
// 同源）：totp / webauthn 走凭证行（is_enabled=1），otp_sms / otp_email 走
// user.phone / user.email 非空；未知因子按未绑定处理。recovery_code 不由
// 白名单单列，totp 可用时由 usableWithUser 显式追加（不进入本函数）。
func bound(ctx context.Context, d Deps, uid int64, user *model.User, factor string) (bool, error) {
	switch factor {
	case kindTotp, kindWebauthn:
		if d.Creds == nil {
			return false, nil
		}
		row, err := d.Creds.FindByUserAndKind(ctx, uid, factor)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return false, nil
			}
			return false, err
		}
		return row != nil && row.IsEnabled == 1, nil
	case factorOtpSms:
		return user != nil && user.Phone != nil && *user.Phone != "", nil
	case factorOtpEmail:
		return user != nil && user.Email != nil && *user.Email != "", nil
	default:
		return false, nil
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
