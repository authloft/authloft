// mfa.go 生成二次因子列表（docs/后端架构.md §3.6 行 347-357、
// docs/接口文档.md §1.3 行 119-128、§2.5）。目标一律取自 uid 的绑定资料，
// 不接受请求参数指定手机号/邮箱；本层不读 DB，依赖以窄接口注入。
package orchestrator

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/internal/factor"
	"authloft/internal/logx"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

// ErrWebauthnDegraded MFA fail-closed 哨兵（§8.3 行
// 1069 窗口期 fail-closed）：mfa_required 用户的唯一可用二次因子为
// webauthn 且因启动降级被剔除时，Build 返回本错误；引擎与三方登录路径
// 据此拒绝登录（status=method_disabled + WebauthnDegradedMessage），绝不
// 静默放行（required=false 直通终点）/ 自动跳过 MFA / 改用更弱因子顶替。
var ErrWebauthnDegraded = errors.New("orchestrator: webauthn unavailable (degraded), user's only usable MFA factor lost")

// WebauthnDegradedMessage fail-closed 的流程态 error.message 明示文案
// （§1.6 行 272「特殊情况可使用 error.message，文案不考虑 i18n」；引擎与
// 三方登录两条路径共用同一句）。
const WebauthnDegradedMessage = "通行密钥暂不可用，请联系管理员"

// MFACredentialReader 只暴露 mfa 需要的两种读法：按 kind 取凭据、
// 列出该用户的通行密钥。实现方负责把 repo 错误原样返回。
type MFACredentialReader interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
	ListWebauthn(ctx context.Context, userID int64) ([]model.UserCredentialWebauthn, error)
}

// MFABuilder 组装 status=mfa_required 的 mfa 对象。
type MFABuilder struct {
	Users       factor.UserRepo
	Credentials MFACredentialReader
	Settings    SettingsReader
	// Factors 因子注册表窄接口（FactorLookup，与 pages 的 FactorSource
	// 同构，*factor.Registry 天然满足）：Build 的 webauthn case 先查注册
	// 表——启动降级未注册时（§8.3 行 1069「MFA 开放集合随之不含
	// webauthn」）不再注入 methods，用户不致「选了才遭
	// dispatch 拒绝」。nil = 不过滤（既有装配与单测行为，保持零回归）。
	Factors FactorLookup
}

// NewMFABuilder 注入依赖。
func NewMFABuilder(users factor.UserRepo, creds MFACredentialReader, s SettingsReader) *MFABuilder {
	return &MFABuilder{Users: users, Credentials: creds, Settings: s}
}

// mfaOrder 是 §1.3 示例与 §5.6 mfa_methods 的默认顺序；recovery_code 不单列，
// 随 totp 生效（§5.6 行 1319-1321）。
var mfaOrder = []string{"totp", "otp_sms", "otp_email", "webauthn"}

// Build 返回 (mfa, required, err)。required 仅在全局 mfa_enabled、用户需
// 二次验证（策略强制 user.mfa_required=1 ∨ 用户自选启用 mfa_setting 行，
// 见下行注释）且至少存在一个可用二次因子时为 true。
func (b *MFABuilder) Build(ctx context.Context, uid int64) (*ssov1.Mfa, bool, error) {
	if uid == 0 || b.Users == nil {
		return nil, false, nil
	}
	user, err := b.Users.FindByID(ctx, uid)
	if err != nil {
		return nil, false, err
	}
	if user == nil {
		return nil, false, nil
	}
	// 方案 B（读取兼容，2026-11-06 定稿）：二次验证触发 =
	// 策略强制（user.mfa_required=1，列语义保持「系统强制」，后端架构 §4
	// 行 649）∨ 用户自选启用（mfa_setting 行存在且 is_enabled=1——kind 与
	// account/mfa.go:99 同值，接口文档 §3.2 行 868「行存在即顶层
	// enabled=true」同源；SetMfa 关闭 = 删行，登录侧随读随消，关闭守卫与
	// mfaPolicy 投影零改动）。存量「行存在但列为 0」经读取自动兼容，零迁移。
	if user.MfaRequired != 1 {
		userEnabled, err := b.hasCredential(ctx, uid, "mfa_setting")
		if err != nil {
			return nil, false, err
		}
		if !userEnabled {
			return nil, false, nil
		}
	}
	if !boolSetting(b.Settings, settings.KeyMfaEnabled, true) {
		return nil, false, nil
	}

	allowed := mfaAllowed(b.Settings)
	var methods []*ssov1.MfaMethod
	degradedLost := false // webauthn 因降级被剔除且该用户已绑定（唯一可用因子候选）
	for _, method := range mfaOrder {
		if !allowed[method] {
			continue
		}
		switch method {
		case "totp":
			ok, err := b.hasCredential(ctx, uid, "totp")
			if err != nil {
				return nil, false, err
			}
			if ok {
				methods = append(methods, &ssov1.MfaMethod{
					Method: "totp",
					Steps:  []string{string(factor.StepForm)},
					Fields: []*ssov1.Field{{Name: "code", Type: "totp", Required: true, Length: 6}},
				})
				// recovery_code 随 totp 生效，不单列（§5.6）。
				methods = append(methods, &ssov1.MfaMethod{
					Method: "recovery_code",
					Steps:  []string{string(factor.StepForm)},
					Fields: []*ssov1.Field{{Name: "code", Type: "text"}},
				})
			}
		case "otp_sms":
			if user.PhoneVerified == 1 && user.Phone != nil && *user.Phone != "" {
				methods = append(methods, &ssov1.MfaMethod{
					Method:       "otp_sms",
					Steps:        []string{string(factor.StepChallenge), string(factor.StepForm)},
					MaskedTarget: maskPhone(*user.Phone),
				})
			}
		case "otp_email":
			if user.EmailVerified == 1 && user.Email != nil && *user.Email != "" {
				methods = append(methods, &ssov1.MfaMethod{
					Method:       "otp_email",
					Steps:        []string{string(factor.StepChallenge), string(factor.StepForm)},
					MaskedTarget: maskEmail(*user.Email),
				})
			}
		case "webauthn":
			// 启动降级联动（§8.3 行 1069）：webauthn 初始化失败被
			// 禁用后不注册进注册表，MFA 开放集合随之不含 webauthn——未注册
			// （含未知 kind）跳过不注入 methods。已绑定用户被剔除后若再无
			// 可用因子，Build 尾部按 fail-closed 哨兵上抛
			//（绝不静默放行）；未绑定用户与窗口无关，仅跳过。
			// 其余错误按 Build 既有口径原样上抛；Factors 为 nil 时不过滤
			//（既有装配与单测行为）。
			if b.Factors != nil {
				if _, err := b.Factors.Get(factor.FactorWebAuthn); err != nil {
					if errors.Is(err, factor.ErrKindNotRegistered) || errors.Is(err, factor.ErrUnknownKind) {
						bound, bErr := b.hasWebauthnCredential(ctx, uid)
						if bErr != nil {
							return nil, false, bErr
						}
						if bound {
							degradedLost = true
						}
						continue
					}
					return nil, false, err
				}
			}
			if b.Credentials != nil {
				list, err := b.Credentials.ListWebauthn(ctx, uid)
				if err != nil {
					return nil, false, err
				}
				if len(list) > 0 {
					methods = append(methods, &ssov1.MfaMethod{
						Method: "webauthn",
						Steps:  []string{string(factor.StepChallenge), string(factor.StepForm)},
					})
				}
			}
		}
	}

	if len(methods) == 0 {
		// fail-closed（§8.3 行 1069 窗口期）：已绑定
		// webauthn 的用户因降级失去唯一可用二次因子 → 绝不 required=false
		// 静默放行（主因子直通终点 = 自动跳过 MFA），返回哨兵错误交调用方
		// 拒绝登录；每次拒绝逐次 WARN（能看出原因是 webauthn 不可用）。
		// 与窗口无关的既有 required=false 语义不变（未绑定任何因子 /
		// mfa_enabled=false 等）。
		if degradedLost {
			logx.Warn(ctx, "orchestrator: mfa fail-closed, webauthn unavailable (degraded window) and user's only usable factor lost", "uid", uid)
			return nil, false, ErrWebauthnDegraded
		}
		return nil, false, nil
	}
	return &ssov1.Mfa{
		ExpiresIn: intSetting(b.Settings, settings.KeyOtpTtl, 300),
		Methods:   methods,
	}, true, nil
}

// hasWebauthnCredential 用户是否已绑定 webauthn 凭据（降级剔除后是否
// 失去可用因子的判定输入）；读取错误按 Build 既有口径上抛。
func (b *MFABuilder) hasWebauthnCredential(ctx context.Context, uid int64) (bool, error) {
	if b.Credentials == nil {
		return false, nil
	}
	list, err := b.Credentials.ListWebauthn(ctx, uid)
	if err != nil {
		return false, err
	}
	return len(list) > 0, nil
}

func (b *MFABuilder) hasCredential(ctx context.Context, uid int64, kind string) (bool, error) {
	if b.Credentials == nil {
		return false, nil
	}
	c, err := b.Credentials.FindByUserAndKind(ctx, uid, kind)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return c != nil && c.IsEnabled == 1, nil
}

func mfaAllowed(s SettingsReader) map[string]bool {
	list := stringSlice(s, settings.KeyMfaMethods)
	out := make(map[string]bool, len(list))
	for _, m := range list {
		out[m] = true
	}
	return out
}

func intSetting(s SettingsReader, key string, def int64) int64 {
	if s != nil {
		if v, ok := s.GetInt64(key); ok && v > 0 {
			return v
		}
	}
	return def
}

// maskPhone 只取 uid 绑定资料，不读请求参数。
func maskPhone(phone string) string {
	if len(phone) >= 7 {
		return phone[:3] + "****" + phone[len(phone)-4:]
	}
	return "****"
}

// maskEmail 只取 uid 绑定资料，不读请求参数。
func maskEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		return "***"
	}
	local := email[:at]
	domain := email[at:]
	if len(local) <= 1 {
		return "*" + domain
	}
	return local[:1] + "***" + domain
}
