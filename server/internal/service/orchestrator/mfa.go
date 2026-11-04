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
	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

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
}

// NewMFABuilder 注入依赖。
func NewMFABuilder(users factor.UserRepo, creds MFACredentialReader, s SettingsReader) *MFABuilder {
	return &MFABuilder{Users: users, Credentials: creds, Settings: s}
}

// mfaOrder 是 §1.3 示例与 §5.6 mfa_methods 的默认顺序；recovery_code 不单列，
// 随 totp 生效（§5.6 行 1319-1321）。
var mfaOrder = []string{"totp", "otp_sms", "otp_email", "webauthn"}

// Build 返回 (mfa, required, err)。required 仅在全局 mfa_enabled、用户
// mfa_required=1 且至少存在一个可用二次因子时为 true。
func (b *MFABuilder) Build(ctx context.Context, uid int64) (*ssov1.Mfa, bool, error) {
	if uid == 0 || b.Users == nil {
		return nil, false, nil
	}
	user, err := b.Users.FindByID(ctx, uid)
	if err != nil {
		return nil, false, err
	}
	if user == nil || user.MfaRequired != 1 {
		return nil, false, nil
	}
	if !boolSetting(b.Settings, settings.KeyMfaEnabled, true) {
		return nil, false, nil
	}

	allowed := mfaAllowed(b.Settings)
	var methods []*ssov1.MfaMethod
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
		return nil, false, nil
	}
	return &ssov1.Mfa{
		ExpiresIn: intSetting(b.Settings, settings.KeyOtpTtl, 300),
		Methods:   methods,
	}, true, nil
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
