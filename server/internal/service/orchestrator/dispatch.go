// dispatch.go 负责登录引擎第 2 步：method/usage/step 校验
// （docs/后端架构.md §7.2 行 974-983、docs/接口文档.md §2.2 行 414-437）。
// 这里不碰存储，只依据注册表、settings 与 login_token 状态做判定。
package orchestrator

import (
	"context"
	"errors"

	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/settings"
)

// FactorLookup 是注册表的窄接口，便于编排层单测替换。
type FactorLookup interface {
	Get(kind factor.FactorKind) (factor.Factor, error)
}

// Dispatched 是校验通过后的分派结果。
type Dispatched struct {
	Factor factor.Factor
	Kind   factor.FactorKind
	Usage  factor.Usage
	Step   factor.StepKind
}

// Dispatcher 执行 method/usage/step 校验。
type Dispatcher struct {
	Registry FactorLookup
	Settings SettingsReader
}

// stepKinds 登录流程只接受 challenge / verify 两种 step 值（§2.2）。
var stepKinds = map[string]factor.StepKind{
	"challenge": factor.StepChallenge,
	"verify":    factor.StepForm,
}

// Resolve 校验并返回分派结果；第二个返回值为非空时表示业务失败 status。
func (d *Dispatcher) Resolve(ctx context.Context, flow string, p *token.LoginTokenPayload, method, step string) (*Dispatched, string) {
	_ = ctx
	if method == "" {
		return nil, StatusInvalidRequest
	}
	kind := factor.FactorKind(method)
	if d.Registry == nil {
		return nil, StatusFailed
	}
	f, err := d.Registry.Get(kind)
	if err != nil {
		if errors.Is(err, factor.ErrUnknownKind) {
			return nil, StatusInvalidRequest
		}
		if errors.Is(err, factor.ErrKindNotRegistered) {
			return nil, StatusMethodDisabled
		}
		return nil, StatusFailed
	}

	stepKind, ok := stepKinds[step]
	if !ok || !stepSupported(f.Steps(), stepKind) {
		return nil, StatusStepInvalid
	}

	usage, ok := resolveUsage(f.Usages(), p)
	if !ok {
		return nil, StatusStepInvalid
	}

	if status := methodStatus(flow, kind, usage, d.Settings); status != "" {
		return nil, status
	}
	return &Dispatched{Factor: f, Kind: kind, Usage: usage, Step: stepKind}, ""
}

// methodStatus 按 flow 判定方式是否启用（§2.2 第 2 步、§2.3、§2.4）。
// 二次因子阶段不看 login_methods，改用 mfa_methods（recovery_code 随 totp 生效）。
func methodStatus(flow string, kind factor.FactorKind, usage factor.Usage, s SettingsReader) string {
	if usage == factor.UsageSecondary {
		if !boolSetting(s, settings.KeyMfaEnabled, true) {
			return StatusMethodDisabled
		}
		if kind == factor.FactorRecovery || sliceContains(stringSlice(s, settings.KeyMfaMethods), string(kind)) {
			return ""
		}
		return StatusMethodDisabled
	}
	switch flow {
	case "login":
		if !sliceContains(stringSlice(s, settings.KeyLoginMethods), string(kind)) {
			return StatusMethodDisabled
		}
		return ""
	case "register":
		if !boolSetting(s, settings.KeyAllowRegistration, true) {
			return StatusSignupDisabled
		}
		switch kind {
		case factor.FactorPassword:
			if !boolSetting(s, settings.KeyAllowSignupPassword, true) {
				return StatusSignupDisabled
			}
		case factor.FactorOTPSMS:
			if !boolSetting(s, settings.KeyAllowSignupPhone, true) {
				return StatusSignupDisabled
			}
		case factor.FactorOTPEmail:
			if !boolSetting(s, settings.KeyAllowSignupEmail, true) {
				return StatusSignupDisabled
			}
		default:
			return StatusMethodDisabled
		}
		return ""
	case "reset":
		if !boolSetting(s, settings.KeyAllowPasswordReset, true) {
			return StatusResetDisabled
		}
		if kind != factor.FactorOTPSMS && kind != factor.FactorOTPEmail {
			return StatusMethodDisabled
		}
		return ""
	default:
		return StatusInvalidRequest
	}
}

// resolveUsage 判定主因子 / 二次因子。二次因子阶段必须 uid != 0 且 passed 非空
// （§7.3 行 985-1004）；仅 secondary 的方式在此阶段之前使用一律 step_invalid。
func resolveUsage(usages []factor.Usage, p *token.LoginTokenPayload) (factor.Usage, bool) {
	hasPrimary := usageContains(usages, factor.UsagePrimary)
	hasSecondary := usageContains(usages, factor.UsageSecondary)
	secondaryStage := p != nil && p.GetUid() != 0 && len(p.GetPassed()) > 0

	switch {
	case secondaryStage && hasSecondary:
		return factor.UsageSecondary, true
	case !secondaryStage && hasPrimary:
		return factor.UsagePrimary, true
	default:
		return "", false
	}
}

func stepSupported(steps []factor.StepKind, want factor.StepKind) bool {
	for _, s := range steps {
		if s == want {
			return true
		}
	}
	return false
}

func usageContains(usages []factor.Usage, want factor.Usage) bool {
	for _, u := range usages {
		if u == want {
			return true
		}
	}
	return false
}

func stringSlice(s SettingsReader, key string) []string {
	if s != nil {
		if v, ok := s.GetStringSlice(key); ok {
			return v
		}
	}
	if def, ok := settings.Defaults()[key].([]string); ok {
		return def
	}
	return nil
}

func boolSetting(s SettingsReader, key string, def bool) bool {
	if s != nil {
		if v, ok := s.GetBool(key); ok {
			return v
		}
	}
	return def
}
