// dispatch.go 负责登录引擎第 2 步：method/usage/step 校验
// （docs/后端架构.md §7.2 行 974-983、docs/接口文档.md §2.2 行 414-437）。
// 这里不碰存储，只依据注册表、settings 与 login_token 状态做判定。
package orchestrator

import (
	"context"
	"errors"

	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/logx"
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

// stepSetPassword 注册 / 重置专用 step（§1.4 行 165 请求侧 step）。
const stepSetPassword = "set_password"

// stepKinds 登录流程接受的 step 值（§2.2；set_password 见 §1.4 行 165、
// §2.3 行 444-450、§2.4 行 462-466，渲染 kind=form）。
var stepKinds = map[string]factor.StepKind{
	"challenge":     factor.StepChallenge,
	"verify":        factor.StepForm,
	stepSetPassword: factor.StepForm,
}

// Resolve 校验并返回分派结果；第二个返回值为非空时表示业务失败 status。
func (d *Dispatcher) Resolve(ctx context.Context, flow string, p *token.LoginTokenPayload, method, step string) (*Dispatched, string) {
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
			// 窗口期逐次日志：webauthn 降级
			// 未注册被拒的每次请求都要能看出原因；其余 kind（pendingKinds
			// 等既有未实现项）维持现状不打日志。
			if kind == factor.FactorWebAuthn {
				logx.Warn(ctx, "orchestrator: webauthn method rejected (factor not registered, degraded window)", "flow", flow)
			}
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

	// set_password 不是因子验证：强制按 primary 语义走方式开关（§2.3 行 453 /
	// §2.4 行 471 的 signup_disabled / reset_disabled 对各 step 一律生效），
	// 避免 reset 验后（uid≠0 且 passed 非空）被 resolveUsage 误判为 MFA 阶段。
	if step == stepSetPassword {
		usage = factor.UsagePrimary
	}

	if status := methodStatus(flow, kind, usage, d.Settings, p); status != "" {
		return nil, status
	}

	// set_password 仅 register | reset 流接受（§1.4 行 165、§7.4 行 1025）：
	// register 直通入口 method=password（§2.3 行 451）无需先过 verify；
	// 其余方式（register / reset 的 otp）必须已完成 verify（passed 含该因子）。
	if step == stepSetPassword {
		if status := setPasswordAccepts(flow, kind, p); status != "" {
			return nil, status
		}
	}
	return &Dispatched{Factor: f, Kind: kind, Usage: usage, Step: stepKind}, ""
}

// setPasswordAccepts 校验 set_password 步的 flow / method / 前置状态。
func setPasswordAccepts(flow string, kind factor.FactorKind, p *token.LoginTokenPayload) string {
	switch flow {
	case "register":
		if kind == factor.FactorPassword {
			// 用户名 + 密码直通入口（§2.3 行 451：无 challenge / verify）。
			return ""
		}
		if kind != factor.FactorOTPSMS && kind != factor.FactorOTPEmail {
			return StatusStepInvalid
		}
	case "reset":
		if kind != factor.FactorOTPSMS && kind != factor.FactorOTPEmail {
			return StatusStepInvalid
		}
	default:
		// login 流不接受 set_password（§1.4 行 165：注册 / 重置专用）。
		return StatusStepInvalid
	}
	// otp 方式必须验后（login_token.passed 含该因子），防止跳过
	// challenge / verify 直达 set_password。
	if p == nil || !sliceContains(p.GetPassed(), string(kind)) {
		return StatusStepInvalid
	}
	return ""
}

// methodStatus 按 flow 判定方式是否启用（§2.2 第 2 步、§2.3、§2.4）。
// 二次因子阶段不看 login_methods，改用 mfa_methods（recovery_code 随 totp 生效）。
// tp 免密建号（login_token.tp 非空 + flow=login）跳过
// allow_signup_password——三方建号开关唯一归 provider enable_signup
// （§2.7.5 行 673 / §12.5 行 1504），allow_registration（整体开关）仍
// fail-closed 生效。
func methodStatus(flow string, kind factor.FactorKind, usage factor.Usage, s SettingsReader, p *token.LoginTokenPayload) string {
	if usage == factor.UsageSecondary {
		if !boolSetting(s, settings.KeyMfaEnabled, true) {
			return StatusMethodDisabled
		}
		if kind == factor.FactorRecovery || sliceContains(stringSlice(s, settings.KeyMfaMethods), string(kind)) {
			return ""
		}
		return StatusMethodDisabled
	}
	// tp 免密建号：Register 端点 method=password 的 set_password 步携
	// login_token.tp（§12.5 行 1505），方式开关不适用于该分支。
	tpSignup := p != nil && p.GetTp() != nil && p.GetFlow() == "login"
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
			if !tpSignup && !boolSetting(s, settings.KeyAllowSignupPassword, true) {
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
