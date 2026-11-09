// methods.go 生成登录方式快照（docs/后端架构.md §3.6 行 347-357、
// docs/接口文档.md §2.1 行 358-413）。快照只读 settings/Provider 配置，
// 不读数据库；captcha 配置由 Gate 现算，保证 site_key 与当前生效 Provider 一致。
package orchestrator

import (
	"context"
	"sort"

	"authloft/internal/captcha"
	"authloft/internal/factor"
	"authloft/internal/settings"
)

// SettingsReader 是 settings.Store 的窄接口（热更新由 Store 自己保证）。
type SettingsReader interface {
	GetString(key string) (string, bool)
	GetInt64(key string) (int64, bool)
	GetBool(key string) (bool, bool)
	GetStringSlice(key string) ([]string, bool)
}

// ThirdPartyProvider 是三方渠道快照项（§2.7.1）。Channel 取
// redirect/api/qrcode，由装配方按 Provider 配置映射，本层不猜。
type ThirdPartyProvider struct {
	ProviderKey string `json:"providerKey"`
	DisplayName string `json:"displayName"`
	Type        string `json:"type"`
	Channel     string `json:"channel"`
	Icon        string `json:"icon,omitempty"`
	UIGroup     string `json:"uiGroup,omitempty"`
	SortOrder   int32  `json:"sortOrder"`
}

// ThirdPartyProviderLister 返回已启用、可登录的三方渠道（按 sort_order 排好序，
// 本层再做一次稳定排序兜底）。
type ThirdPartyProviderLister interface {
	ListLoginProviders(ctx context.Context) ([]ThirdPartyProvider, error)
}

// FieldSnapshot 是前端要渲染的字段（§2.1）。Label 是前端 i18n 键
// （login.field.*，见 factor.Field 契约），不是展示文案。
type FieldSnapshot struct {
	Name     string `json:"name"`
	Label    string `json:"label,omitempty"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

// MethodSnapshot 是单个登录方式的快照（§2.1）。
type MethodSnapshot struct {
	Method          string               `json:"method"`
	Usage           []string             `json:"usage"`
	Steps           []string             `json:"steps,omitempty"`
	Fields          []FieldSnapshot      `json:"fields,omitempty"`
	ChallengeFields []FieldSnapshot      `json:"challengeFields,omitempty"`
	CodeLength      int64                `json:"codeLength,omitempty"`
	ResendAfter     int64                `json:"resendAfter,omitempty"`
	ExpiresIn       int64                `json:"expiresIn,omitempty"`
	Capability      string               `json:"capability,omitempty"`
	Providers       []ThirdPartyProvider `json:"providers,omitempty"`
}

// Flags 是流程开关，前端据此显隐入口（§2.1）。
type Flags struct {
	PasswordReset bool `json:"passwordReset"`
	Registration  bool `json:"registration"`
}

// MethodsSnapshot 是 methods 方法返回的注入快照。
type MethodsSnapshot struct {
	Flags   Flags            `json:"flags"`
	Captcha captcha.Config   `json:"captcha"`
	Methods []MethodSnapshot `json:"methods"`
}

// MethodsBuilder 生成快照。
type MethodsBuilder struct {
	Settings  SettingsReader
	Gate      *captcha.Gate
	Providers ThirdPartyProviderLister
}

// NewMethodsBuilder 注入依赖。
func NewMethodsBuilder(s SettingsReader, gate *captcha.Gate, providers ThirdPartyProviderLister) *MethodsBuilder {
	return &MethodsBuilder{Settings: s, Gate: gate, Providers: providers}
}

// methodOrder 与 §1.10 的推荐渲染顺序一致。
var methodOrder = []factor.FactorKind{
	factor.FactorPassword,
	factor.FactorOTPSMS,
	factor.FactorOTPEmail,
	factor.FactorWebAuthn,
	factor.FactorTOTP,
	factor.FactorRecovery,
	factor.FactorThirdParty,
}

// BuildMethodsSnapshot 按 flow 过滤、排序并组装快照。
// clientID 用于该客户端可用方式过滤；当前文档未定义客户端维度的过滤数据源，
// 本层原样接收并透传，不自行发明过滤规则。
func (b *MethodsBuilder) BuildMethodsSnapshot(ctx context.Context, clientID, flow string) (*MethodsSnapshot, error) {
	_ = clientID
	if flow == "" {
		flow = "login"
	}

	snap := &MethodsSnapshot{
		Flags: Flags{
			PasswordReset: b.boolSetting(settings.KeyAllowPasswordReset, true),
			Registration:  b.boolSetting(settings.KeyAllowRegistration, true),
		},
		Captcha: b.captchaConfig(ctx),
		Methods: []MethodSnapshot{},
	}

	var providers []ThirdPartyProvider
	if flow == "login" && b.Providers != nil {
		ps, err := b.Providers.ListLoginProviders(ctx)
		if err != nil {
			return nil, err
		}
		providers = sortProviders(ps)
	}

	for _, kind := range methodOrder {
		if !b.flowIncludes(flow, kind) {
			continue
		}
		if kind == factor.FactorThirdParty && len(providers) == 0 {
			continue
		}
		m := b.method(kind)
		// 注册 / 重置页只展示主因子入口（§2.1 行 410-411）。
		if flow != "login" {
			m.Usage = []string{string(factor.UsagePrimary)}
		}
		if kind == factor.FactorThirdParty {
			m.Providers = providers
		}
		snap.Methods = append(snap.Methods, m)
	}
	return snap, nil
}

// method 依据 §2.1 的字段定义生成单方式快照。
func (b *MethodsBuilder) method(kind factor.FactorKind) MethodSnapshot {
	m := MethodSnapshot{Method: string(kind)}
	switch kind {
	case factor.FactorPassword:
		m.Usage = []string{string(factor.UsagePrimary)}
		m.Steps = []string{string(factor.StepForm)}
		m.Fields = []FieldSnapshot{
			{Name: "username", Label: "login.field.usernameOrIdentifier", Type: "text", Required: true},
			{Name: "password", Label: "login.field.password", Type: "password", Required: true},
			{Name: "captcha", Label: "login.field.captcha", Type: "captcha", Required: false},
		}
	case factor.FactorOTPSMS, factor.FactorOTPEmail:
		m.Usage = []string{string(factor.UsagePrimary), string(factor.UsageSecondary)}
		m.Steps = []string{string(factor.StepChallenge), string(factor.StepForm)}
		if kind == factor.FactorOTPSMS {
			m.ChallengeFields = []FieldSnapshot{{Name: "phone", Type: "phone", Required: true}}
		} else {
			m.ChallengeFields = []FieldSnapshot{{Name: "email", Type: "email", Required: true}}
		}
		m.CodeLength = 6
		m.ResendAfter = b.intSetting(settings.KeyOtpResendInterval, 60)
		m.ExpiresIn = b.intSetting(settings.KeyOtpTtl, 300)
	case factor.FactorWebAuthn:
		m.Usage = []string{string(factor.UsagePrimary), string(factor.UsageSecondary)}
		m.Steps = []string{string(factor.StepChallenge), string(factor.StepForm)}
		m.Capability = "window.PublicKeyCredential"
	case factor.FactorTOTP:
		m.Usage = []string{string(factor.UsageSecondary)}
		m.Steps = []string{string(factor.StepForm)}
		m.CodeLength = 6
	case factor.FactorRecovery:
		m.Usage = []string{string(factor.UsageSecondary)}
		m.Steps = []string{string(factor.StepForm)}
	case factor.FactorThirdParty:
		// thirdparty 具体步骤由前端按 channel 实现，不出现在快照 steps（§2.1）。
		m.Usage = []string{string(factor.UsagePrimary)}
	}
	return m
}

// flowIncludes 实现 §2.1 的过滤规则：login 看 login_methods；register 看
// allow_registration + allow_signup_*（不读 login_methods）；reset 只看
// allow_password_reset 且仅验证码方式。
func (b *MethodsBuilder) flowIncludes(flow string, kind factor.FactorKind) bool {
	switch flow {
	case "login":
		return sliceContains(b.stringSliceSetting(settings.KeyLoginMethods), string(kind))
	case "register":
		if !b.boolSetting(settings.KeyAllowRegistration, true) {
			return false
		}
		switch kind {
		case factor.FactorPassword:
			return b.boolSetting(settings.KeyAllowSignupPassword, true)
		case factor.FactorOTPSMS:
			return b.boolSetting(settings.KeyAllowSignupPhone, true)
		case factor.FactorOTPEmail:
			return b.boolSetting(settings.KeyAllowSignupEmail, true)
		default:
			return false
		}
	case "reset":
		if !b.boolSetting(settings.KeyAllowPasswordReset, true) {
			return false
		}
		return kind == factor.FactorOTPSMS || kind == factor.FactorOTPEmail
	default:
		return false
	}
}

func (b *MethodsBuilder) captchaConfig(ctx context.Context) captcha.Config {
	if b.Gate == nil {
		return captcha.Config{ProviderKey: captcha.BuiltinProviderKey, Type: captcha.TypeImage}
	}
	return b.Gate.Config(ctx)
}

func (b *MethodsBuilder) boolSetting(key string, def bool) bool {
	if b.Settings != nil {
		if v, ok := b.Settings.GetBool(key); ok {
			return v
		}
	}
	return def
}

func (b *MethodsBuilder) intSetting(key string, def int64) int64 {
	if b.Settings != nil {
		if v, ok := b.Settings.GetInt64(key); ok && v > 0 {
			return v
		}
	}
	return def
}

func (b *MethodsBuilder) stringSliceSetting(key string) []string {
	if b.Settings != nil {
		if v, ok := b.Settings.GetStringSlice(key); ok {
			return v
		}
	}
	if def, ok := settings.Defaults()[key].([]string); ok {
		return def
	}
	return nil
}

func sortProviders(in []ThirdPartyProvider) []ThirdPartyProvider {
	out := make([]ThirdPartyProvider, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SortOrder != out[j].SortOrder {
			return out[i].SortOrder < out[j].SortOrder
		}
		return out[i].ProviderKey < out[j].ProviderKey
	})
	return out
}

func sliceContains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
