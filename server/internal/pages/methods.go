// methods.go __AUTHLOFT_INIT__.methods 快照组装（接口文档 §2.1 行 359-413、
// 后端架构 §12.3 行 1460-1466）：flags 镜像 settings 两开关、captcha 取 Gate
// 现算配置（§2.5 三处同结构出口之一）、methods 按 flow 过滤——login 读
// settings.login_methods 过滤因子注册表（usage / steps 取因子实现，即 §1.10
// 渠道序列的四处取值来源之一），命中 sso_client 行时再按应用级配置做交集
// （§2.1 应用级过滤：应用开关 ∩ 全局开关，仅 flow=login 消费）；thirdparty
// 走 provider Loader（is_enabled=1 且 enable_signin=1，公开视图零凭证字段）。
// 数值字段一律十进制字符串（§1.12 行 339-346：JSON 不出现裸数字）。
package pages

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"authloft/internal/captcha"
	"authloft/internal/factor"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

// flow 取值（§2.1 行 368：login 默认 | register | reset）。
const (
	flowLogin    = "login"
	flowRegister = "register"
	flowReset    = "reset"
)

// categoryOAuth provider 表 category 取值（§4.1；thirdparty 登录渠道）。
const categoryOAuth = "oauth"

// SnapshotField 渲染字段（§2.1 行 384-394、§1.11 type 封闭集合）。
// Label 是前端 i18n 键（login.field.*，见 factor.Field 契约），不是展示文案。
type SnapshotField struct {
	Name     string `json:"name"`
	Label    string `json:"label,omitempty"`
	Type     string `json:"type"`
	Required bool   `json:"required,omitempty"`
}

// SnapshotProvider thirdparty.providers 条目（§2.7.1 行 560-574）：公开视图
// 零凭证字段（§12.3 行 1466）——仅展示属性，绝无 ext 内容。
type SnapshotProvider struct {
	ProviderKey string `json:"providerKey"`
	DisplayName string `json:"displayName,omitempty"`
	Type        string `json:"type"`
	Channel     string `json:"channel"`
	Icon        string `json:"icon,omitempty"`
	UiGroup     string `json:"uiGroup,omitempty"`
	SortOrder   string `json:"sortOrder,omitempty"` // int64 → 十进制字符串（§1.12）
}

// MethodEntry methods[] 单个方式条目（§2.1 行 382-400）。数值字段为十进制
// 字符串（§1.12）。
type MethodEntry struct {
	Method          string             `json:"method"`
	Usage           []string           `json:"usage,omitempty"`
	Steps           []string           `json:"steps,omitempty"`
	Fields          []SnapshotField    `json:"fields,omitempty"`
	ChallengeFields []SnapshotField    `json:"challengeFields,omitempty"`
	CodeLength      string             `json:"codeLength,omitempty"`
	ResendAfter     string             `json:"resendAfter,omitempty"`
	ExpiresIn       string             `json:"expiresIn,omitempty"`
	Capability      string             `json:"capability,omitempty"`
	Providers       []SnapshotProvider `json:"providers,omitempty"`
}

// snapshotFlags 入口可见性（§2.1 行 374-377）：镜像 allow_password_reset /
// allow_registration，只用于隐藏「忘记密码」「注册」入口。
type snapshotFlags struct {
	PasswordReset bool `json:"passwordReset"`
	Registration  bool `json:"registration"`
}

// MethodsSnapshot __AUTHLOFT_INIT__.methods 的值（§2.1 行 370-402）。
// captcha.Config 字段名与 §2.5 唯一定义一致（providerKey / type / siteKey）。
type MethodsSnapshot struct {
	Flags   snapshotFlags  `json:"flags"`
	Captcha captcha.Config `json:"captcha"`
	Methods []MethodEntry  `json:"methods"`
}

// ssoMethodScope sso_client 行的应用级登录方式维度（§2.1 应用级过滤）：
// methods / providers 两集合独立生效，nil / 空集 = 未配置 = 跟随全局。
// 仅 flow=login 消费（register / reset 镜像全局口径，不读应用配置）。
type ssoMethodScope struct {
	methods   map[string]bool // 应用 login_methods（含 thirdparty 整体开关）
	providers map[string]bool // 应用 oauth_providers（provider key 明细白名单）
}

// ssoScopeFromRow sso_client 行 → 应用级维度：两列均为 proto 序列化（§12.0，
// 编解码出口 repo.ParseClientLoginMethods / ParseClientOauthProviders），
// 空列 = 未配置 = 对应集合为空。row 为 nil（client_id 未命中行 / 授权入口）
// → nil scope、零查询。列解码失败 = 服务端故障（渲染层转 500，同
// login_methods 缺键口径），不静默降级为跟随全局。
func ssoScopeFromRow(row *model.SsoClient) (*ssoMethodScope, error) {
	if row == nil {
		return nil, nil
	}
	ms, err := repo.ParseClientLoginMethods(row.LoginMethods)
	if err != nil {
		return nil, fmt.Errorf("pages: parse sso login_methods: %w", err)
	}
	ps, err := repo.ParseClientOauthProviders(row.OauthProviders)
	if err != nil {
		return nil, fmt.Errorf("pages: parse sso oauth_providers: %w", err)
	}
	return &ssoMethodScope{
		methods:   stringSet(ms.GetMethods()),
		providers: stringSet(ps.GetProviders()),
	}, nil
}

// stringSet []string → 成员集合（nil 输入 → 空集合）。
func stringSet(vs []string) map[string]bool {
	out := make(map[string]bool, len(vs))
	for _, v := range vs {
		out[v] = true
	}
	return out
}

// allowsMethod 应用是否放行某方式（§2.1 交集口径前两行）：应用未配置
// （nil / 空集）= 跟随全局；已配置按成员判定——thirdparty 整体开关与因子
// 方式同处应用 login_methods 一个集合，全局序不因应用配置改变。
func (s *ssoMethodScope) allowsMethod(m string) bool {
	if s == nil || len(s.methods) == 0 {
		return true
	}
	return s.methods[m]
}

// allowedProviders 应用 oauth_providers 白名单（§2.1 交集口径第三行的过滤
// 入参）：nil / 空 = 未配置 = 跟随全局（无应用限制）。
func (s *ssoMethodScope) allowedProviders() map[string]bool {
	if s == nil {
		return nil
	}
	return s.providers
}

// buildMethods 组装快照。login 流读不到 login_methods（settings 缺键）即
// 服务端故障（§8 行 1436），返回错误由渲染层转 500。sso 为可变参的
// sso_client 行应用级维度（§2.1）：仅登录端入口传入，授权入口恒缺省；
// 仅 flow=login 消费做交集过滤，register / reset 镜像全局口径不读应用配置。
func (h *Handler) buildMethods(ctx context.Context, flow string, sso ...*ssoMethodScope) (*MethodsSnapshot, error) {
	var scope *ssoMethodScope
	if len(sso) > 0 {
		scope = sso[0]
	}
	snap := &MethodsSnapshot{
		Flags: snapshotFlags{
			PasswordReset: h.boolSetting(settings.KeyAllowPasswordReset, true),
			Registration:  h.boolSetting(settings.KeyAllowRegistration, true),
		},
		Captcha: h.captchaConfig(ctx),
	}

	var (
		methods []MethodEntry
		err     error
	)
	switch flow {
	case flowRegister:
		methods, err = h.registerMethods()
	case flowReset:
		methods, err = h.resetMethods()
	default: // login 默认（§2.1 行 368）
		methods, err = h.loginMethods(scope)
	}
	if err != nil {
		return nil, err
	}
	if methods == nil {
		methods = []MethodEntry{}
	}
	snap.Methods = methods
	return snap, nil
}

// loginMethods flow=login（§2.1 默认）：settings.login_methods 顺序过滤因子
// 注册表，应用开关未放行的方式先被剔除（§2.1 应用级交集：同时开启才算
// 开启）；thirdparty 合成条目走 provider Loader（is_enabled=1 且
// enable_signin=1，§12.3 行 1464）并按应用 oauth_providers 白名单再过滤；
// device 不出现（§2.1 行 406）；未注册 / 拼错的方式跳过不注入。
// login_methods 缺键 → 错误（500）。
func (h *Handler) loginMethods(sso *ssoMethodScope) ([]MethodEntry, error) {
	enabled, ok := h.sliceSetting(settings.KeyLoginMethods)
	if !ok {
		return nil, errors.New("pages: login_methods missing from settings")
	}
	methods := []MethodEntry{}
	for _, m := range enabled {
		if !sso.allowsMethod(m) {
			continue // 应用 login_methods 未放行（§2.1 应用级过滤）
		}
		kind := factor.FactorKind(m)
		switch kind {
		case factor.FactorDevice:
			continue // §2.1 行 406：device 因子不出现
		case factor.FactorThirdParty:
			entry, err := h.thirdpartyEntry(sso.allowedProviders())
			if err != nil {
				return nil, err
			}
			if entry != nil { // 过滤后零可用 Provider 时不注入（未启用口径）
				methods = append(methods, *entry)
			}
		default:
			f, err := h.factor(kind)
			if err != nil {
				continue // 未注册方式不注入（不可登录即不展示）
			}
			methods = append(methods, h.factorEntry(f))
		}
	}
	return methods, nil
}

// registerMethods flow=register（§2.1 行 411）：按注册开关过滤
// allow_registration + allow_signup_password / phone / email（§5.6），
// 不读 login_methods；未开注册 → 空数组（前端隐藏入口）。
func (h *Handler) registerMethods() ([]MethodEntry, error) {
	methods := []MethodEntry{}
	if !h.boolSetting(settings.KeyAllowRegistration, true) {
		return methods, nil
	}
	for _, m := range []struct {
		kind factor.FactorKind
		key  string
	}{
		{factor.FactorPassword, settings.KeyAllowSignupPassword},
		{factor.FactorOTPSMS, settings.KeyAllowSignupPhone},
		{factor.FactorOTPEmail, settings.KeyAllowSignupEmail},
	} {
		if !h.boolSetting(m.key, true) {
			continue
		}
		f, err := h.factor(m.kind)
		if err != nil {
			continue
		}
		methods = append(methods, h.factorEntry(f))
	}
	return methods, nil
}

// resetMethods flow=reset（§2.1 行 412）：只保留 otp_sms / otp_email，
// usage 固定 ["primary"]、steps 为 challenge → form（因子实现即此序列），
// 受 allow_password_reset 控制——false 时空数组（前端隐藏重置入口）。
// 不读 login_methods。
func (h *Handler) resetMethods() ([]MethodEntry, error) {
	methods := []MethodEntry{}
	if !h.boolSetting(settings.KeyAllowPasswordReset, true) {
		return methods, nil
	}
	for _, kind := range []factor.FactorKind{factor.FactorOTPSMS, factor.FactorOTPEmail} {
		f, err := h.factor(kind)
		if err != nil {
			continue
		}
		e := h.factorEntry(f)
		e.Usage = []string{string(factor.UsagePrimary)} // §2.1 行 412「usage 仍为 primary」
		methods = append(methods, e)
	}
	return methods, nil
}

// factorEntry 因子注册表条目 → 快照条目：method / usage / steps 取因子实现
// （§1.10 四处取值来源之一）；各因子渲染补充字段按 §2.1 行 383-397。
func (h *Handler) factorEntry(f factor.Factor) MethodEntry {
	e := MethodEntry{
		Method: string(f.Kind()),
		Usage:  usageStrings(f.Usages()),
		Steps:  stepStrings(f.Steps()),
	}
	switch f.Kind() {
	case factor.FactorPassword:
		e.Fields = []SnapshotField{
			{Name: "username", Label: "login.field.usernameOrIdentifier", Type: "text", Required: true},
			{Name: "password", Label: "login.field.password", Type: "password", Required: true},
			{Name: "captcha", Label: "login.field.captcha", Type: "captcha", Required: false},
		}
	case factor.FactorOTPSMS:
		e.ChallengeFields = []SnapshotField{{Name: "phone", Label: "login.field.phone", Type: "phone", Required: true}}
		e.CodeLength, e.ResendAfter, e.ExpiresIn = h.otpParams()
	case factor.FactorOTPEmail:
		e.ChallengeFields = []SnapshotField{{Name: "email", Label: "login.field.email", Type: "email", Required: true}}
		e.CodeLength, e.ResendAfter, e.ExpiresIn = h.otpParams()
	case factor.FactorWebAuthn:
		e.Capability = "window.PublicKeyCredential"
	case factor.FactorTOTP:
		e.CodeLength = "6"
	}
	return e
}

// thirdpartyEntry 合成 thirdparty 条目（§2.7.1）：枚举 provider 渠道注册表
// 中 category=oauth 的 type，经 Loader 列行，过滤 is_enabled=1 且
// enable_signin=1（§12.3 行 1464），再按 allowed（应用 oauth_providers
// 白名单，nil / 空 = 未配置 = 跟随全局，§2.1 应用级过滤第三行）过滤；
// 过滤后零可用项返回 nil（不注入）。
// steps 为所辖渠道首 kind 的并集（§2.7.1 行 576：redirect / external /
// qrcode 分别是 redirect / api / qrcode 渠道的首个 kind），按 §1.10 表序。
// type 未在渠道注册表登记的 Provider 不参与（无适配器即无法登录）。
func (h *Handler) thirdpartyEntry(allowed map[string]bool) (*MethodEntry, error) {
	if h.loader == nil {
		return nil, nil
	}
	providers := []SnapshotProvider{}
	channels := map[string]bool{}
	for _, meta := range h.registeredMetas() {
		if meta.Category != categoryOAuth {
			continue
		}
		ps, err := h.loader.ListByType(context.Background(), meta.Type)
		if err != nil {
			return nil, fmt.Errorf("pages: list providers %q: %w", meta.Type, err)
		}
		for _, p := range ps {
			if !p.Enabled() || p.Row == nil || p.Row.EnableSignin != 1 {
				continue
			}
			if len(allowed) > 0 && !allowed[p.Key] {
				continue // 应用 oauth_providers 白名单未放行（§2.1）
			}
			providers = append(providers, SnapshotProvider{
				ProviderKey: p.Key,
				DisplayName: p.Row.DisplayName,
				Type:        p.Type,
				Channel:     string(meta.Channel),
				Icon:        p.Row.IconURL,
				UiGroup:     p.Row.UiGroup,
				SortOrder:   strconv.FormatInt(int64(p.Row.SortOrder), 10),
			})
			channels[string(meta.Channel)] = true
		}
	}
	if len(providers) == 0 {
		return nil, nil
	}
	sort.Slice(providers, func(i, j int) bool { // sort_order ASC, provider_key ASC 稳定全序
		if providers[i].sortKey() != providers[j].sortKey() {
			return providers[i].sortKey() < providers[j].sortKey()
		}
		return providers[i].ProviderKey < providers[j].ProviderKey
	})
	steps := []string{}
	for _, s := range []string{
		string(factor.StepRedirect), // redirect 渠道首 kind
		string(factor.StepExternal), // api 渠道首 kind
		string(factor.StepQRCode),   // qrcode 渠道首 kind
	} {
		if channelHasStep(channels, s) {
			steps = append(steps, s)
		}
	}
	return &MethodEntry{
		Method:    string(factor.FactorThirdParty),
		Usage:     []string{string(factor.UsagePrimary)},
		Steps:     steps,
		Providers: providers,
	}, nil
}

// sortKey 排序用的数值形态（SortOrder 为 §1.12 十进制字符串）。
func (p SnapshotProvider) sortKey() int {
	n, _ := strconv.Atoi(p.SortOrder)
	return n
}

// channelHasStep 渠道 → 首 kind 映射（§2.7.1 行 576、§1.10 行 311-313）。
func channelHasStep(channels map[string]bool, step string) bool {
	switch step {
	case string(factor.StepRedirect):
		return channels[string(provider.ChannelRedirect)]
	case string(factor.StepExternal):
		return channels[string(provider.ChannelAPI)]
	case string(factor.StepQRCode):
		return channels[string(provider.ChannelQRCode)]
	}
	return false
}

// registeredMetas 渠道注册表枚举（type → category / channel）；Deps.Metas
// 注入优先，默认读 provider 全局注册表（各渠道包 init 自注册，§15.3）。
func (h *Handler) registeredMetas() []provider.Meta {
	if h.metas != nil {
		return h.metas()
	}
	out := []provider.Meta{}
	for _, t := range provider.Types() {
		if m, ok := provider.Lookup(t); ok {
			out = append(out, m)
		}
	}
	return out
}

// captchaConfig 首屏 captcha 配置（§2.5 行 477 三处同结构之一；每次现算）：
// Gate 缺席（未装配）时降级内置自绘（§2.5 行 515）。
func (h *Handler) captchaConfig(ctx context.Context) captcha.Config {
	if h.gate == nil {
		return captcha.Config{ProviderKey: captcha.BuiltinProviderKey, Type: captcha.TypeImage}
	}
	return h.gate.Config(ctx)
}

// otpParams otp 系快照参数（§2.1 行 391-394）：codeLength 固定 6 位，
// resendAfter / expiresIn 镜像 settings 键 otp_resend_interval / otp_ttl
// （§5.6 行 1303-1311 默认 60 / 300），十进制字符串（§1.12）。
func (h *Handler) otpParams() (codeLength, resendAfter, expiresIn string) {
	resend := int64(60)
	ttl := int64(300)
	if h.settings != nil {
		if v, ok := h.settings.GetInt64(settings.KeyOtpResendInterval); ok && v > 0 {
			resend = v
		}
		if v, ok := h.settings.GetInt64(settings.KeyOtpTtl); ok && v > 0 {
			ttl = v
		}
	}
	return "6", strconv.FormatInt(resend, 10), strconv.FormatInt(ttl, 10)
}

// factor 注册表读取（nil 注册表 = 全部未注册）。
func (h *Handler) factor(kind factor.FactorKind) (factor.Factor, error) {
	if h.factors == nil {
		return nil, fmt.Errorf("pages: factor registry not configured")
	}
	return h.factors.Get(kind)
}

// boolSetting settings bool 读取，缺键回落 def（§5.6 默认值）。
func (h *Handler) boolSetting(key string, def bool) bool {
	if h.settings != nil {
		if v, ok := h.settings.GetBool(key); ok {
			return v
		}
	}
	return def
}

// sliceSetting settings []string 读取；第二返回值 false = 键缺失。
func (h *Handler) sliceSetting(key string) ([]string, bool) {
	if h.settings != nil {
		return h.settings.GetStringSlice(key)
	}
	return nil, false
}

// stringSetting settings string 读取，缺键 / 空值回落 def。
func (h *Handler) stringSetting(key, def string) string {
	if h.settings != nil {
		if v, ok := h.settings.GetString(key); ok && v != "" {
			return v
		}
	}
	return def
}

// intSetting settings int64 读取，缺键 / 非正值回落 def。
func (h *Handler) intSetting(key string, def int64) int64 {
	if h.settings != nil {
		if v, ok := h.settings.GetInt64(key); ok && v > 0 {
			return v
		}
	}
	return def
}

// usageStrings []factor.Usage → []string。
func usageStrings(us []factor.Usage) []string {
	out := make([]string, len(us))
	for i, u := range us {
		out[i] = string(u)
	}
	return out
}

// stepStrings []factor.StepKind → []string。
func stepStrings(ss []factor.StepKind) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return out
}
