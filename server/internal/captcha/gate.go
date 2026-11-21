// Package captcha 是人机校验的唯一拦截点（docs/后端架构.md §9.3，
// docs/接口文档.md §2.5）。是否需要人机校验一律由 Gate 按场景查表判定，
// 调用方只提供本次请求所属场景；触发阈值每次从注入的 settings 读取（不缓存
// 配置），第三方校验运行期经注入的 factory 按当前生效 provider 构造（§9.1
// 阶段三），图形码走内置路径不入 factory，本包不自造图形码算法、不读 DB/Redis。
package captcha

import (
	"context"
	"errors"
	"fmt"

	"authloft/internal/provider"
	"authloft/internal/settings"
)

// 人机校验业务细分码（docs/接口文档.md §1.6）：仅作 ErrorInfo.code，
// 不作登录流程态 status。码值集中在本包常量，生产代码（含 account 域）
// 一律引用，不复制字面量。
const (
	StatusRequired = "captcha_required"
	StatusInvalid  = "captcha_invalid"
)

// 内置图形码（降级目标，docs/接口文档.md §2.5）。
const (
	BuiltinProviderKey = "builtin_image"
	TypeImage          = "image"
)

// 场景（scene）是「是否需要 captcha」的唯一判定维度（docs/后端架构.md §9.3）：
// 场景取值与 docs/接口文档.md §2.5 触发表的行对齐，由调用入口按当前业务环节
// 确定、不经请求传入；与验证内核的 biz_purpose 正交，不得互相引用取值。
const (
	// SceneOtpDispatch 任何一次性验证码下发（触发表第 1 行）。
	SceneOtpDispatch = "otp_dispatch"
	// SceneWebAuthnOptions WebAuthn 取 options（第 2 行）。
	SceneWebAuthnOptions = "webauthn_options"
	// ScenePasswordLogin 密码登录（第 3 行）：按同账号当日失败计数判定。
	ScenePasswordLogin = "password_login"
	// SceneSignupResetDispatch 注册 / 重置的下发（第 4 行）。
	SceneSignupResetDispatch = "signup_reset_dispatch"
	// SceneMfaDispatch 两步验证阶段下发（第 5 行）。
	SceneMfaDispatch = "mfa_dispatch"
	// SceneContactBind 绑定 / 换绑手机号、邮箱（第 6 行）。
	SceneContactBind = "contact_bind"
	// SceneQrcodeFetch 拉取小程序码（第 7 行）：按扫码 provider 的
	// need_captcha 配置判定，判定输入由唯一调用方（qrcode service）从
	// provider 实例 Ext 读取，新调用点不得缺省该输入。
	SceneQrcodeFetch = "qrcode_fetch"
	// SceneNoDispatch 不含下发的环节——已下发后的校验 / 提交、三方免密建号
	// （只提交用户名）——统一用本场景，对应触发表「不需要、本环节无下发」一行。
	SceneNoDispatch = "no_dispatch"
)

// rule 是触发表一行的判定规则。
type rule uint8

const (
	// ruleRequired 必须（也是未知场景的兜底结论）。
	ruleRequired rule = iota
	// ruleNotRequired 不需要。
	ruleNotRequired
	// rulePasswordThreshold 按密码登录失败计数与阈值比较得出。
	rulePasswordThreshold
	// ruleQrcodeNeedCaptcha 按拉码判定输入 NeedCaptcha 得出（扫码 provider
	// 的 need_captcha 配置）。
	ruleQrcodeNeedCaptcha
)

// sceneRules 与 docs/接口文档.md §2.5 触发表的行对齐：表内 7 个场景
// （第 1-7 行）+ SceneNoDispatch（「不需要、本环节无下发」）；新增场景只加行，
// 不改判定逻辑。
// §2.5 触发表第 8 行（TOTP 绑定）当前无 gate 调用点——绑定链路由 account 域
// 承担且本就不触发 captcha；若日后绑定改走 gate，再按该行新增场景。
var sceneRules = map[string]rule{
	SceneOtpDispatch:         ruleRequired,          // 第 1 行 任何一次性验证码下发
	SceneWebAuthnOptions:     ruleNotRequired,       // 第 2 行 WebAuthn 取 options
	ScenePasswordLogin:       rulePasswordThreshold, // 第 3 行 密码登录
	SceneSignupResetDispatch: ruleRequired,          // 第 4 行 注册 / 重置的下发
	SceneMfaDispatch:         ruleRequired,          // 第 5 行 两步验证阶段下发
	SceneContactBind:         ruleRequired,          // 第 6 行 绑定 / 换绑联系方式
	SceneQrcodeFetch:         ruleQrcodeNeedCaptcha, // 第 7 行 拉取小程序码（按 provider 配置）
	SceneNoDispatch:          ruleNotRequired,       // 无下发环节（表「不需要」一行）
}

const defaultPwdFailCapture = 3

// Config 是给前端的当前生效配置（每次现算，不走缓存）。
// 字段名对应接口文档 §1.3 的 captcha.providerKey/type/siteKey。
type Config struct {
	ProviderKey string `json:"providerKey"`
	Type        string `json:"type"`
	SiteKey     string `json:"siteKey,omitempty"`
}

// ProviderCatalog 返回当前生效、可用的 captcha Provider（完整实例，经
// catalog 不读 LRU 的直读通道取得，§9.1）；返回 nil,nil 表示无可用项
// （enable=0 / 未配置 / 健康检查失败），Gate 会降级到内置图形码。
type ProviderCatalog interface {
	Current(ctx context.Context) (*provider.Provider, error)
}

// Settings 只需要读取触发阈值（§9：pwd_fail_capture，运行时热更新）。
type Settings interface {
	GetInt64(key string) (int64, bool)
}

// Request 描述一次拦截判定。Scene 由调用入口按当前业务环节给出（取值见本包
// 场景常量），调用方不自行判定是否触发；FailedAttempts 只由密码登录场景消费，
// 为同账号当日失败次数；NeedCaptcha 只由拉码场景消费，为该扫码 provider 的
// need_captcha 配置（判定输入而非判定结果，与 FailedAttempts 同构）。
type Request struct {
	Scene          string
	FailedAttempts int64
	NeedCaptcha    bool
	Submission     *Submission
}

// Outcome 是判定结果：Status 为空 = 放行；否则为 StatusRequired / StatusInvalid。
type Outcome struct {
	Required bool
	Config   Config
	Status   string
}

// Failure 是一次人机校验失败的领域错误：Code 仅作 ErrorInfo.code，Config 为
// 与判定同源的当前生效配置（§1.5 / §9.1），不套登录流程信封、不作流程态。
type Failure struct {
	Code   string
	Config Config
}

func (f *Failure) Error() string { return "captcha: " + f.Code }

// FailureFrom 把判定结果转成领域错误；放行（Status 为空）时返回 nil。
func FailureFrom(out Outcome) *Failure {
	if out.Status == "" {
		return nil
	}
	return &Failure{Code: out.Status, Config: out.Config}
}

// Gate 唯一拦截点（§9.1 阶段三形态）：持有 factory + 当前 provider 源，
// 运行期按当前生效 provider 经 factory 构造第三方校验实现——配置变化即构造
// 出新对象，不存在「旧配置的 verifier 实例」；图形码不入 factory（校验依赖
// Store 运行时依赖），保留内置路径。
type Gate struct {
	settings Settings
	catalog  ProviderCatalog
	images   Store
	factory  provider.VerifierFactory
}

// NewGate 注入依赖：catalog 为当前生效 provider 源（直读、不缓存，§9.1）；
// images 为内置图形码存储（cache.CaptchaStore，Lua GETDEL 一次性）；factory
// 为第三方校验工厂（生产装配注入 provider.NewVerifier，测试注入 fake）。
// 本包不持有任何 DB 句柄。
func NewGate(s Settings, catalog ProviderCatalog, images Store, factory provider.VerifierFactory) *Gate {
	return &Gate{settings: s, catalog: catalog, images: images, factory: factory}
}

// currentProvider 直读当前生效 provider（§9.1 不缓存通道，每次现算）：
// error / 无可用项一律返回 nil——按健康检查失败降级为内置图形码（§2.5），
// 不阻断判定、不缓存。
func (g *Gate) currentProvider(ctx context.Context) *provider.Provider {
	if g == nil || g.catalog == nil {
		return nil
	}
	p, err := g.catalog.Current(ctx)
	if err != nil || p == nil {
		return nil
	}
	return p
}

// Config 每次现算当前生效配置：当前 Provider 无可用项或配置非法时降级为
// 内置图形码（§2.5 降级语义）。
func (g *Gate) Config(ctx context.Context) Config {
	return normalize(g.currentProvider(ctx))
}

// Evaluate 据场景查表判定本次请求是否需要人机校验，并（在提供 Submission 时）
// 执行校验。返回基础设施错误时由调用方映射为 failed；业务失败通过
// Outcome.Status 表达。
func (g *Gate) Evaluate(ctx context.Context, req Request) (Outcome, error) {
	if !g.requires(req) {
		return Outcome{}, nil
	}

	// 单次直读取值（§9.1）：下发配置与 factory 构造共用同一实例，永远同源；
	// 提前取值归 nil 时按健康检查失败降级内置图形码（§2.5）。
	p := g.currentProvider(ctx)
	out := Outcome{Required: true, Config: normalize(p)}
	if req.Submission == nil {
		out.Status = StatusRequired
		return out, nil
	}
	// 只能拿当前生效配置的 providerKey 校验，防止前端任意指定渠道。
	if req.Submission.ProviderKey != out.Config.ProviderKey {
		out.Status = StatusInvalid
		return out, nil
	}
	// 图形码（内置项与 type=image 的表内行，§9.2 同一校验路径）不入 factory；
	// 第三方经 factory 按当前生效 provider 运行期构造（§9.1）——配置变化即
	// 构造出新对象，不存在「旧配置的 verifier 实例」。
	if out.Config.Type == TypeImage {
		return g.evaluateImage(ctx, out, *req.Submission)
	}
	if g.factory == nil {
		return out, fmt.Errorf("captcha: verifier factory not configured")
	}
	verifier, err := g.factory(p)
	if err != nil {
		return out, err
	}
	err = verifier.Verify(ctx, out.Config.ProviderKey, *req.Submission)
	if err == nil {
		return out, nil
	}
	if errors.Is(err, ErrInvalid) {
		out.Status = StatusInvalid
		return out, nil
	}
	return out, err
}

// evaluateImage 内置图形码判定路径（§9.2）：id + answer 核 al:cap:{id}，
// GETDEL 原子消费由注入的 Store 保证（正确 / 错误都消费）。
func (g *Gate) evaluateImage(ctx context.Context, out Outcome, sub Submission) (Outcome, error) {
	if g.images == nil {
		return out, fmt.Errorf("captcha: image store not configured")
	}
	if sub.ID == "" {
		out.Status = StatusInvalid
		return out, nil
	}
	ok, err := g.images.Verify(ctx, sub.ID, sub.Answer)
	if err != nil {
		return out, fmt.Errorf("captcha: verify image store: %w", err)
	}
	if !ok {
		out.Status = StatusInvalid
		return out, nil
	}
	return out, nil
}

// requires 查触发表得出本次是否必须人机校验。未登记场景（含空串）一律按
// 「必须」处理：宁可多校验一次，也不因调用方漏写场景而静默放行。
func (g *Gate) requires(req Request) bool {
	switch sceneRules[req.Scene] {
	case ruleNotRequired:
		return false
	case rulePasswordThreshold:
		return req.FailedAttempts >= g.threshold()
	case ruleQrcodeNeedCaptcha:
		return req.NeedCaptcha
	default:
		return true
	}
}

// threshold 每次从 settings 读 pwd_fail_capture，未配置或非法时取默认 3。
func (g *Gate) threshold() int64 {
	if g.settings != nil {
		if v, ok := g.settings.GetInt64(settings.KeyPwdFailCapture); ok && v > 0 {
			return v
		}
	}
	return defaultPwdFailCapture
}

// normalize 校验当前生效 Provider 实例并折算下发配置（siteKey 取
// ext.client_id，§9.1）；type 必须属封闭集合，非法即降级。
func normalize(p *provider.Provider) Config {
	if p == nil || p.Key == "" {
		return builtin()
	}
	switch p.Type {
	case TypeImage:
		return Config{ProviderKey: p.Key, Type: TypeImage}
	case TypeTurnstile, TypeRecaptcha, TypeHcaptcha:
		siteKey := ""
		if p.Ext != nil {
			siteKey = p.Ext.GetClientId()
		}
		if siteKey == "" {
			return builtin()
		}
		return Config{ProviderKey: p.Key, Type: p.Type, SiteKey: siteKey}
	default:
		return builtin()
	}
}

func builtin() Config {
	return Config{ProviderKey: BuiltinProviderKey, Type: TypeImage}
}
