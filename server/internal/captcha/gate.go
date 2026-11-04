// Package captcha 是人机校验的唯一拦截点（docs/后端架构.md §9，
// docs/接口文档.md §2.5）。所有 challenge 步与密码登录都经 Gate 判定；
// 触发阈值每次从注入的 settings 读取（不缓存配置），校验一律委托
// 注入的 Verifier，本包不自造图形码算法、不读 DB/Redis。
package captcha

import (
	"context"
	"errors"
	"fmt"

	"authloft/internal/settings"
)

// 登录流程域的人机校验错误状态（docs/接口文档.md §1.6）。
const (
	StatusRequired = "captcha_required"
	StatusInvalid  = "captcha_invalid"
)

// 内置图形码（降级目标，docs/接口文档.md §2.5）。
const (
	BuiltinProviderKey = "builtin_image"
	TypeImage          = "image"
)

const defaultPwdFailCapture = 3

// ErrInvalid 由 Verifier 返回，表示校验不通过或凭据已使用（→ captcha_invalid）。
// 其它错误一律视为基础设施错误，由调用方映射为 failed。
var ErrInvalid = errors.New("captcha: invalid or used")

// Config 是给前端的当前生效配置（每次现算，不走缓存）。
// 字段名对应接口文档 §1.3 的 captcha.providerKey/type/siteKey。
type Config struct {
	ProviderKey string `json:"providerKey"`
	Type        string `json:"type"`
	SiteKey     string `json:"siteKey,omitempty"`
}

// Submission 是前端回传的人机校验凭据（§2.5）。
type Submission struct {
	ProviderKey string
	Token       string
	ID          string
	Answer      string
}

// Provider 由装配方按当前生效 captcha Provider 解析：Type 取
// image/turnstile/recaptcha/hcaptcha，SiteKey 为该渠道站点键。
type Provider struct {
	ProviderKey string
	Type        string
	SiteKey     string
}

// ProviderCatalog 返回当前生效、可用的 captcha Provider；返回 nil,nil
// 表示无可用项（enable=0 / 未配置 / 健康检查失败），Gate 会降级到内置图形码。
type ProviderCatalog interface {
	Current(ctx context.Context) (*Provider, error)
}

// Verifier 按 providerKey 分派到对应渠道的校验实现。
// 校验不通过 / 已使用必须返回 ErrInvalid（可包裹）；其它错误视为基础设施错误。
type Verifier interface {
	Verify(ctx context.Context, providerKey string, sub Submission) error
}

// Settings 只需要读取触发阈值（§9：pwd_fail_capture，运行时热更新）。
type Settings interface {
	GetInt64(key string) (int64, bool)
}

// Request 描述一次拦截判定。
// Challenge 覆盖所有 challenge 步（验证码下发、MFA 挑战、三方二维码拉取等）；
// Password 覆盖密码登录，FailedAttempts 为同账号当日失败次数。
type Request struct {
	Challenge      bool
	Password       bool
	FailedAttempts int64
	Submission     *Submission
}

// Outcome 是判定结果：Status 为空 = 放行；否则为 captcha_required/captcha_invalid。
type Outcome struct {
	Required bool
	Config   Config
	Status   string
}

// Gate 唯一拦截点。
type Gate struct {
	settings Settings
	catalog  ProviderCatalog
	verifier Verifier
}

// NewGate 注入依赖，本包不持有任何存储句柄。
func NewGate(s Settings, catalog ProviderCatalog, verifier Verifier) *Gate {
	return &Gate{settings: s, catalog: catalog, verifier: verifier}
}

// Config 每次现算当前生效配置：当前 Provider 无可用项或配置非法时降级为
// 内置图形码（§2.5 降级语义）。
func (g *Gate) Config(ctx context.Context) Config {
	if g == nil || g.catalog == nil {
		return builtin()
	}
	p, err := g.catalog.Current(ctx)
	if err != nil || p == nil {
		return builtin()
	}
	return normalize(p)
}

// Evaluate 判定本次请求是否需要人机校验，并（在提供 Submission 时）执行校验。
// 返回基础设施错误时由调用方映射为 failed；业务失败通过 Outcome.Status 表达。
func (g *Gate) Evaluate(ctx context.Context, req Request) (Outcome, error) {
	required := req.Challenge
	if req.Password && req.FailedAttempts >= g.threshold() {
		required = true
	}
	if !required {
		return Outcome{}, nil
	}

	out := Outcome{Required: true, Config: g.Config(ctx)}
	if req.Submission == nil {
		out.Status = StatusRequired
		return out, nil
	}
	// 只能拿当前生效配置的 providerKey 校验，防止前端任意指定渠道。
	if req.Submission.ProviderKey != out.Config.ProviderKey {
		out.Status = StatusInvalid
		return out, nil
	}
	if g.verifier == nil {
		return out, fmt.Errorf("captcha: verifier not configured")
	}
	err := g.verifier.Verify(ctx, out.Config.ProviderKey, *req.Submission)
	if err == nil {
		return out, nil
	}
	if errors.Is(err, ErrInvalid) {
		out.Status = StatusInvalid
		return out, nil
	}
	return out, err
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

// normalize 校验 Provider 配置；type 必须属封闭集合，非法即降级。
func normalize(p *Provider) Config {
	if p == nil || p.ProviderKey == "" {
		return builtin()
	}
	switch p.Type {
	case "image":
		return Config{ProviderKey: p.ProviderKey, Type: "image"}
	case "turnstile", "recaptcha", "hcaptcha":
		if p.SiteKey == "" {
			return builtin()
		}
		return Config{ProviderKey: p.ProviderKey, Type: p.Type, SiteKey: p.SiteKey}
	default:
		return builtin()
	}
}

func builtin() Config {
	return Config{ProviderKey: BuiltinProviderKey, Type: TypeImage}
}
