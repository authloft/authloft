// Package otp otp_sms / otp_email 共用因子实现（docs/后端架构.md §3.8 行 389-390、
// §8.2 行 1032-1039）。两因子协议与语义完全一致，仅 target 渠道与投递器不同。
package otp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"authloft/internal/factor"
	core "authloft/internal/otp"
	"authloft/internal/repo/model"
)

// purposeMFA 二次因子阶段写入码的 purpose（接口文档 §10.1 行 1121）。
const purposeMFA = "mfa"

// 登录流程域 status（接口文档 §1.6 行 228-273 封闭集合子集）。
const (
	StatusInvalidRequest  = "invalid_request"
	StatusUserNotFound    = "user_not_found"
	StatusInvalidCode     = "invalid_code"
	StatusCodeExpired     = "code_expired"
	StatusTooManyAttempts = "too_many_attempts"
	StatusStepInvalid     = "step_invalid"
)

// Sender 投递通道（短信 / 邮件），装配方按厂商注入；本包不直接调第三方 SDK。
type Sender interface {
	SendCode(ctx context.Context, target, code string) error
}

// IPResolver 取请求来源 IP（cache/code 的 IP 日限额键，§10.3 行 1145）。
type IPResolver interface {
	ClientIP(ctx context.Context) string
}

// Factor otp_sms / otp_email 因子实例（kind 决定渠道与渲染 method）。
type Factor struct {
	kind   factor.FactorKind
	svc    *core.Service
	sender Sender
	ip     IPResolver
	cfg    core.Config
}

// New 构造因子；kind 只能是 otp_sms / otp_email。
func New(kind factor.FactorKind, svc *core.Service, sender Sender, ip IPResolver, cfg core.Config) (*Factor, error) {
	if kind != factor.FactorOTPSMS && kind != factor.FactorOTPEmail {
		return nil, fmt.Errorf("otp: unsupported kind %q", kind)
	}
	if svc == nil {
		return nil, fmt.Errorf("otp: service not configured")
	}
	return &Factor{kind: kind, svc: svc, sender: sender, ip: ip, cfg: cfg.Effective()}, nil
}

// Kind 返回本实例渠道（otp_sms / otp_email）。
func (f *Factor) Kind() factor.FactorKind { return f.kind }

// Usages 主因子与二次因子均可用（§6.1 行 917-918）。
func (f *Factor) Usages() []factor.Usage {
	return []factor.Usage{factor.UsagePrimary, factor.UsageSecondary}
}

// Steps challenge → form（接口文档 §1.10 行 303-304）。
func (f *Factor) Steps() []factor.StepKind {
	return []factor.StepKind{factor.StepChallenge, factor.StepForm}
}

// Start 处理 challenge 步（§8.2）：解析目标 → 存在性检查 → 生成并写码 → 投递。
// 主因子目标不存在返回 user_not_found，且不写码 / 不发信 / 不签发 login_token。
func (f *Factor) Start(ctx *factor.FactorContext) (*factor.StepResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("otp: nil factor context")
	}

	secondary := isSecondary(ctx)
	var target string
	if secondary {
		t, err := f.mfaTarget(ctx)
		if err != nil {
			return nil, err
		}
		if t == "" {
			// §8.2：MFA 阶段目标必然已绑定且已验证，取不到属内部状态不一致。
			return nil, fmt.Errorf("otp: MFA target not bound")
		}
		target = t
	} else {
		target = f.target(ctx.Payload)
		if target == "" {
			return &factor.StepResult{Status: StatusInvalidRequest}, nil
		}
		user, err := f.findTarget(ctx, target)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		if user == nil {
			return &factor.StepResult{Status: StatusUserNotFound}, nil
		}
	}

	// engine 在 Start 之前即由 loadPayload 生成 tid / 选定 flow，因此
	// 首个 challenge 请求也能按 §10.1 行 1121 以 owner=tid、purpose=flow 绑定写码。
	owner := ctx.Login.GetTid()
	purpose := ctx.Login.GetFlow()
	if secondary {
		purpose = purposeMFA
	}

	code, result, err := f.svc.Issue(ctx.Context, target, purpose, owner, f.clientIP(ctx.Context))
	if err != nil {
		return nil, err
	}
	// 冷却 / 日限额由 cache/code 原子判定，这里只映射结论（§10.3）。
	if denial := core.Judge(result, f.cfg, time.Now()); !denial.Allowed {
		return &factor.StepResult{Status: denial.Status, RetryAfter: denial.RetryAfter}, nil
	}

	if f.sender == nil {
		return nil, fmt.Errorf("otp: sender not configured")
	}
	// §8.2：发送失败不回滚已写的码，允许 60s 后重发；错误交由编排层置 failed。
	if err := f.sender.SendCode(ctx.Context, target, code); err != nil {
		return nil, err
	}

	return f.formStep(), nil
}

// Verify 校验 form 步（§8.2 行 1035-1039）：target/purpose/owner 均取自
// login_token，与 Start 写码时逐项一致；错码 / 超限 / 过期分别映射 status。
func (f *Factor) Verify(ctx *factor.FactorContext) (*factor.VerifyResult, error) {
	if ctx == nil || ctx.Login == nil {
		return &factor.VerifyResult{Status: StatusStepInvalid}, nil
	}

	code := ""
	if ctx.Payload != nil {
		code = strings.TrimSpace(ctx.Payload.Code)
	}
	// 格式错不进入存储、不消耗尝试次数（接口文档 §1.6 invalid_request）。
	if !core.WellFormed(code) {
		return &factor.VerifyResult{Status: StatusInvalidRequest}, nil
	}

	secondary := isSecondary(ctx)
	purpose := ctx.Login.GetFlow()
	target := ctx.Login.GetCh().GetTarget()
	if secondary {
		purpose = purposeMFA
		t, err := f.mfaTarget(ctx)
		if err != nil {
			return nil, err
		}
		if t == "" {
			return nil, fmt.Errorf("otp: MFA target not bound")
		}
		target = t
	}
	if target == "" {
		return &factor.VerifyResult{Status: StatusStepInvalid}, nil
	}

	res, err := f.svc.Check(ctx.Context, target, purpose, ctx.Login.GetTid(), code)
	if err != nil {
		return nil, err
	}
	switch res.Outcome {
	case core.CheckOK:
		if secondary {
			return &factor.VerifyResult{Passed: true, UID: ctx.Login.GetUid()}, nil
		}
		user, err := f.findTarget(ctx, target)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		if user == nil {
			return &factor.VerifyResult{Status: StatusUserNotFound}, nil
		}
		return &factor.VerifyResult{Passed: true, UID: user.ID}, nil
	case core.CheckMismatch:
		return &factor.VerifyResult{Status: StatusInvalidCode, AttemptsLeft: res.AttemptsLeft}, nil
	case core.CheckExhausted:
		return &factor.VerifyResult{Status: StatusTooManyAttempts}, nil
	default:
		return &factor.VerifyResult{Status: StatusCodeExpired}, nil
	}
}

// formStep 下发 form 渲染信息（step / method / fields 与 §1.3 行 114-116 一致）。
func (f *Factor) formStep() *factor.StepResult {
	return &factor.StepResult{
		Kind:   factor.StepForm,
		Method: f.kind,
		Fields: []factor.Field{{
			Name:        "code",
			Label:       "验证码",
			Type:        "otp",
			Required:    true,
			Length:      core.CodeLength,
			MaxAttempts: int64(f.cfg.MaxAttempts),
		}},
		RetryAfter: f.cfg.CooldownSeconds(),
		ExpiresIn:  f.cfg.TTLSeconds(),
	}
}

// target 取本次请求的目标（短信取 phone，邮件取 email）。
func (f *Factor) target(p *factor.Payload) string {
	if p == nil {
		return ""
	}
	switch f.kind {
	case factor.FactorOTPSMS:
		return strings.TrimSpace(p.Phone)
	case factor.FactorOTPEmail:
		return strings.TrimSpace(p.Email)
	}
	return ""
}

// findTarget 按目标反查用户（存在性检查，§8.2 行 1033）。
func (f *Factor) findTarget(ctx *factor.FactorContext, target string) (*model.User, error) {
	if ctx.Users == nil {
		return nil, fmt.Errorf("otp: users repo not configured")
	}
	switch f.kind {
	case factor.FactorOTPSMS:
		return ctx.Users.FindByPhone(ctx.Context, target)
	case factor.FactorOTPEmail:
		return ctx.Users.FindByEmail(ctx.Context, target)
	}
	return nil, fmt.Errorf("otp: unsupported kind %q", f.kind)
}

// mfaTarget 二次因子目标只能取 uid 绑定的资料（禁止请求侧注入，§8.2 行 1036）。
func (f *Factor) mfaTarget(ctx *factor.FactorContext) (string, error) {
	if ctx.Login == nil {
		return "", nil
	}
	uid := ctx.Login.GetUid()
	if uid == 0 {
		return "", nil
	}
	if ctx.Users == nil {
		return "", fmt.Errorf("otp: users repo not configured")
	}
	user, err := ctx.Users.FindByID(ctx.Context, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", nil
		}
		return "", err
	}
	if user == nil {
		return "", nil
	}
	switch f.kind {
	case factor.FactorOTPSMS:
		if user.Phone == nil || user.PhoneVerified != 1 {
			return "", nil
		}
		return *user.Phone, nil
	case factor.FactorOTPEmail:
		if user.Email == nil || user.EmailVerified != 1 {
			return "", nil
		}
		return *user.Email, nil
	}
	return "", nil
}

// clientIP 取来源 IP；装配方未注入时用固定标记兜底，避免空键绕过 IP 日限额。
func (f *Factor) clientIP(ctx context.Context) string {
	if f.ip == nil {
		return "unknown"
	}
	if ip := f.ip.ClientIP(ctx); ip != "" {
		return ip
	}
	return "unknown"
}

// isSecondary 二次因子阶段判定与 engine.change() 同口径（§7.3 行 1000）：
// 已有 uid 且 passed 非空。
func isSecondary(ctx *factor.FactorContext) bool {
	if ctx == nil || ctx.Login == nil {
		return false
	}
	return ctx.Login.GetUid() != 0 && len(ctx.Login.GetPassed()) > 0
}
