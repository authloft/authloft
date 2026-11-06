// Package password 账密因子（docs/后端架构.md §3.8 行 388、§8.1 行 1019-1030）。
// 单步 form、仅主因子：校验凭证，失败累计 / 封禁复用 cache/pwfail，成功投递
// 「清零失败计数」任务（窄接口注入，不直接写队列）。
package password

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"authloft/internal/factor"
	"authloft/internal/repo/model"
	"authloft/internal/security"
)

const (
	// credentialKind user_credential.kind 取值（§4.2 行 680-684）。
	credentialKind = "password"
	// userStatusNormal user.user_status=1 正常，0 禁用（§4.2 行 630）。
	userStatusNormal = 1
)

// 登录流程域 status（接口文档 §1.6 行 228-273 封闭集合子集）。
const (
	StatusInvalidRequest     = "invalid_request"
	StatusInvalidCredentials = "invalid_credentials"
	StatusLocked             = "locked"
	StatusUserDisabled       = "user_disabled"
)

// 接口文档 §5.6 行 1303-1307 默认值。
const (
	defaultFailCapture = 3
	defaultFailBan     = 6
	defaultBanTTL      = 21600 * time.Second
)

// Users 密码因子所需的用户读取子集。接口文档 §2.1 行 350 的 username 字段
// 承载「用户名/邮箱/手机号」，故需 FindByUsername；factor.UserRepo
// 只暴露 FindByID/FindByPhone/FindByEmail，本包声明所需子集由装配方注入，
// 不修改公共接口（repo.UserRepo 天然满足）。
type Users interface {
	FindByUsername(ctx context.Context, username string) (*model.User, error)
	FindByPhone(ctx context.Context, phone string) (*model.User, error)
	FindByEmail(ctx context.Context, email string) (*model.User, error)
}

// FailStore 失败计数 / 封禁（cache/pwfail.go，§5.1 行 839-840）。
type FailStore interface {
	Capture(ctx context.Context, userRef string) (int64, error)
	IsBanned(ctx context.Context, userRef string) (bool, error)
	Ban(ctx context.Context, userRef string) (bool, error)
	BanRemaining(ctx context.Context, userRef string) (time.Duration, error)
}

// ResetQueue 成功登录后投递「清零失败计数」任务（§8.1 行 1029）；
// 延迟队列满时可丢弃，不影响登录结果。
type ResetQueue interface {
	ResetPasswordFailures(ctx context.Context, userRefs ...string) error
}

// IPResolver 取本次请求来源 IP：用户不存在时 user_ref = ip + 输入账号哈希
// （§8.1 行 1027）。装配方从 HTTP 中间件注入。
type IPResolver interface {
	ClientIP(ctx context.Context) string
}

// Options 失败阈值（接口文档 §5.6 行 1303-1307，settings 热更新由装配方注入）。
type Options struct {
	// Capture 达到即要求人机校验（pwd_fail_capture，默认 3）。
	Capture int64
	// Ban 达到即封禁（pwd_fail_ban，默认 6）。
	Ban int64
	// BanTTL 封禁时长（pwd_ban_ttl，默认 21600s）。
	BanTTL time.Duration
}

// DefaultOptions 返回 §5.6 全默认阈值。
func DefaultOptions() Options {
	return Options{Capture: defaultFailCapture, Ban: defaultFailBan, BanTTL: defaultBanTTL}
}

func (o Options) effective() Options {
	d := DefaultOptions()
	if o.Capture <= 0 {
		o.Capture = d.Capture
	}
	if o.Ban <= 0 {
		o.Ban = d.Ban
	}
	if o.BanTTL <= 0 {
		o.BanTTL = d.BanTTL
	}
	return o
}

// Factor 账密因子。
type Factor struct {
	users Users
	fails FailStore
	reset ResetQueue
	ip    IPResolver
	opts  Options
}

// New 注入依赖；fails / reset / ip 可留空（对应能力降级，但生产装配必须提供）。
func New(users Users, fails FailStore, reset ResetQueue, ip IPResolver, opts Options) *Factor {
	return &Factor{users: users, fails: fails, reset: reset, ip: ip, opts: opts.effective()}
}

// Kind 固定 password。
func (f *Factor) Kind() factor.FactorKind { return factor.FactorPassword }

// Usages 仅主因子（§8.1 行 1020）。
func (f *Factor) Usages() []factor.Usage { return []factor.Usage{factor.UsagePrimary} }

// Steps 单步 form（接口文档 §1.10 行 306）。
func (f *Factor) Steps() []factor.StepKind { return []factor.StepKind{factor.StepForm} }

// Start 单步因子没有 challenge 步，派发器不会调用；仍返回 form 描述。
func (f *Factor) Start(*factor.FactorContext) (*factor.StepResult, error) {
	return &factor.StepResult{
		Kind:   factor.StepForm,
		Method: factor.FactorPassword,
		Fields: []factor.Field{
			{Name: "username", Label: "用户名/邮箱/手机号", Type: "text", Required: true},
			{Name: "password", Label: "密码", Type: "password", Required: true},
			// 人机校验按 §8.1 由 captcha/gate.go 统一拦截（§9.3 唯一拦截点），
			// 该字段仅在触发后必填。
			{Name: "captcha", Label: "人机校验", Type: "captcha", Required: false},
		},
	}, nil
}

// Verify 校验账密（§8.1）：先判封禁，再查凭证，失败累计并在阈值处封禁。
func (f *Factor) Verify(ctx *factor.FactorContext) (*factor.VerifyResult, error) {
	if ctx == nil || ctx.Payload == nil {
		return failure(StatusInvalidRequest), nil
	}
	identifier := strings.TrimSpace(ctx.Payload.Username)
	password := ctx.Payload.Password
	if identifier == "" || password == "" {
		return failure(StatusInvalidRequest), nil
	}
	if f == nil || f.users == nil || ctx.Credentials == nil {
		return nil, fmt.Errorf("password: dependencies not configured")
	}

	user, err := f.lookup(ctx.Context, identifier)
	if err != nil {
		return nil, err
	}
	// user_ref = user_id（用户存在）或 ip + 输入账号哈希（用户不存在，§8.1）。
	ref := f.userRef(ctx.Context, identifier, user)

	// ① 封禁判定优先于任何凭证查询（避免封禁期内继续消耗验证开销）。
	if f.fails != nil {
		banned, err := f.fails.IsBanned(ctx.Context, ref)
		if err != nil {
			return nil, err
		}
		if banned {
			return f.locked(ctx.Context, ref)
		}
	}

	if user == nil {
		return f.onFailure(ctx, ref)
	}
	// 账号被禁用单独返回 user_disabled（§8.1）。
	if user.UserStatus != userStatusNormal {
		return failure(StatusUserDisabled), nil
	}

	cred, err := ctx.Credentials.FindByUserAndKind(ctx.Context, user.ID, credentialKind)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return f.onFailure(ctx, ref)
		}
		return nil, err
	}
	if cred == nil || cred.IsEnabled != 1 {
		return f.onFailure(ctx, ref)
	}
	if err := security.VerifyPassword(password, string(cred.Secret)); err != nil {
		if errors.Is(err, security.ErrPasswordMismatch) || errors.Is(err, security.ErrInvalidHash) {
			return f.onFailure(ctx, ref)
		}
		return nil, err
	}

	// 成功：投递清零任务（§8.1 行 1029）。队列满允许丢弃，不影响本次登录。
	if f.reset != nil {
		_ = f.reset.ResetPasswordFailures(ctx.Context, ref)
	}
	return &factor.VerifyResult{Passed: true, UID: user.ID}, nil
}

// lookup 委托共用 lookupIdentifier（与引擎读计数侧共用同一用户
// 解析，保证「用户是否存在」两侧判定一致）。
func (f *Factor) lookup(ctx context.Context, identifier string) (*model.User, error) {
	return lookupIdentifier(ctx, f.users, identifier)
}

// userRef 生成失败计数 / 封禁所用 user_ref：委托 UserRefOf 唯一格式定义
// （§8.1 行 1027；两侧收敛）。
func (f *Factor) userRef(ctx context.Context, identifier string, user *model.User) string {
	ip := ""
	if f.ip != nil {
		ip = f.ip.ClientIP(ctx)
	}
	return UserRefOf(identifier, user, ip)
}

// onFailure 失败累计（§8.1 行 1026-1028）：达到封禁阈值即封禁并返回 locked。
// 达到人机校验阈值（Capture）后的 captcha_required / captcha_invalid 由
// captcha/gate.go 统一拦截（§9.3），本因子不重复校验，避免二次消费凭据。
func (f *Factor) onFailure(ctx *factor.FactorContext, ref string) (*factor.VerifyResult, error) {
	if f.fails == nil {
		return failure(StatusInvalidCredentials), nil
	}
	n, err := f.fails.Capture(ctx.Context, ref)
	if err != nil {
		return nil, err
	}
	if n >= f.opts.Ban {
		if _, err := f.fails.Ban(ctx.Context, ref); err != nil {
			return nil, err
		}
		return f.locked(ctx.Context, ref)
	}
	return failure(StatusInvalidCredentials), nil
}

// locked 返回 locked + 剩余秒数（接口文档 §1.6 行 241）。
func (f *Factor) locked(ctx context.Context, ref string) (*factor.VerifyResult, error) {
	var remaining time.Duration
	if f.fails != nil {
		d, err := f.fails.BanRemaining(ctx, ref)
		if err != nil {
			return nil, err
		}
		remaining = d
	}
	if remaining <= 0 {
		remaining = f.opts.BanTTL
	}
	return &factor.VerifyResult{Status: StatusLocked, RetryAfter: int64((remaining + time.Second - 1) / time.Second)}, nil
}

func failure(status string) *factor.VerifyResult {
	return &factor.VerifyResult{Status: status}
}
