// Package otp 一次性验证码组件（docs/后端架构.md §3.11 行 431-432、
// §10.1 行 1105-1126）。本包只做「6 位码的生成与校验判定」与「发送侧限流
// 判定」；所有键读写一律委托 cache/code.go，不直接访问 Redis、不裸拼键。
// 参数由装配方按 settings（接口文档 §5.6 行 1303-1307）热更新注入。
package otp

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"authloft/internal/cache"
)

// CodeLength 验证码长度（接口文档 §1.3 行 114、§2.6 行 545）。
const CodeLength = 6

// StatusTooManyRequests 发送侧限流命中（接口文档 §1.6 行 242）。
const StatusTooManyRequests = "too_many_requests"

// 接口文档 §5.6 行 1303-1307 的默认值（键名唯一定义处，此处为代码默认）。
const (
	defaultTTL              = 300 * time.Second
	defaultCooldown         = 60 * time.Second
	defaultMaxAttempts      = 5
	defaultTargetDailyLimit = 10
	defaultIPDailyLimit     = 50
)

// Store cache/code.go 的窄接口：本包所有发码 / 校验的键读写都经它，
// 不重复实现键读写（§3.11 行 431）。
type Store interface {
	Send(ctx context.Context, target, purpose, owner, ip, code string) (cache.SendResult, error)
	Verify(ctx context.Context, target, purpose, owner, code string) (cache.CodeVerifyResult, error)
}

// Config 验证码参数（接口文档 §5.6 行 1303-1307 五项，零值回落默认）。
type Config struct {
	// TTL 验证码有效期（otp_ttl，默认 300s）。
	TTL time.Duration
	// Cooldown 同目标重发冷却（otp_resend_interval，默认 60s）。
	Cooldown time.Duration
	// MaxAttempts 单条验证码最大校验失败次数（otp_max_attempts，默认 5）。
	MaxAttempts int
	// TargetDailyLimit 单目标日限额（otp_daily_limit_target，默认 10）。
	TargetDailyLimit int
	// IPDailyLimit 单 IP 日限额（otp_daily_limit_ip，默认 50）。
	IPDailyLimit int
}

// DefaultConfig 返回 §5.6 全默认参数。
func DefaultConfig() Config {
	return Config{
		TTL:              defaultTTL,
		Cooldown:         defaultCooldown,
		MaxAttempts:      defaultMaxAttempts,
		TargetDailyLimit: defaultTargetDailyLimit,
		IPDailyLimit:     defaultIPDailyLimit,
	}
}

// Effective 零值字段回落默认值（settings 只下发部分项时仍可用）。
func (c Config) Effective() Config {
	d := DefaultConfig()
	if c.TTL <= 0 {
		c.TTL = d.TTL
	}
	if c.Cooldown <= 0 {
		c.Cooldown = d.Cooldown
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = d.MaxAttempts
	}
	if c.TargetDailyLimit <= 0 {
		c.TargetDailyLimit = d.TargetDailyLimit
	}
	if c.IPDailyLimit <= 0 {
		c.IPDailyLimit = d.IPDailyLimit
	}
	return c
}

// TTLSeconds 下发 next_step.expires_in（接口文档 §1.3 行 116）。
func (c Config) TTLSeconds() int64 { return seconds(c.Effective().TTL) }

// CooldownSeconds 下发 next_step.retry_after（接口文档 §1.3 行 115）。
func (c Config) CooldownSeconds() int64 { return seconds(c.Effective().Cooldown) }

// CheckOutcome 校验判定（与 cache/code.go 的 VerifyResult 一一对应）。
type CheckOutcome int

const (
	// CheckOK 校验通过，码已消费。
	CheckOK CheckOutcome = iota
	// CheckMismatch 错码，键保留（未达尝试上限）。
	CheckMismatch
	// CheckExhausted 错码且达到尝试上限，键已作废。
	CheckExhausted
	// CheckMissing 无码（未发送 / 已消费 / 已过期 / 值损坏）。
	CheckMissing
)

// CheckResult 校验结果。AttemptsLeft 为剩余可尝试次数：仅错码且键保留时
// 有效（接口文档 §2.6 行 553），成功 / 作废 / 无码均为 0。
type CheckResult struct {
	Outcome      CheckOutcome
	AttemptsLeft int64
}

// Service 验证码生成 / 校验入口。
type Service struct {
	store Store
	cfg   Config
}

// NewService 注入存储与参数；cfg 零值字段按 §5.6 默认值回落。
func NewService(store Store, cfg Config) *Service {
	return &Service{store: store, cfg: cfg.Effective()}
}

// Generate 生成 6 位数字码（crypto/rand，禁 math/rand，§3.11 行 430）。
func Generate() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("otp: generate code: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// WellFormed 是否 6 位纯数字：格式错误由调用方直接判 invalid_request，
// 不进入存储、不消耗尝试次数。
func WellFormed(code string) bool {
	if len(code) != CodeLength {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Issue 生成并原子写入验证码（§10.1 行 1108-1115：一次 EVAL 四写由
// cache/code.go 完成）。target 为手机号 / 邮箱，purpose 为场景，owner 为
// 归属标识（登录链路 tid），ip 为来源 IP。返回码值供调用方投递发送。
func (s *Service) Issue(ctx context.Context, target, purpose, owner, ip string) (string, cache.SendResult, error) {
	if s == nil || s.store == nil {
		return "", cache.SendResult(-1), fmt.Errorf("otp: store not configured")
	}
	// 三要素缺一即拒绝：空 owner 会写出无法校验的码（§10.1 行 1121）。
	if target == "" || purpose == "" || owner == "" {
		return "", cache.SendResult(-1), fmt.Errorf("otp: target/purpose/owner required")
	}
	code, err := Generate()
	if err != nil {
		return "", cache.SendResult(-1), err
	}
	res, err := s.store.Send(ctx, target, purpose, owner, ip, code)
	if err != nil {
		return "", res, err
	}
	return code, res, nil
}

// Check 校验并消费验证码（§10.1 行 1112、1126；code 与 owner 双比对，
// 错码 tries+1，第 MaxAttempts 次错码后键作废）。调用方须先做 WellFormed。
func (s *Service) Check(ctx context.Context, target, purpose, owner, code string) (CheckResult, error) {
	if s == nil || s.store == nil {
		return CheckResult{Outcome: CheckMissing}, fmt.Errorf("otp: store not configured")
	}
	if target == "" || purpose == "" || owner == "" {
		return CheckResult{Outcome: CheckMissing}, fmt.Errorf("otp: target/purpose/owner required")
	}
	res, err := s.store.Verify(ctx, target, purpose, owner, code)
	if err != nil {
		return CheckResult{Outcome: CheckMissing}, err
	}
	switch res.Result {
	case cache.VerifyOK:
		return CheckResult{Outcome: CheckOK}, nil
	case cache.VerifyMismatch:
		return CheckResult{Outcome: CheckMismatch, AttemptsLeft: res.AttemptsLeft}, nil
	case cache.VerifyExhausted:
		return CheckResult{Outcome: CheckExhausted}, nil
	default:
		return CheckResult{Outcome: CheckMissing}, nil
	}
}

// seconds 把 Duration 转为秒数（至少 1s）。
func seconds(d time.Duration) int64 {
	n := int64(d / time.Second)
	if n < 1 {
		n = 1
	}
	return n
}
