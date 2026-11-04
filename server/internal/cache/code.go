// 验证码的存储与校验（docs/后端架构.md §3.10 行 418）：发码 4 次写合并为
// 1 次 Lua EVAL，校验用 Lua 原子 GETDEL；原子性全部由 Lua 保证，otp 层
// 不直接碰 Redis。键名统一由 keys.go 构造（§5.1 行 835-838）。
//
// Redis 客户端经构造注入（叶子件，不 import config / repo，同 nonce.go /
// epoch.go 口径）；TTL / 冷却 / 日限额 / 尝试上限由调用方按 settings 热更新
// 注入（§10.3），零值字段回落 §10.3 默认值。
package cache

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

//go:embed lua/send_code.lua
var sendCodeScript string

//go:embed lua/verify_code.lua
var verifyCodeScript string

// 验证码相关默认值（docs/后端架构.md §10.3 行 1143-1147；接口文档 §5.6
// 行 1304-1308 为键名与默认值的唯一定义处，§10.3 为速查）。
const (
	defaultCodeTTL         = 300 * time.Second
	defaultCodeCooldown    = 60 * time.Second
	defaultCodeTargetLimit = 10
	defaultCodeIPLimit     = 50
	defaultCodeMaxAttempts = 5
)

// codeRedis 本文件用到的 Redis 命令窄接口（*redis.Client 天然满足；
// 窄化便于测试注入计数 Hook 与 fake，不暴露整个 Cmdable）。
type codeRedis interface {
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
}

// CodeOptions 发码 / 校验参数（由调用方按 settings 注入，零值字段取默认）。
type CodeOptions struct {
	// TTL 验证码有效期（otp_ttl，默认 300s）。
	TTL time.Duration
	// Cooldown 同目标重发冷却（otp_resend_interval，默认 60s）。
	Cooldown time.Duration
	// TargetDailyLimit 单目标日限额（otp_daily_limit_target，默认 10）。
	TargetDailyLimit int
	// IPDailyLimit 单 IP 日限额（otp_daily_limit_ip，默认 50）。
	IPDailyLimit int
	// MaxAttempts 单条验证码最大校验失败次数（otp_max_attempts，默认 5）。
	MaxAttempts int
}

// DefaultCodeOptions 返回 §10.3 全默认参数。
func DefaultCodeOptions() CodeOptions {
	return CodeOptions{
		TTL:              defaultCodeTTL,
		Cooldown:         defaultCodeCooldown,
		TargetDailyLimit: defaultCodeTargetLimit,
		IPDailyLimit:     defaultCodeIPLimit,
		MaxAttempts:      defaultCodeMaxAttempts,
	}
}

// withDefaults 零值字段回落默认值（settings 只下发部分项时仍可用）。
func (o CodeOptions) withDefaults() CodeOptions {
	d := DefaultCodeOptions()
	if o.TTL <= 0 {
		o.TTL = d.TTL
	}
	if o.Cooldown <= 0 {
		o.Cooldown = d.Cooldown
	}
	if o.TargetDailyLimit <= 0 {
		o.TargetDailyLimit = d.TargetDailyLimit
	}
	if o.IPDailyLimit <= 0 {
		o.IPDailyLimit = d.IPDailyLimit
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = d.MaxAttempts
	}
	return o
}

// CodeStore 验证码唯一存储与校验实现。
type CodeStore struct {
	rdb  codeRedis
	opts CodeOptions
	now  func() time.Time
}

// NewCodeStore 构造验证码存储。rdb 为已连通的 go-redis 客户端，
// opts 零值字段按 §10.3 默认值回落。
func NewCodeStore(rdb codeRedis, opts CodeOptions) *CodeStore {
	return &CodeStore{rdb: rdb, opts: opts.withDefaults(), now: time.Now}
}

// storedCode al:code:{target}:{purpose} 的值（§10.1 行 1117：JSON
// {code,owner,tries,sent_at}）。owner 语义由调用方决定：登录链路传 tid，
// 账号域传 uid（此处不做业务判断）。
type storedCode struct {
	Code   string `json:"code"`
	Owner  string `json:"owner"`
	Tries  int    `json:"tries"`
	SentAt int64  `json:"sent_at"`
}

// SendResult 发码结果；三种拒绝各自独立，不得吞成同一种错误。
type SendResult int

const (
	// SendOK 发码成功（4 写已原子落库）。
	SendOK SendResult = iota
	// SendCooldown 冷却中（al:rl:send:{target} 已存在）。
	SendCooldown
	// SendTargetDailyLimit 单目标日限额到达。
	SendTargetDailyLimit
	// SendIPDailyLimit 单 IP 日限额到达。
	SendIPDailyLimit
)

// Send 发码：一次 EVAL 原子完成 code 写入 + 冷却 SET NX EX + 两级日计数
// INCR/EXPIRE（§10.1 行 1108-1115）。target 为手机号 / 邮箱等发送目标，
// purpose 为场景（login / register / reset / bind 等），owner 为归属标识，
// ip 为请求来源。
func (s *CodeStore) Send(ctx context.Context, target, purpose, owner, ip, code string) (SendResult, error) {
	now := s.now()
	payload, err := json.Marshal(storedCode{
		Code:   code,
		Owner:  owner,
		Tries:  0,
		SentAt: now.Unix(),
	})
	if err != nil {
		return SendResult(-1), fmt.Errorf("cache: marshal code: %w", err)
	}
	ymd := dayStamp(now)
	keys := []string{
		CodeKey(target, purpose),
		SendCooldownKey(target),
		SendDayKey(target, ymd),
		IPDayKey(ip, ymd),
	}
	n, err := s.rdb.Eval(ctx, sendCodeScript, keys,
		string(payload),
		seconds(s.opts.TTL),
		seconds(s.opts.Cooldown),
		int64(s.opts.TargetDailyLimit),
		int64(s.opts.IPDailyLimit),
		dayTTL(now),
	).Int64()
	if err != nil {
		return SendResult(-1), fmt.Errorf("cache: send code eval: %w", err)
	}
	switch SendResult(n) {
	case SendOK, SendCooldown, SendTargetDailyLimit, SendIPDailyLimit:
		return SendResult(n), nil
	default:
		return SendResult(-1), fmt.Errorf("cache: send code eval: unexpected result %d", n)
	}
}

// VerifyResult 校验结果。
type VerifyResult int

const (
	// VerifyOK 校验成功，验证码已消费（键已删）。
	VerifyOK VerifyResult = 1
	// VerifyMismatch 错码，tries+1 后键保留（tries < 上限）。
	VerifyMismatch VerifyResult = 0
	// VerifyExhausted 错码且达到尝试上限，键已作废删除。
	VerifyExhausted VerifyResult = 2
	// VerifyMissing 无码（未发送 / 已消费 / 已过期 / 值损坏）。
	VerifyMissing VerifyResult = -1
)

// CodeVerifyResult 校验结论与剩余尝试次数（接口文档 §2.6 行 553：
// invalid_code 必须携带剩余次数）。AttemptsLeft 仅在错码且键保留时有效，
// 成功 / 作废 / 无码均为 0。
type CodeVerifyResult struct {
	Result       VerifyResult
	AttemptsLeft int64
}

// Verify 校验验证码：Lua 原子 GETDEL（§10.1 行 1112、1126），比对 code
// 与 owner；错码 tries+1 仅在 tries < MaxAttempts 时回写（保留原 TTL），
// 第 MaxAttempts 次错码删除键；正确码消费后键必删。Lua 同时返回剩余次数。
func (s *CodeStore) Verify(ctx context.Context, target, purpose, owner, code string) (CodeVerifyResult, error) {
	raw, err := s.rdb.Eval(ctx, verifyCodeScript,
		[]string{CodeKey(target, purpose)},
		code, owner, int64(s.opts.MaxAttempts),
	).Slice()
	if err != nil {
		return CodeVerifyResult{Result: VerifyMissing}, fmt.Errorf("cache: verify code eval: %w", err)
	}
	if len(raw) != 2 {
		return CodeVerifyResult{Result: VerifyMissing}, fmt.Errorf("cache: verify code eval: unexpected reply length %d", len(raw))
	}
	n, ok := raw[0].(int64)
	if !ok {
		return CodeVerifyResult{Result: VerifyMissing}, fmt.Errorf("cache: verify code eval: unexpected result %v", raw[0])
	}
	left, ok := raw[1].(int64)
	if !ok {
		return CodeVerifyResult{Result: VerifyMissing}, fmt.Errorf("cache: verify code eval: unexpected attempts %v", raw[1])
	}
	switch VerifyResult(n) {
	case VerifyOK, VerifyMismatch, VerifyExhausted, VerifyMissing:
		return CodeVerifyResult{Result: VerifyResult(n), AttemptsLeft: left}, nil
	default:
		return CodeVerifyResult{Result: VerifyMissing}, fmt.Errorf("cache: verify code eval: unexpected result %d", n)
	}
}

// seconds 把 Duration 转为 Redis EX 秒数（至少 1s）。
func seconds(d time.Duration) int64 {
	n := int64(d / time.Second)
	if n < 1 {
		n = 1
	}
	return n
}

// dayTTL 返回距服务器本地当天 24:00 的秒数（§5.1 行 837-838「当天 24:00」
// 过期；日计数键首次 INCR 时由 Lua EXPIRE）。跨午夜时钟回拨等极端情况
// 至少保留 1s。
func dayTTL(now time.Time) int64 {
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
	n := int64(next.Sub(now) / time.Second)
	if n < 1 {
		n = 1
	}
	return n
}
