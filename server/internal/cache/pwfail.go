// 密码失败计数与临时封禁（docs/后端架构.md §3.10 行 419、§5.1 行 839-840、
// §21.2-C 行 1825）：al:pwf:{user_ref}:{yyyymmdd} 当日失败计数（INCR，首次 /
// 缺失 TTL 时 EXPIRE 至服务器本地当日 24:00），al:pwban:{user_ref} 达阈值
// 后禁止密码登录（SET NX EX，默认 21600s = 6h，可由调用方按 pwd_ban_ttl 注入）。
// 状态映射（status=locked / retry_after 文案）与阈值判定归 service（不在本模块范围）；
// 本文件只做键空间原子读写。
//
// 时区口径：文档只写「当天 24:00」未写时区，代码按 time.Local，时钟经
// Clock 注入（默认 time.Now）便于跨天 / 边界测试。
package cache

import (
	"context"
	_ "embed"
	"fmt"
	"regexp"
	"time"

	"github.com/redis/go-redis/v9"
)

//go:embed lua/capture_pwfail.lua
var capturePwFailScript string

// defaultPwBanTTL 密码登录封禁默认时长（接口文档 §5.6 行 1323：pwd_ban_ttl
// 默认 21600s = 6h；后端架构 §5.1 行 840）。
const defaultPwBanTTL = 21600 * time.Second

// pwFailRedis 本文件用到的 Redis 命令窄接口（*redis.Client 天然满足；
// 窄化便于测试注入 fake，不暴露整个 Cmdable，同 codeRedis 口径）。
// Scan 供管理员解锁的「ip + 账号哈希」维度模式匹配删除。
type pwFailRedis interface {
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
	Get(ctx context.Context, key string) *redis.StringCmd
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd
	Exists(ctx context.Context, keys ...string) *redis.IntCmd
	PTTL(ctx context.Context, key string) *redis.DurationCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Scan(ctx context.Context, cursor uint64, match string, count int64) *redis.ScanCmd
}

// PwFailOptions 密码失败保护参数（由调用方按 settings 注入，零值取默认）。
type PwFailOptions struct {
	// BanTTL 禁止密码登录时长（pwd_ban_ttl，默认 21600s）。
	BanTTL time.Duration
}

// DefaultPwFailOptions 返回 §5.6 默认参数。
func DefaultPwFailOptions() PwFailOptions {
	return PwFailOptions{BanTTL: defaultPwBanTTL}
}

// withDefaults 零值字段回落默认值（settings 只下发部分项时仍可用）。
func (o PwFailOptions) withDefaults() PwFailOptions {
	if o.BanTTL <= 0 {
		o.BanTTL = defaultPwBanTTL
	}
	return o
}

// PwFailStore 密码失败计数 / 封禁存储。
type PwFailStore struct {
	rdb  pwFailRedis
	opts PwFailOptions
	now  func() time.Time
}

// NewPwFailStore 构造密码失败保护存储。rdb 为已连通的 go-redis 客户端，
// opts 零值字段按 §5.6 默认值回落。
func NewPwFailStore(rdb pwFailRedis, opts PwFailOptions) *PwFailStore {
	return newPwFailStore(rdb, opts, time.Now)
}

// newPwFailStore 可注入时钟的内部构造（仅供本包测试跨天 / 边界用）。
func newPwFailStore(rdb pwFailRedis, opts PwFailOptions, now func() time.Time) *PwFailStore {
	return &PwFailStore{rdb: rdb, opts: opts.withDefaults(), now: now}
}

// Capture 记录一次密码失败：INCR 当日计数键，首次 / 缺失 TTL 时 EXPIRE
// 至服务器本地当日 24:00（§5.1 行 839）。返回计数写入后的当前值，供调用方
// 与 pwd_fail_capture / pwd_fail_ban 阈值比较（阈值不在本文件）。
func (s *PwFailStore) Capture(ctx context.Context, userRef string) (int64, error) {
	now := s.now()
	n, err := s.rdb.Eval(ctx, capturePwFailScript,
		[]string{PwFailKey(userRef, dayStamp(now))},
		dayTTL(now),
	).Int64()
	if err != nil {
		return 0, fmt.Errorf("cache: capture pwfail eval: %w", err)
	}
	return n, nil
}

// Count 读取当日失败计数（键缺失 / 已跨天过期视为 0）。
func (s *PwFailStore) Count(ctx context.Context, userRef string) (int64, error) {
	n, err := s.rdb.Get(ctx, PwFailKey(userRef, dayStamp(s.now()))).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("cache: get pwfail: %w", err)
	}
	return n, nil
}

// Ban 禁止密码登录：SET al:pwban:{user_ref} 1 NX EX {BanTTL}（§5.1 行 840）。
// 返回 true 表示本次写入成功（此前未封禁）；false 表示已在封禁中，原 TTL
// 不被续期（NX 语义，避免重复触发无限延长）。
func (s *PwFailStore) Ban(ctx context.Context, userRef string) (bool, error) {
	ok, err := s.rdb.SetNX(ctx, PwBanKey(userRef), "1", s.opts.BanTTL).Result()
	if err != nil {
		return false, fmt.Errorf("cache: ban pwfail: %w", err)
	}
	return ok, nil
}

// IsBanned 返回当前是否处于密码登录封禁期。
func (s *PwFailStore) IsBanned(ctx context.Context, userRef string) (bool, error) {
	n, err := s.rdb.Exists(ctx, PwBanKey(userRef)).Result()
	if err != nil {
		return false, fmt.Errorf("cache: exists pwban: %w", err)
	}
	return n == 1, nil
}

// BanRemaining 返回封禁剩余时长（PTTL），供响应 retry_after（§21.2-C 行
// 1825）。键不存在（-2）或无 TTL（-1）均返回 0，不向调用方暴露负值。
func (s *PwFailStore) BanRemaining(ctx context.Context, userRef string) (time.Duration, error) {
	d, err := s.rdb.PTTL(ctx, PwBanKey(userRef)).Result()
	if err != nil {
		return 0, fmt.Errorf("cache: pttl pwban: %w", err)
	}
	if d < 0 {
		return 0, nil
	}
	return d, nil
}

// Reset 清除当日失败计数与封禁（登录成功 / 管理员解锁等场景）。单个多键
// DEL 命令在 Redis 侧原子执行（§21.2-C 行 1825 的 Reset 语义）。
// 历史日期的计数键已按当日 24:00 自然过期，无需遍历删除。
func (s *PwFailStore) Reset(ctx context.Context, userRef string) error {
	keys := []string{
		PwFailKey(userRef, dayStamp(s.now())),
		PwBanKey(userRef),
	}
	if err := s.rdb.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("cache: reset pwfail: %w", err)
	}
	return nil
}

// accountHashPattern 账号哈希段格式（§8.1 行 1027 user_ref 组合的哈希段：
// sha256(identifier) 的小写十六进制，64 字符）：非该格式（空 / 长度不符 /
// 非 hex）静默 no-op——合法调用方按同款算法构造，脏值只会来自程序错误，
// 不扩散为模式匹配风险（hex 字符集外含 glob 元字符时会误删自有键）。
var accountHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// scanBatchSize SCAN 单批 COUNT（提示值而非硬上限，Redis 自行攒批）。
const scanBatchSize = 100

// DeleteAccountRef 清除「ip + 输入账号哈希」维度的全部失败计数与封禁键
// （管理员解锁，后端架构 §8.1 行 1041：该维度 user_ref = ip + "|" +
// hex(sha256(identifier))，factor/password userRef 同款格式——「账号不存在」
// 阶段种下的键 ip 未知，无法直接构造键名，只能按账号哈希段 SCAN 模式
// 匹配删除：al:pwf:*|{accountHash}:{任意日期} 与 al:pwban:*|{accountHash}）。
// SCAN 游标遍历 + 命中即分批 DEL；pattern 绑定在自有键前缀内，不触碰
// 其它业务键空间。accountHash 非 64 位小写 hex 时 no-op（见上方注释）。
func (s *PwFailStore) DeleteAccountRef(ctx context.Context, accountHash string) error {
	if !accountHashPattern.MatchString(accountHash) {
		return nil
	}
	patterns := []string{
		pwFailKeyPrefix + "*|" + accountHash + ":*",
		pwBanKeyPrefix + "*|" + accountHash,
	}
	for _, pattern := range patterns {
		if err := s.deleteMatching(ctx, pattern); err != nil {
			return err
		}
	}
	return nil
}

// deleteMatching SCAN 游标遍历匹配 pattern 的键并逐批 DEL（游标为 0 时
// 结束；SCAN 期间键集变动由 Redis 保证只遍历开始前存在且未被删除的键，
// 重复出现由 DEL 幂等承担）。
func (s *PwFailStore) deleteMatching(ctx context.Context, pattern string) error {
	var cursor uint64
	for {
		keys, next, err := s.rdb.Scan(ctx, cursor, pattern, scanBatchSize).Result()
		if err != nil {
			return fmt.Errorf("cache: scan pwfail %q: %w", pattern, err)
		}
		if len(keys) > 0 {
			if err := s.rdb.Del(ctx, keys...).Err(); err != nil {
				return fmt.Errorf("cache: delete pwfail %q: %w", pattern, err)
			}
		}
		if next == 0 {
			return nil
		}
		cursor = next
	}
}
