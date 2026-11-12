// 扫码票据结果存储（docs/后端架构.md §3.10 行 419、§5.1 行 842、§11.6.4
// 行 1323-1324、§11.6.5 行 1327-1355）：键 al:ticket:{ticket_id} 的值是
// TicketResult 整值加密后的串（复用 §11.6.1 封装、purpose=ticket），Redis
// 内不留明文（§11.6.5 行 1327）。
//
// 写入语义（接口文档 §2.7.4 行 643-644）：
//   - scanned：SET NX，重复上报幂等，已存在（含 success）一律不覆盖；
//   - complete：覆盖 scanned，但已存在 success 时不覆盖——先 GET 解密判断，
//     再以 Lua CAS（原值未变才替换）原子落库，避免并发写覆盖已成功票据。
//
// 读取语义（§11.6.5 行 1355）：Take 用 GETDEL 原子取走并解密，同一票据只有
// 一个读取方能取到（仅限 success / failed 终态）；Peek 读取并解密但不清除，
// 供轮询读取 mfa_pending 等非终态快照；Wait 只轮询键是否存在（200ms 退避，
// 受 ctx 取消），不消费。
//
// 加密实现不在本包：sealer 由装配方注入（purpose=ticket 固定在 sealer 实现内），
// 本包不自造加密、不引 security 真密钥；测试用 Fake sealer。
// Redis 客户端经构造注入（叶子件，不 import config / repo，同 code.go 口径）。
package cache

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"authloft/gen/go/token"
)

const (
	// defaultTicketTTL 票据结果缺省寿命（§11.6.4 行 1318：TicketPayload.exp
	// 默认 600s）。
	defaultTicketTTL = 600 * time.Second
	// ticketWaitInterval Wait 的轮询退避（§3.10 行 419：200ms）。
	ticketWaitInterval = 200 * time.Millisecond
	// ticketCASMaxAttempts complete 阶段 CAS 重试上限（同一票据并发写的极端
	// 情形；正常单写方一次即成功）。
	ticketCASMaxAttempts = 3
)

// ticketStatusSuccess TicketResult.status 的成功终态（§11.6.5 行 1333：
// scanned | success | failed），用于 complete 阶段「已存在 success 不覆盖」。
const ticketStatusSuccess = "success"

// ErrTicketWaitTimeout Wait 在超时窗口内未等到键出现。可判别结果，区别于
// ctx 取消返回的 context.Canceled / context.DeadlineExceeded。
var ErrTicketWaitTimeout = errors.New("cache: ticket wait timeout")

// TicketSealer 把 TicketResult 与存储串互转（§11.6.1 / §11.6.5：整值加密，
// purpose=ticket 由实现内固定，本包不感知密钥与算法）。
type TicketSealer interface {
	// Seal 加密整值，返回可写入 Redis 的串。
	Seal(*token.TicketResult) (string, error)
	// Open 解密存储串为 TicketResult。
	Open(string) (*token.TicketResult, error)
}

// TicketOptions 票据存储参数（由调用方按 ticket.exp 注入，零值取默认）。
type TicketOptions struct {
	// TTL TicketResult.expires_at 缺省（<=0）时的键寿命，默认 600s。
	TTL time.Duration
}

// DefaultTicketOptions 返回 §11.6.4 默认参数（600s）。
func DefaultTicketOptions() TicketOptions {
	return TicketOptions{TTL: defaultTicketTTL}
}

// withDefaults 零值字段回落默认值。
func (o TicketOptions) withDefaults() TicketOptions {
	if o.TTL <= 0 {
		o.TTL = defaultTicketTTL
	}
	return o
}

// TicketWriteResult 写入结论。
type TicketWriteResult int

const (
	// TicketWriteSkipped 已存在，按写入语义不覆盖。
	TicketWriteSkipped TicketWriteResult = 0
	// TicketWriteOK 已写入（新建或覆盖 scanned / failed）。
	TicketWriteOK TicketWriteResult = 1
)

// ticketRedis 本文件用到的 Redis 命令窄接口（*redis.Client 天然满足；
// 窄化便于测试注入 fake，不暴露整个 Cmdable，同 codeRedis 口径）。
type ticketRedis interface {
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd
	Get(ctx context.Context, key string) *redis.StringCmd
	GetDel(ctx context.Context, key string) *redis.StringCmd
	Exists(ctx context.Context, keys ...string) *redis.IntCmd
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
}

// ticketWriteScript complete 阶段原子覆盖写（接口文档 §2.7.4）：仅当键值仍
// 为调用方此前读到的版本（ARGV[1]，"" 表示期望键不存在）才 SET，否则返回 0
// 由调用方重读重试。Lua 无法解密状态，故「是否 success」的判断在 Go 侧，
// 键的替换原子性由 cache/lua/ticket_write.lua 保证（§3.10 行 420）。
//
//go:embed lua/ticket_write.lua
var ticketWriteScript string

// TicketStore al:ticket:{ticket_id} 读写封装。
type TicketStore struct {
	rdb    ticketRedis
	sealer TicketSealer
	opts   TicketOptions
	now    func() time.Time
}

// NewTicketStore 构造票据存储。rdb 为已连通的 go-redis 客户端，sealer 为
// §11.6.1 封装的注入实现，opts 零值字段按 600s 回落。
func NewTicketStore(rdb ticketRedis, sealer TicketSealer, opts TicketOptions) *TicketStore {
	return newTicketStore(rdb, sealer, opts, time.Now)
}

// newTicketStore 可注入时钟的内部构造（仅供本包测试 TTL 对齐用）。
func newTicketStore(rdb ticketRedis, sealer TicketSealer, opts TicketOptions, now func() time.Time) *TicketStore {
	return &TicketStore{rdb: rdb, sealer: sealer, opts: opts.withDefaults(), now: now}
}

// WriteScanned 写入 stage=scanned 的空结果（接口文档 §2.7.4 行 643）：
// SET NX EX，重复上报幂等，已存在则不覆盖（含 success）。返回
// TicketWriteSkipped 表示键已存在、本次未写入。
func (s *TicketStore) WriteScanned(ctx context.Context, id string, res *token.TicketResult) (TicketWriteResult, error) {
	sealed, ttl, err := s.sealResult(res)
	if err != nil {
		return TicketWriteSkipped, err
	}
	ok, err := s.rdb.SetNX(ctx, TicketKey(id), sealed, ttl).Result()
	if err != nil {
		return TicketWriteSkipped, fmt.Errorf("cache: setnx ticket: %w", err)
	}
	if !ok {
		return TicketWriteSkipped, nil
	}
	return TicketWriteOK, nil
}

// WriteComplete 写入 stage=complete 结果（接口文档 §2.7.4 行 644）：整体
// 覆盖 scanned，但已存在 success 时不覆盖。并发下以 Lua CAS 保证不覆盖
// 已成功票据；CAS 冲突时重读重试（上限 ticketCASMaxAttempts）。
func (s *TicketStore) WriteComplete(ctx context.Context, id string, res *token.TicketResult) (TicketWriteResult, error) {
	sealed, ttl, err := s.sealResult(res)
	if err != nil {
		return TicketWriteSkipped, err
	}
	key := TicketKey(id)
	for attempt := 0; attempt < ticketCASMaxAttempts; attempt++ {
		expected, successExists, err := s.currentValue(ctx, key)
		if err != nil {
			return TicketWriteSkipped, err
		}
		if successExists {
			return TicketWriteSkipped, nil
		}
		n, err := s.rdb.Eval(ctx, ticketWriteScript, []string{key}, expected, sealed, seconds(ttl)).Int64()
		if err != nil {
			return TicketWriteSkipped, fmt.Errorf("cache: write ticket eval: %w", err)
		}
		if n == 1 {
			return TicketWriteOK, nil
		}
	}
	return TicketWriteSkipped, fmt.Errorf("cache: write ticket: cas conflict after %d attempts", ticketCASMaxAttempts)
}

// currentValue 读取当前存储串并解密判断是否已 success。返回 expected 为
// 当前原始值（键不存在时为空串），successExists 为 true 时调用方不再写入。
func (s *TicketStore) currentValue(ctx context.Context, key string) (expected string, successExists bool, err error) {
	raw, err := s.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("cache: get ticket: %w", err)
	}
	prev, err := s.sealer.Open(raw)
	if err != nil {
		return "", false, fmt.Errorf("cache: open ticket result: %w", err)
	}
	if prev == nil {
		return "", false, errors.New("cache: open ticket result: nil result")
	}
	if prev.GetStatus() == ticketStatusSuccess {
		return "", true, nil
	}
	return raw, false, nil
}

// Peek 读取并解密票据结果但不清除（§11.6.5 行 1424：mfa_pending 为非终态，
// 轮询只读快照、不 GETDEL）。nil / nil 表示键不存在（未就绪 / 已过期 /
// 已被消费）。
func (s *TicketStore) Peek(ctx context.Context, id string) (*token.TicketResult, error) {
	raw, err := s.rdb.Get(ctx, TicketKey(id)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cache: get ticket: %w", err)
	}
	res, err := s.sealer.Open(raw)
	if err != nil {
		return nil, fmt.Errorf("cache: open ticket result: %w", err)
	}
	return res, nil
}

// Take 以 GETDEL 原子取走并解密（§11.6.5 行 1355）：同一票据仅一个读取方
// 能取到，其余因键不存在得到 (nil, nil)。nil / nil 表示未就绪、已过期或
// 已被消费。
func (s *TicketStore) Take(ctx context.Context, id string) (*token.TicketResult, error) {
	raw, err := s.rdb.GetDel(ctx, TicketKey(id)).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cache: getdel ticket: %w", err)
	}
	res, err := s.sealer.Open(raw)
	if err != nil {
		return nil, fmt.Errorf("cache: open ticket result: %w", err)
	}
	return res, nil
}

// Wait 等待票据结果键出现（§3.10 行 419：200ms 退避、受请求 ctx 取消），
// 只等待不消费：
//   - 键已存在或等待中出现 → nil；
//   - 超时未出现 → ErrTicketWaitTimeout；
//   - ctx 取消 / 截止 → ctx.Err()。
func (s *TicketStore) Wait(ctx context.Context, id string, timeout time.Duration) error {
	exists := func() (bool, error) {
		n, err := s.rdb.Exists(ctx, TicketKey(id)).Result()
		if err != nil {
			return false, fmt.Errorf("cache: exists ticket: %w", err)
		}
		return n == 1, nil
	}
	if ok, err := exists(); err != nil || ok {
		return err
	}
	if timeout <= 0 {
		return ErrTicketWaitTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(ticketWaitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return ErrTicketWaitTimeout
		case <-ticker.C:
			ok, err := exists()
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
		}
	}
}

// sealResult 加密整值并算出键 TTL。TTL 与 TicketPayload.exp 对齐
// （§11.6.4 行 1323、§11.6.5 行 1337：TicketResult.expires_at 与
// ticket.exp 一致）；expires_at 缺省（<=0）时用 opts.TTL（默认 600s）。
func (s *TicketStore) sealResult(res *token.TicketResult) (string, time.Duration, error) {
	if res == nil {
		return "", 0, errors.New("cache: seal ticket result: nil result")
	}
	sealed, err := s.sealer.Seal(res)
	if err != nil {
		return "", 0, fmt.Errorf("cache: seal ticket result: %w", err)
	}
	return sealed, time.Duration(s.ttlSeconds(res)) * time.Second, nil
}

// ttlSeconds 返回键寿命秒数（至少 1s，不产生无 TTL 的键）。
func (s *TicketStore) ttlSeconds(res *token.TicketResult) int64 {
	if exp := res.GetExpiresAt(); exp > 0 {
		return seconds(time.Unix(exp, 0).Sub(s.now()))
	}
	return seconds(s.opts.TTL)
}
