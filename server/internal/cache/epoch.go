// epoch 读取链（docs/后端架构.md §11.1 步骤 3 + §5.1 行 863）：
// 进程内 localCache（TTL 60s）→ Redis GET al:pwdep:{uid} → 缺失回源
// 注入函数并 SET 新值（TTL 24h）。Redis client 与回源函数由构造注入
// （叶子件，不 import config / repo）；epoch 递增写路径（改密 / 重置 /
// 管理员禁用）不在本文件，归对应链路卡。
package cache

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// EpochSource epoch 回源函数：从 DB 真源读 user.epoch。真源装配文档未
// 覆盖（§11.1 只写「回源 DB」），按注入函数实现（装配点归
// 后续 handler / bootstrap）。
type EpochSource func(ctx context.Context, uid int64) (int64, error)

// epochRedis 本文件用到的 Redis 命令窄接口（*redis.Client 天然满足；
// 窄化便于测试注入 fake 计数，不暴露整个 Cmdable）。
type epochRedis interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
}

const (
	// epochLocalTTL 进程内 localCache TTL（§11.1 步骤 3：60s）。
	epochLocalTTL = 60 * time.Second
	// epochRedisTTL al:pwdep:{uid} 键 TTL（§5.1 行 863：24h）。
	epochRedisTTL = 24 * time.Hour
)

// EpochStore al:pwdep 读取 / 回源写回 + 进程内 localCache。
type EpochStore struct {
	rdb    epochRedis
	source EpochSource
	local  *epochLocalCache
}

// NewEpochStore 构造 epoch 读取链。rdb 为已连通的 go-redis 客户端；
// source 为 DB 回源函数（Redis 缺失时调用并 SET 新值 TTL 24h）。
func NewEpochStore(rdb epochRedis, source EpochSource) *EpochStore {
	return newEpochStore(rdb, source, epochLocalTTL)
}

// newEpochStore 可注入 localCache TTL 的内部构造（仅供本包测试用）。
func newEpochStore(rdb epochRedis, source EpochSource, localTTL time.Duration) *EpochStore {
	return &EpochStore{
		rdb:    rdb,
		source: source,
		local:  newEpochLocalCache(localTTL),
	}
}

// Current 返回 uid 当前 epoch，三级读取（§11.1 步骤 3）：
//  1. 进程内 localCache（TTL 60s）命中即返回；
//  2. Redis GET al:pwdep:{uid} 命中即返回（并回填 localCache）；
//  3. 缺失（redis.Nil）→ 调回源 source 并 SET 新值 TTL 24h（回填 localCache）。
//
// 取舍（文档未覆盖，待定）：Redis 故障（非 Nil 错误）时
// 同样降级回源 DB——缓存故障不应放大为全站校验不可用；回源后 SET 失败
// 仅忽略（值已在手，下次读取再回源）；并发 miss 会重复回源（幂等读，
// 可接受，不做 singleflight）。
func (s *EpochStore) Current(ctx context.Context, uid int64) (int64, error) {
	if v, ok := s.local.get(uid); ok {
		return v, nil
	}
	v, err := s.rdb.Get(ctx, EpochKey(uid)).Int64()
	if err == nil {
		s.local.set(uid, v)
		return v, nil
	}
	// redis.Nil（键缺失，§11.1 正常回源路径）与 Redis 故障（降级，见上
	// 方注释取舍）均走回源。
	cur, srcErr := s.source(ctx, uid)
	if srcErr != nil {
		return 0, srcErr
	}
	_ = s.rdb.Set(ctx, EpochKey(uid), cur, epochRedisTTL).Err()
	s.local.set(uid, cur)
	return cur, nil
}

// epochLocalCache 进程内 epoch 缓存：RWMutex + map（读多写少，热路径
// RLock）。条目按 TTL 失效；活跃 uid 有界（≈60s 窗口内校验过的用户数），
// 过期项不主动清除，仅失效后可被覆盖。
type epochLocalCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[int64]epochLocalEntry
}

// epochLocalEntry 单条缓存值与过期时刻。
type epochLocalEntry struct {
	value   int64
	expires time.Time
}

func newEpochLocalCache(ttl time.Duration) *epochLocalCache {
	return &epochLocalCache{ttl: ttl, entries: make(map[int64]epochLocalEntry)}
}

// get 读取未过期条目；过期视同 miss。
func (c *epochLocalCache) get(uid int64) (int64, bool) {
	c.mu.RLock()
	e, ok := c.entries[uid]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return 0, false
	}
	return e.value, true
}

// set 写入条目（过期时刻 = now + ttl）。
func (c *epochLocalCache) set(uid, value int64) {
	c.mu.Lock()
	c.entries[uid] = epochLocalEntry{value: value, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}
