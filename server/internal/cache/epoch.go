// epoch 键空间读取链（docs/后端架构.md §11.1 步骤 3 + §5.1）：
//   - Check：会话校验热路径，一条 MGET 双键读 al:pwdep:{uid} +
//     al:sess:ev:{sid}（epoch 比对 + sid 逐出判定合并为一次 Redis 访问；
//     进程内 epoch 本地缓存已移除——逐出须实时生效，逐出状态不进 60s
//     本地缓存，热路径固定 1 次 Redis）；
//   - Current：签发侧读（SessionWriter.Write / OIDC 令牌盖章），GET →
//     缺失回源 SET（TTL 24h），不在每请求校验热路径上。
//
// Redis client 与回源函数由构造注入（叶子件，不 import config / repo）；
// epoch 的 DB 递增写路径（改密 / 重置 / 管理员禁用，repo.UserRepo.IncEpoch）
// 不在本文件，改密链路通过 Sync 同步缓存。
package cache

import (
	"context"
	"strconv"
	"time"
)

// EpochSource epoch 回源函数：从 DB 真源读 user.epoch。
type EpochSource func(ctx context.Context, uid int64) (int64, error)

// epochRedis 本文件用到的 Redis 命令窄接口（*RedisClient 适配器天然满足；
// 窄化便于测试注入 fake 计数，不暴露整个客户端）。
type epochRedis interface {
	Get(ctx context.Context, key string) StringResult
	MGet(ctx context.Context, keys ...string) MGetResult
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) StatusResult
	Del(ctx context.Context, keys ...string) IntResult
}

// epochRedisTTL al:pwdep:{uid} 键 TTL（§5.1：24h）。
const epochRedisTTL = 24 * time.Hour

// EpochStore al:pwdep 读取 / 回源写回 + 会话失效检查（Check 双键读）。
type EpochStore struct {
	rdb    epochRedis
	source EpochSource
}

// NewEpochStore 构造。rdb 为已连通的 Redis 客户端适配器；source 为 DB
// 回源函数（Redis 缺失 / 命令级故障 fail-open 时调用，键缺失回源后 SET
// 新值 TTL 24h）。
func NewEpochStore(rdb epochRedis, source EpochSource) *EpochStore {
	return &EpochStore{rdb: rdb, source: source}
}

// Current 返回 uid 当前 epoch（签发侧：会话签发盖章 / OIDC 令牌）：
//  1. Redis GET al:pwdep:{uid} 命中即返回；
//  2. 缺失（redis.Nil）→ 调回源 source 并 SET 新值 TTL 24h。
//
// 取舍（文档未覆盖，待定）：Redis 故障（非 Nil 错误）时同样降级回源 DB
// ——缓存故障不应放大为签发不可用；回源后 SET 失败仅忽略（值已在手，
// 下次读取再回源）；并发 miss 会重复回源（幂等读，可接受）。
// 注意：校验侧已改走 Check（双键一次读、无本地缓存），本方法不在每请求
// 校验热路径上。
func (s *EpochStore) Current(ctx context.Context, uid int64) (int64, error) {
	v, err := s.rdb.Get(ctx, EpochKey(uid)).Int64()
	if err == nil {
		return v, nil
	}
	// Nil（键缺失，正常回源路径）与 Redis 故障（降级，见上方注释取舍）
	// 均走回源。
	cur, srcErr := s.source(ctx, uid)
	if srcErr != nil {
		return 0, srcErr
	}
	_ = s.rdb.Set(ctx, EpochKey(uid), cur, epochRedisTTL).Err()
	return cur, nil
}

// Check 会话失效检查（§11.1 步骤 3，每请求热路径）：一条 MGET 双键读
// al:pwdep:{uid} + al:sess:ev:{sid}，返回 uid 当前 epoch 与 sid 逐出标记
// （epoch 比对归校验链）。逐出键存在即 revoked，短路返回（不再回源 epoch
// ——失效判定不需要值）。分支顺序与 §11.1 口径一致：
//  1. 逐出标记存在 → (0, true, nil)；
//  2. epoch 缓存存在 → (缓存值, false, nil)；
//  3. epoch 缓存缺失（正常 Nil）→ 回源 DB 取 epoch，SET al:pwdep（TTL 24h
//     不变）；SET 失败仅忽略（值已在手，下次读取再回源）。
//
// 命令级错误（网络 / 故障）→ fail-open 降级：逐出状态无法判定按「未逐出」
// 放行（revoked=false），回源 DB 取 epoch 供比对，不回写缓存（故障期写入
// 不可靠，且缓存回写会掩盖故障）；仅回源也失败才返回错误（上层按基础设施
// 错误语义处理，与原 epoch 链故障边界一致）。固有取舍：故障期逐出可被绕过
// （被逐出的 sid 仍能通过校验，直到故障恢复），epoch 侧有 DB 真源兜底。
// 缓存值损坏（非整数）同按故障走回源比对，DB 为唯一真源。
func (s *EpochStore) Check(ctx context.Context, uid int64, sid string) (int64, bool, error) {
	epochKey, evictKey := EpochKey(uid), SessionEvictKey(sid)
	vals, err := s.rdb.MGet(ctx, epochKey, evictKey).Result()
	if err == nil && len(vals) == 2 {
		// 逐出优先：标记存在即失效，epoch 不再回源。
		if vals[1] != nil {
			return 0, true, nil
		}
		if vals[0] != nil {
			if cur, perr := strconv.ParseInt(*vals[0], 10, 64); perr == nil {
				return cur, false, nil
			}
		} else {
			// 正常 Nil：回源 + SET TTL 24h。
			cur, srcErr := s.source(ctx, uid)
			if srcErr != nil {
				return 0, false, srcErr
			}
			_ = s.rdb.Set(ctx, epochKey, cur, epochRedisTTL).Err()
			return cur, false, nil
		}
	}
	// 命令级错误 / 应答长度异常 / 缓存值损坏 → fail-open 回源比对
	//（revoked=false，不回写缓存）。
	cur, srcErr := s.source(ctx, uid)
	if srcErr != nil {
		return 0, false, srcErr
	}
	return cur, false, nil
}

// Sync 覆盖式同步 al:pwdep:{uid}（改密 / 重置 / 管理员禁用后的写路径，
// §5.1、TTL 24h）：SET 新值，让后续校验立即看到新 epoch。SET 失败时退而
// DEL（读取链 miss 后回源 DB 真源，避免 Redis 残留旧值最长 24h）；DEL 也
// 失败才向调用方报错（由调用方决定失败语义）。
func (s *EpochStore) Sync(ctx context.Context, uid int64, epoch int16) error {
	if err := s.rdb.Set(ctx, EpochKey(uid), int64(epoch), epochRedisTTL).Err(); err != nil {
		_ = s.rdb.Del(ctx, EpochKey(uid)).Err()
		return err
	}
	return nil
}
