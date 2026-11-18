// al:perm:admins（SET）读写封装：登录签发侧读成员判定、回源后回填，
// 正常模式启动预热重建全量集合。集合无 TTL，与 user_permission 的一致性
// 由启动预热 + 登录回填共同保证（§5.1、§4.8）。
package cache

import (
	"context"
)

// permAdminsRedis 本文件用到的 Redis 命令窄接口（*RedisClient 适配器天然满足；
// 窄化便于测试注入 fake）。
type permAdminsRedis interface {
	SIsMember(ctx context.Context, key string, member interface{}) BoolResult
	SAdd(ctx context.Context, key string, members ...interface{}) IntResult
	Del(ctx context.Context, keys ...string) IntResult
}

// PermissionAdminsStore al:perm:admins 集合的读 / 回填 / 预热封装。
type PermissionAdminsStore struct {
	rdb permAdminsRedis
}

// NewPermissionAdminsStore 注入已连通的 Redis 客户端适配器（或其窄接口 fake）。
func NewPermissionAdminsStore(rdb permAdminsRedis) *PermissionAdminsStore {
	return &PermissionAdminsStore{rdb: rdb}
}

// IsMember 判定 uid 是否在集合（SISMEMBER）。
func (s *PermissionAdminsStore) IsMember(ctx context.Context, uid int64) (bool, error) {
	return s.rdb.SIsMember(ctx, PermissionAdminsKey(), uid).Result()
}

// Add 回填补全集合（SADD）；无 TTL，写入失败交由调用方按「仅忽略」处理。
func (s *PermissionAdminsStore) Add(ctx context.Context, uid int64) error {
	return s.rdb.SAdd(ctx, PermissionAdminsKey(), uid).Err()
}

// Rebuild 启动预热：先 DEL 清旧集合再批量 SADD 全量 uid，避免重启后残留
// 上一生命周期的成员；空集合只 DEL，不留空键之外的陈旧数据。
func (s *PermissionAdminsStore) Rebuild(ctx context.Context, uids []int64) error {
	key := PermissionAdminsKey()
	if err := s.rdb.Del(ctx, key).Err(); err != nil {
		return err
	}
	if len(uids) == 0 {
		return nil
	}
	members := make([]interface{}, 0, len(uids))
	for _, uid := range uids {
		members = append(members, uid)
	}
	return s.rdb.SAdd(ctx, key, members...).Err()
}
