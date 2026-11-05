// wxacode.go 微信服务端 access_token 跨实例共享缓存（docs/后端架构.md
// §3.4 行 469：`access_token` 经 `cache/wxacode` 缓存）。weapp SDK 的
// cache.Cache 桥接消费本存储（桥接体在 internal/provider/oauth/wechat_mp*
// 内，§13.0 行 1578：SDK 引用只许出现在 wechat_mp* 包）。
//
// 键空间：`al:wxacode:{sdk key}`——SDK 侧 key 形如
// "weapp.{appid}.access.token"（weapp auth.go tokenCacheKey），加前缀
// 隔离以防与其他域键冲突。本文件只做 Redis 读写，不含微信 API 语义。
package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// wxacodeRedis 本文件用到的 Redis 命令窄接口（*redis.Client 天然满足；
// 窄化便于测试注入 fake，同 ticketRedis 口径）。
type wxacodeRedis interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
}

// wxacodeKeyPrefix 键前缀（§5.1 键空间命名约定 al: 域前缀）。
const wxacodeKeyPrefix = "al:wxacode:"

// WxacodeStore access_token 存储：Get 未命中返回 ("", false)，Set 以
// 微信侧 expires_in（SDK 传入秒数）为 TTL 写入。
type WxacodeStore struct {
	rdb wxacodeRedis
}

// NewWxacodeStore 构造。rdb 为已连通的 go-redis 客户端。
func NewWxacodeStore(rdb wxacodeRedis) *WxacodeStore {
	return &WxacodeStore{rdb: rdb}
}

// Get 读取 access_token；键不存在 / 已过期返回 ("", false)。
func (s *WxacodeStore) Get(ctx context.Context, key string) (string, bool) {
	v, err := s.rdb.Get(ctx, wxacodeKeyPrefix+key).Result()
	if err != nil {
		return "", false
	}
	return v, true
}

// Set 写入 access_token。ttl <= 0 / 空值不写（无效凭证不落缓存）；写
// 失败静默——缓存层故障不影响主链路，下次拉码回源微信即可。
func (s *WxacodeStore) Set(ctx context.Context, key, val string, ttl time.Duration) {
	if ttl <= 0 || val == "" {
		return
	}
	_ = s.rdb.Set(ctx, wxacodeKeyPrefix+key, val, ttl).Err()
}
