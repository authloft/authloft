// Provider 缓存键空间的读写封装（docs/后端架构.md §3.10 行 422、§5.1
// 行 847-849、§15.3 行 1716）：整行缓存 al:prov:v:{key}（TTL 600s）、
// 版本号 al:prov:ver、变更频道 al:prov:chg。键名一律由 keys.go 构造。
//
// 写入路径（后台写 Provider）固定三步：DEL 整行 → INCR 版本 → PUBLISH
// 变更；由 Invalidate 一次封装，避免调用方各自拼键或漏步。
// Redis 客户端经构造注入（叶子件，不 import config / repo，同 epoch.go 口径）。
package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// providerRowTTL 整行缓存 TTL（§5.1 行 847：600s）。
const providerRowTTL = 600 * time.Second

// providerRedis 本文件用到的 Redis 命令窄接口（*redis.Client 天然满足；
// 窄化便于测试注入 fake，不暴露整个 Cmdable，同 epochRedis 口径）。
type providerRedis interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Incr(ctx context.Context, key string) *redis.IntCmd
	Publish(ctx context.Context, channel string, message interface{}) *redis.IntCmd
}

// ProviderCache Provider 整行缓存 / 版本号 / 变更通知的读写封装。
type ProviderCache struct {
	rdb providerRedis
}

// NewProviderCache 构造 Provider 缓存。rdb 为已连通的 go-redis 客户端。
func NewProviderCache(rdb providerRedis) *ProviderCache {
	return &ProviderCache{rdb: rdb}
}

// GetRow 读整行缓存；键不存在返回 ok=false（不视为错误）。
func (c *ProviderCache) GetRow(ctx context.Context, providerKey string) ([]byte, bool, error) {
	raw, err := c.rdb.Get(ctx, ProviderRowKey(providerKey)).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("cache: get provider row %q: %w", providerKey, err)
	}
	return raw, true, nil
}

// SetRow 写整行缓存（TTL 600s，§5.1 行 847）。
func (c *ProviderCache) SetRow(ctx context.Context, providerKey string, raw []byte) error {
	if err := c.rdb.Set(ctx, ProviderRowKey(providerKey), raw, providerRowTTL).Err(); err != nil {
		return fmt.Errorf("cache: set provider row %q: %w", providerKey, err)
	}
	return nil
}

// Version 读缓存版本号；键不存在返回 0（尚未有过写入）。
func (c *ProviderCache) Version(ctx context.Context) (int64, error) {
	n, err := c.rdb.Get(ctx, ProviderVersionKey()).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("cache: get provider version: %w", err)
	}
	return n, nil
}

// BumpVersion 递增版本号（§15.3 行 1716）。
func (c *ProviderCache) BumpVersion(ctx context.Context) (int64, error) {
	n, err := c.rdb.Incr(ctx, ProviderVersionKey()).Result()
	if err != nil {
		return 0, fmt.Errorf("cache: incr provider version: %w", err)
	}
	return n, nil
}

// PublishChange 发布变更通知（§15.3 行 1716：PUBLISH al:prov:chg {key}）。
func (c *ProviderCache) PublishChange(ctx context.Context, providerKey string) error {
	if err := c.rdb.Publish(ctx, ProviderChgKey(), providerKey).Err(); err != nil {
		return fmt.Errorf("cache: publish provider change %q: %w", providerKey, err)
	}
	return nil
}

// Invalidate 后台写 Provider 后的固定三步（§15.3 行 1716）：
// DEL al:prov:v:{key} → INCR al:prov:ver → PUBLISH al:prov:chg {key}。
// 任一步失败立即返回，后续步骤不执行；PUBLISH 无订阅者时返回 0 不算错误。
func (c *ProviderCache) Invalidate(ctx context.Context, providerKey string) error {
	if err := c.rdb.Del(ctx, ProviderRowKey(providerKey)).Err(); err != nil {
		return fmt.Errorf("cache: del provider row %q: %w", providerKey, err)
	}
	if _, err := c.BumpVersion(ctx); err != nil {
		return err
	}
	if err := c.PublishChange(ctx, providerKey); err != nil {
		return err
	}
	return nil
}
