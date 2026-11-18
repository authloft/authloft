// 模板 content 缓存封装（后端架构 §5.1：al:tpl:v:{key}，String、TTL
// 600s，只存 content 原文；不设版本号、不进 Pub/Sub，写路径单步 DEL 失效）。
// 键名由 keys.go 构造；Redis 客户端经构造注入（叶子件，不 import config /
// repo，同 provider.go 口径），窄接口便于测试注入 fake。
package cache

import (
	"context"
	"fmt"
	"time"
)

// templateRowTTL 模板 content 缓存 TTL（§5.1：600s）。
const templateRowTTL = 600 * time.Second

// templateRedis 本文件用到的 Redis 命令窄接口（*RedisClient 适配器天然满足；
// 窄化便于测试注入 fake，同 providerRedis 口径）。
type templateRedis interface {
	Get(ctx context.Context, key string) StringResult
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) StatusResult
	Del(ctx context.Context, keys ...string) IntResult
}

// TemplateCache 模板 content 缓存读写封装。
type TemplateCache struct {
	rdb templateRedis
}

// NewTemplateCache 构造模板缓存。rdb 为已连通的 Redis 客户端适配器。
func NewTemplateCache(rdb templateRedis) *TemplateCache {
	return &TemplateCache{rdb: rdb}
}

// Get 读模板 content 缓存；键不存在返回 ok=false（不视为错误）。
// 返回值为 content 原文（string），非整行序列化。
func (c *TemplateCache) Get(ctx context.Context, key string) (string, bool, error) {
	content, err := c.rdb.Get(ctx, TemplateRowKey(key)).Result()
	if err == Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("cache: get template %q: %w", key, err)
	}
	return content, true, nil
}

// SetRow 写模板 content 缓存（TTL 600s，§5.1）。
func (c *TemplateCache) SetRow(ctx context.Context, key, content string) error {
	if err := c.rdb.Set(ctx, TemplateRowKey(key), content, templateRowTTL).Err(); err != nil {
		return fmt.Errorf("cache: set template %q: %w", key, err)
	}
	return nil
}

// Invalidate 写路径成功后单步 DEL 失效（§5.1：不 INCR、不 PUBLISH；Update
// 改 key 时旧 + 新双失效由上层分别调用本方法）。
func (c *TemplateCache) Invalidate(ctx context.Context, key string) error {
	if err := c.rdb.Del(ctx, TemplateRowKey(key)).Err(); err != nil {
		return fmt.Errorf("cache: del template %q: %w", key, err)
	}
	return nil
}
