// Package cache 提供 Redis 访问层基础设施（docs/后端架构.md §3.10 行 430-433）。
//
// 本文件只做客户端初始化；全部键空间的构造与读写封装（keys.go / code.go /
// captcha.go 等，TTL 严格按 §5.1）归后续实现。客户端选型：后端架构文档未指定
// 具体库，采用 Go 社区标准选择 github.com/redis/go-redis/v9。
package cache

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"

	"authloft/internal/config"
)

// NewClient 按 cfg.Redis 初始化 go-redis v9 客户端（§3.2 行 273-277：
// addr / password / db / pool_size），返回前 PING 一次确认连通——
// fail-fast 口径与 DB 侧 gorm.Open 自动 ping 一致。
func NewClient(ctx context.Context, cfg *config.Config) (*redis.Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
		PoolSize: cfg.Redis.PoolSize,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return rdb, nil
}
