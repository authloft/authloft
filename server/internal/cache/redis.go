// Package cache 提供 Redis 访问层基础设施（docs/后端架构.md §3.10 行 430-433）。
//
// 本文件只做客户端初始化；全部键空间的构造与读写封装（keys.go / code.go /
// captcha.go 等，TTL 严格按 §5.1）归后续实现。客户端选型：rueidis（RESP3，
// 单连接多路复用），经包内适配层（rueidis.go）翻译为自有结果类型后供各
// 键空间封装使用。
package cache

import (
	"context"
	"fmt"

	"github.com/redis/rueidis"

	"authloft/internal/config"
)

// NewClient 按 cfg.Redis 初始化 rueidis 客户端（§3.2 行 273-277：addr /
// password / db）。部署形态为单机 Redis（§3.2），ForceSingleClient 跳过
// 集群探测；rueidis 连接按需自动伸缩，无 go-redis PoolSize 对应项。
// 返回前 PING 一次确认连通——fail-fast 口径与 DB 侧 gorm.Open 自动 ping
// 一致。
func NewClient(ctx context.Context, cfg *config.Config) (*RedisClient, error) {
	client, err := rueidis.NewClient(rueidis.ClientOption{
		InitAddress:       []string{cfg.Redis.Addr},
		Password:          cfg.Redis.Password,
		SelectDB:          int(cfg.Redis.DB),
		ForceSingleClient: true,
	})
	if err != nil && client == nil {
		return nil, fmt.Errorf("redis: new client: %w", err)
	}
	// ForceSingleClient 下首连失败仍返回可用句柄（err 非空但 client 非空），
	// 连通性统一由下方 PING fail-fast 判定。
	c := &RedisClient{c: client}
	if err := c.Ping(ctx); err != nil {
		client.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return c, nil
}
