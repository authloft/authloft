// once_store.go 高风险断言消费的 al:once:{nonce} 去重（docs/后端架构.md
// §5.1 行 880），结构化满足 verification.OnceStore。
package cache

import (
	"context"
	"time"
)

// OnceStore 高风险断言消费的 al:once:{nonce} 去重（§5.1 行 880）。
type OnceStore struct {
	rdb *RedisClient
}

func (s OnceStore) SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error) {
	return s.rdb.SetNX(ctx, key, value, ttl).Result()
}

// NewOnceStore 构造一次性断言消费去重存储。
func NewOnceStore(rdb *RedisClient) *OnceStore {
	return &OnceStore{rdb: rdb}
}
