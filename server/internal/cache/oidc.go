// OIDC 授权码存储（docs/后端架构.md §3.10 行 419、§5.1 行 843、§14.3 行 1587；
// 接口文档 §4.2 行 1080、§4.7 行 1134）：键 al:oidc:code:{code}，SET EX 120s，
// 消费侧 GETDEL 一次性，同一授权码只有第一个换取令牌的请求能取到。
//
// 值为不透明字符串：授权码载荷 proto 缺失（待定），
// §11.6.1 的封装归后续 OIDC service 卡；本文件原样存取、不做 JSON / 加密。
// Redis 客户端经构造注入（叶子件，不 import config / repo，同 code.go 口径）。
package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// oidcCodeTTL 授权码有效期（接口文档 §4.7 行 1134：120 秒，全文档唯一定义处）。
const oidcCodeTTL = 120 * time.Second

// oidcCodeRedis 本文件用到的 Redis 命令窄接口（*redis.Client 天然满足；
// 窄化便于测试注入 fake，不暴露整个 Cmdable，同 codeRedis 口径）。
type oidcCodeRedis interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	GetDel(ctx context.Context, key string) *redis.StringCmd
}

// OIDCCodeStore OIDC 授权码存储。
type OIDCCodeStore struct {
	rdb oidcCodeRedis
}

// NewOIDCCodeStore 构造授权码存储。rdb 为已连通的 go-redis 客户端。
func NewOIDCCodeStore(rdb oidcCodeRedis) *OIDCCodeStore {
	return &OIDCCodeStore{rdb: rdb}
}

// Set 写入授权码：SET al:oidc:code:{code} = value EX 120s（§5.1 行 843）。
// value 为不透明字符串，本方法不做封装。
func (s *OIDCCodeStore) Set(ctx context.Context, code, value string) error {
	if err := s.rdb.Set(ctx, OIDCCodeKey(code), value, oidcCodeTTL).Err(); err != nil {
		return fmt.Errorf("cache: set oidc code: %w", err)
	}
	return nil
}

// Consume 一次性取走授权码：GETDEL 原子（§14.3 行 1587）。ok=false 表示
// 键不存在（未签发 / 已消费 / 已过期），value 原样返回。
func (s *OIDCCodeStore) Consume(ctx context.Context, code string) (value string, ok bool, err error) {
	v, err := s.rdb.GetDel(ctx, OIDCCodeKey(code)).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("cache: getdel oidc code: %w", err)
	}
	return v, true, nil
}
