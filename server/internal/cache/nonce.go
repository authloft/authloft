// nonce 去重（docs/后端架构.md §5.1 行 861 + §17 行 1718）：RPC 请求的
// X-Nonce-ID 以 SET NX EX 30s 写入 al:rpc:nonce:{client_id}:{sha256(nonce)}，
// 抢占失败即 30s 窗口内重放。nonce 去重必须先于签名校验（§3.3 行 314），
// 顺序由调用方（middleware/rpc.go）负责。Redis 客户端经构造注入（叶子件，
// 不 import config / repo，同 epoch.go 口径）。
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/redis/go-redis/v9"
)

// nonceRedis 本文件用到的 Redis 命令窄接口（*redis.Client 天然满足；
// 窄化便于测试注入 fake 计数，不暴露整个 Cmdable，同 epochRedis 口径）。
type nonceRedis interface {
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd
}

// rpcNonceTTL nonce 去重键 TTL（接口文档 §7 行 1370：Redis 去重 TTL 30s）。
const rpcNonceTTL = 30 * time.Second

// NonceStore RPC nonce 去重存储。
type NonceStore struct {
	rdb nonceRedis
}

// NewNonceStore 构造 nonce 去重存储。rdb 为已连通的 go-redis 客户端。
func NewNonceStore(rdb nonceRedis) *NonceStore {
	return &NonceStore{rdb: rdb}
}

// nonceHash sha256(nonce) 的小写十六进制（§5.1 行 861 键名的哈希段）。
// 哈希只为缩短键长并统一大小写口径，nonce 本身就是一次性随机串。
func nonceHash(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(sum[:])
}

// Store 把 (clientID, nonce) 记入去重键：SET NX EX 30s
// al:rpc:nonce:{client_id}:{sha256(nonce)}，返回是否首次出现（false =
// 30s 窗口内重放）。value 固定 "1"（§5.1 行 861 键类型 String，只需占位存在性）。
func (s *NonceStore) Store(ctx context.Context, clientID, nonce string) (bool, error) {
	return s.rdb.SetNX(ctx, RPCNonceKey(clientID, nonceHash(nonce)), "1", rpcNonceTTL).Result()
}
