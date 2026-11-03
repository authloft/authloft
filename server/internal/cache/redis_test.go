// cache 包 Redis 客户端初始化测试：不可达地址的 fail-fast 用例
// 本地可跑；真连用例 skip-on-no-env（UC_TEST_REDIS_ADDR），共享测试实例只
// 做 PING 与自有键（al:t030:*）读写，测后 DEL 自证零残留。连接串只经环境
// 变量注入，代码不含主机 / 凭证信息。
package cache

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"authloft/internal/config"
)

// redisTestConfig 构造只填 Redis 段的自造 *config.Config（§3.2 约定 1 / §20）。
func redisTestConfig(addr string) *config.Config {
	return &config.Config{
		Redis: config.RedisConfig{Addr: addr, DB: 0, PoolSize: 10},
	}
}

// TestNewClientUnreachable：Redis 不可达（保留端口）→ PING 失败，返回
// "redis: ping" 前缀错误（fail-fast，NewClient 不返回半初始化客户端）。
func TestNewClientUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := NewClient(ctx, redisTestConfig("127.0.0.1:1"))
	if err == nil || !strings.Contains(err.Error(), "redis: ping") {
		t.Fatalf("err = %v, want \"redis: ping\" prefixed error", err)
	}
}

// TestNewClientReal（env-skip）：真连 Redis 测试实例——PING 通 + 自有键
// al:t030:probe SET/GET/DEL，测后 EXISTS=0 零残留。
func TestNewClientReal(t *testing.T) {
	addr := os.Getenv("UC_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("环境变量 UC_TEST_REDIS_ADDR 未设置，跳过 Redis 连接用例")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rdb, err := NewClient(ctx, redisTestConfig(addr))
	if err != nil {
		t.Fatalf("NewClient 真连失败: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	const key = "al:t030:probe"
	if err := rdb.Set(ctx, key, "v1", time.Minute).Err(); err != nil {
		t.Fatalf("set %s: %v", key, err)
	}
	if v, err := rdb.Get(ctx, key).Result(); err != nil || v != "v1" {
		t.Fatalf("get %s = %q, err %v; want v1", key, v, err)
	}
	if err := rdb.Del(ctx, key).Err(); err != nil {
		t.Fatalf("del %s: %v", key, err)
	}
	if n, err := rdb.Exists(ctx, key).Result(); err != nil || n != 0 {
		t.Fatalf("exists %s = %d, err %v; want 0（测后零残留）", key, n, err)
	}
}
