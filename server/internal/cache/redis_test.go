// cache 包 Redis 客户端初始化测试：不可达地址的软降级用例（返回句柄 +
// 降级状态置位）本地可跑；真连用例 skip-on-no-env（UC_TEST_REDIS_ADDR），
// 共享测试实例只做 PING 与自有键（al:t030:*）读写，测后 DEL 自证零残留。
// 连接串只经环境变量注入，代码不含主机 / 凭证信息。
package cache

import (
	"context"
	"os"
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

// degradedClient 构造指向不可达地址的客户端句柄（NewClient 软降级：保留
// 句柄不返回错误，降级状态已置位）。供各 store 的「Redis 故障」用例复用，
// 本地可跑、不连 Redis。
func degradedClient(t *testing.T) *RedisClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	rdb, err := NewClient(ctx, redisTestConfig("127.0.0.1:1"))
	if err != nil {
		t.Fatalf("不可达地址应软降级返回句柄, got err: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	if !rdb.Degrade().IsDegraded() {
		t.Fatal("不可达地址构造后降级状态应已置位")
	}
	return rdb
}

// TestNewClientUnreachableServesDegraded：Redis 不可达（保留端口）→
// NewClient 保留句柄不退出（err = nil），降级状态已置位（软降级口径：
// 后端架构 §5.3），句柄可关闭。
func TestNewClientUnreachableServesDegraded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rdb, err := NewClient(ctx, redisTestConfig("127.0.0.1:1"))
	if err != nil {
		t.Fatalf("不可达地址应软降级而非报错, got: %v", err)
	}
	if rdb == nil {
		t.Fatal("应返回可用句柄")
	}
	defer func() { _ = rdb.Close() }()
	if !rdb.Degrade().IsDegraded() {
		t.Fatal("PING 失败后降级状态应已置位")
	}
	if rdb.Degrade().Reason() == "" {
		t.Error("降级原因应留痕")
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
	if rdb.Degrade().IsDegraded() {
		t.Fatal("真连成功不应处于降级态")
	}
	if err := rdb.Ping(ctx); err != nil {
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

// TestPingSuccessClearsDegrade（env-skip）：探活 PING 成功清除降级状态
// ——恢复检测挂探活路径（后端架构 §5.3），业务读不探测。手动置位模拟
// 故障期，再以真实 PING 验证自愈。
func TestPingSuccessClearsDegrade(t *testing.T) {
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

	rdb.Degrade().Set("test degraded")
	if !rdb.Degrade().IsDegraded() {
		t.Fatal("置位后应处于降级态")
	}
	if err := rdb.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if rdb.Degrade().IsDegraded() {
		t.Fatal("PING 成功应清除降级状态（自愈）")
	}
}
