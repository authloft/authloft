// watcher 集成测试：真实 MariaDB + Redis 测试实例经
// UC_TEST_MYSQL_DSN / UC_TEST_REDIS_ADDR env 注入，缺任一整组 skip。
// 覆盖：写入 → PUBLISH al:settings:chg → 订阅方快照刷新（§15.3 行 1684
// 秒级生效链路端到端）→ Close 优雅关闭后不再刷新。Pub/Sub 频道不落键，
// Redis 侧零残留；DB 侧清理由 setupTestDB 统一处理。
package settings

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"authloft/internal/cache"
	"authloft/internal/config"
)

// setupTestRedis env-skip：真连 Redis 测试实例（cache.NewClient 自带
// PING fail-fast），随 t.Cleanup 关闭。
func setupTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("UC_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("环境变量 UC_TEST_REDIS_ADDR 未设置，跳过 watcher 集成用例")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rdb, err := cache.NewClient(ctx, &config.Config{
		Redis: config.RedisConfig{Addr: addr, DB: 0, PoolSize: 10},
	})
	if err != nil {
		t.Fatalf("NewClient 真连失败: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// waitFor 轮询等待条件成立（pub/sub 投递异步，无 channel 长度可断言）。
func waitFor(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("等待超时（%s）: %s", timeout, desc)
}

// TestSetPublishSubscribeRefresh（env-skip DB+Redis）：实例 A Set →
// 本实例立即生效 + al:settings:chg 收到变更键 payload + 实例 B（watcher）
// 快照秒级刷新；updated_by 落库；SetMany 多键批量同链路。
func TestSetPublishSubscribeRefresh(t *testing.T) {
	rp, raw := setupTestDB(t)
	rdb := setupTestRedis(t)
	ctx := context.Background()

	storeA := NewStore(rp, rdb) // 写方实例
	storeB := NewStore(rp, rdb) // 订阅方实例（另一进程的替身）
	for _, st := range []*Store{storeA, storeB} {
		if err := st.Preload(ctx); err != nil {
			t.Fatalf("Preload 失败: %v", err)
		}
	}

	// 独立裸订阅者：断言 PUBLISH 真实发生且 payload 为变更键数组。
	rawSub := rdb.Subscribe(ctx, cache.SettingsChgKey())
	defer rawSub.Close()
	if _, err := rawSub.Receive(ctx); err != nil {
		t.Fatalf("裸订阅确认失败: %v", err)
	}

	w := NewWatcher(rdb, storeB)
	if err := w.Start(ctx); err != nil {
		t.Fatalf("watcher 启动失败: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	// 单键写入：A 立即生效 → 裸订阅者收到 payload → B 刷新。
	if err := storeA.Set(ctx, KeyPwdMinLength, int64(12), 42); err != nil {
		t.Fatalf("Set 失败: %v", err)
	}
	if v, _ := storeA.GetInt64(KeyPwdMinLength); v != 12 {
		t.Errorf("写方本实例应立即生效，得 %d", v)
	}
	select {
	case msg := <-rawSub.Channel():
		if msg.Payload != `["pwd_min_length"]` {
			t.Errorf("PUBLISH payload = %q，应 [\"pwd_min_length\"]", msg.Payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("5s 内未收到 al:settings:chg 通知（PUBLISH 未发生或订阅失败）")
	}
	waitFor(t, 5*time.Second, "实例 B 快照应刷新为 12", func() bool {
		v, _ := storeB.GetInt64(KeyPwdMinLength)
		return v == 12
	})
	var by int
	if err := raw.QueryRow("SELECT updated_by FROM settings WHERE k = ?", KeyPwdMinLength).Scan(&by); err != nil || by != 42 {
		t.Errorf("updated_by 应落库 42，得 %d, err %v", by, err)
	}

	// 多键批量：单事务 UPSERT + 一次 PUBLISH，B 同步收敛。
	if err := storeA.SetMany(ctx, map[string]any{
		KeyStaticBase:   "/cdn-assets",
		KeyQueueWorkers: int64(8),
	}, 7); err != nil {
		t.Fatalf("SetMany 失败: %v", err)
	}
	select {
	case msg := <-rawSub.Channel():
		if msg.Payload != `["queue_workers","static_base"]` {
			t.Errorf("SetMany payload = %q，应排序键数组", msg.Payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("5s 内未收到 SetMany 通知")
	}
	waitFor(t, 5*time.Second, "实例 B 应见 static_base=/cdn-assets 与 queue_workers=8", func() bool {
		sb, _ := storeB.GetString(KeyStaticBase)
		qw, _ := storeB.GetInt64(KeyQueueWorkers)
		return sb == "/cdn-assets" && qw == 8
	})
	if v, _ := storeA.GetInt64(KeyPwdMinLength); v != 12 {
		t.Errorf("SetMany 不应影响未涉及键，pwd_min_length = %d", v)
	}

	// 切片值类型走完整链路（JSON 数组存储 / 解码 / 副本）。
	if err := storeA.Set(ctx, KeySsoDomains, []string{"a.com", "b.com"}, 9); err != nil {
		t.Fatalf("Set 切片失败: %v", err)
	}
	waitFor(t, 5*time.Second, "实例 B 应见 sso_domains 双域名", func() bool {
		d, ok := storeB.GetStringSlice(KeySsoDomains)
		return ok && len(d) == 2 && d[0] == "a.com" && d[1] == "b.com"
	})
}

// TestWatcherCloseStopsReload（env-skip DB+Redis）：Close 优雅关闭
// （不挂起、可重复调用）后，后续通知不再触发重载（快照保持旧值）。
// 负向窗口 500ms：本实例 Redis 订阅投递为毫秒级，留足裕量防抖。
func TestWatcherCloseStopsReload(t *testing.T) {
	rp, _ := setupTestDB(t)
	rdb := setupTestRedis(t)
	ctx := context.Background()

	storeA := NewStore(rp, rdb)
	storeB := NewStore(rp, rdb)
	for _, st := range []*Store{storeA, storeB} {
		if err := st.Preload(ctx); err != nil {
			t.Fatalf("Preload 失败: %v", err)
		}
	}
	w := NewWatcher(rdb, storeB)
	if err := w.Start(ctx); err != nil {
		t.Fatalf("watcher 启动失败: %v", err)
	}

	if err := storeA.Set(ctx, KeySessionTtl, int64(3600), 1); err != nil {
		t.Fatalf("Set 失败: %v", err)
	}
	waitFor(t, 5*time.Second, "关闭前 B 应正常刷新", func() bool {
		v, _ := storeB.GetInt64(KeySessionTtl)
		return v == 3600
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close 应无错误: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("重复 Close 应幂等 nil: %v", err)
	}
	if err := storeA.Set(ctx, KeySessionTtl, int64(7200), 1); err != nil {
		t.Fatalf("关闭后 Set 失败: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if v, _ := storeB.GetInt64(KeySessionTtl); v != 3600 {
		t.Errorf("Close 后不应再刷新，得 %d（应保持 3600）", v)
	}
}
