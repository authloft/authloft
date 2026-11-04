// Provider 缓存键与读写封装单测：键名（§5.1 行 847-849）、
// 整行缓存 TTL 600s、版本号 / 变更通知的三步失效顺序；真连 Redis 用例
// 沿 redis_test.go 的 env-skip 模式（UC_TEST_REDIS_ADDR），只碰自有
// al:prov:v:t084_* 键，测后 DEL 零残留。
package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeProviderRedis 实现 providerRedis 窄接口并记录操作顺序。
type fakeProviderRedis struct {
	mu      sync.Mutex
	ops     []string
	vals    map[string]string
	version int64
	getErr  error
	setTTLs map[string]time.Duration
}

func newFakeProviderRedis() *fakeProviderRedis {
	return &fakeProviderRedis{vals: make(map[string]string), setTTLs: make(map[string]time.Duration)}
}

func (f *fakeProviderRedis) Get(ctx context.Context, key string) *redis.StringCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, "GET "+key)
	cmd := redis.NewStringCmd(ctx)
	if f.getErr != nil {
		cmd.SetErr(f.getErr)
		return cmd
	}
	if v, ok := f.vals[key]; ok {
		cmd.SetVal(v)
	} else {
		cmd.SetErr(redis.Nil)
	}
	return cmd
}

func (f *fakeProviderRedis) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, "SET "+key)
	if b, ok := value.([]byte); ok {
		f.vals[key] = string(b)
	} else {
		f.vals[key] = fmt.Sprint(value)
	}
	f.setTTLs[key] = expiration
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetVal("OK")
	return cmd
}

func (f *fakeProviderRedis) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := redis.NewIntCmd(ctx)
	for _, k := range keys {
		f.ops = append(f.ops, "DEL "+k)
		delete(f.vals, k)
	}
	cmd.SetVal(int64(len(keys)))
	return cmd
}

func (f *fakeProviderRedis) Incr(ctx context.Context, key string) *redis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, "INCR "+key)
	f.version++
	f.vals[key] = fmt.Sprint(f.version)
	cmd := redis.NewIntCmd(ctx)
	cmd.SetVal(f.version)
	return cmd
}

func (f *fakeProviderRedis) Publish(ctx context.Context, channel string, message interface{}) *redis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, fmt.Sprintf("PUBLISH %s %v", channel, message))
	cmd := redis.NewIntCmd(ctx)
	cmd.SetVal(0)
	return cmd
}

func (f *fakeProviderRedis) operations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ops...)
}

// TestProviderKeys §5.1 行 847-849 键名格式。
func TestProviderKeys(t *testing.T) {
	if got, want := ProviderRowKey("wx_mp"), "al:prov:v:wx_mp"; got != want {
		t.Fatalf("ProviderRowKey = %q, want %q", got, want)
	}
	if got, want := ProviderVersionKey(), "al:prov:ver"; got != want {
		t.Fatalf("ProviderVersionKey = %q, want %q", got, want)
	}
	if got, want := ProviderChgKey(), "al:prov:chg"; got != want {
		t.Fatalf("ProviderChgKey = %q, want %q", got, want)
	}
}

// TestProviderCacheRowRoundTrip：整行缓存写入 TTL 600s，未命中返回 ok=false。
func TestProviderCacheRowRoundTrip(t *testing.T) {
	fake := newFakeProviderRedis()
	c := NewProviderCache(fake)
	ctx := context.Background()

	if _, ok, err := c.GetRow(ctx, "wx_mp"); err != nil || ok {
		t.Fatalf("GetRow missing = (ok=%v, err=%v), want false/nil", ok, err)
	}
	if err := c.SetRow(ctx, "wx_mp", []byte("row-bytes")); err != nil {
		t.Fatalf("SetRow: %v", err)
	}
	if got := fake.setTTLs[ProviderRowKey("wx_mp")]; got != 600*time.Second {
		t.Fatalf("row TTL = %v, want 600s（§5.1 行 847）", got)
	}
	raw, ok, err := c.GetRow(ctx, "wx_mp")
	if err != nil || !ok || string(raw) != "row-bytes" {
		t.Fatalf("GetRow = (%q, %v, %v), want row-bytes/true/nil", raw, ok, err)
	}
}

// TestProviderCacheVersion：缺失版本返回 0；BumpVersion 递增。
func TestProviderCacheVersion(t *testing.T) {
	fake := newFakeProviderRedis()
	c := NewProviderCache(fake)
	ctx := context.Background()

	if v, err := c.Version(ctx); err != nil || v != 0 {
		t.Fatalf("Version = (%d, %v), want 0/nil", v, err)
	}
	if v, err := c.BumpVersion(ctx); err != nil || v != 1 {
		t.Fatalf("BumpVersion = (%d, %v), want 1/nil", v, err)
	}
	if v, err := c.Version(ctx); err != nil || v != 1 {
		t.Fatalf("Version after bump = (%d, %v), want 1/nil", v, err)
	}
}

// TestProviderCacheInvalidateOrder：DEL 行 → INCR 版本 → PUBLISH 变更，
// 顺序与 §15.3 行 1716 逐字一致。
func TestProviderCacheInvalidateOrder(t *testing.T) {
	fake := newFakeProviderRedis()
	c := NewProviderCache(fake)
	ctx := context.Background()

	if err := c.Invalidate(ctx, "wx_mp"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	ops := fake.operations()
	want := []string{
		"DEL al:prov:v:wx_mp",
		"INCR al:prov:ver",
		"PUBLISH al:prov:chg wx_mp",
	}
	if len(ops) != len(want) {
		t.Fatalf("ops = %v, want %v", ops, want)
	}
	for i := range want {
		if ops[i] != want[i] {
			t.Fatalf("ops[%d] = %q, want %q", i, ops[i], want[i])
		}
	}
}

// TestProviderCacheGetRowError：Redis GET 故障时返回 error，不当成 miss。
func TestProviderCacheGetRowError(t *testing.T) {
	fake := newFakeProviderRedis()
	fake.getErr = errors.New("redis down")
	c := NewProviderCache(fake)
	if _, ok, err := c.GetRow(context.Background(), "wx_mp"); err == nil || ok {
		t.Fatalf("GetRow with redis error = (ok=%v, err=%v), want error", ok, err)
	}
}

// TestProviderCacheRealRedis（env-skip）：真连测试实例，整行缓存写入 /
// 读取 / TTL 600s，测后 DEL 自有键自证零残留；不改动全局 al:prov:ver。
func TestProviderCacheRealRedis(t *testing.T) {
	addr := os.Getenv("UC_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("环境变量 UC_TEST_REDIS_ADDR 未设置，跳过 Redis 连接用例")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rdb, err := NewClient(ctx, redisTestConfig(addr))
	if err != nil {
		t.Fatalf("NewClient 真连失败: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	const key = "t084_probe"
	rowKey := ProviderRowKey(key)
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ccancel()
		if err := rdb.Del(cctx, rowKey).Err(); err != nil {
			t.Fatalf("测后清理 DEL %s: %v", rowKey, err)
		}
		if n, err := rdb.Exists(cctx, rowKey).Result(); err != nil || n != 0 {
			t.Fatalf("exists %s = %d, err %v; want 0（测后零残留）", rowKey, n, err)
		}
	})
	if err := rdb.Del(ctx, rowKey).Err(); err != nil {
		t.Fatalf("前置清理 DEL %s: %v", rowKey, err)
	}

	c := NewProviderCache(rdb)
	if err := c.SetRow(ctx, key, []byte(`{"provider_key":"t084_probe"}`)); err != nil {
		t.Fatalf("SetRow: %v", err)
	}
	raw, ok, err := c.GetRow(ctx, key)
	if err != nil || !ok || string(raw) != `{"provider_key":"t084_probe"}` {
		t.Fatalf("GetRow = (%q, %v, %v)", raw, ok, err)
	}
	ttl, err := rdb.TTL(ctx, rowKey).Result()
	if err != nil || ttl <= 590*time.Second {
		t.Fatalf("ttl = (%v, %v), want ~600s（§5.1 行 847）", ttl, err)
	}
}
