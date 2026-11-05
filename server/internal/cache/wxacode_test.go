// wxacode_test.go 覆盖 access_token 缓存：fake redis 语义（命中 / 未命
// 中 / TTL 透传 / 非法参数不写）+ 键空间前缀 + 真连 Redis 用例
// （env-skip：UC_TEST_REDIS_ADDR，测后 DEL 自证零残留）。
package cache

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeWxacodeRedis 记录 Set 调用、按 map 返回 Get。
type fakeWxacodeRedis struct {
	store map[string]item
	ttls  map[string]time.Duration
}

type item struct {
	val string
}

func (f *fakeWxacodeRedis) Get(ctx context.Context, key string) *redis.StringCmd {
	cmd := redis.NewStringCmd(ctx)
	if v, ok := f.store[key]; ok {
		cmd.SetVal(v.val)
		return cmd
	}
	cmd.SetErr(redis.Nil)
	return cmd
}

func (f *fakeWxacodeRedis) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	if f.store == nil {
		f.store = map[string]item{}
	}
	if f.ttls == nil {
		f.ttls = map[string]time.Duration{}
	}
	f.store[key] = item{val: value.(string)}
	f.ttls[key] = expiration
	return cmd
}

// TestWxacodeStoreFake 命中 / 未命中 / 键前缀 / TTL 透传 / 非法不写。
func TestWxacodeStoreFake(t *testing.T) {
	ctx := context.Background()
	fake := &fakeWxacodeRedis{}
	s := NewWxacodeStore(fake)

	if _, ok := s.Get(ctx, "weapp.app.access.token"); ok {
		t.Fatalf("空缓存不应命中")
	}
	s.Set(ctx, "weapp.app.access.token", "tok-1", 7200*time.Second)
	got, ok := s.Get(ctx, "weapp.app.access.token")
	if !ok || got != "tok-1" {
		t.Fatalf("Get = (%q, %v), want (tok-1, true)", got, ok)
	}
	if fake.store["al:wxacode:weapp.app.access.token"].val != "tok-1" {
		t.Fatalf("键空间应加 al:wxacode: 前缀, got %v", fake.store)
	}
	if fake.ttls["al:wxacode:weapp.app.access.token"] != 7200*time.Second {
		t.Fatalf("TTL 应原样透传, got %v", fake.ttls)
	}
	// 非法参数不写。
	before := len(fake.store)
	s.Set(ctx, "k", "", time.Minute)
	s.Set(ctx, "k", "v", 0)
	if len(fake.store) != before {
		t.Fatalf("空值 / ttl<=0 不应写入")
	}
}

// TestWxacodeStoreReal 真连 Redis（env-skip）：Set → Get 往返 + 前缀键
// 存在性断言，测后 DEL 零残留。
func TestWxacodeStoreReal(t *testing.T) {
	addr := os.Getenv("UC_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("环境变量 UC_TEST_REDIS_ADDR 未设置，跳过 Redis 连接用例")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rdb, err := NewClient(ctx, redisTestConfig(addr))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	s := NewWxacodeStore(rdb)
	const sdkKey = "weapp.t110-test.access.token"
	const full = wxacodeKeyPrefix + sdkKey
	t.Cleanup(func() { _ = rdb.Del(context.Background(), full).Err() })

	s.Set(ctx, sdkKey, "tok-real", time.Minute)
	if v, ok := s.Get(ctx, sdkKey); !ok || v != "tok-real" {
		t.Fatalf("Get = (%q, %v), want (tok-real, true)", v, ok)
	}
	if n, err := rdb.Exists(ctx, full).Result(); err != nil || n != 1 {
		t.Fatalf("Exists(%q) = (%d, %v)", full, n, err)
	}
	if _, err := rdb.Del(ctx, full).Result(); err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if _, ok := s.Get(ctx, sdkKey); ok {
		t.Fatalf("DEL 后不应命中")
	}
}
