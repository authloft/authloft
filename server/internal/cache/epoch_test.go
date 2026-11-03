// EpochStore 单测：三级读取链 localCache → Redis → 回源 DB
// 逐级覆盖（fake redis 计数 + 可注入 localCache TTL）；真连用例沿
// redis_test.go 的 env-skip 模式（UC_TEST_REDIS_ADDR），只碰自有键
// al:pwdep:{uid}，测后 DEL 零残留，连接串只经环境变量注入。
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

// fakeEpochRedis 计数型 fake（实现 epochRedis 窄接口）：vals 为键值表，
// getErr 非 nil 时 GET 返回故障错误（模拟 Redis 挂掉）。
type fakeEpochRedis struct {
	mu      sync.Mutex
	gets    int
	sets    int
	getKeys []string
	setKeys []string
	setTTNs []time.Duration
	vals    map[string]string
	getErr  error
}

func (f *fakeEpochRedis) Get(ctx context.Context, key string) *redis.StringCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	f.getKeys = append(f.getKeys, key)
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

func (f *fakeEpochRedis) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets++
	f.setKeys = append(f.setKeys, key)
	f.setTTNs = append(f.setTTNs, expiration)
	if f.vals == nil {
		f.vals = make(map[string]string)
	}
	f.vals[key] = fmt.Sprint(value)
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetVal("OK")
	return cmd
}

// snapshot 返回各计数与键名快照。
func (f *fakeEpochRedis) snapshot() (gets, sets int, getKeys, setKeys []string, setTTNs []time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets, f.sets,
		append([]string(nil), f.getKeys...),
		append([]string(nil), f.setKeys...),
		append([]time.Duration(nil), f.setTTNs...)
}

// fakeSource 计数型回源函数。
type fakeSource struct {
	mu    sync.Mutex
	calls []int64
	value int64
	err   error
}

func (s *fakeSource) call(ctx context.Context, uid int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, uid)
	return s.value, s.err
}

func (s *fakeSource) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// TestEpochKey 键名格式与负数 uid（键名唯一出处 keys.go）。
func TestEpochKey(t *testing.T) {
	if got, want := EpochKey(42), "al:pwdep:42"; got != want {
		t.Fatalf("EpochKey(42) = %q, want %q", got, want)
	}
	if got, want := EpochKey(-1), "al:pwdep:-1"; got != want {
		t.Fatalf("EpochKey(-1) = %q, want %q", got, want)
	}
}

// TestEpochCurrentMissThenFallback：Redis 未命中 → 回源 → SET 新值
// TTL 24h + 回填 localCache（第二次调用零 Redis 访问）。
func TestEpochCurrentMissThenFallback(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEpochRedis{}
	src := &fakeSource{value: 7}
	store := NewEpochStore(fake, src.call)

	v, err := store.Current(ctx, 42)
	if err != nil || v != 7 {
		t.Fatalf("Current = (%d, %v), want (7, nil)", v, err)
	}
	gets, sets, getKeys, setKeys, setTTNs := fake.snapshot()
	if gets != 1 || sets != 1 {
		t.Fatalf("redis calls gets=%d sets=%d, want 1/1", gets, sets)
	}
	if want := EpochKey(42); getKeys[0] != want || setKeys[0] != want {
		t.Fatalf("key mismatch: get=%q set=%q, want %q", getKeys[0], setKeys[0], want)
	}
	if setTTNs[0] != 24*time.Hour {
		t.Fatalf("set ttl = %v, want 24h（§5.1 行 863）", setTTNs[0])
	}
	if src.count() != 1 {
		t.Fatalf("source calls = %d, want 1", src.count())
	}

	// 第二次：localCache 命中，不再碰 Redis 与回源。
	v, err = store.Current(ctx, 42)
	if err != nil || v != 7 {
		t.Fatalf("second Current = (%d, %v), want (7, nil)", v, err)
	}
	gets, sets, _, _, _ = fake.snapshot()
	if gets != 1 || sets != 1 {
		t.Fatalf("after cache hit gets=%d sets=%d, want unchanged 1/1", gets, sets)
	}
	if src.count() != 1 {
		t.Fatalf("source calls after cache hit = %d, want 1", src.count())
	}
}

// TestEpochCurrentRedisHit：Redis 命中直接返回，不调回源、不 SET。
func TestEpochCurrentRedisHit(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEpochRedis{vals: map[string]string{EpochKey(42): "9"}}
	src := &fakeSource{value: 7}
	store := NewEpochStore(fake, src.call)

	v, err := store.Current(ctx, 42)
	if err != nil || v != 9 {
		t.Fatalf("Current = (%d, %v), want (9, nil)", v, err)
	}
	gets, sets, _, _, _ := fake.snapshot()
	if gets != 1 || sets != 0 {
		t.Fatalf("redis calls gets=%d sets=%d, want 1/0", gets, sets)
	}
	if src.count() != 0 {
		t.Fatalf("source calls = %d, want 0", src.count())
	}

	// Redis 命中也回填 localCache：第二次零 Redis 访问。
	if _, err := store.Current(ctx, 42); err != nil {
		t.Fatalf("second Current: %v", err)
	}
	gets, _, _, _, _ = fake.snapshot()
	if gets != 1 {
		t.Fatalf("after cache hit gets=%d, want unchanged 1", gets)
	}
}

// TestEpochCurrentLocalTTLExpire：localCache 过期后重新走 Redis。
func TestEpochCurrentLocalTTLExpire(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEpochRedis{vals: map[string]string{EpochKey(42): "9"}}
	src := &fakeSource{value: 7}
	store := newEpochStore(fake, src.call, -time.Second) // TTL 已过期

	for i := 0; i < 2; i++ {
		v, err := store.Current(ctx, 42)
		if err != nil || v != 9 {
			t.Fatalf("Current #%d = (%d, %v), want (9, nil)", i, v, err)
		}
	}
	gets, _, _, _, _ := fake.snapshot()
	if gets != 2 {
		t.Fatalf("gets = %d, want 2（TTL 过期后每次都查 Redis）", gets)
	}
}

// TestEpochCurrentSourceError：回源失败错误传播（Redis miss 时）。
func TestEpochCurrentSourceError(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("db down")
	fake := &fakeEpochRedis{}
	src := &fakeSource{err: boom}
	store := NewEpochStore(fake, src.call)

	if _, err := store.Current(ctx, 42); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want db down", err)
	}
	_, sets, _, _, _ := fake.snapshot()
	if sets != 0 {
		t.Fatalf("sets = %d, want 0（回源失败不写回）", sets)
	}
}

// TestEpochCurrentRedisDownFallback：Redis 故障（非 Nil）降级回源成功
// （取舍见 epoch.go Current 注释，待定）。
func TestEpochCurrentRedisDownFallback(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEpochRedis{getErr: errors.New("connection reset")}
	src := &fakeSource{value: 7}
	store := NewEpochStore(fake, src.call)

	v, err := store.Current(ctx, 42)
	if err != nil || v != 7 {
		t.Fatalf("Current = (%d, %v), want (7, nil)（Redis 故障降级回源）", v, err)
	}
	if src.count() != 1 {
		t.Fatalf("source calls = %d, want 1", src.count())
	}
}

// TestEpochCurrentConcurrent：并发读取不 panic、值一致（RWMutex 正确性）。
func TestEpochCurrentConcurrent(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEpochRedis{vals: map[string]string{EpochKey(42): "3"}}
	src := &fakeSource{value: 3}
	store := NewEpochStore(fake, src.call)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, err := store.Current(ctx, 42); err != nil || v != 3 {
				t.Errorf("concurrent Current = (%d, %v)", v, err)
			}
		}()
	}
	wg.Wait()
}

// TestEpochStoreReal（env-skip）：真连测试实例——回源写回（SET 值与
// TTL 24h 量级）、localCache 命中（DEL 后不回源）、新 store 走 Redis
// 命中；测后 DEL 自证零残留。
func TestEpochStoreReal(t *testing.T) {
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

	const uid = int64(997003) // 测试专用 uid，避免与真实数据键冲突
	key := EpochKey(uid)
	// 测后清理用独立 ctx（deferred cancel 会先于 Cleanup 执行）。
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ccancel()
		if err := rdb.Del(cctx, key).Err(); err != nil {
			t.Fatalf("测后清理 DEL %s: %v", key, err)
		}
		if n, err := rdb.Exists(cctx, key).Result(); err != nil || n != 0 {
			t.Fatalf("exists %s = %d, err %v; want 0（测后零残留）", key, n, err)
		}
	})
	if err := rdb.Del(ctx, key).Err(); err != nil { // 前置清理
		t.Fatalf("前置清理 DEL %s: %v", key, err)
	}

	var srcCalls int
	src := func(ctx context.Context, uid int64) (int64, error) {
		srcCalls++
		return 42, nil
	}

	// ① Redis miss → 回源 + 写回（值 42、TTL 24h 量级）。
	store := NewEpochStore(rdb, src)
	v, err := store.Current(ctx, uid)
	if err != nil || v != 42 {
		t.Fatalf("Current = (%d, %v), want (42, nil)", v, err)
	}
	if srcCalls != 1 {
		t.Fatalf("source calls = %d, want 1", srcCalls)
	}
	if got, err := rdb.Get(ctx, key).Int64(); err != nil || got != 42 {
		t.Fatalf("redis GET %s = (%d, %v), want 42（回源写回）", key, got, err)
	}
	ttl, err := rdb.TTL(ctx, key).Result()
	if err != nil || ttl <= 23*time.Hour {
		t.Fatalf("ttl = (%v, %v), want > 23h（§5.1 行 863：24h）", ttl, err)
	}

	// ② localCache 命中：DEL 掉 Redis 键后再读，不回源、值不变。
	if err := rdb.Del(ctx, key).Err(); err != nil {
		t.Fatalf("DEL %s: %v", key, err)
	}
	if v, err := store.Current(ctx, uid); err != nil || v != 42 {
		t.Fatalf("Current after DEL = (%d, %v), want (42, nil)（localCache 命中）", v, err)
	}
	if srcCalls != 1 {
		t.Fatalf("source calls after cache hit = %d, want 1", srcCalls)
	}

	// ③ 新 store（localCache 空）：Redis 未命中（已被 DEL）→ 再次回源。
	store2 := NewEpochStore(rdb, src)
	if v, err := store2.Current(ctx, uid); err != nil || v != 42 {
		t.Fatalf("store2 Current = (%d, %v), want (42, nil)", v, err)
	}
	if srcCalls != 2 {
		t.Fatalf("source calls = %d, want 2", srcCalls)
	}

	// ④ 再来一个新 store：Redis 已写回 → 命中、不回源。
	store3 := NewEpochStore(rdb, src)
	if v, err := store3.Current(ctx, uid); err != nil || v != 42 {
		t.Fatalf("store3 Current = (%d, %v), want (42, nil)", v, err)
	}
	if srcCalls != 2 {
		t.Fatalf("source calls = %d, want 2（Redis 命中不回源）", srcCalls)
	}
}
