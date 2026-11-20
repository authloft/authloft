// EpochStore 单测：Check 双键一次读（MGET 三态 + 单键 Nil 与命令错误
// 分离）与签发侧 Current / Sync（fake redis 计数）；真连用例沿
// redis_test.go 的 env-skip 模式（UC_TEST_REDIS_ADDR），只碰自有键
// al:pwdep:{uid} / al:sess:ev:{sid}，测后 DEL 零残留，连接串只经环境
// 变量注入。
package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// fakeEpochRedis 计数型 fake（实现 epochRedis 窄接口）：vals 为键值表；
// getErr / mgetErr 非 nil 时 GET / MGET 返回故障错误（模拟 Redis 挂掉，
// 命令级错误——区别于单键 Nil）；setErr 非 nil 时 SET 返回故障错误（模拟
// Sync 写入失败）。
type fakeEpochRedis struct {
	mu       sync.Mutex
	gets     int
	mgets    int
	sets     int
	dels     int
	getKeys  []string
	mgetKeys [][]string
	setKeys  []string
	setTTNs  []time.Duration
	vals     map[string]string
	getErr   error
	mgetErr  error
	setErr   error
}

func (f *fakeEpochRedis) Get(ctx context.Context, key string) StringResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	f.getKeys = append(f.getKeys, key)
	if f.getErr != nil {
		return NewStringResult("", f.getErr)
	}
	if v, ok := f.vals[key]; ok {
		return NewStringResult(v, nil)
	}
	return NewStringResult("", Nil)
}

func (f *fakeEpochRedis) MGet(ctx context.Context, keys ...string) MGetResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mgets++
	f.mgetKeys = append(f.mgetKeys, append([]string(nil), keys...))
	if f.mgetErr != nil {
		return NewMGetResult(nil, f.mgetErr)
	}
	vals := make([]*string, len(keys))
	for i, key := range keys {
		if v, ok := f.vals[key]; ok {
			s := v
			vals[i] = &s
		}
	}
	return NewMGetResult(vals, nil)
}

func (f *fakeEpochRedis) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) StatusResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets++
	f.setKeys = append(f.setKeys, key)
	f.setTTNs = append(f.setTTNs, expiration)
	if f.setErr != nil {
		return NewStatusResult(f.setErr)
	}
	if f.vals == nil {
		f.vals = make(map[string]string)
	}
	f.vals[key] = fmt.Sprint(value)
	return NewStatusResult(nil)
}

func (f *fakeEpochRedis) Del(ctx context.Context, keys ...string) IntResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dels++
	for _, key := range keys {
		delete(f.vals, key)
	}
	return NewIntResult(1, nil)
}

// snapshot 返回各计数与键名快照。
func (f *fakeEpochRedis) snapshot() (gets, mgets, sets, dels int, getKeys []string, mgetKeys [][]string, setKeys []string, setTTNs []time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets, f.mgets, f.sets, f.dels,
		append([]string(nil), f.getKeys...),
		append([][]string(nil), f.mgetKeys...),
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

// strPtr 构造 MGET 应答的非 nil 元素。
func strPtr(s string) *string { return &s }

// TestEpochKey 键名格式与负数 uid（键名唯一出处 keys.go）。
func TestEpochKey(t *testing.T) {
	if got, want := EpochKey(42), "al:pwdep:42"; got != want {
		t.Fatalf("EpochKey(42) = %q, want %q", got, want)
	}
	if got, want := EpochKey(-1), "al:pwdep:-1"; got != want {
		t.Fatalf("EpochKey(-1) = %q, want %q", got, want)
	}
}

// TestSessionEvictKey 键名格式（键名唯一出处 keys.go；sid 为 32 位
// URL-safe 串原样作键片段）。
func TestSessionEvictKey(t *testing.T) {
	if got, want := SessionEvictKey("sid-0001"), "al:sess:ev:sid-0001"; got != want {
		t.Fatalf("SessionEvictKey = %q, want %q", got, want)
	}
	if got := SessionEvictKey(""); got != "al:sess:ev:" {
		t.Fatalf("SessionEvictKey(empty) = %q, want al:sess:ev:", got)
	}
}

// ---- Check：一条 MGET 双键（§11.1 步骤 3）----

// TestCheckMGETReadsBothKeysInOrder Check 固定一条 MGET 且按键序
// al:pwdep:{uid} + al:sess:ev:{sid}（双键一次读，热路径固定 1 次 Redis）。
func TestCheckMGETReadsBothKeysInOrder(t *testing.T) {
	fake := &fakeEpochRedis{vals: map[string]string{EpochKey(42): "7"}}
	store := NewEpochStore(fake, (&fakeSource{}).call)

	cur, revoked, err := store.Check(context.Background(), 42, "sid-0001")
	if err != nil || revoked || cur != 7 {
		t.Fatalf("Check = (%d, %v, %v), want (7, false, nil)", cur, revoked, err)
	}
	_, mgets, sets, _, _, mgetKeys, _, _ := fake.snapshot()
	if mgets != 1 || sets != 0 {
		t.Fatalf("redis calls mgets=%d sets=%d, want 1/0（一次读、命中不回写）", mgets, sets)
	}
	if len(mgetKeys) != 1 || len(mgetKeys[0]) != 2 ||
		mgetKeys[0][0] != EpochKey(42) || mgetKeys[0][1] != SessionEvictKey("sid-0001") {
		t.Fatalf("mget keys = %v, want [%s %s]", mgetKeys, EpochKey(42), SessionEvictKey("sid-0001"))
	}
}

// TestCheckRevoked 逐出标记存在即 revoked=true 并短路：epoch 缓存缺失 /
// 存在两形态都不回源、不 SET（失效判定不需要值）。
func TestCheckRevoked(t *testing.T) {
	ctx := context.Background()
	// a) 逐出标记存在 + epoch 缓存缺失。
	fake := &fakeEpochRedis{vals: map[string]string{SessionEvictKey("sid-0001"): "password_change"}}
	src := &fakeSource{value: 7}
	store := NewEpochStore(fake, src.call)
	cur, revoked, err := store.Check(ctx, 42, "sid-0001")
	if err != nil || !revoked {
		t.Fatalf("Check = (%d, %v, %v), want revoked", cur, revoked, err)
	}
	if n := src.count(); n != 0 {
		t.Fatalf("source calls = %d, want 0（逐出短路，不回源 epoch）", n)
	}
	_, _, sets, _, _, _, _, _ := fake.snapshot()
	if sets != 0 {
		t.Fatalf("sets = %d, want 0（逐出分支不写缓存）", sets)
	}

	// b) 逐出优先：epoch 缓存也在场时仍以逐出为准。
	fake2 := &fakeEpochRedis{vals: map[string]string{
		EpochKey(42):                "7",
		SessionEvictKey("sid-0001"): "admin_disable",
	}}
	cur2, revoked2, err2 := NewEpochStore(fake2, src.call).Check(ctx, 42, "sid-0001")
	if err2 != nil || !revoked2 || cur2 != 0 {
		t.Fatalf("Check = (%d, %v, %v), want (0, true, nil)（逐出优先）", cur2, revoked2, err2)
	}
}

// TestCheckEpochHit epoch 缓存命中 + 无逐出标记：直接返回缓存值，
// 零回源、零写回。
func TestCheckEpochHit(t *testing.T) {
	fake := &fakeEpochRedis{vals: map[string]string{EpochKey(42): "9"}}
	src := &fakeSource{value: 7}
	store := NewEpochStore(fake, src.call)

	cur, revoked, err := store.Check(context.Background(), 42, "sid-0001")
	if err != nil || revoked || cur != 9 {
		t.Fatalf("Check = (%d, %v, %v), want (9, false, nil)", cur, revoked, err)
	}
	if n := src.count(); n != 0 {
		t.Fatalf("source calls = %d, want 0（缓存命中不回源）", n)
	}
}

// TestCheckEpochMissBackfillsTTL24h epoch 缓存缺失（正常 Nil）→ 回源
// SET al:pwdep TTL 24h（§11.1 步骤 3 / §5.1：TTL 不变）。
func TestCheckEpochMissBackfillsTTL24h(t *testing.T) {
	fake := &fakeEpochRedis{}
	src := &fakeSource{value: 7}
	store := NewEpochStore(fake, src.call)

	cur, revoked, err := store.Check(context.Background(), 42, "sid-0001")
	if err != nil || revoked || cur != 7 {
		t.Fatalf("Check = (%d, %v, %v), want (7, false, nil)", cur, revoked, err)
	}
	if n := src.count(); n != 1 {
		t.Fatalf("source calls = %d, want 1", n)
	}
	_, mgets, sets, _, _, _, setKeys, setTTNs := fake.snapshot()
	if mgets != 1 || sets != 1 {
		t.Fatalf("redis calls mgets=%d sets=%d, want 1/1", mgets, sets)
	}
	if len(setKeys) != 1 || setKeys[0] != EpochKey(42) {
		t.Fatalf("set keys = %v, want [%s]", setKeys, EpochKey(42))
	}
	if len(setTTNs) != 1 || setTTNs[0] != 24*time.Hour {
		t.Fatalf("set ttl = %v, want 24h（§5.1）", setTTNs)
	}
}

// TestCheckSingleKeyNilIsNotCommandError 单键 Nil ≠ 命令错误（方向一：
// 把 Nil 当错误会多一次无谓 DB 回源）：epoch 缓存在场、仅逐出键缺失（正常
// Nil）→ 零回源。若实现把 Nil 误读为命令级故障走 fail-open，source 会被
// 调用、计数断言即红。
func TestCheckSingleKeyNilIsNotCommandError(t *testing.T) {
	fake := &fakeEpochRedis{vals: map[string]string{EpochKey(42): "9"}}
	src := &fakeSource{value: 7}
	store := NewEpochStore(fake, src.call)

	cur, revoked, err := store.Check(context.Background(), 42, "sid-0001")
	if err != nil || revoked || cur != 9 {
		t.Fatalf("Check = (%d, %v, %v), want (9, false, nil)", cur, revoked, err)
	}
	if n := src.count(); n != 0 {
		t.Fatalf("source calls = %d, want 0（单键 Nil 是正常路径，不触发 fail-open）", n)
	}
}

// TestCheckCommandErrorIsNotSingleKeyNil 单键 Nil ≠ 命令错误（方向二：
// 把错误当 Nil 会在真故障时漏掉逐出判定并错误回写缓存）：MGET 命令级故障
// （逐出标记真实存在但不可读）→ fail-open 回源比对、revoked=false、
// **不回写缓存**。若实现把命令错误误读为「双键缺失」走正常回源路径，
// SET 会发生、计数断言即红。
func TestCheckCommandErrorIsNotSingleKeyNil(t *testing.T) {
	fake := &fakeEpochRedis{
		mgetErr: errors.New("connection reset"),
		vals:    map[string]string{SessionEvictKey("sid-0001"): "password_change"},
	}
	src := &fakeSource{value: 7}
	store := NewEpochStore(fake, src.call)

	cur, revoked, err := store.Check(context.Background(), 42, "sid-0001")
	if err != nil || revoked || cur != 7 {
		t.Fatalf("Check = (%d, %v, %v), want (7, false, nil)（fail-open 回源）", cur, revoked, err)
	}
	if n := src.count(); n != 1 {
		t.Fatalf("source calls = %d, want 1", n)
	}
	_, _, sets, _, _, _, _, _ := fake.snapshot()
	if sets != 0 {
		t.Fatalf("sets = %d, want 0（fail-open 不回写缓存）", sets)
	}
}

// TestCheckCommandErrorDBMismatch Propagates epoch 值：fail-open 返回
// DB 真值，比对归校验链（DB 不一致 → ErrSessionStale，session 层用例）。
func TestCheckCommandErrorReturnsDBEpoch(t *testing.T) {
	fake := &fakeEpochRedis{mgetErr: errors.New("redis down")}
	src := &fakeSource{value: 8}
	store := NewEpochStore(fake, src.call)

	cur, revoked, err := store.Check(context.Background(), 42, "sid-0001")
	if err != nil || revoked || cur != 8 {
		t.Fatalf("Check = (%d, %v, %v), want (8, false, nil)", cur, revoked, err)
	}
}

// TestCheckCommandErrorAndSourceFails 命令级故障 + 回源也失败 → 返回
// 错误（内部错误语义，由上层按基础设施错误处理；不放大为逐出 / 放行）。
func TestCheckCommandErrorAndSourceFails(t *testing.T) {
	boom := errors.New("db down")
	fake := &fakeEpochRedis{mgetErr: errors.New("redis down")}
	src := &fakeSource{err: boom}
	store := NewEpochStore(fake, src.call)

	if _, _, err := store.Check(context.Background(), 42, "sid-0001"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want db down", err)
	}
}

// TestCheckEpochMissSourceFails epoch 缓存缺失且回源失败 → 错误传播、
// 不写回。
func TestCheckEpochMissSourceFails(t *testing.T) {
	boom := errors.New("db down")
	fake := &fakeEpochRedis{}
	src := &fakeSource{err: boom}
	store := NewEpochStore(fake, src.call)

	if _, _, err := store.Check(context.Background(), 42, "sid-0001"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want db down", err)
	}
	_, _, sets, _, _, _, _, _ := fake.snapshot()
	if sets != 0 {
		t.Fatalf("sets = %d, want 0（回源失败不写回）", sets)
	}
}

// TestCheckCorruptedValueFallsBackToSource 缓存值损坏（非整数）→ 按故障
// 走回源比对（DB 唯一真源），不把损坏值当 Nil 静默放行比对缺失。
func TestCheckCorruptedValueFallsBackToSource(t *testing.T) {
	fake := &fakeEpochRedis{vals: map[string]string{EpochKey(42): "not-a-number"}}
	src := &fakeSource{value: 8}
	store := NewEpochStore(fake, src.call)

	cur, revoked, err := store.Check(context.Background(), 42, "sid-0001")
	if err != nil || revoked || cur != 8 {
		t.Fatalf("Check = (%d, %v, %v), want (8, false, nil)（损坏值 fail-open 回源）", cur, revoked, err)
	}
	if n := src.count(); n != 1 {
		t.Fatalf("source calls = %d, want 1", n)
	}
	_, _, sets, _, _, _, _, _ := fake.snapshot()
	if sets != 0 {
		t.Fatalf("sets = %d, want 0（故障路径不回写）", sets)
	}
}

// ---- Current：签发侧读（GET → 缺失回源 SET）----

// TestEpochCurrentMissThenFallback：Redis 未命中 → 回源 → SET 新值
// TTL 24h；再次读取走 Redis 命中（无本地缓存，每读一次 Redis）。
func TestEpochCurrentMissThenFallback(t *testing.T) {
	ctx := context.Background()
	fake := &fakeEpochRedis{}
	src := &fakeSource{value: 7}
	store := NewEpochStore(fake, src.call)

	v, err := store.Current(ctx, 42)
	if err != nil || v != 7 {
		t.Fatalf("Current = (%d, %v), want (7, nil)", v, err)
	}
	gets, _, sets, _, getKeys, _, setKeys, setTTNs := fake.snapshot()
	if gets != 1 || sets != 1 {
		t.Fatalf("redis calls gets=%d sets=%d, want 1/1", gets, sets)
	}
	if want := EpochKey(42); getKeys[0] != want || setKeys[0] != want {
		t.Fatalf("key mismatch: get=%q set=%q, want %q", getKeys[0], setKeys[0], want)
	}
	if setTTNs[0] != 24*time.Hour {
		t.Fatalf("set ttl = %v, want 24h（§5.1）", setTTNs[0])
	}
	if src.count() != 1 {
		t.Fatalf("source calls = %d, want 1", src.count())
	}

	// 第二次：Redis 已有值 → GET 命中（不再回源、不重复 SET）。
	v, err = store.Current(ctx, 42)
	if err != nil || v != 7 {
		t.Fatalf("second Current = (%d, %v), want (7, nil)", v, err)
	}
	gets, _, sets, _, _, _, _, _ = fake.snapshot()
	if gets != 2 || sets != 1 {
		t.Fatalf("after hit gets=%d sets=%d, want 2/1", gets, sets)
	}
	if src.count() != 1 {
		t.Fatalf("source calls after hit = %d, want 1", src.count())
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
	gets, _, sets, _, _, _, _, _ := fake.snapshot()
	if gets != 1 || sets != 0 {
		t.Fatalf("redis calls gets=%d sets=%d, want 1/0", gets, sets)
	}
	if src.count() != 0 {
		t.Fatalf("source calls = %d, want 0", src.count())
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
	_, _, sets, _, _, _, _, _ := fake.snapshot()
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

// TestEpochCurrentConcurrent：并发读取不 panic、值一致（fake 锁正确性）。
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
// TTL 24h 量级）、Redis 命中不回源、Check 双键一次读（含逐出键真值形态）；
// 测后 DEL 自证零残留。
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
	const sid = "real-sid-0001"
	key, evictKey := EpochKey(uid), SessionEvictKey(sid)
	// 测后清理用独立 ctx（deferred cancel 会先于 Cleanup 执行）。
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ccancel()
		if err := rdb.Del(cctx, key, evictKey).Err(); err != nil {
			t.Fatalf("测后清理 DEL: %v", err)
		}
		if n, err := rdb.Exists(cctx, key, evictKey).Result(); err != nil || n != 0 {
			t.Fatalf("exists = %d, err %v; want 0（测后零残留）", n, err)
		}
	})
	if err := rdb.Del(ctx, key, evictKey).Err(); err != nil { // 前置清理
		t.Fatalf("前置清理 DEL: %v", err)
	}

	var srcCalls int
	src := func(ctx context.Context, uid int64) (int64, error) {
		srcCalls++
		return 42, nil
	}

	// ① Check 双键 miss → 回源 + 写回（值 42、TTL 24h 量级）。
	store := NewEpochStore(rdb, src)
	cur, revoked, err := store.Check(ctx, uid, sid)
	if err != nil || revoked || cur != 42 {
		t.Fatalf("Check = (%d, %v, %v), want (42, false, nil)", cur, revoked, err)
	}
	if srcCalls != 1 {
		t.Fatalf("source calls = %d, want 1", srcCalls)
	}
	if got, err := rdb.Get(ctx, key).Int64(); err != nil || got != 42 {
		t.Fatalf("redis GET %s = (%d, %v), want 42（回源写回）", key, got, err)
	}
	ttl, err := rdb.TTL(ctx, key).Result()
	if err != nil || ttl <= 23*time.Hour {
		t.Fatalf("ttl = (%v, %v), want > 23h（§5.1：24h）", ttl, err)
	}

	// ② Check 再次执行：MGET 命中（写回值在场）→ 不回源、不写回。
	if cur, revoked, err = store.Check(ctx, uid, sid); err != nil || revoked || cur != 42 {
		t.Fatalf("Check #2 = (%d, %v, %v), want (42, false, nil)", cur, revoked, err)
	}
	if srcCalls != 1 {
		t.Fatalf("source calls = %d, want 1（MGET 命中不回源）", srcCalls)
	}

	// ③ Current 签发侧读：Redis 命中（键已在）→ 不回源。
	if v, err := store.Current(ctx, uid); err != nil || v != 42 {
		t.Fatalf("Current = (%d, %v), want (42, nil)", v, err)
	}
	if srcCalls != 1 {
		t.Fatalf("source calls = %d, want 1（Redis 命中不回源）", srcCalls)
	}

	// ④ 逐出键真值形态：SET 逐出标记后 Check → revoked=true。
	if err := rdb.Set(ctx, evictKey, "password_change", time.Minute).Err(); err != nil {
		t.Fatalf("SET evict: %v", err)
	}
	if cur, revoked, err = store.Check(ctx, uid, sid); err != nil || !revoked {
		t.Fatalf("Check after evict = (%d, %v, %v), want revoked", cur, revoked, err)
	}
}

// TestEpochSyncWritesNewValue Sync 覆盖式同步（§5.1）：SET 新值
// （TTL 24h 量级），后续 Current 经 Redis 命中读回新值、不再回源。
func TestEpochSyncWritesNewValue(t *testing.T) {
	fake := &fakeEpochRedis{vals: map[string]string{EpochKey(42): "3"}}
	src := &fakeSource{value: 3}
	store := NewEpochStore(fake, src.call)

	if err := store.Sync(context.Background(), 42, 4); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	_, _, sets, _, _, _, setKeys, setTTNs := fake.snapshot()
	if sets != 1 || len(setKeys) != 1 || setKeys[0] != EpochKey(42) {
		t.Fatalf("sets = %d keys = %v, want 1 × %s", sets, setKeys, EpochKey(42))
	}
	if len(setTTNs) != 1 || setTTNs[0] <= 23*time.Hour {
		t.Fatalf("set ttl = %v, want > 23h（§5.1：24h）", setTTNs)
	}
	if fake.vals[EpochKey(42)] != "4" {
		t.Fatalf("redis value = %q, want 4", fake.vals[EpochKey(42)])
	}

	// Redis 命中：Current 读回新值（不 GET 回源——命中读不触发 source）。
	v, err := store.Current(context.Background(), 42)
	if err != nil || v != 4 {
		t.Fatalf("Current after Sync = (%d, %v), want (4, nil)", v, err)
	}
}

// TestEpochSyncSetFailureFallsBackToDel Sync 的 SET 失败退而 DEL
// （读取链 miss 后回源 DB 真源，避免 Redis 残留旧值最长 24h）。
func TestEpochSyncSetFailureFallsBackToDel(t *testing.T) {
	fake := &fakeEpochRedis{
		vals:   map[string]string{EpochKey(42): "3"},
		setErr: errors.New("redis write error"),
	}
	src := &fakeSource{value: 5}
	store := NewEpochStore(fake, src.call)

	if err := store.Sync(context.Background(), 42, 4); err == nil {
		t.Fatal("Sync must report SET failure")
	}
	_, _, _, dels, _, _, _, _ := fake.snapshot()
	if dels != 1 {
		t.Fatalf("dels = %d, want 1（SET 失败退 DEL）", dels)
	}
	// 键已 DEL → Current 回源拿到 DB 真值（而非残留的 3）。
	v, err := store.Current(context.Background(), 42)
	if err != nil || v != 5 {
		t.Fatalf("Current after failed Sync = (%d, %v), want (5, nil)（回源真值）", v, err)
	}
}
