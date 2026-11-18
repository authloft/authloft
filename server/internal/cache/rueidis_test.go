// rueidis.go 适配层语义等价用例（真连 Redis，env-skip）：对齐 go-redis
// 时代同命令的行为口径——SetNX 原子性（nil 即 false 无错）、GETDEL 一次性、
// PTTL/TTL 负值哨兵（-1 无 TTL / -2 缺失）、EVAL 整数 / 数组应答与参数
// 传递、SCAN 游标分页、SADD/SISMEMBER、INCR、EXISTS、GET miss → Nil、
// PUBLISH/Subscribe 投递。键全部落在 al:t070:* 前缀内，测后 SCAN 全清
// 自证零残留；连接串只经环境变量注入。
package cache

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/redis/rueidis"
)

// t070Client 真连适配器实例 + 测试键清理。
func t070Client(t *testing.T) (context.Context, *RedisClient) {
	t.Helper()
	addr := os.Getenv("UC_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("环境变量 UC_TEST_REDIS_ADDR 未设置，跳过 Redis 连接用例")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	rdb, err := NewClient(ctx, redisTestConfig(addr))
	if err != nil {
		cancel()
		t.Fatalf("NewClient 真连失败: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		if err := clearT070Keys(cctx, rdb); err != nil {
			t.Fatalf("测后清理 al:t070:*: %v", err)
		}
		_ = rdb.Close()
	})
	t.Cleanup(cancel)
	return ctx, rdb
}

// clearT070Keys SCAN 全清 al:t070:* 测试键并复核零残留。
func clearT070Keys(ctx context.Context, rdb *RedisClient) error {
	var all []string
	var cursor uint64
	for {
		keys, next, err := rdb.Scan(ctx, cursor, "al:t070:*", 100).Result()
		if err != nil {
			return err
		}
		all = append(all, keys...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	if len(all) > 0 {
		if err := rdb.Del(ctx, all...).Err(); err != nil {
			return err
		}
	}
	var rest []string
	cursor = 0
	for {
		keys, next, err := rdb.Scan(ctx, cursor, "al:t070:*", 100).Result()
		if err != nil {
			return err
		}
		rest = append(rest, keys...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	if len(rest) != 0 {
		return fmt.Errorf("al:t070:* 残留 %d 键", len(rest))
	}
	return nil
}

// TestAdapterSetNXAtomicity SetNX 原子性：首次 true 并落值，重复写 false
// 且原值不被覆盖（对齐 go-redis「键已存在 → (false, nil)」口径）。
func TestAdapterSetNXAtomicity(t *testing.T) {
	ctx, rdb := t070Client(t)
	key := "al:t070:setnx"

	ok, err := rdb.SetNX(ctx, key, "first", time.Minute).Result()
	if err != nil || !ok {
		t.Fatalf("首次 SetNX = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = rdb.SetNX(ctx, key, "second", time.Minute).Result()
	if err != nil || ok {
		t.Fatalf("重复 SetNX = (%v, %v), want (false, nil)（nil 即 false 无错）", ok, err)
	}
	if v, err := rdb.Get(ctx, key).Result(); err != nil || v != "first" {
		t.Fatalf("Get = (%q, %v), want (first, nil)（原值不被覆盖）", v, err)
	}
}

// TestAdapterGetDelOneShot GETDEL 一次性 + GET miss → Nil 哨兵。
func TestAdapterGetDelOneShot(t *testing.T) {
	ctx, rdb := t070Client(t)
	key := "al:t070:getdel"

	if _, err := rdb.Get(ctx, key).Result(); err != Nil {
		t.Fatalf("Get 缺失 err = %v, want Nil 哨兵", err)
	}
	if err := rdb.Set(ctx, key, "v1", time.Minute).Err(); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if v, err := rdb.GetDel(ctx, key).Result(); err != nil || v != "v1" {
		t.Fatalf("首次 GetDel = (%q, %v), want (v1, nil)", v, err)
	}
	if v, err := rdb.GetDel(ctx, key).Result(); err != Nil || v != "" {
		t.Fatalf("二次 GetDel = (%q, %v), want (\"\", Nil)（一次性）", v, err)
	}
}

// TestAdapterPTTLTTL PTTL / TTL 数值口径：有 TTL 正值、无 TTL -1、键缺失 -2。
func TestAdapterPTTLTTL(t *testing.T) {
	ctx, rdb := t070Client(t)
	withTTL, noTTL, missing := "al:t070:pttl", "al:t070:pttl-nttl", "al:t070:pttl-missing"

	if err := rdb.Set(ctx, withTTL, "v", 30*time.Second).Err(); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := rdb.Set(ctx, noTTL, "v", 0).Err(); err != nil { // 0 = 不带过期
		t.Fatalf("Set 无 TTL: %v", err)
	}
	if d, err := rdb.PTTL(ctx, withTTL).Result(); err != nil || d <= 25*time.Second || d > 30*time.Second {
		t.Fatalf("PTTL 有 TTL = (%v, %v), want (25s, 30s]", d, err)
	}
	if d, err := rdb.TTL(ctx, withTTL).Result(); err != nil || d <= 25*time.Second || d > 30*time.Second {
		t.Fatalf("TTL 有 TTL = (%v, %v), want (25s, 30s]", d, err)
	}
	if d, err := rdb.PTTL(ctx, noTTL).Result(); err != nil || d != -1 {
		t.Fatalf("PTTL 无 TTL = (%v, %v), want (-1, nil)", d, err)
	}
	if d, err := rdb.PTTL(ctx, missing).Result(); err != nil || d != -2 {
		t.Fatalf("PTTL 缺失 = (%v, %v), want (-2, nil)", d, err)
	}
}

// TestAdapterIntCmds Incr / Exists / Del 的整数值应答。
func TestAdapterIntCmds(t *testing.T) {
	ctx, rdb := t070Client(t)
	key := "al:t070:counter"

	if n, err := rdb.Incr(ctx, key).Result(); err != nil || n != 1 {
		t.Fatalf("首次 Incr = (%d, %v), want (1, nil)", n, err)
	}
	if n, err := rdb.Incr(ctx, key).Result(); err != nil || n != 2 {
		t.Fatalf("二次 Incr = (%d, %v), want (2, nil)", n, err)
	}
	if n, err := rdb.Exists(ctx, key).Result(); err != nil || n != 1 {
		t.Fatalf("Exists = (%d, %v), want (1, nil)", n, err)
	}
	if n, err := rdb.Exists(ctx, key, "al:t070:absent").Result(); err != nil || n != 1 {
		t.Fatalf("多键 Exists = (%d, %v), want (1, nil)", n, err)
	}
	if n, err := rdb.Del(ctx, key, "al:t070:absent").Result(); err != nil || n != 1 {
		t.Fatalf("Del = (%d, %v), want (1, nil)", n, err)
	}
	if n, err := rdb.Exists(ctx, key).Result(); err != nil || n != 0 {
		t.Fatalf("Del 后 Exists = (%d, %v), want (0, nil)", n, err)
	}
}

// TestAdapterSetOps SADD / SISMEMBER 集合语义。
func TestAdapterSetOps(t *testing.T) {
	ctx, rdb := t070Client(t)
	key := "al:t070:set"

	if ok, err := rdb.SIsMember(ctx, key, int64(7)).Result(); err != nil || ok {
		t.Fatalf("空集 SIsMember = (%v, %v), want (false, nil)", ok, err)
	}
	if n, err := rdb.SAdd(ctx, key, int64(7), int64(9)).Result(); err != nil || n != 2 {
		t.Fatalf("SAdd = (%d, %v), want (2, nil)", n, err)
	}
	if ok, err := rdb.SIsMember(ctx, key, int64(7)).Result(); err != nil || !ok {
		t.Fatalf("SIsMember(7) = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := rdb.SIsMember(ctx, key, int64(8)).Result(); err != nil || ok {
		t.Fatalf("SIsMember(8) = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestAdapterEvalReplyTypes EVAL 应答类型与参数传递：整数应答走 Int64，
// 数组应答走 Slice（整数元素 int64、字符串元素 string），KEYS/ARGV 原样
// 透传到脚本。
func TestAdapterEvalReplyTypes(t *testing.T) {
	ctx, rdb := t070Client(t)
	key := "al:t070:eval"

	// 整数应答 + 参数传递：校验 KEYS/ARGV 到达脚本内部。
	script := "if #KEYS ~= 2 or #ARGV ~= 2 then return -1 end " +
		"if KEYS[1] ~= 'al:t070:eval' or KEYS[2] ~= 'al:t070:eval2' then return -2 end " +
		"if ARGV[1] ~= 'plain' or ARGV[2] ~= '42' then return -3 end " +
		"redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2]) " +
		"return 7"
	n, err := rdb.Eval(ctx, script, []string{key, key + "2"}, "plain", int64(42)).Int64()
	if err != nil || n != 7 {
		t.Fatalf("Eval 整数 = (%d, %v), want (7, nil)（参数透传失败码: %d）", n, err, n)
	}
	if v, err := rdb.Get(ctx, key).Result(); err != nil || v != "plain" {
		t.Fatalf("脚本内 SET 值 = (%q, %v), want (plain, nil)", v, err)
	}

	// 数组应答：整数元素 int64、字符串元素 string（go-redis Lua 解码口径）。
	raw, err := rdb.Eval(ctx, "return {1, 'abc', 0}", nil).Slice()
	if err != nil {
		t.Fatalf("Eval 数组: %v", err)
	}
	if len(raw) != 3 {
		t.Fatalf("Slice 长度 = %d, want 3", len(raw))
	}
	if v, ok := raw[0].(int64); !ok || v != 1 {
		t.Fatalf("Slice[0] = (%v, %T), want (1, int64)", raw[0], raw[0])
	}
	if v, ok := raw[1].(string); !ok || v != "abc" {
		t.Fatalf("Slice[1] = (%v, %T), want (abc, string)", raw[1], raw[1])
	}
	if v, ok := raw[2].(int64); !ok || v != 0 {
		t.Fatalf("Slice[2] = (%v, %T), want (0, int64)", raw[2], raw[2])
	}

	// 整数应答误用 Slice / 数组应答误用 Int64 的判别。
	if n, err := rdb.Eval(ctx, "return {1, 2}", nil).Int64(); err == nil {
		t.Fatalf("数组应答 Int64 应报错, got %d", n)
	}
}

// TestAdapterScanCursorPagination SCAN 游标分页：COUNT=1 强制多页遍历，
// 全量键均被访问且游标最终归零（对齐 go-redis ScanCmd 的 (keys, cursor) 口径）。
func TestAdapterScanCursorPagination(t *testing.T) {
	ctx, rdb := t070Client(t)
	const total = 5
	for i := 0; i < total; i++ {
		if err := rdb.Set(ctx, "al:t070:scan:"+strconv.Itoa(i), "v", time.Minute).Err(); err != nil {
			t.Fatalf("种键 #%d: %v", i, err)
		}
	}
	seen := make(map[string]bool)
	var cursor uint64
	pages := 0
	for {
		keys, next, err := rdb.Scan(ctx, cursor, "al:t070:scan:*", 1).Result()
		if err != nil {
			t.Fatalf("Scan 游标 %d: %v", cursor, err)
		}
		pages++
		for _, k := range keys {
			seen[k] = true
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	if pages < total {
		t.Fatalf("SCAN 页数 = %d, want >= %d（COUNT=1 强制多页）", pages, total)
	}
	if len(seen) != total {
		t.Fatalf("遍历键数 = %d, want %d", len(seen), total)
	}
	for i := 0; i < total; i++ {
		if !seen["al:t070:scan:"+strconv.Itoa(i)] {
			t.Fatalf("键 #%d 未被游标遍历到", i)
		}
	}
}

// TestAdapterPublishSubscribe PUBLISH → Subscribe 投递：订阅确认后收到
// 频道与消息体（payload 与 go-redis Message.Payload 同口径），Stop 后通道
// 关闭、Done 收敛。
func TestAdapterPublishSubscribe(t *testing.T) {
	ctx, rdb := t070Client(t)
	const channel = "al:t070:chg"

	sub, err := rdb.Subscribe(ctx, channel)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	// 确认订阅已建立后再发布（订阅前发布的消息不投递）。
	if err := rdb.Publish(ctx, channel, "hello").Err(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	select {
	case msg := <-sub.Channel():
		if msg.Channel != channel || msg.Payload != "hello" {
			t.Fatalf("消息 = (%q, %q), want (%q, %q)", msg.Channel, msg.Payload, channel, "hello")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("5s 内未收到 PUBLISH 投递")
	}

	// 二次投递后 Stop：通道关闭，Done 收敛。
	if err := rdb.Publish(ctx, channel, "bye").Err(); err != nil {
		t.Fatalf("Publish 2: %v", err)
	}
	select {
	case msg := <-sub.Channel():
		if msg.Payload != "bye" {
			t.Fatalf("二次消息 payload = %q, want bye", msg.Payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("5s 内未收到二次投递")
	}
	sub.Stop()
	select {
	case <-sub.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Stop 后 Done 未收敛")
	}
	for range sub.Channel() { // Channel 已关闭，循环应立即退出
	}

	// Stop 幂等。
	sub.Stop()

	// 订阅失败 fail-fast：指向保留端口的客户端（无 PING 直连构造）Subscribe
	// 应返回错误；限时 ctx 防底层重试拖挂用例。
	deadCtx, deadCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer deadCancel()
	deadClient, _ := rueidis.NewClient(rueidis.ClientOption{
		InitAddress:       []string{"127.0.0.1:1"},
		ForceSingleClient: true,
	})
	dead := NewClientWithRueidis(deadClient)
	t.Cleanup(func() { _ = dead.Close() })
	if _, err := dead.Subscribe(deadCtx, channel); err == nil {
		t.Fatal("不可达客户端 Subscribe 应返回错误")
	}
}

// TestAdapterPublishSubscriberCount Publish 返回接收订阅方数量（语义对齐
// go-redis IntCmd 应答）：有订阅者时 >= 1。
func TestAdapterPublishSubscriberCount(t *testing.T) {
	ctx, rdb := t070Client(t)
	const channel = "al:t070:chg2"

	sub, err := rdb.Subscribe(ctx, channel)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	t.Cleanup(sub.Stop)

	// 订阅确认与 PUBLISH 之间有真实 RTT，此处轮询直到数量 >= 1（上限 5s）。
	var n int64
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, err = rdb.Publish(ctx, channel, "x").Result()
		if err != nil {
			t.Fatalf("Publish: %v", err)
		}
		if n >= 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Publish 订阅方数量 = %d, want >= 1", n)
}

// TestAdapterSetExpiry Set 的 TTL 透传：带过期写入后 TTL 为正，0 过期
// 写入无 TTL（PTTL = -1）。
func TestAdapterSetExpiry(t *testing.T) {
	ctx, rdb := t070Client(t)
	key1, key2 := "al:t070:setexp", "al:t070:setexp-nttl"

	if err := rdb.Set(ctx, key1, "v", time.Minute).Err(); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if d, err := rdb.PTTL(ctx, key1).Result(); err != nil || d <= 55*time.Second {
		t.Fatalf("PTTL = (%v, %v), want > 55s", d, err)
	}
	if err := rdb.Set(ctx, key2, []byte("raw"), 0).Err(); err != nil {
		t.Fatalf("Set 无 TTL: %v", err)
	}
	if v, err := rdb.Get(ctx, key2).Result(); err != nil || v != "raw" {
		t.Fatalf("[]byte 值往返 = (%q, %v), want (raw, nil)", v, err)
	}
	if d, err := rdb.PTTL(ctx, key2).Result(); err != nil || d != -1 {
		t.Fatalf("无 TTL 键 PTTL = (%v, %v), want (-1, nil)", d, err)
	}
}

// TestAdapterConcurrentGetSet 并发 Get/Set 不串话（多路复用正确性冒烟）。
func TestAdapterConcurrentGetSet(t *testing.T) {
	ctx, rdb := t070Client(t)
	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "al:t070:cc:" + strconv.Itoa(i)
			if err := rdb.Set(ctx, key, strconv.Itoa(i), time.Minute).Err(); err != nil {
				t.Errorf("Set #%d: %v", i, err)
				return
			}
			v, err := rdb.Get(ctx, key).Result()
			if err != nil || v != strconv.Itoa(i) {
				t.Errorf("Get #%d = (%q, %v), want (%q, nil)", i, v, err, strconv.Itoa(i))
			}
		}(i)
	}
	wg.Wait()
}
