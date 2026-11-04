// cache/code.go 单测（覆盖 docs/后端架构.md §21.2-C 行 1822-1823）：
// 发码 6 项（首次 / 冷却 / 单目标日限额 / IP 日限额 / TTL / 单次 EVAL），
// 校验 5 项（成功消费 / 错码 tries+1 保留 / 第 5 次作废 / owner 隔离 /
// 并发 100 次仅 1 次成功）。真连 Redis（UC_TEST_REDIS_ADDR），无 env skip；
// 每个用例用唯一 token 作 target/ip 片段，测后按 token SCAN 全清自证零残留。
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// codeTestRDB 真连测试实例，返回 ctx / client / 每用例唯一 token。
func codeTestRDB(t *testing.T) (context.Context, *redis.Client, string) {
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
	token := "t051-" + randNonce(t)
	t.Cleanup(func() { _ = rdb.Close() })
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		if err := clearCodeTestKeys(cctx, rdb, token); err != nil {
			t.Fatalf("测后清理 %s 键: %v", token, err)
		}
	})
	t.Cleanup(cancel)
	return ctx, rdb, token
}

// clearCodeTestKeys 删除全部含 token 的 al:* 键并复核零残留。
func clearCodeTestKeys(ctx context.Context, rdb *redis.Client, token string) error {
	pattern := "al:*" + token + "*"
	var all []string
	var cursor uint64
	for {
		keys, next, err := rdb.Scan(ctx, cursor, pattern, 100).Result()
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
		keys, next, err := rdb.Scan(ctx, cursor, pattern, 100).Result()
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
		return fmt.Errorf("%s 键残留 %d 个", token, len(rest))
	}
	return nil
}

// commandCounter go-redis Hook：记录经过客户端的命令名（用于断言发码仅
// 1 次 EVAL 往返，§21.2-C 行 1822 ⑥）。
type commandCounter struct {
	mu    sync.Mutex
	names []string
}

func (c *commandCounter) reset() {
	c.mu.Lock()
	c.names = nil
	c.mu.Unlock()
}

func (c *commandCounter) add(name string) {
	c.mu.Lock()
	c.names = append(c.names, name)
	c.mu.Unlock()
}

func (c *commandCounter) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.names...)
}

func (c *commandCounter) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (c *commandCounter) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		c.add(cmd.Name())
		return next(ctx, cmd)
	}
}

func (c *commandCounter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			c.add(cmd.Name())
		}
		return next(ctx, cmds)
	}
}

// mustSend 断言发码成功。
func mustSend(t *testing.T, ctx context.Context, store *CodeStore, target, purpose, owner, ip, code string) {
	t.Helper()
	res, err := store.Send(ctx, target, purpose, owner, ip, code)
	if err != nil || res != SendOK {
		t.Fatalf("Send(%s) = (%v, %v), want (SendOK, nil)", target, res, err)
	}
}

// readStoredCode 读取并解析 al:code 值。
func readStoredCode(t *testing.T, ctx context.Context, rdb *redis.Client, key string) storedCode {
	t.Helper()
	raw, err := rdb.Get(ctx, key).Result()
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	var v storedCode
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("解析 %s 值 %q: %v", key, raw, err)
	}
	return v
}

// TestCodeSendFirst 发码 ①：首次成功，code 值含 code/owner/tries/sent_at，
// 冷却键与两级日计数键同步写入（§10.1 行 1108-1115）。
func TestCodeSendFirst(t *testing.T) {
	ctx, rdb, token := codeTestRDB(t)
	store := NewCodeStore(rdb, CodeOptions{})
	target := token + "-first"
	ip := token + "-ip"
	purpose := "login"
	before := time.Now().Unix()

	mustSend(t, ctx, store, target, purpose, "tid-1", ip, "123456")

	key := CodeKey(target, purpose)
	v := readStoredCode(t, ctx, rdb, key)
	if v.Code != "123456" || v.Owner != "tid-1" || v.Tries != 0 {
		t.Fatalf("stored = %+v, want code 123456 / owner tid-1 / tries 0", v)
	}
	if v.SentAt < before-5 || v.SentAt > time.Now().Unix()+5 {
		t.Fatalf("sent_at = %d, 偏离 now（%d）过大", v.SentAt, before)
	}
	if n, err := rdb.Exists(ctx, SendCooldownKey(target)).Result(); err != nil || n != 1 {
		t.Fatalf("cooldown exists = (%d, %v), want (1, nil)", n, err)
	}
	ymd := dayStamp(time.Now())
	if n, err := rdb.Get(ctx, SendDayKey(target, ymd)).Int(); err != nil || n != 1 {
		t.Fatalf("sendday = (%d, %v), want (1, nil)", n, err)
	}
	if n, err := rdb.Get(ctx, IPDayKey(ip, ymd)).Int(); err != nil || n != 1 {
		t.Fatalf("ipday = (%d, %v), want (1, nil)", n, err)
	}
}

// TestCodeSendCooldown 发码 ②：60s 内二次发码被拒（SendCooldown），且
// 原验证码不被覆盖。
func TestCodeSendCooldown(t *testing.T) {
	ctx, rdb, token := codeTestRDB(t)
	store := NewCodeStore(rdb, CodeOptions{})
	target := token + "-cd"
	ip := token + "-ip"
	purpose := "login"

	mustSend(t, ctx, store, target, purpose, "tid-1", ip, "111111")
	res, err := store.Send(ctx, target, purpose, "tid-1", ip, "222222")
	if err != nil || res != SendCooldown {
		t.Fatalf("二次 Send = (%v, %v), want (SendCooldown, nil)", res, err)
	}
	if v := readStoredCode(t, ctx, rdb, CodeKey(target, purpose)); v.Code != "111111" {
		t.Fatalf("cooled code = %q, want 111111（原码不被覆盖）", v.Code)
	}
}

// TestCodeSendTargetDailyLimit 发码 ③：单目标日限额到达被拒；日计数等于限额。
func TestCodeSendTargetDailyLimit(t *testing.T) {
	ctx, rdb, token := codeTestRDB(t)
	store := NewCodeStore(rdb, CodeOptions{TargetDailyLimit: 2})
	target := token + "-dlt"
	ip := token + "-ip"
	purpose := "login"

	for i := 0; i < 2; i++ {
		mustSend(t, ctx, store, target, purpose, "tid-1", ip, "123456")
		// 模拟冷却已过：删冷却键后再发（日限额与冷却相互独立）。
		if err := rdb.Del(ctx, SendCooldownKey(target)).Err(); err != nil {
			t.Fatalf("del cooldown: %v", err)
		}
	}
	res, err := store.Send(ctx, target, purpose, "tid-1", ip, "123456")
	if err != nil || res != SendTargetDailyLimit {
		t.Fatalf("第三次 Send = (%v, %v), want (SendTargetDailyLimit, nil)", res, err)
	}
	if n, err := rdb.Get(ctx, SendDayKey(target, dayStamp(time.Now()))).Int(); err != nil || n != 2 {
		t.Fatalf("sendday = (%d, %v), want (2, nil)", n, err)
	}
}

// TestCodeSendIPDailyLimit 发码 ④：单 IP 日限额到达被拒（换 target 仍命中同 IP）。
func TestCodeSendIPDailyLimit(t *testing.T) {
	ctx, rdb, token := codeTestRDB(t)
	store := NewCodeStore(rdb, CodeOptions{IPDailyLimit: 1})
	ip := token + "-ip"
	purpose := "login"
	targetA := token + "-ipa"
	targetB := token + "-ipb"

	mustSend(t, ctx, store, targetA, purpose, "tid-1", ip, "111111")
	res, err := store.Send(ctx, targetB, purpose, "tid-2", ip, "222222")
	if err != nil || res != SendIPDailyLimit {
		t.Fatalf("第二目标 Send = (%v, %v), want (SendIPDailyLimit, nil)", res, err)
	}
	if n, err := rdb.Get(ctx, IPDayKey(ip, dayStamp(time.Now()))).Int(); err != nil || n != 1 {
		t.Fatalf("ipday = (%d, %v), want (1, nil)", n, err)
	}
	if n, err := rdb.Exists(ctx, CodeKey(targetB, purpose)).Result(); err != nil || n != 0 {
		t.Fatalf("被拒目标验证码 exists = (%d, %v), want (0, nil)", n, err)
	}
}

// TestCodeSendTTL 发码 ⑤：验证码 TTL 300s、冷却 60s、日计数键至当天 24:00。
func TestCodeSendTTL(t *testing.T) {
	ctx, rdb, token := codeTestRDB(t)
	store := NewCodeStore(rdb, CodeOptions{})
	target := token + "-ttl"
	ip := token + "-ip"
	purpose := "login"

	mustSend(t, ctx, store, target, purpose, "tid-1", ip, "123456")

	ttl, err := rdb.TTL(ctx, CodeKey(target, purpose)).Result()
	if err != nil || ttl <= 290*time.Second || ttl > 300*time.Second {
		t.Fatalf("code ttl = (%v, %v), want (290s, 300s]", ttl, err)
	}
	ttl, err = rdb.TTL(ctx, SendCooldownKey(target)).Result()
	if err != nil || ttl <= 50*time.Second || ttl > 60*time.Second {
		t.Fatalf("cooldown ttl = (%v, %v), want (50s, 60s]", ttl, err)
	}
	ymd := dayStamp(time.Now())
	for _, key := range []string{SendDayKey(target, ymd), IPDayKey(ip, ymd)} {
		ttl, err = rdb.TTL(ctx, key).Result()
		if err != nil || ttl <= 0 || ttl > 24*time.Hour {
			t.Fatalf("日计数键 %s ttl = (%v, %v), want (0, 24h]", key, ttl, err)
		}
	}
}

// TestCodeSendSingleEval 发码 ⑥：4 写合并后仅 1 次客户端命令往返（EVAL）。
func TestCodeSendSingleEval(t *testing.T) {
	ctx, rdb, token := codeTestRDB(t)
	store := NewCodeStore(rdb, CodeOptions{})
	counter := &commandCounter{}
	rdb.AddHook(counter)
	counter.reset()

	mustSend(t, ctx, store, token+"-one", "login", "tid-1", token+"-ip", "123456")

	names := counter.snapshot()
	if len(names) != 1 || names[0] != "eval" {
		t.Fatalf("发码命令 = %v, want [eval]（4 写合并为 1 次往返）", names)
	}
}

// TestCodeVerifySuccess 校验 ①：正确码成功且键被删（一次性消费）。
func TestCodeVerifySuccess(t *testing.T) {
	ctx, rdb, token := codeTestRDB(t)
	store := NewCodeStore(rdb, CodeOptions{})
	target := token + "-vok"
	purpose := "login"

	mustSend(t, ctx, store, target, purpose, "tid-1", token+"-ip", "123456")
	res, err := store.Verify(ctx, target, purpose, "tid-1", "123456")
	if err != nil || res.Result != VerifyOK {
		t.Fatalf("Verify = (%v, %v), want (VerifyOK, nil)", res, err)
	}
	if res.AttemptsLeft != 0 {
		t.Fatalf("成功后剩余次数 = %d, want 0", res.AttemptsLeft)
	}
	if n, err := rdb.Exists(ctx, CodeKey(target, purpose)).Result(); err != nil || n != 0 {
		t.Fatalf("消费后 exists = (%d, %v), want (0, nil)", n, err)
	}
	// 再次校验同一码应视为无码。
	if res, err := store.Verify(ctx, target, purpose, "tid-1", "123456"); err != nil || res.Result != VerifyMissing {
		t.Fatalf("二次 Verify = (%v, %v), want (VerifyMissing, nil)", res, err)
	}
}

// TestCodeVerifyWrongRetains 校验 ②：错码 tries+1 且键保留（tries < 5），
// 同时返回剩余尝试次数（接口文档 §2.6 行 553）。
func TestCodeVerifyWrongRetains(t *testing.T) {
	ctx, rdb, token := codeTestRDB(t)
	store := NewCodeStore(rdb, CodeOptions{})
	target := token + "-vwr"
	purpose := "login"

	mustSend(t, ctx, store, target, purpose, "tid-1", token+"-ip", "123456")
	for want := 1; want <= 2; want++ {
		res, err := store.Verify(ctx, target, purpose, "tid-1", "000000")
		if err != nil || res.Result != VerifyMismatch {
			t.Fatalf("错码 Verify #%d = (%v, %v), want (VerifyMismatch, nil)", want, res, err)
		}
		if res.AttemptsLeft != int64(5-want) {
			t.Fatalf("错码 Verify #%d 剩余次数 = %d, want %d", want, res.AttemptsLeft, 5-want)
		}
		v := readStoredCode(t, ctx, rdb, CodeKey(target, purpose))
		if v.Tries != want {
			t.Fatalf("错码后 tries = %d, want %d", v.Tries, want)
		}
	}
}

// TestCodeVerifyExhausted 校验 ③：剩余次数逐次递减，第 5 次错码后键被删（作废）。
func TestCodeVerifyExhausted(t *testing.T) {
	ctx, rdb, token := codeTestRDB(t)
	store := NewCodeStore(rdb, CodeOptions{})
	target := token + "-vex"
	purpose := "login"

	mustSend(t, ctx, store, target, purpose, "tid-1", token+"-ip", "123456")
	for i := 1; i <= 4; i++ {
		res, err := store.Verify(ctx, target, purpose, "tid-1", "000000")
		if err != nil || res.Result != VerifyMismatch {
			t.Fatalf("第 %d 次错码 = (%v, %v), want (VerifyMismatch, nil)", i, res, err)
		}
		if res.AttemptsLeft != int64(5-i) {
			t.Fatalf("第 %d 次错码剩余次数 = %d, want %d", i, res.AttemptsLeft, 5-i)
		}
		if n, err := rdb.Exists(ctx, CodeKey(target, purpose)).Result(); err != nil || n != 1 {
			t.Fatalf("第 %d 次错码后 exists = (%d, %v), want (1, nil)", i, n, err)
		}
	}
	res, err := store.Verify(ctx, target, purpose, "tid-1", "000000")
	if err != nil || res.Result != VerifyExhausted {
		t.Fatalf("第 5 次错码 = (%v, %v), want (VerifyExhausted, nil)", res, err)
	}
	if res.AttemptsLeft != 0 {
		t.Fatalf("作废后剩余次数 = %d, want 0", res.AttemptsLeft)
	}
	if n, err := rdb.Exists(ctx, CodeKey(target, purpose)).Result(); err != nil || n != 0 {
		t.Fatalf("第 5 次错码后 exists = (%d, %v), want (0, nil)", n, err)
	}
}

// TestCodeVerifyOwnerMismatch 校验 ④：不同归属标识的码不可用（tid 与 uid 隔离）。
func TestCodeVerifyOwnerMismatch(t *testing.T) {
	ctx, rdb, token := codeTestRDB(t)
	store := NewCodeStore(rdb, CodeOptions{})
	target := token + "-vown"
	purpose := "login"

	mustSend(t, ctx, store, target, purpose, "tid-A", token+"-ip", "123456")
	res, err := store.Verify(ctx, target, purpose, "uid-B", "123456")
	if err != nil || res.Result != VerifyMismatch {
		t.Fatalf("owner 不匹配 Verify = (%v, %v), want (VerifyMismatch, nil)", res, err)
	}
	if res.AttemptsLeft != 4 {
		t.Fatalf("owner 不匹配剩余次数 = %d, want 4", res.AttemptsLeft)
	}
	if v := readStoredCode(t, ctx, rdb, CodeKey(target, purpose)); v.Tries != 1 {
		t.Fatalf("owner 不匹配后 tries = %d, want 1（键保留）", v.Tries)
	}
	// 正确 owner 仍可消费（此前仅 1 次失败）。
	if res, err := store.Verify(ctx, target, purpose, "tid-A", "123456"); err != nil || res.Result != VerifyOK {
		t.Fatalf("正确 owner Verify = (%v, %v), want (VerifyOK, nil)", res, err)
	}
}

// TestCodeVerifyConcurrent 校验 ⑤：并发 100 次校验仅 1 次成功。
func TestCodeVerifyConcurrent(t *testing.T) {
	ctx, rdb, token := codeTestRDB(t)
	store := NewCodeStore(rdb, CodeOptions{})
	target := token + "-vcc"
	purpose := "login"

	mustSend(t, ctx, store, target, purpose, "tid-1", token+"-ip", "888888")

	const n = 100
	results := make([]CodeVerifyResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = store.Verify(ctx, target, purpose, "tid-1", "888888")
		}(i)
	}
	wg.Wait()

	ok, missing, other := 0, 0, 0
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("并发 Verify #%d err = %v", i, errs[i])
		}
		switch results[i].Result {
		case VerifyOK:
			ok++
		case VerifyMissing:
			missing++
		default:
			other++
		}
	}
	if ok != 1 || missing != n-1 || other != 0 {
		t.Fatalf("并发结果 ok=%d missing=%d other=%d, want ok=1 missing=%d other=0", ok, missing, other, n-1)
	}
}

// TestCodeVerifyNoTTLKey 校验 ⑥：al:code 键缺失 TTL（PTTL<=0）时不得回写
// 永久键，必须作废删除；再次校验仍为 VerifyMissing（§3.10 行 418-419、§5.1 行 835）。
func TestCodeVerifyNoTTLKey(t *testing.T) {
	ctx, rdb, token := codeTestRDB(t)
	store := NewCodeStore(rdb, CodeOptions{})
	target := token + "-vntl"
	purpose := "login"
	key := CodeKey(target, purpose)

	raw, err := json.Marshal(storedCode{Code: "123456", Owner: "tid-1", Tries: 0, SentAt: time.Now().Unix()})
	if err != nil {
		t.Fatalf("marshal stored code: %v", err)
	}
	// 直接 SET 且不带过期时间，模拟遗留的无 TTL 键。
	if err := rdb.Set(ctx, key, raw, 0).Err(); err != nil {
		t.Fatalf("set no-ttl key: %v", err)
	}
	if pttl, err := rdb.PTTL(ctx, key).Result(); err != nil || pttl != -1 {
		t.Fatalf("PTTL = (%v, %v), want (-1, nil) 无 TTL", pttl, err)
	}

	res, err := store.Verify(ctx, target, purpose, "tid-1", "000000")
	if err != nil || res.Result != VerifyMissing {
		t.Fatalf("无 TTL 键 Verify = (%v, %v), want (VerifyMissing, nil)", res, err)
	}
	if n, err := rdb.Exists(ctx, key).Result(); err != nil || n != 0 {
		t.Fatalf("无 TTL 键校验后 exists = (%d, %v), want (0, nil)", n, err)
	}
	// 正确码也不可用：键已作废且不得重建。
	if res, err := store.Verify(ctx, target, purpose, "tid-1", "123456"); err != nil || res.Result != VerifyMissing {
		t.Fatalf("作废后 Verify = (%v, %v), want (VerifyMissing, nil)", res, err)
	}
	if n, err := rdb.Exists(ctx, key).Result(); err != nil || n != 0 {
		t.Fatalf("再次校验后 exists = (%d, %v), want (0, nil)（不得重建无 TTL 键）", n, err)
	}
}
