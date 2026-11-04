// cache/captcha.go 单测（覆盖 docs/后端架构.md §21.2-C 行 1824）：
// GETDEL 一次性（正确 / 错误都消费、并发仅 1 次成功）与 TTL 300s。
// 真连 Redis（UC_TEST_REDIS_ADDR），无 env skip（与 code_test.go 口径一致：
// env 未设置才 skip，acceptance 命令显式注入）；每个用例用唯一 token 作 id，
// 测后按 token SCAN 全清自证零残留。
package cache

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// t052RDB 真连测试实例，返回 ctx / client / 每用例唯一 token
// （"t052-"+随机串，落在 al:cap / al:pwf / al:pwban 键名内，captcha_test.go
// 与 pwfail_test.go 共用）。
func t052RDB(t *testing.T) (context.Context, *redis.Client, string) {
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
	token := "t052-" + randNonce(t)
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

// TestCaptchaKeys 图形码键名格式（键名唯一出处 keys.go，§5.1 行 841）。
func TestCaptchaKeys(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{"b7f3", "al:cap:b7f3"},
		{"a:b", "al:cap:a:b"},
		{"", "al:cap:"},
	}
	for _, c := range cases {
		if got := CaptchaKey(c.id); got != c.want {
			t.Fatalf("CaptchaKey(%q) = %q, want %q", c.id, got, c.want)
		}
	}
}

// TestCaptchaSetVerifyOnce：写入 TTL 300s；正确校验成功且键被删；再次校验
// 同一 answer 失败（一次性消费，§9.2 行 1088）。
func TestCaptchaSetVerifyOnce(t *testing.T) {
	ctx, rdb, token := t052RDB(t)
	store := NewCaptchaStore(rdb)
	id, answer := token+"-once", "1234"

	if err := store.Set(ctx, id, answer); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if v, err := rdb.Get(ctx, CaptchaKey(id)).Result(); err != nil || v != answer {
		t.Fatalf("get al:cap = (%q, %v), want (%q, nil)", v, err, answer)
	}
	if ttl, err := rdb.TTL(ctx, CaptchaKey(id)).Result(); err != nil || ttl <= 290*time.Second || ttl > 300*time.Second {
		t.Fatalf("captcha ttl = (%v, %v), want (290s, 300s]", ttl, err)
	}

	ok, err := store.Verify(ctx, id, answer)
	if err != nil || !ok {
		t.Fatalf("Verify 正确 = (%v, %v), want (true, nil)", ok, err)
	}
	if n, err := rdb.Exists(ctx, CaptchaKey(id)).Result(); err != nil || n != 0 {
		t.Fatalf("消费后 exists = (%d, %v), want (0, nil)", n, err)
	}
	if ok, err := store.Verify(ctx, id, answer); err != nil || ok {
		t.Fatalf("二次 Verify = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestCaptchaWrongAnswerConsumes：错误答案同样消费（键删除），之后的正确
// 答案也不可用（§9.2「一次性语义」）。
func TestCaptchaWrongAnswerConsumes(t *testing.T) {
	ctx, rdb, token := t052RDB(t)
	store := NewCaptchaStore(rdb)
	id, answer := token+"-wrong", "5678"

	if err := store.Set(ctx, id, answer); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if ok, err := store.Verify(ctx, id, "0000"); err != nil || ok {
		t.Fatalf("Verify 错误 = (%v, %v), want (false, nil)", ok, err)
	}
	if n, err := rdb.Exists(ctx, CaptchaKey(id)).Result(); err != nil || n != 0 {
		t.Fatalf("错误校验后 exists = (%d, %v), want (0, nil)", n, err)
	}
	if ok, err := store.Verify(ctx, id, answer); err != nil || ok {
		t.Fatalf("错误消费后 Verify 正确 = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestCaptchaVerifyMissing：id 不存在 / 已过期 / 从未生成 → false，无错误。
func TestCaptchaVerifyMissing(t *testing.T) {
	ctx, rdb, token := t052RDB(t)
	store := NewCaptchaStore(rdb)
	ok, err := store.Verify(ctx, token+"-unused", "1234")
	if err != nil || ok {
		t.Fatalf("Verify 缺失 = (%v, %v), want (false, nil)", ok, err)
	}
}

// TestCaptchaConcurrentOnce：同一 id/answer 并发 100 次校验仅 1 次成功
// （GETDEL 原子一次性，§21.2-C 行 1824）。
func TestCaptchaConcurrentOnce(t *testing.T) {
	ctx, rdb, token := t052RDB(t)
	store := NewCaptchaStore(rdb)
	id, answer := token+"-cc", "9999"

	if err := store.Set(ctx, id, answer); err != nil {
		t.Fatalf("Set: %v", err)
	}
	const n = 100
	oks := make([]bool, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			oks[i], errs[i] = store.Verify(ctx, id, answer)
		}(i)
	}
	wg.Wait()

	ok := 0
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("并发 Verify #%d err = %v", i, errs[i])
		}
		if oks[i] {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("并发成功次数 = %d, want 1", ok)
	}
}
