// cache/oidc.go 单测（覆盖接口文档 §4.2 行 1080 / §4.7 行 1134、
// 后端架构 §14.3 行 1587）：授权码 SET EX 120s、GETDEL 一次性（仅第一个
// 消费方取到）、值为不透明字符串原样存取。真连 Redis（UC_TEST_REDIS_ADDR，
// env 未设置才 skip）；每个用例用唯一 token（t053-*）作 code，测后按 token
// SCAN 全清自证零残留。
package cache

import (
	"sync"
	"testing"
	"time"
)

// TestOIDCCodeSetConsumeOnce：SET EX 120s；首次 Consume 取到原值并删除键；
// 二次 Consume 得到 ok=false（一次性，§14.3 行 1587）。
func TestOIDCCodeSetConsumeOnce(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewOIDCCodeStore(rdb)
	code := tok + "-once"
	value := "opaque|client_id=c1|uid=10086|nonce=n1"

	if err := store.Set(ctx, code, value); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got, err := rdb.Get(ctx, OIDCCodeKey(code)).Result(); err != nil || got != value {
		t.Fatalf("get al:oidc:code = (%q, %v), want (%q, nil)", got, err, value)
	}
	if ttl, err := rdb.TTL(ctx, OIDCCodeKey(code)).Result(); err != nil || ttl < 110*time.Second || ttl > 120*time.Second {
		t.Fatalf("oidc code ttl = (%v, %v), want (110s, 120s]", ttl, err)
	}

	got, ok, err := store.Consume(ctx, code)
	if err != nil || !ok || got != value {
		t.Fatalf("Consume = (%q, %v, %v), want (%q, true, nil)", got, ok, err, value)
	}
	if n, err := rdb.Exists(ctx, OIDCCodeKey(code)).Result(); err != nil || n != 0 {
		t.Fatalf("消费后 exists = (%d, %v), want (0, nil)", n, err)
	}
	if got, ok, err := store.Consume(ctx, code); err != nil || ok || got != "" {
		t.Fatalf("二次 Consume = (%q, %v, %v), want (\"\", false, nil)", got, ok, err)
	}
}

// TestOIDCCodeConsumeMissing：未签发 / 已过期的 code → ok=false，无错误。
func TestOIDCCodeConsumeMissing(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewOIDCCodeStore(rdb)
	if got, ok, err := store.Consume(ctx, tok+"-unused"); err != nil || ok || got != "" {
		t.Fatalf("Consume 缺失 = (%q, %v, %v), want (\"\", false, nil)", got, ok, err)
	}
}

// TestOIDCCodeConcurrentOnce：同一 code 并发 100 次 Consume 仅 1 次成功
// （GETDEL 原子一次性）。
func TestOIDCCodeConcurrentOnce(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewOIDCCodeStore(rdb)
	code := tok + "-cc"
	value := tok + "-v"

	if err := store.Set(ctx, code, value); err != nil {
		t.Fatalf("Set: %v", err)
	}
	const n = 100
	oks := make([]bool, n)
	vals := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			vals[i], oks[i], errs[i] = store.Consume(ctx, code)
		}(i)
	}
	wg.Wait()

	ok := 0
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("并发 Consume #%d err = %v", i, errs[i])
		}
		if oks[i] {
			ok++
			if vals[i] != value {
				t.Fatalf("并发成功值 = %q, want %q", vals[i], value)
			}
		}
	}
	if ok != 1 {
		t.Fatalf("并发成功次数 = %d, want 1", ok)
	}
}

// TestOIDCCodeOpaqueValue：值按不透明字符串原样存取，不做 JSON / 加密
// （载荷 proto 缺失，§11.6.1 封装归 OIDC service 卡）。
func TestOIDCCodeOpaqueValue(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewOIDCCodeStore(rdb)
	code := tok + "-raw"
	value := "v1.not.a.json.{\"k\":1}"

	if err := store.Set(ctx, code, value); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got, ok, err := store.Consume(ctx, code); err != nil || !ok || got != value {
		t.Fatalf("Consume = (%q, %v, %v), want (%q, true, nil)", got, ok, err, value)
	}
}
