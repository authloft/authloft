// cache/ticket.go 单测：scanned 幂等且不覆盖（含 success）、complete
// 覆盖 scanned 但不覆盖 success、Take GETDEL 仅 1 次成功、Wait 超时 / ctx
// 取消 / 不消费、TTL 与 expires_at 对齐（接口文档 §2.7.4 行 643-644、§2.8
// 行 709-728；后端架构 §11.6.4 / §11.6.5）。真连 Redis（UC_TEST_REDIS_ADDR，
// env 未设置才 skip）；每个用例用唯一 token（t053-*）作 id，测后按 token
// SCAN 全清自证零残留。
package cache

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"

	"authloft/gen/go/token"
)

// t053RDB 真连测试实例，返回 ctx / client / 每用例唯一 token
// （"t053-"+随机串，落在 al:ticket / al:oidc:code 键名内，ticket_test.go 与
// oidc_test.go 共用）。
func t053RDB(t *testing.T) (context.Context, *redis.Client, string) {
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
	tokenID := "t053-" + randNonce(t)
	t.Cleanup(func() { _ = rdb.Close() })
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		if err := clearCodeTestKeys(cctx, rdb, tokenID); err != nil {
			t.Fatalf("测后清理 %s 键: %v", tokenID, err)
		}
	})
	t.Cleanup(cancel)
	return ctx, rdb, tokenID
}

// fakeTicketSealer 测试用 sealer：proto 序列化 + base64（模拟「整值加密、
// Redis 内不留明文」），不引 security 真密钥；可注入错误。
type fakeTicketSealer struct {
	sealErr error
	openErr error
}

const fakeSealPrefix = "fake:"

// Seal 加密整值（Fake：base64 包裹，真实实现归 security.Codec 适配器）。
func (f *fakeTicketSealer) Seal(res *token.TicketResult) (string, error) {
	if f.sealErr != nil {
		return "", f.sealErr
	}
	b, err := proto.Marshal(res)
	if err != nil {
		return "", err
	}
	return fakeSealPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Open 解密存储串。
func (f *fakeTicketSealer) Open(v string) (*token.TicketResult, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	if !strings.HasPrefix(v, fakeSealPrefix) {
		return nil, fmt.Errorf("fake sealer: 非法存储串 %q", v)
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(v, fakeSealPrefix))
	if err != nil {
		return nil, err
	}
	var res token.TicketResult
	if err := proto.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ticketSeed 造一个 TicketResult；expiresAt=0 表示走缺省 600s。
func ticketSeed(status string, createdAt, expiresAt int64) *token.TicketResult {
	return &token.TicketResult{
		V:           1,
		Scene:       "login",
		Status:      status,
		ProviderKey: "wechat_mp_scan",
		Channel:     "qrcode",
		CreatedAt:   createdAt,
		ExpiresAt:   expiresAt,
	}
}

// readTicket 直接读原始存储串并解密（断言「不覆盖」用）。
func readTicket(t *testing.T, ctx context.Context, rdb *redis.Client, sealer TicketSealer, id string) *token.TicketResult {
	t.Helper()
	raw, err := rdb.Get(ctx, TicketKey(id)).Result()
	if err != nil {
		t.Fatalf("get %s: %v", TicketKey(id), err)
	}
	res, err := sealer.Open(raw)
	if err != nil {
		t.Fatalf("open %s: %v", TicketKey(id), err)
	}
	return res
}

// TestTicketWriteScannedIdempotent scanned 重复上报幂等：首次写入 OK、TTL 默认
// 600s、值为 Fake 封闭串（非明文）；第二次上报 skipped 且原值不变。
func TestTicketWriteScannedIdempotent(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	sealer := &fakeTicketSealer{}
	store := NewTicketStore(rdb, sealer, TicketOptions{})
	id := tok + "-scan"
	first := ticketSeed("scanned", 0, 0)

	res, err := store.WriteScanned(ctx, id, first)
	if err != nil || res != TicketWriteOK {
		t.Fatalf("首次 WriteScanned = (%v, %v), want (TicketWriteOK, nil)", res, err)
	}
	if ttl, err := rdb.TTL(ctx, TicketKey(id)).Result(); err != nil || ttl < 580*time.Second || ttl > 600*time.Second {
		t.Fatalf("ticket ttl = (%v, %v), want (580s, 600s]", ttl, err)
	}
	raw, err := rdb.Get(ctx, TicketKey(id)).Result()
	if err != nil || !strings.HasPrefix(raw, fakeSealPrefix) {
		t.Fatalf("存储值 = (%q, %v), want Fake 加密串前缀 %q（Redis 内不留明文）", raw, err, fakeSealPrefix)
	}

	second := ticketSeed("scanned", 12345, 0)
	res, err = store.WriteScanned(ctx, id, second)
	if err != nil || res != TicketWriteSkipped {
		t.Fatalf("二次 WriteScanned = (%v, %v), want (TicketWriteSkipped, nil)", res, err)
	}
	if got := readTicket(t, ctx, rdb, sealer, id); !proto.Equal(got, first) {
		t.Fatalf("二次上报后值 = %v, want 原值 %v（幂等不覆盖）", got, first)
	}
}

// TestTicketScannedNotOverwriteSuccess：已存在 success 时 scanned 上报不覆盖
// （接口文档 §2.7.4 行 643）。
func TestTicketScannedNotOverwriteSuccess(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	sealer := &fakeTicketSealer{}
	store := NewTicketStore(rdb, sealer, TicketOptions{})
	id := tok + "-sc-su"
	success := ticketSeed("success", 1, 0)

	if res, err := store.WriteComplete(ctx, id, success); err != nil || res != TicketWriteOK {
		t.Fatalf("WriteComplete = (%v, %v), want (TicketWriteOK, nil)", res, err)
	}
	if res, err := store.WriteScanned(ctx, id, ticketSeed("scanned", 2, 0)); err != nil || res != TicketWriteSkipped {
		t.Fatalf("success 后 WriteScanned = (%v, %v), want (TicketWriteSkipped, nil)", res, err)
	}
	if got := readTicket(t, ctx, rdb, sealer, id); !proto.Equal(got, success) {
		t.Fatalf("scanned 上报后值 = %v, want success 原值 %v", got, success)
	}
}

// TestTicketCompleteOverwritesScanned：complete 整体覆盖 scanned（§2.7.4 行 644）。
func TestTicketCompleteOverwritesScanned(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	sealer := &fakeTicketSealer{}
	store := NewTicketStore(rdb, sealer, TicketOptions{})
	id := tok + "-cp-ov"
	success := ticketSeed("success", 2, 0)

	if res, err := store.WriteScanned(ctx, id, ticketSeed("scanned", 1, 0)); err != nil || res != TicketWriteOK {
		t.Fatalf("WriteScanned = (%v, %v), want (TicketWriteOK, nil)", res, err)
	}
	if res, err := store.WriteComplete(ctx, id, success); err != nil || res != TicketWriteOK {
		t.Fatalf("WriteComplete = (%v, %v), want (TicketWriteOK, nil)", res, err)
	}
	if got := readTicket(t, ctx, rdb, sealer, id); !proto.Equal(got, success) {
		t.Fatalf("complete 后值 = %v, want %v", got, success)
	}
}

// TestTicketCompleteNotOverwriteSuccess：已存在 success 时 complete 不覆盖
// （卡片语义；键上出现 success 即成功终态）。
func TestTicketCompleteNotOverwriteSuccess(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	sealer := &fakeTicketSealer{}
	store := NewTicketStore(rdb, sealer, TicketOptions{})
	id := tok + "-cp-su"
	success := ticketSeed("success", 1, 0)

	if res, err := store.WriteComplete(ctx, id, success); err != nil || res != TicketWriteOK {
		t.Fatalf("首次 WriteComplete = (%v, %v), want (TicketWriteOK, nil)", res, err)
	}
	if res, err := store.WriteComplete(ctx, id, ticketSeed("failed", 2, 0)); err != nil || res != TicketWriteSkipped {
		t.Fatalf("success 后 WriteComplete = (%v, %v), want (TicketWriteSkipped, nil)", res, err)
	}
	if got := readTicket(t, ctx, rdb, sealer, id); !proto.Equal(got, success) {
		t.Fatalf("二次 complete 后值 = %v, want success 原值 %v", got, success)
	}
}

// TestTicketWriteErrors：nil 结果 / sealer 加密失败均返回 error 且不写键。
func TestTicketWriteErrors(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewTicketStore(rdb, &fakeTicketSealer{}, TicketOptions{})
	id := tok + "-err"

	if _, err := store.WriteScanned(ctx, id, nil); err == nil {
		t.Fatalf("WriteScanned(nil) err = nil, want 非空 error")
	}
	if n, err := rdb.Exists(ctx, TicketKey(id)).Result(); err != nil || n != 0 {
		t.Fatalf("nil 结果后 exists = (%d, %v), want (0, nil)", n, err)
	}

	badStore := NewTicketStore(rdb, &fakeTicketSealer{sealErr: errors.New("boom")}, TicketOptions{})
	if _, err := badStore.WriteComplete(ctx, id, ticketSeed("success", 1, 0)); err == nil {
		t.Fatalf("sealer 失败时 WriteComplete err = nil, want 非空 error")
	}
}

// TestTicketTakeOnce：Take 以 GETDEL 取走并解密，键随删除消失；第二次
// Take 返回 (nil, nil)（同一票据只有 1 个读取方取到，§11.6.5 行 1355）。
func TestTicketTakeOnce(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewTicketStore(rdb, &fakeTicketSealer{}, TicketOptions{})
	id := tok + "-take"
	success := ticketSeed("success", 1, 0)

	if res, err := store.WriteComplete(ctx, id, success); err != nil || res != TicketWriteOK {
		t.Fatalf("WriteComplete = (%v, %v), want (TicketWriteOK, nil)", res, err)
	}
	got, err := store.Take(ctx, id)
	if err != nil || got == nil || !proto.Equal(got, success) {
		t.Fatalf("Take = (%v, %v), want (%v, nil)", got, err, success)
	}
	if n, err := rdb.Exists(ctx, TicketKey(id)).Result(); err != nil || n != 0 {
		t.Fatalf("Take 后 exists = (%d, %v), want (0, nil)", n, err)
	}
	got, err = store.Take(ctx, id)
	if err != nil || got != nil {
		t.Fatalf("二次 Take = (%v, %v), want (nil, nil)", got, err)
	}
}

// TestTicketPeekNonConsuming Peek 只读不删除（mfa_pending 非终态，轮询只读
// 快照、不 GETDEL，§11.6.5 行 1424）：可重复读到同值，键仍在；Take 才消费。
func TestTicketPeekNonConsuming(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewTicketStore(rdb, &fakeTicketSealer{}, TicketOptions{})
	id := tok + "-peek"
	seed := ticketSeed("mfa_pending", 1, 0)

	if res, err := store.WriteComplete(ctx, id, seed); err != nil || res != TicketWriteOK {
		t.Fatalf("WriteComplete = (%v, %v), want (TicketWriteOK, nil)", res, err)
	}
	for i := 0; i < 2; i++ {
		got, err := store.Peek(ctx, id)
		if err != nil || got == nil || !proto.Equal(got, seed) {
			t.Fatalf("第 %d 次 Peek = (%v, %v), want (%v, nil)", i+1, got, err, seed)
		}
	}
	if n, err := rdb.Exists(ctx, TicketKey(id)).Result(); err != nil || n != 1 {
		t.Fatalf("Peek 后 exists = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := store.Take(ctx, id); err != nil {
		t.Fatalf("Take: %v", err)
	}
	if got, err := store.Peek(ctx, id); err != nil || got != nil {
		t.Fatalf("消费后 Peek = (%v, %v), want (nil, nil)", got, err)
	}
}

// TestTicketTakeConcurrent：同一票据并发 100 次 Take 仅 1 次取到结果。
func TestTicketTakeConcurrent(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewTicketStore(rdb, &fakeTicketSealer{}, TicketOptions{})
	id := tok + "-take-cc"

	if res, err := store.WriteComplete(ctx, id, ticketSeed("success", 1, 0)); err != nil || res != TicketWriteOK {
		t.Fatalf("WriteComplete = (%v, %v), want (TicketWriteOK, nil)", res, err)
	}
	const n = 100
	got := make([]*token.TicketResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = store.Take(ctx, id)
		}(i)
	}
	wg.Wait()

	hits := 0
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("并发 Take #%d err = %v", i, errs[i])
		}
		if got[i] != nil {
			hits++
		}
	}
	if hits != 1 {
		t.Fatalf("并发取到次数 = %d, want 1（GETDEL 原子一次性）", hits)
	}
}

// TestTicketTTLAlignExp：键 TTL 与 TicketResult.expires_at（= ticket.exp）对齐。
func TestTicketTTLAlignExp(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewTicketStore(rdb, &fakeTicketSealer{}, TicketOptions{})
	id := tok + "-ttl"
	exp := time.Now().Add(90 * time.Second).Unix()

	if res, err := store.WriteScanned(ctx, id, ticketSeed("scanned", 0, exp)); err != nil || res != TicketWriteOK {
		t.Fatalf("WriteScanned = (%v, %v), want (TicketWriteOK, nil)", res, err)
	}
	if ttl, err := rdb.TTL(ctx, TicketKey(id)).Result(); err != nil || ttl < 85*time.Second || ttl > 90*time.Second {
		t.Fatalf("ticket ttl = (%v, %v), want (85s, 90s]（与 expires_at 对齐）", ttl, err)
	}
}

// TestTicketWaitReady：键已存在时 Wait 立即返回 nil，且不消费（随后 Take 仍
// 能取到结果）。
func TestTicketWaitReady(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewTicketStore(rdb, &fakeTicketSealer{}, TicketOptions{})
	id := tok + "-wait-rd"

	if res, err := store.WriteScanned(ctx, id, ticketSeed("scanned", 1, 0)); err != nil || res != TicketWriteOK {
		t.Fatalf("WriteScanned = (%v, %v), want (TicketWriteOK, nil)", res, err)
	}
	if err := store.Wait(ctx, id, time.Second); err != nil {
		t.Fatalf("Wait 已就绪 = %v, want nil", err)
	}
	got, err := store.Take(ctx, id)
	if err != nil || got == nil {
		t.Fatalf("Wait 后 Take = (%v, %v), want 非 nil（Wait 不消费）", got, err)
	}
}

// TestTicketWaitArrives：键在等待过程中出现 → Wait 返回 nil（200ms 退避轮询）。
func TestTicketWaitArrives(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewTicketStore(rdb, &fakeTicketSealer{}, TicketOptions{})
	id := tok + "-wait-arr"
	errCh := make(chan error, 1)
	go func() {
		time.Sleep(220 * time.Millisecond)
		_, err := store.WriteScanned(ctx, id, ticketSeed("scanned", 1, 0))
		errCh <- err
	}()

	start := time.Now()
	err := store.Wait(ctx, id, 2*time.Second)
	elapsed := time.Since(start)
	if werr := <-errCh; werr != nil {
		t.Fatalf("并发写入失败: %v", werr)
	}
	if err != nil {
		t.Fatalf("Wait 等到键 = %v, want nil", err)
	}
	if elapsed < 200*time.Millisecond {
		t.Fatalf("Wait 耗时 = %v, want >= 200ms（首轮 200ms 退避）", elapsed)
	}
}

// TestTicketWaitTimeout：超时未出现 → ErrTicketWaitTimeout（可判别结果）。
func TestTicketWaitTimeout(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewTicketStore(rdb, &fakeTicketSealer{}, TicketOptions{})
	start := time.Now()
	err := store.Wait(ctx, tok+"-wait-to", 400*time.Millisecond)
	if !errors.Is(err, ErrTicketWaitTimeout) {
		t.Fatalf("Wait 超时 err = %v, want ErrTicketWaitTimeout", err)
	}
	if elapsed := time.Since(start); elapsed < 350*time.Millisecond {
		t.Fatalf("Wait 超时耗时 = %v, want >= 350ms", elapsed)
	}
}

// TestTicketWaitContextCancel：ctx 取消立即结束等待，返回 context.Canceled。
func TestTicketWaitContextCancel(t *testing.T) {
	ctx, rdb, tok := t053RDB(t)
	store := NewTicketStore(rdb, &fakeTicketSealer{}, TicketOptions{})
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	err := store.Wait(cctx, tok+"-wait-cx", 2*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait ctx 取消 err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Wait ctx 取消耗时 = %v, want < 1s（应立即返回）", elapsed)
	}
}
