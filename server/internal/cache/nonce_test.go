// NonceStore 单测：fake redis 计数覆盖键名 / 首次 / 重放 / 隔离 /
// 错误传播；真连用例沿 redis_test.go 的 env-skip 模式（UC_TEST_REDIS_ADDR），
// 只碰 RPC 鉴权专有键空间 al:rpc:nonce:*，前置 + 测后 SCAN 全清自证零残留，
// 连接串只经环境变量注入。
package cache

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeNonceRedis 计数型 fake（实现 nonceRedis 窄接口）：exists 模拟 SET NX
// 语义（键已存在返回 false），err 非 nil 时返回故障错误。
type fakeNonceRedis struct {
	mu     sync.Mutex
	calls  int
	keys   []string
	values []string
	ttls   []time.Duration
	exists map[string]bool
	err    error
}

func (f *fakeNonceRedis) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.keys = append(f.keys, key)
	f.values = append(f.values, fmt.Sprint(value))
	f.ttls = append(f.ttls, expiration)
	cmd := redis.NewBoolCmd(ctx)
	if f.err != nil {
		cmd.SetErr(f.err)
		return cmd
	}
	if f.exists == nil {
		f.exists = make(map[string]bool)
	}
	if f.exists[key] {
		cmd.SetVal(false)
		return cmd
	}
	f.exists[key] = true
	cmd.SetVal(true)
	return cmd
}

// snapshot 返回调用计数与键名 / 值 / TTL 快照。
func (f *fakeNonceRedis) snapshot() (calls int, keys, values []string, ttls []time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls,
		append([]string(nil), f.keys...),
		append([]string(nil), f.values...),
		append([]time.Duration(nil), f.ttls...)
}

// TestRPCNonceKey 键名格式（键名唯一出处 keys.go，§5.1 行 861）。
func TestRPCNonceKey(t *testing.T) {
	if got, want := RPCNonceKey("web-1", "ab12cd"), "al:rpc:nonce:web-1:ab12cd"; got != want {
		t.Fatalf("RPCNonceKey(\"web-1\", \"ab12cd\") = %q, want %q", got, want)
	}
}

// TestNonceHash 小写 hex、64 字符；空串 sha256 已知向量锚定（RFC 6234）。
func TestNonceHash(t *testing.T) {
	if got, want := nonceHash(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; got != want {
		t.Fatalf("nonceHash(\"\") = %q, want %q", got, want)
	}
	h := nonceHash("authloft")
	if len(h) != 64 || h != strings.ToLower(h) {
		t.Fatalf("nonceHash(\"authloft\") = %q, want 64-char lowercase hex", h)
	}
}

// TestNonceStoreFirst 首次 Store 返回 true：键 = al:rpc:nonce:{client_id}:{sha256(nonce)}、
// value "1"、TTL 30s（§5.1 行 861）。
func TestNonceStoreFirst(t *testing.T) {
	fake := &fakeNonceRedis{}
	store := NewNonceStore(fake)

	ok, err := store.Store(context.Background(), "web-1", "n1")
	if err != nil || !ok {
		t.Fatalf("Store = (%v, %v), want (true, nil)", ok, err)
	}
	calls, keys, values, ttls := fake.snapshot()
	if calls != 1 {
		t.Fatalf("redis calls = %d, want 1", calls)
	}
	if want := RPCNonceKey("web-1", nonceHash("n1")); keys[0] != want {
		t.Fatalf("key = %q, want %q", keys[0], want)
	}
	if ttls[0] != 30*time.Second {
		t.Fatalf("ttl = %v, want 30s（§5.1 行 861）", ttls[0])
	}
	if values[0] != "1" {
		t.Fatalf("value = %q, want \"1\"", values[0])
	}
}

// TestNonceStoreReplay 同 (clientID, nonce) 二次 Store 返回 false（30s 窗口内
// 重放）；换 nonce 或换 clientID 均首次 true（client_id 入键隔离，§5.1 行 861）。
func TestNonceStoreReplay(t *testing.T) {
	fake := &fakeNonceRedis{}
	store := NewNonceStore(fake)
	ctx := context.Background()

	if ok, _ := store.Store(ctx, "web-1", "n1"); !ok {
		t.Fatalf("first Store = %v, want true", ok)
	}
	if ok, err := store.Store(ctx, "web-1", "n1"); err != nil || ok {
		t.Fatalf("replay Store = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := store.Store(ctx, "web-1", "n2"); err != nil || !ok {
		t.Fatalf("new nonce Store = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := store.Store(ctx, "web-2", "n1"); err != nil || !ok {
		t.Fatalf("other client Store = (%v, %v), want (true, nil)（client_id 入键隔离）", ok, err)
	}
}

// TestNonceStoreError Redis 故障错误原样传播（去重不可判定，拒绝与否由调用方决定）。
func TestNonceStoreError(t *testing.T) {
	boom := errors.New("connection reset")
	store := NewNonceStore(&fakeNonceRedis{err: boom})

	ok, err := store.Store(context.Background(), "web-1", "n1")
	if !errors.Is(err, boom) || ok {
		t.Fatalf("Store = (%v, %v), want (false, connection reset)", ok, err)
	}
}

// scanRPCNonceKeys SCAN 收集全部 al:rpc:nonce:* 键（测试专用辅助）。
func scanRPCNonceKeys(ctx context.Context, rdb *redis.Client) ([]string, error) {
	var all []string
	var cursor uint64
	for {
		keys, next, err := rdb.Scan(ctx, cursor, rpcNonceKeyPrefix+"*", 100).Result()
		if err != nil {
			return nil, err
		}
		all = append(all, keys...)
		cursor = next
		if cursor == 0 {
			return all, nil
		}
	}
}

// clearRPCNonceKeys 删除全部 al:rpc:nonce:* 键并复核零残留（该键空间为
// RPC 鉴权专有，测试实例内不会触碰他卡键）。
func clearRPCNonceKeys(ctx context.Context, rdb *redis.Client) error {
	keys, err := scanRPCNonceKeys(ctx, rdb)
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		if err := rdb.Del(ctx, keys...).Err(); err != nil {
			return err
		}
		rest, err := scanRPCNonceKeys(ctx, rdb)
		if err != nil || len(rest) != 0 {
			return fmt.Errorf("al:rpc:nonce:* 残留 %d 键, err %v", len(rest), err)
		}
	}
	return nil
}

// randNonce 每次生成 16 字节随机 hex（接口文档 §7 行 1370「随机串」口径），
// 避免与历史残留键撞名。
func randNonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return hex.EncodeToString(b)
}

// TestNonceStoreReal（env-skip）：真连测试实例——首次 true / 重放 false /
// TTL 30s 量级；前置 + 测后 SCAN al:rpc:nonce:* 全清自证零残留。
func TestNonceStoreReal(t *testing.T) {
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

	// 测后清理用独立 ctx（deferred cancel 会先于 Cleanup 执行）。
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ccancel()
		if err := clearRPCNonceKeys(cctx, rdb); err != nil {
			t.Fatalf("测后清理 al:rpc:nonce:*: %v", err)
		}
	})
	if err := clearRPCNonceKeys(ctx, rdb); err != nil { // 前置清理
		t.Fatalf("前置清理 al:rpc:nonce:*: %v", err)
	}

	const clientID = "t038" // 测试专用 client，键前缀 al:rpc:nonce:t038:
	nonce := randNonce(t)
	store := NewNonceStore(rdb)

	if ok, err := store.Store(ctx, clientID, nonce); err != nil || !ok {
		t.Fatalf("Store 首次 = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := store.Store(ctx, clientID, nonce); err != nil || ok {
		t.Fatalf("Store 重放 = (%v, %v), want (false, nil)", ok, err)
	}
	if ok, err := store.Store(ctx, clientID, randNonce(t)); err != nil || !ok {
		t.Fatalf("Store 新 nonce = (%v, %v), want (true, nil)", ok, err)
	}

	// TTL 30s 量级（键刚写入，应 ∈ (20s, 30s]）。
	key := RPCNonceKey(clientID, nonceHash(nonce))
	ttl, err := rdb.TTL(ctx, key).Result()
	if err != nil || ttl <= 20*time.Second || ttl > 30*time.Second {
		t.Fatalf("ttl %s = (%v, %v), want (20s, 30s]", key, ttl, err)
	}
}
