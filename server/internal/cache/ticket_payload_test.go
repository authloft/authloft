// cache/ticket_payload.go 单测：快照写入（TTL = exp − iat、缺省
// 600s 兜底）、读取往返、缺失（不存在 / 已过期）(nil, nil)、非法载荷拒绝、
// sealer 错误透传（接口文档 §2.7.4 行 658、§2.8 行 719；后端架构 §5.1 行
// 863、§11.6.4 行 1350）。真连 Redis（UC_TEST_REDIS_ADDR，env 未设置才
// skip）；每个用例用唯一 token 作 ticket_id，测后按 token SCAN 全清自证零
// 残留（复用 t053RDB，ticket_test.go / oidc_test.go / 本文件共用）。
package cache

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"authloft/gen/go/token"
)

// fakePayloadSealer 测试用快照 sealer：proto 序列化 + base64（模拟「整值
// 加密、Redis 内不留明文」），不引 security 真密钥；可注入错误。
type fakePayloadSealer struct {
	sealErr error
	openErr error
}

// Seal 加密整值（Fake：base64 包裹，真实实现归 security.Codec 适配器）。
func (f *fakePayloadSealer) Seal(p *token.TicketPayload) (string, error) {
	if f.sealErr != nil {
		return "", f.sealErr
	}
	b, err := proto.Marshal(p)
	if err != nil {
		return "", err
	}
	return fakeSealPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Open 解密存储串。
func (f *fakePayloadSealer) Open(v string) (*token.TicketPayload, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	if !strings.HasPrefix(v, fakeSealPrefix) {
		return nil, errors.New("fake sealer: 非法存储串")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(v, fakeSealPrefix))
	if err != nil {
		return nil, err
	}
	var p token.TicketPayload
	if err := proto.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// payloadSeed 造一个快照；expGap = exp − iat（秒）。
func payloadSeed(id string, expGap int64) *token.TicketPayload {
	now := time.Now().Unix()
	return &token.TicketPayload{
		TicketId:    id,
		ProviderKey: "wechat_mp_scan",
		Scene:       "login",
		Iat:         now,
		Exp:         now + expGap,
	}
}

// TestTicketPayloadWriteReadRoundtrip 写入 → 读取往返：字段逐项保真，
// 存储串非明文（带 fake 封装前缀）。
func TestTicketPayloadWriteReadRoundtrip(t *testing.T) {
	ctx, rdb, id := t053RDB(t)
	st := NewTicketPayloadStore(rdb, &fakePayloadSealer{})

	seed := payloadSeed(id, 600)
	seed.Scene = "bind"
	seed.ProviderKey = "scan_other"
	if err := st.Write(ctx, seed); err != nil {
		t.Fatalf("Write: %v", err)
	}
	raw, err := rdb.Get(ctx, TicketPayloadKey(id)).Result()
	if err != nil {
		t.Fatalf("get raw: %v", err)
	}
	if !strings.HasPrefix(raw, fakeSealPrefix) {
		t.Fatalf("存储串应为 fake 封装（非明文）, got %q", raw)
	}
	got, err := st.Read(ctx, id)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.GetTicketId() != seed.GetTicketId() || got.GetProviderKey() != seed.GetProviderKey() ||
		got.GetScene() != seed.GetScene() || got.GetIat() != seed.GetIat() || got.GetExp() != seed.GetExp() {
		t.Fatalf("往返失真: got %+v, want %+v", got, seed)
	}
}

// TestTicketPayloadReadMissing 缺失（不存在 / 已过期）→ (nil, nil)。
func TestTicketPayloadReadMissing(t *testing.T) {
	ctx, rdb, id := t053RDB(t)
	st := NewTicketPayloadStore(rdb, &fakePayloadSealer{})

	got, err := st.Read(ctx, id)
	if err != nil || got != nil {
		t.Fatalf("Read 缺失 = (%+v, %v), want (nil, nil)", got, err)
	}
}

// TestTicketPayloadWriteTTL 键寿命 = exp − iat（§11.6.4 行 1350）；退化值
// （exp <= iat）回落 600s 缺省，不产生无 TTL 的键。
func TestTicketPayloadWriteTTL(t *testing.T) {
	ctx, rdb, id := t053RDB(t)
	st := NewTicketPayloadStore(rdb, &fakePayloadSealer{})

	if err := st.Write(ctx, payloadSeed(id, 120)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	ttl, err := rdb.TTL(ctx, TicketPayloadKey(id)).Result()
	if err != nil {
		t.Fatalf("TTL: %v", err)
	}
	if ttl <= 0 || ttl > 120*time.Second {
		t.Fatalf("TTL = %v, want (0, 120s]", ttl)
	}

	// 退化（exp == iat）→ 600s 缺省。
	id2 := id + "x"
	if err := st.Write(ctx, payloadSeed(id2, 0)); err != nil {
		t.Fatalf("Write degenerate: %v", err)
	}
	ttl2, err := rdb.TTL(ctx, TicketPayloadKey(id2)).Result()
	if err != nil {
		t.Fatalf("TTL degenerate: %v", err)
	}
	if ttl2 <= 0 || ttl2 > defaultTicketTTL {
		t.Fatalf("退化 TTL = %v, want (0, 600s]", ttl2)
	}
}

// TestTicketPayloadWriteRejects 非法载荷：nil / 空 ticket_id 拒绝（不落键）。
func TestTicketPayloadWriteRejects(t *testing.T) {
	ctx, rdb, id := t053RDB(t)
	st := NewTicketPayloadStore(rdb, &fakePayloadSealer{})

	if err := st.Write(ctx, nil); err == nil {
		t.Fatal("nil payload 应报错")
	}
	if err := st.Write(ctx, &token.TicketPayload{ProviderKey: "p"}); err == nil {
		t.Fatal("空 ticket_id 应报错")
	}
	if n, _ := rdb.Exists(ctx, TicketPayloadKey(id)).Result(); n != 0 {
		t.Fatalf("非法载荷不应落键, exists=%d", n)
	}
}

// TestTicketPayloadSealerErrors seal / open 错误透传（不吞）。
func TestTicketPayloadSealerErrors(t *testing.T) {
	ctx, rdb, id := t053RDB(t)
	st := NewTicketPayloadStore(rdb, &fakePayloadSealer{sealErr: errors.New("boom")})
	if err := st.Write(ctx, payloadSeed(id, 600)); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("seal 错误应透传, got %v", err)
	}

	// 预置一个坏值 → Read 返回错误。
	if err := rdb.Set(ctx, TicketPayloadKey(id), "not-a-sealed-value", time.Minute).Err(); err != nil {
		t.Fatalf("set raw: %v", err)
	}
	st2 := NewTicketPayloadStore(rdb, &fakePayloadSealer{})
	if _, err := st2.Read(ctx, id); err == nil {
		t.Fatal("open 失败应报错")
	}
}
