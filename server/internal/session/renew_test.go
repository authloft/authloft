// session 包重签 + Cookie 单测（§21.2 D 行 1856）：重签纯计算
// （可控时钟断言 iat/exp 刷新、epoch/sid/amr 不变；fake redis 计数断言
// 零存储写入）；Cookie 属性与清除按接口文档 §1.9 逐项断言。
package session

import (
	"context"
	"net/http"
	"testing"
	"time"

	"authloft/internal/cache"
)

// TestRenew 刷新 iat/exp、保留 id/epoch/amr/sid；新串可解析回同值。
func TestRenew(t *testing.T) {
	tokens := NewTokens(newTestCodec(t))
	renewer := NewRenewer(tokens, 7*24*time.Hour) // session_ttl 默认 7 天
	renewer.now = func() time.Time { return time.Unix(5000, 0) }

	old := testPayload() // iat=1000 exp=2000
	fresh, newTok, err := renewer.Renew(old)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if fresh.GetIat() != 5000 {
		t.Fatalf("iat = %d, want 5000（刷新为当前时刻）", fresh.GetIat())
	}
	if want := int64(5000 + 7*24*3600); fresh.GetExp() != want {
		t.Fatalf("exp = %d, want %d（iat + ttl）", fresh.GetExp(), want)
	}
	if fresh.GetId() != old.GetId() || fresh.GetEpoch() != old.GetEpoch() || fresh.GetSid() != old.GetSid() {
		t.Fatalf("immutable fields changed: id %d→%d, epoch %d→%d, sid %q→%q",
			old.GetId(), fresh.GetId(), old.GetEpoch(), fresh.GetEpoch(), old.GetSid(), fresh.GetSid())
	}
	if len(fresh.GetAmr()) != 2 || fresh.GetAmr()[0] != "pwd" || fresh.GetAmr()[1] != "otp" {
		t.Fatalf("amr = %v, want [pwd otp]（不变）", fresh.GetAmr())
	}
	// 旧载荷不被改动。
	if old.GetIat() != 1000 || old.GetExp() != 2000 {
		t.Fatalf("old payload mutated: iat=%d exp=%d", old.GetIat(), old.GetExp())
	}

	got, err := tokens.Parse(newTok)
	if err != nil {
		t.Fatalf("Parse renewed: %v", err)
	}
	if got.GetIat() != 5000 || got.GetExp() != 5000+7*24*3600 || got.GetEpoch() != 7 || got.GetSid() != "sid-0001" {
		t.Fatalf("renewed token payload = %+v", got)
	}
}

// TestRenewZeroRedisCalls 重签纯计算：Verify 走 epoch 链（有 Redis 调用）
// 之后 Renew 前后 fake redis 调用计数不变（§11.5：无任何存储写入）。
func TestRenewZeroRedisCalls(t *testing.T) {
	ctx := context.Background()
	tokens := NewTokens(newTestCodec(t))
	tok, err := tokens.Sign(testPayload())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cr := &countingRedis{}
	src := func(ctx context.Context, uid int64) (int64, error) { return 7, nil }
	store := cache.NewEpochStore(cr, src)
	v := newVerifierAt(tokens, store)
	renewer := NewRenewer(tokens, 7*24*time.Hour)
	renewer.now = func() time.Time { return time.Unix(5000, 0) }

	p, err := v.Verify(ctx, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	getsBefore, setsBefore := cr.counts()
	if getsBefore == 0 && setsBefore == 0 {
		t.Fatal("前置：Verify 应已触发 epoch 链（Redis 调用 > 0）")
	}

	for i := 0; i < 3; i++ { // 多次重签均零存储写入
		if _, _, err := renewer.Renew(p); err != nil {
			t.Fatalf("Renew #%d: %v", i, err)
		}
	}
	getsAfter, setsAfter := cr.counts()
	if getsAfter != getsBefore || setsAfter != setsBefore {
		t.Fatalf("renew touched storage: gets %d→%d, sets %d→%d（必须零调用）",
			getsBefore, getsAfter, setsBefore, setsAfter)
	}
}

// TestCookieSet 写值 Cookie 属性逐项断言（接口文档 §1.9 行 288、
// 后端架构 §11.1 行 1175）。
func TestCookieSet(t *testing.T) {
	c := NewCookie("al_session", "example.com", 7*24*time.Hour)
	ck := c.Set("tok-value")
	if ck.Name != "al_session" {
		t.Fatalf("Name = %q, want al_session", ck.Name)
	}
	if ck.Value != "tok-value" {
		t.Fatalf("Value = %q, want tok-value", ck.Value)
	}
	if ck.Path != "/" {
		t.Fatalf("Path = %q, want /", ck.Path)
	}
	if ck.Domain != "example.com" {
		t.Fatalf("Domain = %q, want example.com（根域注入）", ck.Domain)
	}
	if want := 7 * 24 * 3600; ck.MaxAge != want {
		t.Fatalf("MaxAge = %d, want %d（session_ttl）", ck.MaxAge, want)
	}
	if !ck.HttpOnly || !ck.Secure {
		t.Fatalf("HttpOnly=%v Secure=%v, want true/true", ck.HttpOnly, ck.Secure)
	}
	if ck.SameSite != http.SameSiteNoneMode {
		t.Fatalf("SameSite = %v, want None", ck.SameSite)
	}
}

// TestCookieDefaultName 名传空串回落默认 al_session。
func TestCookieDefaultName(t *testing.T) {
	c := NewCookie("", "example.com", time.Hour)
	if ck := c.Set("v"); ck.Name != "al_session" {
		t.Fatalf("Name = %q, want al_session（默认）", ck.Name)
	}
}

// TestCookieClear 清除 Cookie：MaxAge=-1、值空，其余属性与 Set 一致
// （同名同 Path/Domain 才能覆盖删除）。
func TestCookieClear(t *testing.T) {
	c := NewCookie("al_session", "example.com", 7*24*time.Hour)
	ck := c.Clear()
	if ck.Name != "al_session" || ck.Path != "/" || ck.Domain != "example.com" {
		t.Fatalf("clear cookie identity = %q %q %q, want 同 Set", ck.Name, ck.Path, ck.Domain)
	}
	if ck.Value != "" {
		t.Fatalf("Value = %q, want 空", ck.Value)
	}
	if ck.MaxAge != -1 {
		t.Fatalf("MaxAge = %d, want -1（立即删除）", ck.MaxAge)
	}
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteNoneMode {
		t.Fatalf("attrs HttpOnly=%v Secure=%v SameSite=%v, want 与 Set 一致",
			ck.HttpOnly, ck.Secure, ck.SameSite)
	}
}

// TestRenewTTLZeroEdge ttl=0 的边界：exp == iat（构造注入值原样生效）。
func TestRenewTTLZeroEdge(t *testing.T) {
	tokens := NewTokens(newTestCodec(t))
	renewer := NewRenewer(tokens, 0)
	renewer.now = func() time.Time { return time.Unix(5000, 0) }
	fresh, _, err := renewer.Renew(testPayload())
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if fresh.GetIat() != 5000 || fresh.GetExp() != 5000 {
		t.Fatalf("iat/exp = %d/%d, want 5000/5000", fresh.GetIat(), fresh.GetExp())
	}
}
