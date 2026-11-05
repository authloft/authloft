// sync_test.go GET /sso/sync_cookie 接收端测试（§2.9 行 758、
// §11.2 行 1203-1210）：登录载荷写 Cookie + TTL、逐跳重封（exp 按剩余
// 地址数重算）、末跳 302 final、解密失败 / 过期 / 空载荷 → 空体 200 中断。
package pages

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/security"
)

// sealPayload 测试直封载荷。
func sealPayload(t *testing.T, codec *security.Codec, p *token.SyncCookiePayload) string {
	t.Helper()
	sealed, err := codec.Seal(security.PurposeSyncPayload, p)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return sealed
}

// openPayload 测试解封载荷。
func openPayload(t *testing.T, codec *security.Codec, sealed string) *token.SyncCookiePayload {
	t.Helper()
	p, err := security.Open[token.SyncCookiePayload](codec, security.PurposeSyncPayload, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return p
}

// fixedNow 固定时钟（exp 断言确定性）。
func fixedNow() time.Time { return time.Unix(1700000000, 0) }

// TestSyncCookieLoginPayload 登录形态载荷：写 Cookie（值 + Max-Age=TTL）、
// remaining 非空 → 重封 302 下一跳，新载荷 remaining 推进、exp 重算
// （§11.2 行 1207：now + 30s × 剩余地址数）。
func TestSyncCookieLoginPayload(t *testing.T) {
	f := newFixture(t)
	f.deps.Now = fixedNow
	r := f.engine(t)

	next := "https://b.example/sso/sync_cookie"
	final := "https://auth.example.com/done"
	sealed := sealPayload(t, f.deps.Codec, &token.SyncCookiePayload{
		CookieName:  "al_session",
		CookieValue: "session-value",
		CookieTtl:   "3600",
		Remaining:   []string{next, "https://c.example/sso/sync_cookie"},
		FinalUrl:    final,
		Exp:         fixedNow().Add(5 * time.Minute).Unix(),
	})

	rec := doGet(t, r, "/sso/sync_cookie?"+sealed)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	ck := setCookieHeader(rec)
	if !strings.HasPrefix(ck, "al_session=session-value;") {
		t.Errorf("Set-Cookie = %q, want al_session=session-value（覆盖写入）", ck)
	}
	if !strings.Contains(ck, "Max-Age=3600") {
		t.Errorf("Set-Cookie = %q, want Max-Age=3600", ck)
	}
	if !strings.Contains(ck, "Domain=auth.example.com") {
		t.Errorf("Set-Cookie = %q, want Domain=本部署根域", ck)
	}

	loc := rec.Header().Get("Location")
	base, q, ok := strings.Cut(loc, "?")
	if !ok || base != next {
		t.Fatalf("Location = %q, want 下一跳 %s?{payload}", loc, next)
	}
	p := openPayload(t, f.deps.Codec, q)
	if len(p.GetRemaining()) != 1 || p.GetRemaining()[0] != "https://c.example/sso/sync_cookie" {
		t.Errorf("新载荷 remaining = %v, want [c.example]（推进）", p.GetRemaining())
	}
	if p.GetFinalUrl() != final {
		t.Errorf("新载荷 final = %q, want %q", p.GetFinalUrl(), final)
	}
	// exp 重算：now + 30s ×（下一跳 + 新 remaining + final = 3）。
	if want := fixedNow().Unix() + 90; p.GetExp() != want {
		t.Errorf("新载荷 exp = %d, want %d（30s × 剩余地址数）", p.GetExp(), want)
	}
	if p.GetCookieValue() != "session-value" || p.GetCookieTtl() != "3600" {
		t.Errorf("新载荷 cookie 字段被改写: %v/%v", p.GetCookieValue(), p.GetCookieTtl())
	}
}

// TestSyncCookieLastHop 末跳（remaining 空）：写 Cookie 后 302 final，
// final 不带载荷（§11.2 行 1208）。
func TestSyncCookieLastHop(t *testing.T) {
	f := newFixture(t)
	r := f.engine(t)

	sealed := sealPayload(t, f.deps.Codec, &token.SyncCookiePayload{
		CookieName: "al_session", CookieValue: "v", CookieTtl: "60",
		FinalUrl: "https://auth.example.com/ok",
		Exp:      time.Now().Add(time.Minute).Unix(),
	})
	rec := doGet(t, r, "/sso/sync_cookie?"+sealed)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://auth.example.com/ok" {
		t.Errorf("Location = %q, want final（不带载荷）", loc)
	}
	if ck := setCookieHeader(rec); !strings.HasPrefix(ck, "al_session=v;") {
		t.Errorf("末跳 Set-Cookie = %q, want 照常写入", ck)
	}
}

// TestSyncCookieLogoutPayload 登出形态载荷（值空 TTL "0"）：写入即清除
// （Max-Age=0），不需要区分登录 / 登出（§11.2 行 1206）。
func TestSyncCookieLogoutPayload(t *testing.T) {
	f := newFixture(t)
	r := f.engine(t)

	sealed := sealPayload(t, f.deps.Codec, &token.SyncCookiePayload{
		CookieName: "al_session", CookieValue: "", CookieTtl: "0",
		Remaining: []string{"https://b.example/sso/sync_cookie"},
		FinalUrl:  "https://auth.example.com/",
		Exp:       time.Now().Add(time.Minute).Unix(),
	})
	rec := doGet(t, r, "/sso/sync_cookie?"+sealed)
	if ck := setCookieHeader(rec); !strings.HasPrefix(ck, "al_session=;") || !strings.Contains(ck, "Max-Age=0") {
		t.Errorf("Set-Cookie = %q, want 清除形态（值空 + Max-Age=0）", ck)
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), "https://b.example/sso/sync_cookie?") {
		t.Errorf("Location = %q, want 继续推进", rec.Header().Get("Location"))
	}
}

// TestSyncCookieBadPayload 解密失败 / 过期 / 空载荷 → 空体 200 不带
// Location、不写 Cookie（§11.2 行 1205 / 1210）。
func TestSyncCookieBadPayload(t *testing.T) {
	f := newFixture(t)
	f.deps.Now = fixedNow
	r := f.engine(t)

	expired := sealPayload(t, f.deps.Codec, &token.SyncCookiePayload{
		CookieName: "al_session", CookieValue: "v", CookieTtl: "60",
		FinalUrl: "https://auth.example.com/never",
		Exp:      fixedNow().Unix() - 1,
	})
	cases := []string{
		"/sso/sync_cookie",                     // 空载荷
		"/sso/sync_cookie?garbage-not-a-token", // 解密失败
		"/sso/sync_cookie?" + expired,          // 过期
	}
	for _, target := range cases {
		rec := doGet(t, r, target)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200（链路中断）", target, rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("%s: body = %q, want 空", target, rec.Body.String())
		}
		if rec.Header().Get("Location") != "" {
			t.Errorf("%s: Location = %q, want 无（不带 Location）", target, rec.Header().Get("Location"))
		}
		if ck := setCookieHeader(rec); ck != "" {
			t.Errorf("%s: Set-Cookie = %q, want 不写（过期不得再写 Cookie）", target, ck)
		}
	}
}
