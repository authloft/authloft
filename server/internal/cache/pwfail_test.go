// cache/pwfail.go 单测（覆盖 docs/后端架构.md §21.2-C 行 1825）：
// 计数递增、当日 24:00 过期（含跨天与缺失 TTL 补设）、pwban 的 TTL /
// 剩余时长（供 retry_after）、Reset 清除两类键。真连 Redis
// （UC_TEST_REDIS_ADDR，env 未设置才 skip）；时钟注入固定时刻以便断言
// 跨天边界（time.Local 口径，与实现一致）。
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

// t052Clock 固定时钟（跨天用例改闭包变量即可推进时间）。
func t052Clock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

// TestPwFailKeys 失败计数 / 封禁键名格式（键名唯一出处 keys.go，§5.1 行 839-840）。
func TestPwFailKeys(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"PwFailKey", PwFailKey("user-1", "20261104"), "al:pwf:user-1:20261104"},
		{"PwFailKey-冒号不转义", PwFailKey("a:b", "20261104"), "al:pwf:a:b:20261104"},
		{"PwBanKey", PwBanKey("user-1"), "al:pwban:user-1"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Fatalf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// TestPwFailDefaults 默认封禁时长 6h（接口文档 §5.6 行 1323：pwd_ban_ttl=21600）。
func TestPwFailDefaults(t *testing.T) {
	if d := DefaultPwFailOptions().BanTTL; d != 6*time.Hour {
		t.Fatalf("DefaultPwFailOptions().BanTTL = %v, want 6h", d)
	}
	// 零值 options 同样回落 6h。
	// rdb 不参与构造，可不连通。
	if got := NewPwFailStore(nil, PwFailOptions{}).opts.BanTTL; got != 6*time.Hour {
		t.Fatalf("零值 BanTTL 回落 = %v, want 6h", got)
	}
}

// TestPwFailCaptureIncrement：连续失败计数 1→2→3；首次 INCR 即设 TTL 至
// 服务器本地当日 24:00；TTL 缺失（人为清掉）时下一次 Capture 补设。
func TestPwFailCaptureIncrement(t *testing.T) {
	ctx, rdb, token := t052RDB(t)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.Local)
	store := newPwFailStore(rdb, PwFailOptions{}, t052Clock(now))
	ref := token + "-inc"
	key := PwFailKey(ref, "20261104")

	for want := int64(1); want <= 3; want++ {
		n, err := store.Capture(ctx, ref)
		if err != nil || n != want {
			t.Fatalf("第 %d 次 Capture = (%d, %v), want (%d, nil)", want, n, err, want)
		}
	}
	if n, err := store.Count(ctx, ref); err != nil || n != 3 {
		t.Fatalf("Count = (%d, %v), want (3, nil)", n, err)
	}
	wantTTL := time.Duration(dayTTL(now)) * time.Second // 12:00 → 43200s
	if ttl, err := rdb.TTL(ctx, key).Result(); err != nil || ttl < wantTTL-10*time.Second || ttl > wantTTL {
		t.Fatalf("pwf ttl = (%v, %v), want ≈ %v（当日 24:00）", ttl, err, wantTTL)
	}

	// TTL 缺失（如人工 SET 无过期）→ 下一次 Capture 必须补设，且不得产生永久键。
	if err := rdb.Set(ctx, key, "3", 0).Err(); err != nil {
		t.Fatalf("重置无 TTL 键: %v", err)
	}
	if n, err := store.Capture(ctx, ref); err != nil || n != 4 {
		t.Fatalf("TTL 缺失后 Capture = (%d, %v), want (4, nil)", n, err)
	}
	if ttl, err := rdb.TTL(ctx, key).Result(); err != nil || ttl < wantTTL-10*time.Second || ttl > wantTTL {
		t.Fatalf("补设后 pwf ttl = (%v, %v), want ≈ %v", ttl, err, wantTTL)
	}
}

// TestPwFailCrossDay：23:59 的计数键 TTL 约 60s（当日 24:00 过期），跨天后
// 新一天从 1 重新计数，旧日键按原 TTL 自然过期。
func TestPwFailCrossDay(t *testing.T) {
	ctx, rdb, token := t052RDB(t)
	now := time.Date(2026, 11, 4, 23, 59, 0, 0, time.Local)
	store := newPwFailStore(rdb, PwFailOptions{}, func() time.Time { return now })
	ref := token + "-day"

	for i := 0; i < 3; i++ {
		if _, err := store.Capture(ctx, ref); err != nil {
			t.Fatalf("Day1 Capture #%d: %v", i+1, err)
		}
	}
	day1Key := PwFailKey(ref, "20261104")
	if ttl, err := rdb.TTL(ctx, day1Key).Result(); err != nil || ttl <= 50*time.Second || ttl > 60*time.Second {
		t.Fatalf("Day1 pwf ttl = (%v, %v), want (50s, 60s]", ttl, err)
	}

	now = time.Date(2026, 11, 5, 0, 1, 0, 0, time.Local)
	if n, err := store.Capture(ctx, ref); err != nil || n != 1 {
		t.Fatalf("Day2 Capture = (%d, %v), want (1, nil)（跨天重新计数）", n, err)
	}
	day2Key := PwFailKey(ref, "20261105")
	wantTTL := time.Duration(dayTTL(now)) * time.Second // 00:01 → 86340s
	if ttl, err := rdb.TTL(ctx, day2Key).Result(); err != nil || ttl < wantTTL-10*time.Second || ttl > wantTTL {
		t.Fatalf("Day2 pwf ttl = (%v, %v), want ≈ %v", ttl, err, wantTTL)
	}
	if n, err := store.Count(ctx, ref); err != nil || n != 1 {
		t.Fatalf("Day2 Count = (%d, %v), want (1, nil)", n, err)
	}
	if n, err := rdb.Exists(ctx, day1Key).Result(); err != nil || n != 1 {
		t.Fatalf("Day1 键 exists = (%d, %v), want (1, nil)（按原 TTL 自然过期）", n, err)
	}
}

// TestPwFailBanTTL：SET NX EX 使封禁 TTL = 注入的 pwd_ban_ttl；NX 不续期；
// PTTL 换算为 retry_after 剩余时长（§21.2-C 行 1825）。
func TestPwFailBanTTL(t *testing.T) {
	ctx, rdb, token := t052RDB(t)
	banTTL := 90 * time.Second
	store := NewPwFailStore(rdb, PwFailOptions{BanTTL: banTTL})
	ref := token + "-ban"

	ok, err := store.Ban(ctx, ref)
	if err != nil || !ok {
		t.Fatalf("Ban = (%v, %v), want (true, nil)", ok, err)
	}
	if banned, err := store.IsBanned(ctx, ref); err != nil || !banned {
		t.Fatalf("IsBanned = (%v, %v), want (true, nil)", banned, err)
	}
	if ttl, err := rdb.TTL(ctx, PwBanKey(ref)).Result(); err != nil || ttl < banTTL-5*time.Second || ttl > banTTL {
		t.Fatalf("pwban ttl = (%v, %v), want (%v, %v]", ttl, err, banTTL-5*time.Second, banTTL)
	}
	if rem, err := store.BanRemaining(ctx, ref); err != nil || rem < banTTL-5*time.Second || rem > banTTL {
		t.Fatalf("BanRemaining = (%v, %v), want (%v, %v]", rem, err, banTTL-5*time.Second, banTTL)
	}
	// NX：再次 Ban 返回 false，不续期。
	prev, _ := store.BanRemaining(ctx, ref)
	if ok, err := store.Ban(ctx, ref); err != nil || ok {
		t.Fatalf("二次 Ban = (%v, %v), want (false, nil)", ok, err)
	}
	if rem, _ := store.BanRemaining(ctx, ref); rem > prev {
		t.Fatalf("二次 Ban 后剩余 = %v, 此前 = %v（应不续期）", rem, prev)
	}
}

// TestPwFailBanRemainingMissing：未封禁 / 已解除时剩余 0，不返回负值。
func TestPwFailBanRemainingMissing(t *testing.T) {
	ctx, rdb, token := t052RDB(t)
	store := NewPwFailStore(rdb, PwFailOptions{})
	if rem, err := store.BanRemaining(ctx, token+"-noban"); err != nil || rem != 0 {
		t.Fatalf("未封禁 BanRemaining = (%v, %v), want (0, nil)", rem, err)
	}
	if banned, err := store.IsBanned(ctx, token+"-noban"); err != nil || banned {
		t.Fatalf("未封禁 IsBanned = (%v, %v), want (false, nil)", banned, err)
	}
}

// TestPwFailReset：Reset 一次清除当日失败计数与封禁键。
func TestPwFailReset(t *testing.T) {
	ctx, rdb, token := t052RDB(t)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.Local)
	store := newPwFailStore(rdb, PwFailOptions{}, t052Clock(now))
	ref := token + "-reset"

	for i := 0; i < 2; i++ {
		if _, err := store.Capture(ctx, ref); err != nil {
			t.Fatalf("Capture #%d: %v", i+1, err)
		}
	}
	if ok, err := store.Ban(ctx, ref); err != nil || !ok {
		t.Fatalf("Ban = (%v, %v), want (true, nil)", ok, err)
	}
	if err := store.Reset(ctx, ref); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if n, err := store.Count(ctx, ref); err != nil || n != 0 {
		t.Fatalf("Reset 后 Count = (%d, %v), want (0, nil)", n, err)
	}
	if banned, err := store.IsBanned(ctx, ref); err != nil || banned {
		t.Fatalf("Reset 后 IsBanned = (%v, %v), want (false, nil)", banned, err)
	}
	for _, key := range []string{PwFailKey(ref, dayStamp(now)), PwBanKey(ref)} {
		if n, err := rdb.Exists(ctx, key).Result(); err != nil || n != 0 {
			t.Fatalf("Reset 后 %s exists = (%d, %v), want (0, nil)", key, n, err)
		}
	}
	if rem, err := store.BanRemaining(ctx, ref); err != nil || rem != 0 {
		t.Fatalf("Reset 后 BanRemaining = (%v, %v), want (0, nil)", rem, err)
	}
}

// TestPwFailDeleteAccountRef：管理员解锁的「ip + 账号哈希」维度
// SCAN 清除——按账号哈希段删除该维度任意 ip / 任意日期的 pwf / pwban 键，
// 不触碰同前缀的其它账号键与非本键空间的键；非 64 位 hex 入参 no-op。
func TestPwFailDeleteAccountRef(t *testing.T) {
	ctx, rdb, token := t052RDB(t)
	store := NewPwFailStore(rdb, PwFailOptions{})

	// 账号哈希段：sha256("alice@example.com") 的 64 位 hex（factor/password
	// userRef 的哈希段同款格式，§8.1 行 1027）。
	hash := sha256SumHex("alice@example.com")
	// 同账号不同 ip 维度键（用户不存在阶段由两个 ip 种下）+ 不同日期。
	hashKeys := []string{
		PwFailKey("10.0.0.1|"+hash, "20261104"),
		PwFailKey("192.168.1.8|"+hash, "20261105"),
		PwBanKey("10.0.0.1|" + hash),
	}
	for _, k := range hashKeys {
		if err := rdb.Set(ctx, k, "1", time.Hour).Err(); err != nil {
			t.Fatalf("种键 %s 失败: %v", k, err)
		}
	}
	// 干扰项：其它账号哈希维度 + uid 维度 + 非本键空间。
	otherHash := sha256SumHex("bob@example.com")
	unrelated := []string{
		PwFailKey("10.0.0.1|"+otherHash, "20261104"),
		PwBanKey("42"),
		PwFailKey("42", "20261104"),
		EpochKey(42), // al:pwdep 键空间（同 al: 前缀族，验证不误删）
		token + "-unrelated",
	}
	for _, k := range unrelated {
		if err := rdb.Set(ctx, k, "1", time.Hour).Err(); err != nil {
			t.Fatalf("种干扰键 %s 失败: %v", k, err)
		}
	}

	if err := store.DeleteAccountRef(ctx, hash); err != nil {
		t.Fatalf("DeleteAccountRef: %v", err)
	}
	for _, k := range hashKeys {
		if n, err := rdb.Exists(ctx, k).Result(); err != nil || n != 0 {
			t.Fatalf("维度键 %s exists = (%d, %v), want 0", k, n, err)
		}
	}
	for _, k := range unrelated {
		if n, err := rdb.Exists(ctx, k).Result(); err != nil || n != 1 {
			t.Fatalf("干扰键 %s exists = (%d, %v), want 1（不得误删）", k, n, err)
		}
	}

	// 非 64 位 hex（空 / 短 / 含 glob 元字符）→ no-op 不报错、不动任何键。
	if err := store.DeleteAccountRef(ctx, ""); err != nil {
		t.Fatalf("空哈希应 no-op: %v", err)
	}
	if err := store.DeleteAccountRef(ctx, "abc*"); err != nil {
		t.Fatalf("脏哈希应 no-op: %v", err)
	}
	for _, k := range unrelated {
		if n, err := rdb.Exists(ctx, k).Result(); err != nil || n != 1 {
			t.Fatalf("no-op 后干扰键 %s exists = (%d, %v), want 1", k, n, err)
		}
	}
}

// sha256SumHex sha256 → 小写十六进制（factor/password userRef 的账号哈希段
// 同款算法，测试辅助）。
func sha256SumHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
