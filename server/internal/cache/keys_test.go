// keys.go 验证码键空间单测：表驱动断言键名格式与零值 / 边界
// 输入（§5.1 行 835-838）。TTL 断言需真连 Redis，放在 code_test.go。
package cache

import (
	"testing"
	"time"
)

// TestKeysCodeSpace 验证码四类键名格式（键名唯一出处 keys.go，§5.1 行 835-838）。
func TestKeysCodeSpace(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"CodeKey", CodeKey("13800138000", "login"), "al:code:13800138000:login"},
		{"CodeKey-配置中的冒号不转义", CodeKey("a:b", "bind"), "al:code:a:b:bind"},
		{"SendCooldownKey", SendCooldownKey("13800138000"), "al:rl:send:13800138000"},
		{"SendDayKey", SendDayKey("13800138000", "20261104"), "al:rl:sendday:13800138000:20261104"},
		{"IPDayKey", IPDayKey("192.168.10.2", "20261104"), "al:rl:ipday:192.168.10.2:20261104"},
		{"IPDayKey-IPv6", IPDayKey("::1", "20261104"), "al:rl:ipday:::1:20261104"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Fatalf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// TestKeysDayStamp 日期段格式 yyyymmdd（§5.1 行 837-838）。
func TestKeysDayStamp(t *testing.T) {
	cases := []struct {
		in   time.Time
		want string
	}{
		{time.Date(2026, 11, 4, 12, 0, 0, 0, time.Local), "20261104"},
		{time.Date(2026, 1, 9, 0, 0, 0, 0, time.Local), "20260109"},
		{time.Date(2026, 12, 31, 23, 59, 59, 0, time.Local), "20261231"},
	}
	for _, c := range cases {
		if got := dayStamp(c.in); got != c.want {
			t.Fatalf("dayStamp(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
