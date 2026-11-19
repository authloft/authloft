package partition

import (
	"testing"
	"time"
)

func TestNameForDate(t *testing.T) {
	cases := []struct {
		in   time.Time
		want string
	}{
		{mustDate("2026-11-20"), "p20261120"},
		{mustDate("2027-01-01"), "p20270101"},
		{mustDate("2028-02-29"), "p20280229"},
		// 时钟部分与调用方时区不改变墙钟日期。
		{time.Date(2026, 11, 20, 23, 59, 59, 0, time.UTC), "p20261120"},
		{time.Date(2026, 11, 20, 7, 30, 0, 0, time.FixedZone("CST", 8*3600)), "p20261120"},
	}
	for _, tc := range cases {
		if got := NameForDate(tc.in); got != tc.want {
			t.Errorf("NameForDate(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseName(t *testing.T) {
	cases := []struct {
		name   string
		want   time.Time
		wantOK bool
	}{
		{name: "p20261120", want: mustDate("2026-11-20"), wantOK: true},
		{name: "p20270101", want: mustDate("2027-01-01"), wantOK: true},
		{name: "p20280229", want: mustDate("2028-02-29"), wantOK: true},
		// 解析出的上界统一锚定 UTC 零点。
		{name: "p20261120", want: time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC), wantOK: true},
	}
	for _, tc := range cases {
		got, ok := ParseName(tc.name)
		if ok != tc.wantOK {
			t.Errorf("ParseName(%q) ok = %v, want %v", tc.name, ok, tc.wantOK)
			continue
		}
		if !tc.wantOK {
			continue
		}
		if !got.Equal(tc.want) {
			t.Errorf("ParseName(%q) = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestParseNameInvalid(t *testing.T) {
	invalid := []string{
		"",
		"p",
		"pmax",              // MySQL 兜底分区
		"event_log_default", // PG 兜底分区
		"P20261120",         // 前缀大小写敏感
		"x20261120",
		"p_20261120",
		"p2026112",   // 位数不足
		"p202611200", // 位数超出
		"p2026112a",  // 含非数字
		"p2026-1120",
		" p20261120",
		"p20261120 ",
		"p20260001", // 月份越界
		"p20261301", // 月份越界
		"p20261100", // 日越界
		"p20261131", // 日越界
		"p20260230", // 非闰月日越界
		"p20260229", // 非闰年
	}
	for _, name := range invalid {
		if got, ok := ParseName(name); ok {
			t.Errorf("ParseName(%q) = (%s, true), want rejected", name, got)
		}
	}
}
