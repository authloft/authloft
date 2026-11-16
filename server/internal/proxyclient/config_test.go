// NewConfig / Config.Equal 单测（后端架构 §15.4 单一规则源）：scheme 封闭集、
// host 禁字符与 IPv6 补括号、port 边界、password 伴随 user、RFC 3986 编码、
// 拼串超长，以及语义字段比对。错误串一律不含字段值与凭据（脱敏口径平移）。
package proxyclient

import (
	"errors"
	"strings"
	"testing"
)

// TestNewConfigValid 合法输入逐项断言语义字段与拼串：Host 保留 trim 后原文
// （IPv6 不带括号），u 的 Host 按 IPv6 字面量补 []，凭据经 RFC 3986 编码，
// NewConfig 产物不可能是直连配置（proxy 行五字段必填齐全）。
func TestNewConfigValid(t *testing.T) {
	cases := []struct {
		name           string
		scheme, host   string
		port           int32
		user, password string
		wantHost       string
		wantURL        string
		wantHasAuth    bool
	}{
		{"socks5 无凭据", "socks5", "127.0.0.1", 1080, "", "", "127.0.0.1", "socks5://127.0.0.1:1080", false},
		{"http 无凭据", "http", "proxy.example.com", 8080, "", "", "proxy.example.com", "http://proxy.example.com:8080", false},
		{"https 带凭据", "https", "proxy.example.com", 8443, "alice", "s3cr3t", "proxy.example.com", "https://alice:s3cr3t@proxy.example.com:8443", true},
		{"host trim", "http", "  proxy.example.com  ", 8080, "", "", "proxy.example.com", "http://proxy.example.com:8080", false},
		{"仅用户名", "socks5", "127.0.0.1", 1080, "bob", "", "127.0.0.1", "socks5://bob:@127.0.0.1:1080", true},
		{"IPv6 补括号", "socks5", "::1", 1080, "", "", "::1", "socks5://[::1]:1080", false},
		{"完整 IPv6", "socks5", "2001:db8::1", 1080, "", "", "2001:db8::1", "socks5://[2001:db8::1]:1080", false},
		{"凭据 RFC 3986 编码", "socks5", "127.0.0.1", 1080, "u@ser", "p:ss", "127.0.0.1", "socks5://u%40ser:p%3Ass@127.0.0.1:1080", true},
		{"port 下界", "http", "leaky-host", 1, "", "", "leaky-host", "http://leaky-host:1", false},
		{"port 上界", "http", "leaky-host", 65535, "", "", "leaky-host", "http://leaky-host:65535", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewConfig(tc.scheme, tc.host, tc.port, tc.user, tc.password)
			if err != nil {
				t.Fatalf("NewConfig: %v", err)
			}
			if cfg.Scheme != tc.scheme || cfg.Host != tc.wantHost || cfg.Port != int(tc.port) ||
				cfg.User != tc.user || cfg.Password != tc.password || cfg.HasAuth != tc.wantHasAuth {
				t.Fatalf("语义字段 = %+v, want host=%q port=%d user=%q pass=%q auth=%v",
					cfg, tc.wantHost, tc.port, tc.user, tc.password, tc.wantHasAuth)
			}
			if cfg.Direct() {
				t.Error("NewConfig 产物不可能是直连配置")
			}
			if got := cfg.u.String(); got != tc.wantURL {
				t.Fatalf("拼串 = %q, want %q", got, tc.wantURL)
			}
		})
	}
}

// TestNewConfigInvalid 非法输入逐条可证伪：每条断言具体可判别哨兵，任一校验
// 被删即对应子例变红；错误串不含字段值与凭据。
func TestNewConfigInvalid(t *testing.T) {
	cases := []struct {
		name           string
		scheme, host   string
		port           int32
		user, password string
		want           error
	}{
		{"空 scheme", "", "leaky-host", 1080, "", "", ErrUnsupportedScheme},
		{"大写 scheme", "SOCKS5", "leaky-host", 1080, "", "", ErrUnsupportedScheme},
		{"scheme 带空白", " https", "leaky-host", 8443, "", "", ErrUnsupportedScheme},
		{"socks5h 非封闭", "socks5h", "leaky-host", 1080, "", "", ErrUnsupportedScheme},
		{"ftp 非封闭", "ftp", "leaky-host", 21, "", "", ErrUnsupportedScheme},
		{"空 host", "http", "", 8080, "", "", ErrMissingHost},
		{"纯空白 host", "http", "   ", 8080, "", "", ErrMissingHost},
		{"host 空格", "http", "leaky host", 8080, "", "", ErrMalformedURL},
		{"host 制表符", "http", "leaky\thost", 8080, "", "", ErrMalformedURL},
		{"host 全角空格", "http", "leaky\u3000host", 8080, "", "", ErrMalformedURL},
		{"host 含 /", "http", "leaky/host", 8080, "", "", ErrMalformedURL},
		{"host 含 ?", "http", "leaky?host", 8080, "", "", ErrMalformedURL},
		{"host 含 #", "http", "leaky#host", 8080, "", "", ErrMalformedURL},
		{"host 含 @", "http", "leaky@host", 8080, "", "", ErrMalformedURL},
		{"host 含 []", "http", "[::1]", 8080, "", "", ErrMalformedURL},
		{"port 0", "http", "leaky-host", 0, "", "", ErrInvalidPort},
		{"port 负数", "http", "leaky-host", -1, "", "", ErrInvalidPort},
		{"port 65536", "http", "leaky-host", 65536, "", "", ErrInvalidPort},
		{"有 password 无 user", "http", "leaky-host", 8080, "", "leaky-pass", ErrInvalidUserinfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewConfig(tc.scheme, tc.host, tc.port, tc.user, tc.password)
			if !errors.Is(err, tc.want) {
				t.Fatalf("NewConfig(%q, %q, %d, %q, %q) err = %v, want %v",
					tc.scheme, tc.host, tc.port, tc.user, tc.password, err, tc.want)
			}
			for _, secret := range []string{tc.host, tc.user, tc.password} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Errorf("错误串泄漏字段值: %q", err.Error())
				}
			}
		})
	}
}

// TestNewConfigLengthBoundary 拼串（编码后 u.String()）512 字节恰好合法、
// 513 拒绝：host 长度按 "socks5://"(9) + host + ":"(1) + "65535"(5) 折算。
func TestNewConfigLengthBoundary(t *testing.T) {
	mk := func(n int) string { return strings.Repeat("a", n) }
	cfg, err := NewConfig("socks5", mk(497), 65535, "", "")
	if err != nil {
		t.Fatalf("512 字节应合法: %v", err)
	}
	if got := len(cfg.u.String()); got != maxRawLen {
		t.Fatalf("边界用例拼串长度 = %d, want %d", got, maxRawLen)
	}
	if _, err := NewConfig("socks5", mk(498), 65535, "", ""); !errors.Is(err, ErrTooLong) {
		t.Fatalf("513 字节 err = %v, want ErrTooLong", err)
	}
}

// TestConfigEqual 语义字段逐一比对：同构配置相等（两次独立构造、u 指针不同
// 不影响），任一语义字段不同即不等；零值配置与零值相等、与代理配置不等。
func TestConfigEqual(t *testing.T) {
	a, err := NewConfig("socks5", "127.0.0.1", 1080, "u", "p")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewConfig("socks5", "127.0.0.1", 1080, "u", "p")
	if err != nil {
		t.Fatal(err)
	}
	if a.u == b.u {
		t.Fatal("用例自检：两次独立构造应产生不同 u")
	}
	if !a.Equal(b) || !b.Equal(a) {
		t.Fatal("同构配置应相等")
	}
	mutants := []Config{
		{Scheme: "http", Host: "127.0.0.1", Port: 1080, User: "u", Password: "p", HasAuth: true},
		{Scheme: "socks5", Host: "127.0.0.2", Port: 1080, User: "u", Password: "p", HasAuth: true},
		{Scheme: "socks5", Host: "127.0.0.1", Port: 1081, User: "u", Password: "p", HasAuth: true},
		{Scheme: "socks5", Host: "127.0.0.1", Port: 1080, User: "u2", Password: "p", HasAuth: true},
		{Scheme: "socks5", Host: "127.0.0.1", Port: 1080, User: "u", Password: "p2", HasAuth: true},
		{Scheme: "socks5", Host: "127.0.0.1", Port: 1080},
	}
	for i, m := range mutants {
		if a.Equal(m) || m.Equal(a) {
			t.Fatalf("mutant %d 不应相等: %+v", i, m)
		}
	}
	var zero Config
	if !zero.Equal(Config{}) {
		t.Fatal("零值配置与零值应相等")
	}
	if zero.Equal(a) {
		t.Fatal("零值配置与代理配置不应相等")
	}
}
