package proxyclient

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestParseSchemes 三 scheme 构造 + 带 / 不带 userinfo：逐项断言解码后的
// Scheme / Host / Port / 凭据，非恒真（改任一解析分支即红）。
func TestParseSchemes(t *testing.T) {
	cases := []struct {
		name            string
		raw             string
		scheme, host    string
		port            int
		user, pass      string
		hasAuth, direct bool
	}{
		{"socks5 无凭据", "socks5://127.0.0.1:1080", "socks5", "127.0.0.1", 1080, "", "", false, false},
		{"socks5 带凭据", "socks5://alice:s3cr3t@127.0.0.1:1080", "socks5", "127.0.0.1", 1080, "alice", "s3cr3t", true, false},
		{"http 无凭据", "http://proxy.example.com:8080", "http", "proxy.example.com", 8080, "", "", false, false},
		{"http 仅用户名", "http://bob@proxy.example.com:8080", "http", "proxy.example.com", 8080, "bob", "", true, false},
		{"https 带编码凭据", "https://u%40ser:p%3Ass@proxy.example.com:8443", "https", "proxy.example.com", 8443, "u@ser", "p:ss", true, false},
		{"IPv6 host", "socks5://[::1]:1080", "socks5", "::1", 1080, "", "", false, false},
		{"空串直连", "  ", "", "", 0, "", "", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(tc.raw)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tc.raw, err)
			}
			if cfg.Direct() != tc.direct || cfg.Scheme != tc.scheme || cfg.Host != tc.host ||
				cfg.Port != tc.port || cfg.User != tc.user || cfg.Password != tc.pass || cfg.HasAuth != tc.hasAuth {
				t.Fatalf("Parse(%q) = %+v, want scheme=%q host=%q port=%d user=%q pass=%q auth=%v direct=%v",
					tc.raw, cfg, tc.scheme, tc.host, tc.port, tc.user, tc.pass, tc.hasAuth, tc.direct)
			}
		})
	}
}

// TestParseInvalid 非法格式逐条可证伪：每条断言具体可判别哨兵，任一校验被删
// 即对应子例变红。错误串一律不含完整 URL / 凭据（脱敏）。
func TestParseInvalid(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"socks5h 非封闭 scheme", "socks5h://h:1080", ErrUnsupportedScheme},
		{"socks4 非封闭 scheme", "socks4://h:1080", ErrUnsupportedScheme},
		{"ftp 非封闭 scheme", "ftp://h:21", ErrUnsupportedScheme},
		{"空 scheme", "://h:1080", ErrMalformedURL},
		{"大写 scheme", "HTTP://h:8080", ErrUnsupportedScheme},
		{"缺 ://", "http:h:8080", ErrMalformedURL},
		{"空 host", "http://:8080", ErrMissingHost},
		{"空 host 带 userinfo", "http://bob@:8080", ErrMissingHost},
		{"缺 port", "http://h", ErrInvalidPort},
		{"port 0", "http://h:0", ErrInvalidPort},
		{"port 65536", "http://h:65536", ErrInvalidPort},
		{"port 非数字", "http://h:abc", ErrMalformedURL},
		{"path", "http://h:8080/path", ErrUnexpectedPath},
		{"根 path", "http://h:8080/", ErrUnexpectedPath},
		{"query", "http://h:8080?x=1", ErrUnexpectedPath},
		{"空 query", "http://h:8080?", ErrUnexpectedPath},
		{"fragment", "http://h:8080#f", ErrUnexpectedPath},
		{"空 fragment", "http://h:8080#", ErrUnexpectedPath},
		{"空 userinfo 用户名", "http://:pw@h:8080", ErrInvalidUserinfo},
		{"非法百分号", "http://u%zz@h:8080", ErrMalformedURL},
		{"超 512 字节", "http://h:8080/" + strings.Repeat("a", 512), ErrTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.raw)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Parse(%q) err = %v, want %v", tc.raw, err, tc.want)
			}
			if strings.Contains(err.Error(), "://") || strings.Contains(err.Error(), "s3cr3t") {
				t.Errorf("错误串泄漏 URL / 凭据: %q", err.Error())
			}
		})
	}
}

// TestParseTrimAndLengthBoundary trim 后为空即直连；整串 512 字节恰好合法、
// 513 拒绝（用长 hostname 拉开长度、不引入 path，长度边界可证伪）。
func TestParseTrimAndLengthBoundary(t *testing.T) {
	if cfg, err := Parse("   http://h:8080   "); err != nil || cfg.Scheme != "http" || cfg.Host != "h" {
		t.Fatalf("trim 后解析 = (%+v, %v)", cfg, err)
	}
	at512 := "http://" + strings.Repeat("a", 500) + ":8080" // 7+500+5 = 512
	if len(at512) != maxRawLen {
		t.Fatalf("512 用例长度 = %d", len(at512))
	}
	if _, err := Parse(at512); err != nil {
		t.Errorf("512 字节应合法: %v", err)
	}
	if _, err := Parse(at512 + "a"); !errors.Is(err, ErrTooLong) {
		t.Errorf("513 字节 err = %v, want ErrTooLong", err)
	}
}

// TestHTTPClientConstruction 三 scheme + 空串均能构造 client（不触网）：
// 空串走直连默认 transport（Transport==nil），http/https 设 Proxy，socks5 设
// DialContext，且都不改写 http.DefaultTransport。
func TestHTTPClientConstruction(t *testing.T) {
	before := http.DefaultTransport
	cases := []struct {
		name, raw string
		wantProxy bool
		wantDial  bool
	}{
		{"http", "http://127.0.0.1:8080", true, false},
		{"https", "https://127.0.0.1:8443", true, false},
		{"socks5", "socks5://127.0.0.1:1080", false, true},
		{"空串直连", "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cl, err := HTTPClient(tc.raw, 7*time.Second)
			if err != nil {
				t.Fatalf("HTTPClient(%q): %v", tc.raw, err)
			}
			if cl.Timeout != 7*time.Second {
				t.Errorf("Timeout = %v, want 7s", cl.Timeout)
			}
			tr, ok := cl.Transport.(*http.Transport)
			if tc.raw == "" {
				if cl.Transport != nil {
					t.Errorf("空串应走直连默认 client，Transport = %T", cl.Transport)
				}
			} else {
				if !ok {
					t.Fatalf("Transport = %T, want *http.Transport", cl.Transport)
				}
				if (tr.Proxy != nil) != tc.wantProxy || (tr.DialContext != nil) != tc.wantDial {
					t.Errorf("proxy=%v dial=%v, want proxy=%v dial=%v", tr.Proxy != nil, tr.DialContext != nil, tc.wantProxy, tc.wantDial)
				}
			}
		})
	}
	if http.DefaultTransport != before {
		t.Error("HTTPClient 不得改写 http.DefaultTransport")
	}
}

// TestHTTPClientHTTPProxyCarriesTraffic 本地 http 代理桩实证流量经代理：
// 目标 example.invalid 不可解析，唯有经代理桩才可能拿到桩的响应，证伪性强。
func TestHTTPClientHTTPProxyCarriesTraffic(t *testing.T) {
	hits := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- r.URL.String()
		w.Header().Set("X-Via-Proxy", "1")
		_, _ = io.WriteString(w, "proved")
	}))
	defer proxy.Close()

	u, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	cl, err := HTTPClient(u.String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Get("http://example.invalid/probe")
	if err != nil {
		t.Fatalf("经代理 GET 失败: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "proved" || resp.Header.Get("X-Via-Proxy") != "1" {
		t.Fatalf("响应 = %q / header=%q，流量未经代理桩", body, resp.Header.Get("X-Via-Proxy"))
	}
	select {
	case got := <-hits:
		if got != "http://example.invalid/probe" {
			t.Errorf("代理收到 %q", got)
		}
	default:
		t.Error("代理桩未被命中")
	}
}

// socks5Obs 最小握手桩观测项。
type socks5Obs struct {
	methods     []byte
	hadAuth     bool
	user, pass  string
	dst         string
	httpRequest string
}

// socks5Stub 最小 SOCKS5 桩：读 greeting（记录 method，user/pass 时读子协商）、
// 读 CONNECT 目标、回成功、收一段 HTTP 请求后回固定响应。返回代理地址与观测通道。
func socks5Stub(t *testing.T) (string, <-chan socks5Obs, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan socks5Obs, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		var obs socks5Obs
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(r, hdr); err != nil || hdr[0] != 0x05 {
			return
		}
		obs.methods = make([]byte, hdr[1])
		if _, err := io.ReadFull(r, obs.methods); err != nil {
			return
		}
		method := byte(0x00)
		for _, m := range obs.methods {
			if m == 0x02 {
				method = 0x02
				break
			}
		}
		if _, err := conn.Write([]byte{0x05, method}); err != nil {
			return
		}
		if method == 0x02 {
			ah := make([]byte, 2) // 版本 + 用户名长度
			if _, err := io.ReadFull(r, ah); err != nil {
				return
			}
			u := make([]byte, ah[1])
			if _, err := io.ReadFull(r, u); err != nil {
				return
			}
			pl := make([]byte, 1)
			if _, err := io.ReadFull(r, pl); err != nil {
				return
			}
			p := make([]byte, pl[0])
			if _, err := io.ReadFull(r, p); err != nil {
				return
			}
			obs.user, obs.pass, obs.hadAuth = string(u), string(p), true
			if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
				return
			}
		}
		req := make([]byte, 4) // ver cmd rsv atyp
		if _, err := io.ReadFull(r, req); err != nil || req[0] != 0x05 || req[1] != 0x01 {
			return
		}
		var host string
		switch req[3] {
		case 0x01:
			b := make([]byte, 4)
			io.ReadFull(r, b)
			host = net.IP(b).String()
		case 0x03:
			l := make([]byte, 1)
			io.ReadFull(r, l)
			b := make([]byte, l[0])
			io.ReadFull(r, b)
			host = string(b)
		case 0x04:
			b := make([]byte, 16)
			io.ReadFull(r, b)
			host = net.IP(b).String()
		}
		port := make([]byte, 2)
		io.ReadFull(r, port)
		obs.dst = net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port))))
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		buf := make([]byte, 1024)
		if n, err := r.Read(buf); err == nil {
			obs.httpRequest = string(buf[:n])
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
		ch <- obs
	}()
	return ln.Addr().String(), ch, func() { ln.Close(); <-done }
}

// TestHTTPClientSOCKS5Handshake socks5 最小握手桩实证：带 / 不带 userinfo
// 两条分支分别走 no-auth 与 user/pass 子协商，CONNECT 目标与隧道内 HTTP 请求
// 均被桩观测，证明流量经 socks5 代理而非直连。
func TestHTTPClientSOCKS5Handshake(t *testing.T) {
	for _, tc := range []struct {
		name, user, pass string
	}{
		{"无凭据", "", ""},
		{"带 userinfo", "alice", "s3cr3t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, ch, cleanup := socks5Stub(t)
			defer cleanup()
			raw := "socks5://" + addr
			if tc.user != "" {
				raw = "socks5://" + tc.user + ":" + tc.pass + "@" + addr
			}
			cl, err := HTTPClient(raw, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := cl.Get("http://example.invalid/probe")
			if err != nil {
				t.Fatalf("经 socks5 GET 失败: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "OK" {
				t.Fatalf("响应 = %q，隧道未通", body)
			}
			obs := <-ch
			if obs.dst != "example.invalid:80" {
				t.Errorf("CONNECT 目标 = %q", obs.dst)
			}
			if !strings.Contains(obs.httpRequest, "GET /probe") || !strings.Contains(obs.httpRequest, "Host: example.invalid") {
				t.Errorf("隧道内请求 = %q", obs.httpRequest)
			}
			wantAuth := tc.user != ""
			if obs.hadAuth != wantAuth || obs.user != tc.user || obs.pass != tc.pass {
				t.Errorf("userinfo 观测 = (auth=%v user=%q pass=%q), want (%v, %q, %q)",
					obs.hadAuth, obs.user, obs.pass, wantAuth, tc.user, tc.pass)
			}
		})
	}
}

// TestDialerSMTPReuse Dialer 供 SMTP 复用：socks5 返回 ContextDialer；http/https
// 与空串按 §15.4 静默失效返回直连拨号器（不报错、不降级）。
func TestDialerSMTPReuse(t *testing.T) {
	for _, raw := range []string{"", "http://h:8080", "https://h:8443", "socks5://alice:pw@h:1080"} {
		d, err := Dialer(raw)
		if err != nil || d == nil {
			t.Fatalf("Dialer(%q) = (%v, %v)", raw, d, err)
		}
	}
	if _, err := Dialer("ftp://h:21"); !errors.Is(err, ErrUnsupportedScheme) {
		t.Errorf("非法 scheme err = %v", err)
	}
}
