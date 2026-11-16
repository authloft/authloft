// 池构造出站流量的端到端实证（后端架构 §15.4）：本地 http 代理桩与最小
// SOCKS5 握手桩证明经 Pool.HTTPClient 取得的 client 流量真实过代理（http/https
// 与 socks5 两类 Transport 接线均覆盖）。config / pool 的结构性断言见
// config_test.go / pool_test.go。
package proxyclient

import (
	"bufio"
	"encoding/binary"
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

// TestPoolHTTPProxyCarriesTraffic 本地 http 代理桩实证流量经代理：目标
// example.invalid 不可解析，唯有经代理桩才可能拿到桩的响应，证伪性强。
func TestPoolHTTPProxyCarriesTraffic(t *testing.T) {
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
	portNum, _ := strconv.Atoi(u.Port())
	cfg, err := NewConfig("http", u.Hostname(), int32(portNum), "", "")
	if err != nil {
		t.Fatal(err)
	}
	cl := NewPoolSet().Get("k", cfg).HTTPClient(3 * time.Second)

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

// TestPoolSOCKS5Handshake socks5 最小握手桩实证：带 / 不带 userinfo 两条分支
// 分别走 no-auth 与 user/pass 子协商，CONNECT 目标与隧道内 HTTP 请求均被桩
// 观测，证明池化 client 的流量经 socks5 代理而非直连。
func TestPoolSOCKS5Handshake(t *testing.T) {
	for _, tc := range []struct {
		name, user, pass string
	}{
		{"无凭据", "", ""},
		{"带 userinfo", "alice", "s3cr3t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, ch, cleanup := socks5Stub(t)
			defer cleanup()
			host, port := splitAddr(addr)
			cfg, err := NewConfig("socks5", host, port, tc.user, tc.pass)
			if err != nil {
				t.Fatal(err)
			}
			cl := NewPoolSet().Get(tc.name, cfg).HTTPClient(3 * time.Second)
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
