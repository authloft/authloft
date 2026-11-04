// smtp_test.go：SMTP Sender 单测（本地 net.Listen 假 SMTP 服务器，不打真实
// 外部服务）：完整投递对话（EHLO → MAIL → RCPT → DATA → QUIT）、报文头与
// 模板渲染口径、构造期 Ext 校验。
package smtp

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// testProviderExt 构造 Ext（唯一编解码出口 repo）。
func testProviderExt(t *testing.T, mutate func(*providerpb.Ext)) *providerpb.Ext {
	t.Helper()
	ext := &providerpb.Ext{Host: "127.0.0.1", From: "no-reply@authloft.example.com"}
	if mutate != nil {
		mutate(ext)
	}
	return ext
}

func testProvider(t *testing.T, mutate func(*providerpb.Ext)) *provider.Provider {
	t.Helper()
	ext := testProviderExt(t, mutate)
	raw, err := repo.MarshalProviderExt(ext)
	if err != nil {
		t.Fatalf("marshal ext: %v", err)
	}
	return &provider.Provider{
		Key:  "eml_main",
		Type: Type,
		Row:  &model.Provider{ProviderKey: "eml_main", Type: Type, IsEnabled: 1, Ext: raw},
		Ext:  ext,
	}
}

// TestBuildRequiresHostAndFrom 构造期校验：host / from 缺一即 ErrNotConfigured；
// port 缺省回落 587。
func TestBuildRequiresHostAndFrom(t *testing.T) {
	if _, err := newSender(testProvider(t, func(e *providerpb.Ext) { e.Host = "" })); err == nil ||
		!strings.Contains(err.Error(), "not configured") {
		t.Fatalf("missing host err = %v, want not-configured", err)
	}
	if _, err := newSender(testProvider(t, func(e *providerpb.Ext) { e.From = "" })); err == nil ||
		!strings.Contains(err.Error(), "not configured") {
		t.Fatalf("missing from err = %v, want not-configured", err)
	}
	if _, err := newSender(nil); err != provider.ErrNilProvider {
		t.Fatalf("nil provider err = %v", err)
	}
	s, err := newSender(testProvider(t, nil))
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}
	if s.(*Sender).port != defaultPort {
		t.Fatalf("default port = %d, want %d", s.(*Sender).port, defaultPort)
	}
}

// TestRenderTemplates 模板口径（§15.2 行 1725：模板内容存 metadata）：
// metadata 按模板键取标题 / 正文；{code} 占位符替换；缺省回落默认文案。
func TestRenderTemplates(t *testing.T) {
	s := &Sender{
		subjects: map[string]string{"otp": "Authloft 登录验证码"},
		bodies:   map[string]string{"otp": "code={code} ttl=300"},
	}
	subject, body := s.render("otp", map[string]string{"code": "246810"})
	if subject != "Authloft 登录验证码" {
		t.Fatalf("subject = %q", subject)
	}
	if body != "code=246810 ttl=300" {
		t.Fatalf("body = %q, want placeholder substituted", body)
	}

	// 缺省模板回落默认文案。
	bare := &Sender{}
	subject, body = bare.render("otp", map[string]string{"code": "123456"})
	if subject != defaultSubject || body != "您的验证码：123456" {
		t.Fatalf("default render = %q / %q", subject, body)
	}
}

// TestBuildMessageHeaderShape 报文形态：From / To / Subject encoded-word /
// MIME 头逐项断言，行结束 CRLF。
func TestBuildMessageHeaderShape(t *testing.T) {
	msg := string(buildMessage("a@x.example", "b@y.example", "验证码主题", "正文一行"))
	for _, want := range []string{
		"From: a@x.example\r\n",
		"To: b@y.example\r\n",
		"MIME-Version: 1.0\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n",
		"Content-Transfer-Encoding: 8bit\r\n",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
	if !strings.Contains(msg, "Subject: =?utf-8?") {
		t.Errorf("Subject must be RFC 2047 encoded-word:\n%s", msg)
	}
	if strings.Contains(msg, "\n") && !strings.Contains(msg, "\r\n") {
		t.Error("message must use CRLF line endings")
	}
}

// smtpCapture 假服务器捕获的一次投递。
type smtpCapture struct {
	mailFrom string
	rcptTo   string
	data     string
}

// fakeSMTPServer 起一个最小对话 SMTP 假服务器（无 TLS / 无 AUTH 广告），
// 返回监听地址；会话结束后向返回的 channel 投递捕获内容。
func fakeSMTPServer(t *testing.T) (addr string, captured chan smtpCapture) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	captured = make(chan smtpCapture, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		r := bufio.NewReader(conn)
		write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		readLine := func() string {
			line, _ := r.ReadString('\n')
			return strings.TrimRight(line, "\r\n")
		}

		var got smtpCapture
		write("220 test ESMTP ready")
		for {
			line := readLine()
			if line == "" {
				captured <- got
				return
			}
			cmd := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				write("250-test ESMTP")
				write("250 OK")
			case strings.HasPrefix(cmd, "MAIL FROM:"):
				got.mailFrom = strings.TrimSuffix(strings.TrimPrefix(line[10:], "<"), ">")
				write("250 ok")
			case strings.HasPrefix(cmd, "RCPT TO:"):
				got.rcptTo = strings.TrimSuffix(strings.TrimPrefix(line[8:], "<"), ">")
				write("250 ok")
			case strings.HasPrefix(cmd, "DATA"):
				write("354 end with <CRLF>.<CRLF>")
				for {
					chunk := readLine()
					if chunk == "." {
						break
					}
					got.data += chunk + "\n"
				}
				write("250 ok")
			case strings.HasPrefix(cmd, "QUIT"):
				write("221 bye")
				captured <- got
				return
			default:
				write("250 ok")
			}
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	return "127.0.0.1:" + portStr, captured
}

// TestSendFullDialogAgainstFakeServer 端到端：Send 走完整 SMTP 对话（EHLO →
// MAIL → RCPT → DATA → QUIT）；报文含 From/To/Subject 与替换后的验证码。
func TestSendFullDialogAgainstFakeServer(t *testing.T) {
	addr, captured := fakeSMTPServer(t)
	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	s, err := newSender(testProvider(t, func(e *providerpb.Ext) {
		e.Host = "127.0.0.1"
		e.Port = int32(port)
		e.Metadata = map[string]string{
			"subject.otp": "Authloft 验证码",
			"body.otp":    "您的验证码：{code}（5 分钟内有效）",
		}
	}))
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}
	if err := s.Send(context.Background(), "alice@example.com", "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case got := <-captured:
		if got.mailFrom != "no-reply@authloft.example.com" {
			t.Errorf("MAIL FROM = %q", got.mailFrom)
		}
		if got.rcptTo != "alice@example.com" {
			t.Errorf("RCPT TO = %q", got.rcptTo)
		}
		if !strings.Contains(got.data, "Subject: =?utf-8?") {
			t.Errorf("DATA missing encoded subject: %q", got.data)
		}
		if !strings.Contains(got.data, "您的验证码：246810（5 分钟内有效）") {
			t.Errorf("DATA missing substituted body: %q", got.data)
		}
		if !strings.Contains(got.data, "From: no-reply@authloft.example.com") ||
			!strings.Contains(got.data, "To: alice@example.com") {
			t.Errorf("DATA missing From/To headers: %q", got.data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake SMTP server did not capture a session")
	}
}

// TestSendValidation 收件人为空 → 明确错误，不起连接。
func TestSendValidation(t *testing.T) {
	s, err := newSender(testProvider(t, nil))
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}
	if err := s.Send(context.Background(), "", "otp", map[string]string{"code": "1"}); err != ErrEmptyTo {
		t.Fatalf("empty to err = %v, want ErrEmptyTo", err)
	}
	// 端口不可达 → 连接错误上抛（不吞错）。
	s2, err := newSender(testProvider(t, func(e *providerpb.Ext) {
		e.Host = "127.0.0.1"
		e.Port = 1
	}))
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}
	if err := s2.Send(context.Background(), "a@example.com", "otp", map[string]string{"code": "1"}); err == nil {
		t.Fatal("Send to unreachable port must fail")
	}
}

// TestInitRegistersAsEmailVendor init() 已按 §15.3 注册（category=email）。
func TestInitRegistersAsEmailVendor(t *testing.T) {
	meta, ok := provider.LookupSenderMeta(Type)
	if !ok {
		t.Fatal("smtp not registered in sender registry")
	}
	if meta.Category != provider.CategoryEmail {
		t.Fatalf("category = %q, want email", meta.Category)
	}
	var hasHost, hasPort, hasMetadata bool
	for _, f := range meta.Fields {
		switch f.Key {
		case "host":
			hasHost = f.Section == "endpoint" && f.Required
		case "port":
			hasPort = f.Section == "endpoint"
		case "metadata":
			hasMetadata = f.Section == "credential"
		}
	}
	if !hasHost || !hasPort || !hasMetadata {
		t.Fatalf("meta.Fields incomplete for /schema: host=%v port=%v metadata=%v", hasHost, hasPort, hasMetadata)
	}
}

// selfSignedCert 生成自签测试证书（IP SAN=127.0.0.1），返回证书与含该证书
// 的信任池（测试侧客户端 tls.Client 用 RootCAs 信任它；生产 dial/StartTLS
// 走系统根池，严格验证不放宽——见 TestDial465UsesTLSAndVerifies）。
func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// smtpSession TLS / AUTH 分支 fake server 捕获的一次会话。
type smtpSession struct {
	events   []string // 命令时序；«TLS» = STARTTLS 升级完成标记
	authLine string   // AUTH 命令原文（未出现为空）
	mailFrom string
	rcptTo   string
	data     string
}

// tlsAuthFakeSMTPServer 可配置 fake SMTP server（本地 listener，单会话）：
//   - implicitTLS：listener 即 TLS（465 隐式 TLS 形态，需 cert）
//   - advertiseStartTLS：明文 listener，EHLO 声明 STARTTLS，收到该命令后
//     原地升级（587 形态，需 cert）
//   - advertiseAuth：EHLO 声明 AUTH PLAIN
//
// 会话结束把捕获投进 channel。
func tlsAuthFakeSMTPServer(t *testing.T, cert *tls.Certificate, advertiseStartTLS, advertiseAuth, implicitTLS bool) (addr string, captured chan smtpSession) {
	t.Helper()
	if (advertiseStartTLS || implicitTLS) && cert == nil {
		t.Fatal("TLS requested but no certificate provided")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if implicitTLS {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{*cert}})
	}
	captured = make(chan smtpSession, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		starttlsAdvertised := advertiseStartTLS
		r := bufio.NewReader(conn)
		write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		readLine := func() string {
			line, _ := r.ReadString('\n')
			return strings.TrimRight(line, "\r\n")
		}

		var got smtpSession
		write("220 test ESMTP ready")
		for {
			line := readLine()
			if line == "" {
				captured <- got
				return
			}
			cmd := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				write("250-test ESMTP")
				if starttlsAdvertised {
					write("250-STARTTLS")
				}
				if advertiseAuth {
					write("250-AUTH PLAIN")
				}
				write("250 OK")
				got.events = append(got.events, "EHLO")
			case strings.HasPrefix(cmd, "STARTTLS"):
				if !starttlsAdvertised {
					write("500 STARTTLS not available")
					continue
				}
				write("220 Go ahead")
				got.events = append(got.events, "STARTTLS")
				tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{*cert}})
				if err := tlsConn.Handshake(); err != nil {
					captured <- got
					return
				}
				conn = tlsConn
				r = bufio.NewReader(conn)
				starttlsAdvertised = false // RFC 3207：升级后不再声明
				got.events = append(got.events, "«TLS»")
			case strings.HasPrefix(cmd, "AUTH"):
				got.authLine = line
				got.events = append(got.events, "AUTH")
				write("235 ok")
			case strings.HasPrefix(cmd, "MAIL FROM:"):
				got.mailFrom = strings.TrimSuffix(strings.TrimPrefix(line[10:], "<"), ">")
				got.events = append(got.events, "MAIL")
				write("250 ok")
			case strings.HasPrefix(cmd, "RCPT TO:"):
				got.rcptTo = strings.TrimSuffix(strings.TrimPrefix(line[8:], "<"), ">")
				got.events = append(got.events, "RCPT")
				write("250 ok")
			case strings.HasPrefix(cmd, "DATA"):
				got.events = append(got.events, "DATA")
				write("354 end with <CRLF>.<CRLF>")
				for {
					chunk := readLine()
					if chunk == "." {
						break
					}
					got.data += chunk + "\n"
				}
				write("250 ok")
			case strings.HasPrefix(cmd, "QUIT"):
				got.events = append(got.events, "QUIT")
				write("221 bye")
				captured <- got
				return
			default:
				write("500 unknown command")
			}
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	return "127.0.0.1:" + portStr, captured
}

// TestSendImplicitTLS465 465 隐式 TLS 分支：port=465 时 Send 全程在 TLS
// 通道且不发 STARTTLS 协商。生产的 s.dial 用 tls.Dialer 且严格走系统根池
// 验证（见 TestDial465UsesTLSAndVerifies），无法信任测试自签证书，故此处
// 注入 dialContext，由测试侧完成到 fake TLS listener 的 TLS 握手
// （RootCAs=自签证书池），会话层分支被完整覆盖。
func TestSendImplicitTLS465(t *testing.T) {
	cert, pool := selfSignedCert(t)
	addr, captured := tlsAuthFakeSMTPServer(t, &cert, false, false, true)

	s, err := newSender(testProvider(t, func(e *providerpb.Ext) {
		e.Host = "127.0.0.1"
		e.Port = tlsPort
	}))
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}
	sender := s.(*Sender)
	sender.dialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		raw, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, &tls.Config{ServerName: "127.0.0.1", RootCAs: pool})
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return tc, nil
	}
	if err := sender.Send(context.Background(), "tls465@example.com", "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case got := <-captured:
		if got.mailFrom != "no-reply@authloft.example.com" || got.rcptTo != "tls465@example.com" {
			t.Errorf("MAIL FROM = %q, RCPT TO = %q", got.mailFrom, got.rcptTo)
		}
		for _, ev := range got.events {
			if ev == "STARTTLS" {
				t.Error("implicit TLS (465) must not negotiate STARTTLS")
			}
		}
		if !strings.Contains(got.data, "您的验证码：246810") {
			t.Errorf("DATA missing substituted body: %q", got.data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake TLS SMTP server did not capture a session")
	}
}

// TestDial465UsesTLSAndVerifies 生产 dial 的 465 分支必须走 TLS 且对服务器
// 证书做严格验证：连自签证书 listener 应得到 unknown-authority 错误——
// 若改回明文拨号或放宽验证（InsecureSkipVerify），此断言即红。
func TestDial465UsesTLSAndVerifies(t *testing.T) {
	cert, _ := selfSignedCert(t)
	addr, _ := tlsAuthFakeSMTPServer(t, &cert, false, false, true)
	s := &Sender{host: "127.0.0.1", port: tlsPort}
	_, err := s.dial(context.Background(), "tcp", addr)
	var ua x509.UnknownAuthorityError
	if err == nil || !errors.As(err, &ua) {
		t.Fatalf("465 dial must TLS-dial with strict cert verification: err = %v", err)
	}
}

// TestSendStartTLSUpgrade 明文 + STARTTLS 分支：服务器声明 STARTTLS 时客户端
// 必须主动发起升级，且升级失败即中止——MAIL/RCPT/DATA 不得在升级完成前
// 明文上线。实现的 StartTLS 配置写死 ServerName=host、根池走系统信任
// （严格验证），测试自签证书进不了信任链，升级后对话无法在纯 fake 环境
// 完整走通，故覆盖到能到达的最深层：①明文段确实发出 STARTTLS；
// ②升级握手对不可信证书拒绝（防 InsecureSkipVerify 回归）；
// ③升级失败后 MAIL/RCPT/DATA 一律不发出（凭据与信件不得明文上线）。
func TestSendStartTLSUpgrade(t *testing.T) {
	cert, _ := selfSignedCert(t)
	addr, captured := tlsAuthFakeSMTPServer(t, &cert, true, false, false)
	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	s, err := newSender(testProvider(t, func(e *providerpb.Ext) {
		e.Host = "127.0.0.1"
		e.Port = int32(port)
	}))
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}
	err = s.Send(context.Background(), "starttls@example.com", "otp", map[string]string{"code": "135790"})
	if err == nil || !strings.Contains(err.Error(), "starttls") {
		t.Fatalf("Send err = %v, want STARTTLS handshake failure surfaced", err)
	}

	select {
	case got := <-captured:
		hasStartTLS := false
		for _, ev := range got.events {
			switch ev {
			case "STARTTLS":
				hasStartTLS = true
			case "MAIL", "RCPT", "DATA":
				t.Errorf("command %q leaked onto plaintext connection before TLS upgrade: %v", ev, got.events)
			}
		}
		if !hasStartTLS {
			t.Fatalf("client must issue STARTTLS when server advertises it: %v", got.events)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake SMTP server did not capture a session")
	}
}

// TestSendAuthPlainCredentials AUTH PLAIN 分支：凭据以 RFC 4616 初始响应
// 形态上线（AUTH PLAIN base64(\x00user\x00pass)），且 AUTH 在 MAIL FROM
// 之前完成。host=127.0.0.1 属 stdlib isLocalhost 豁免，明文连接可测。
func TestSendAuthPlainCredentials(t *testing.T) {
	addr, captured := tlsAuthFakeSMTPServer(t, nil, false, true, false)
	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	s, err := newSender(testProvider(t, func(e *providerpb.Ext) {
		e.Host = "127.0.0.1"
		e.Port = int32(port)
		e.Metadata = map[string]string{"username": "otp-user", "password": "otp-pass"}
	}))
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}
	if err := s.Send(context.Background(), "auth@example.com", "otp", map[string]string{"code": "975310"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case got := <-captured:
		want := "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00otp-user\x00otp-pass"))
		if got.authLine != want {
			t.Errorf("AUTH line = %q, want %q", got.authLine, want)
		}
		authAt, mailAt := -1, -1
		for i, ev := range got.events {
			switch ev {
			case "AUTH":
				authAt = i
			case "MAIL":
				mailAt = i
			}
		}
		if authAt < 0 || mailAt < authAt {
			t.Errorf("AUTH must complete before MAIL FROM: %v", got.events)
		}
		if got.rcptTo != "auth@example.com" {
			t.Errorf("RCPT TO = %q", got.rcptTo)
		}
		if !strings.Contains(got.data, "您的验证码：975310") {
			t.Errorf("DATA missing substituted body: %q", got.data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake SMTP server did not capture a session")
	}
}
