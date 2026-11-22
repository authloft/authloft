// aws_ses_test.go：aws_ses 薄封装单测（本地 net.Listen 假 SMTP 服务器，不打
// 真实外部服务，mock 口径同 smtp 基座测试）：Schema 收窄（固化项不透出、
// from 必填）、构造期委托 smtp 基座（fail-closed 同口径、返回具体类型即基座
// Sender）、完整投递对话中 SES SMTP 凭证走 AUTH PLAIN。
package awsses

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/email/smtp"
	"authloft/internal/provider/schemafield"
)

// testSESProvider 构造测试 Provider 实例：user / password 取 SES SMTP 凭证
// 形态（非 IAM AccessKey 语义由 schema help 键声明），from 为已验证发件地址。
func testSESProvider(mutate func(*providerpb.Ext)) *provider.Provider {
	ext := &providerpb.Ext{
		Host:     "127.0.0.1",
		User:     "ses-smtp-user",
		Password: "ses-smtp-pass",
		From:     "no-reply@authloft.example.com",
	}
	if mutate != nil {
		mutate(ext)
	}
	return &provider.Provider{Key: "eml_ses", Type: Type, Ext: ext}
}

// TestSchemaNarrowsPlanAFields 注册表与 Schema 收窄口径：category=email；
// host / user / password / from 必填（from 为已验证发件地址，基座留空回落
// 认证 user 的语义对 SES 不成立）；password 为 secret；port / disable_ssl
// 等固化项不声明（表单透出即制造死字段）；引用键声明与单一来源零漂移。
func TestSchemaNarrowsPlanAFields(t *testing.T) {
	meta, ok := provider.LookupSenderMeta(Type)
	if !ok {
		t.Fatal("aws_ses not registered in sender registry")
	}
	if meta.Category != provider.CategoryEmail {
		t.Fatalf("category = %q, want %q", meta.Category, provider.CategoryEmail)
	}
	if meta.DisplayName != "Amazon SES" {
		t.Fatalf("display name = %q, want Amazon SES", meta.DisplayName)
	}
	schema := meta.Schema()
	if len(schema) == 0 {
		t.Fatal("meta.Schema() must declare full field schema for /schema")
	}
	byKey := make(map[string]provider.FieldMeta, len(schema))
	for _, f := range schema {
		byKey[f.Key] = f
	}
	// 方案 A 字段表：host（endpoint）/ user / password / from 必填，password
	// secret；SES 专属凭证语义（非 IAM AccessKey）与端点形态以可证伪的 AUTH
	// PLAIN / MAIL FROM 断言落在发送链路测试（help 文案归 web 字典，见实现注释）。
	for key, want := range map[string]struct {
		section  string
		required bool
	}{
		"host":     {"endpoint", true},
		"user":     {"credential", true},
		"password": {"credential", true},
		"from":     {"credential", true},
	} {
		f, ok := byKey[key]
		if !ok {
			t.Errorf("schema missing %q", key)
			continue
		}
		if f.Section != want.section || f.Required != want.required {
			t.Errorf("%s = section/%q required/%v, want section/%q required/%v", key, f.Section, f.Required, want.section, want.required)
		}
		if f.Storage != provider.StorageExt {
			t.Errorf("%s storage = %q, want ext", key, f.Storage)
		}
	}
	if byKey["password"].Type != "secret" {
		t.Errorf("password type = %q, want secret", byKey["password"].Type)
	}
	// sign_name / metadata 可选（同 smtp 行口径）。
	if f, present := byKey["sign_name"]; !present || f.Required || f.Section != "credential" {
		t.Errorf("sign_name = %+v, want optional credential field", f)
	}
	if f := byKey["metadata"]; f.Type != "json" || !f.Advanced || f.Section != "credential" {
		t.Errorf("metadata = %+v, want advanced json credential field", f)
	}
	// 固化项不透出：port（基座默认 587 STARTTLS）与 disable_ssl（保持 false）
	// 不进 Schema；其余无意义键同样不声明。
	for _, key := range []string{"port", "disable_ssl", "template_code", "client_id", "client_secret", "region"} {
		if _, ok := byKey[key]; ok {
			t.Errorf("schema must not declare %q（固化项 / 无意义键不透出）", key)
		}
	}
	// 引用键声明 = schemafield.ProxyRef() 原样（单一来源零漂移）。
	ref, hasRef := byKey[provider.ProxyRefKey]
	if !hasRef {
		t.Fatalf("schema missing proxy ref %q", provider.ProxyRefKey)
	}
	if !reflect.DeepEqual(ref, schemafield.ProxyRef()) {
		t.Errorf("proxy ref drift: %+v, want %+v", ref, schemafield.ProxyRef())
	}
}

// TestNewDelegatesToBaseConstructor 构造期整体委托 smtp 基座：nil / 缺必填
// 项的 fail-closed 判定与基座同口径；返回具体类型即 *smtp.Sender（发送链路
// 零重写的可证伪形态）。
func TestNewDelegatesToBaseConstructor(t *testing.T) {
	if _, err := newSender(nil); !errors.Is(err, provider.ErrNilProvider) {
		t.Fatalf("nil provider err = %v, want ErrNilProvider（基座口径）", err)
	}
	for _, mutate := range []func(*providerpb.Ext){
		func(e *providerpb.Ext) { e.Host = "" },
		func(e *providerpb.Ext) { e.User = "" },
		func(e *providerpb.Ext) { e.Password = "" },
	} {
		if _, err := newSender(testSESProvider(mutate)); err == nil ||
			!strings.Contains(err.Error(), "not configured") {
			t.Fatalf("missing required field err = %v, want 基座 not-configured fail-closed", err)
		}
	}
	s, err := newSender(testSESProvider(nil))
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}
	if _, ok := s.(*smtp.Sender); !ok {
		t.Fatalf("sender = %T, want *smtp.Sender（委托基座，不重写发送链路）", s)
	}
}

// sesCapture 假服务器捕获的一次投递。
type sesCapture struct {
	authLine string
	mailFrom string
	rcptTo   string
	data     string
}

// fakeSESSMTPServer 最小对话假服务器（明文 listener，EHLO 声明 AUTH PLAIN，
// host=127.0.0.1 属 stdlib isLocalhost 豁免可明文认证），返回监听地址；会话
// 结束向 channel 投递捕获内容。mock 口径同 smtp 基座测试。
func fakeSESSMTPServer(t *testing.T) (addr string, captured chan sesCapture) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	captured = make(chan sesCapture, 1)

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

		var got sesCapture
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
				write("250-AUTH PLAIN")
				write("250 OK")
			case strings.HasPrefix(cmd, "AUTH"):
				got.authLine = line
				write("235 ok")
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

// TestSendFullDialogWithSESCredentials 端到端委托：Send 经基座走完整 SMTP
// 对话，SES SMTP 凭证（user / password）以 RFC 4616 初始响应上线 AUTH PLAIN，
// MAIL FROM 为已验证发件地址，正文 {code} 替换生效。
func TestSendFullDialogWithSESCredentials(t *testing.T) {
	addr, captured := fakeSESSMTPServer(t)
	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	// 生产表单不透出 port（固化基座默认 587）；测试指向本地假服务器须显式
	// 填 Port，委托链路与生产同径（默认回落行为由基座测试覆盖）。
	s, err := newSender(testSESProvider(func(e *providerpb.Ext) {
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
		want := "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00ses-smtp-user\x00ses-smtp-pass"))
		if got.authLine != want {
			t.Errorf("AUTH line = %q, want %q（SES SMTP 凭证而非 IAM AccessKey）", got.authLine, want)
		}
		if got.mailFrom != "no-reply@authloft.example.com" {
			t.Errorf("MAIL FROM = %q, want 已验证发件地址", got.mailFrom)
		}
		if got.rcptTo != "alice@example.com" {
			t.Errorf("RCPT TO = %q", got.rcptTo)
		}
		if !strings.Contains(got.data, "您的验证码：246810（5 分钟内有效）") {
			t.Errorf("DATA missing substituted body: %q", got.data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake SMTP server did not capture a session")
	}
}
