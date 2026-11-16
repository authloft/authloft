// SMTP 邮件 Sender 实现（docs/后端架构.md §15.2 行 1724、§3.9 行 417）：
// stdlib net/smtp，零新第三方依赖。支持隐式 TLS（465）与明文 + STARTTLS
// （587 等），AUTH PLAIN 可选。
//
// Ext 字段口径（接口文档 §5.3 行 1236 email 追加字段，供 /schema 渲染）：
//   - host = SMTP 服务器地址（endpoint 区块，必填）
//   - port = 端口（endpoint；0 → 默认 587；465 = 隐式 TLS，其余明文连接、
//     服务器支持且未关 STARTTLS 时升级）
//   - from = 发件人地址（basic，必填；RFC 5322 From / MAIL FROM）
//   - disable_ssl = 内网自签场景跳过 STARTTLS（policy）
//   - metadata["username"] / metadata["password"] = SMTP 认证凭证
//   - metadata["subject."+tpl] = 标题模板（缺省 "验证码"）
//   - metadata["body."+tpl] = 正文模板（缺省 "您的验证码：{code}"），正文
//     中 {key} 占位符按 params 逐项替换（当前验证码链路 tpl="otp"，见
//     provider/sender.go codeTpl；§15.2 行 1725 最小实现，多语言归后续 i18n 卡）
//
// sign_name / template_code 对本厂商无意义，不消费。
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"

	"authloft/internal/provider"
	"authloft/internal/provider/schemafield"
	"authloft/internal/proxyclient"
)

// Type 渠道类型（§15.2 行 1724 内置清单）。
const Type = "smtp"

// 默认参数。
const (
	// defaultPort Ext.port 为 0 时的端口（587 = 明文 + STARTTLS）。
	defaultPort = 587
	// tlsPort 隐式 TLS 端口（SMTPS，465）。
	tlsPort = 465
	// ehloDomain 客户端 EHLO 标识（固定值，不暴露部署信息）。
	ehloDomain = "authloft"
	// 默认模板（§15.2 行 1725：模板内容存 metadata 的最小兜底）。
	defaultSubject = "验证码"
	defaultBody    = "您的验证码：{code}"
)

// 可判别错误。
var (
	// ErrNotConfigured Ext 缺必填项（host / from）。
	ErrNotConfigured = errors.New("smtp: provider not configured")
	// ErrEmptyTo 收件地址为空。
	ErrEmptyTo = errors.New("smtp: empty recipient")
)

func init() {
	provider.RegisterSender(Type, provider.SenderMeta{
		Type:        Type,
		DisplayName: "SMTP（通用）",
		Category:    provider.CategoryEmail,
		Schema:      smtpSchema,
	}, newSender)
}

// smtpSchema /schema 唯一数据源：完整字段声明（表列 + Ext，接口文档 §5.3），
// 属性与 wire 输出逐字段一致；Ext 部分就地声明而非复用 schemafield.Metadata——
// metadata 的 Help 是 SMTP 专属语义（认证凭证 + 按模板键覆盖标题 / 正文）。
func smtpSchema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 13)
	fields = append(fields, schemafield.ProviderKey(), schemafield.DisplayName())
	fields = append(fields,
		provider.FieldMeta{Key: "host", Label: "admin.schemaField.smtpHostLabel", Type: "text", Section: "endpoint", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "port", Label: "admin.schemaField.smtpPortLabel", Type: "number", Section: "endpoint", Default: "587",
			Help: "admin.schemaField.smtpPortHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "from", Label: "admin.schemaField.smtpFromLabel", Type: "text", Section: "basic", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "disable_ssl", Label: "admin.schemaField.smtpDisableSslLabel", Type: "checkbox", Section: "policy",
			Help: "admin.schemaField.smtpDisableSslHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "metadata", Label: "admin.schemaField.metadataLabel", Type: "json", Section: "credential", Advanced: true,
			Help: "admin.schemaField.smtpMetadataHelp", Storage: provider.StorageExt},
	)
	fields = append(fields, schemafield.IconURL(), schemafield.UiGroup(), schemafield.SortOrder(), schemafield.Remark())
	// email 类别只下发 is_enabled：登录 / 建号 / 自动绑定开关是 oauth 专属。
	for _, f := range schemafield.EnableFlags() {
		if f.Key == "is_enabled" {
			fields = append(fields, f)
		}
	}
	fields = append(fields, schemafield.ProxyRef())
	return fields
}

// Sender SMTP 客户端（装配期固化连接参数与凭证，运行期只发信）。
type Sender struct {
	host        string
	port        int
	from        string
	disableSSL  bool
	username    string
	password    string
	subjects    map[string]string                                                 // metadata["subject."+tpl]
	bodies      map[string]string                                                 // metadata["body."+tpl]
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error) // 测试注入（优先）
	proxyDial   proxyclient.ContextDialer                                         // 构造期固化；仅 socks5 生效
}

// newSender 注册表工厂：从 Provider 实例取 Ext 构造客户端。
func newSender(p *provider.Provider) (provider.Sender, error) {
	if p == nil || p.Ext == nil {
		return nil, provider.ErrNilProvider
	}
	meta := p.Ext.GetMetadata()
	s := &Sender{
		host:       strings.TrimSpace(p.Ext.GetHost()),
		port:       int(p.Ext.GetPort()),
		from:       strings.TrimSpace(p.Ext.GetFrom()),
		disableSSL: p.Ext.GetDisableSsl(),
		username:   meta["username"],
		password:   meta["password"],
	}
	// 构造期固化代理拨号器：Outbound 非 nil 时按池的 scheme 分流（仅 socks5
	// 生效；http/https 由池静默按直连拨号，§15.4）；nil（proxy_provider_key
	// 空 = 直连）沿用直连拨号器。引用不可解析在 Loader 装配期已 fail，本层
	// 无代理失败路径。
	s.proxyDial = &net.Dialer{}
	if p.Outbound != nil {
		s.proxyDial = p.Outbound.Dialer()
	}
	for k, v := range meta {
		if tpl, ok := strings.CutPrefix(k, "subject."); ok {
			if s.subjects == nil {
				s.subjects = map[string]string{}
			}
			s.subjects[tpl] = v
		}
		if tpl, ok := strings.CutPrefix(k, "body."); ok {
			if s.bodies == nil {
				s.bodies = map[string]string{}
			}
			s.bodies[tpl] = v
		}
	}
	if s.host == "" || s.from == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	if s.port <= 0 {
		s.port = defaultPort
	}
	return s, nil
}

// Send 投递一封纯文本邮件（to=收件地址，tpl=模板键，params=模板变量）。
func (s *Sender) Send(ctx context.Context, to string, tpl string, params map[string]string) error {
	if to == "" {
		return ErrEmptyTo
	}
	subject, body := s.render(tpl, params)

	dial := s.dialContext
	if dial == nil {
		dial = s.dial
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(s.host, fmt.Sprintf("%d", s.port)))
	if err != nil {
		return fmt.Errorf("smtp: dial %s: %w", s.host, err)
	}
	defer conn.Close()

	cl, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("smtp: handshake: %w", err)
	}
	if err := cl.Hello(ehloDomain); err != nil {
		return fmt.Errorf("smtp: ehlo: %w", err)
	}
	if s.port != tlsPort && !s.disableSSL {
		if ok, _ := cl.Extension("STARTTLS"); ok {
			if err := cl.StartTLS(&tls.Config{ServerName: s.host}); err != nil {
				return fmt.Errorf("smtp: starttls: %w", err)
			}
		}
	}
	if s.username != "" {
		if err := cl.Auth(smtp.PlainAuth("", s.username, s.password, s.host)); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
	if err := cl.Mail(s.from); err != nil {
		return fmt.Errorf("smtp: mail from: %w", err)
	}
	if err := cl.Rcpt(to); err != nil {
		return fmt.Errorf("smtp: rcpt to: %w", err)
	}
	w, err := cl.Data()
	if err != nil {
		return fmt.Errorf("smtp: data: %w", err)
	}
	if _, err := w.Write(buildMessage(s.from, to, subject, body)); err != nil {
		return fmt.Errorf("smtp: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: close body: %w", err)
	}
	return cl.Quit()
}

// dial 生产连接：底层用构造期固化的代理拨号器（socks5 生效，http/https 与
// 空串静默直连）；465 在拨号后包一层隐式 TLS（ServerName=host、严格验证），
// 其余明文，STARTTLS 由扩展协商。测试注入的 dialContext 优先（见 Send）。
func (s *Sender) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := s.proxyDial
	if d == nil {
		d = &net.Dialer{}
	}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if s.port == tlsPort {
		tc := tls.Client(raw, &tls.Config{ServerName: s.host})
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return tc, nil
	}
	return raw, nil
}

// render 取模板并替换变量（§15.2 行 1725 最小实现）。
func (s *Sender) render(tpl string, params map[string]string) (subject, body string) {
	subject = defaultSubject
	body = defaultBody
	if v, ok := s.subjects[tpl]; ok && v != "" {
		subject = v
	}
	if v, ok := s.bodies[tpl]; ok && v != "" {
		body = v
	}
	for k, val := range params {
		body = strings.ReplaceAll(body, "{"+k+"}", val)
	}
	return subject, body
}

// buildMessage 组装 RFC 5322 报文（纯文本 UTF-8；Subject 用 encoded-word，
// 行结束统一 CRLF）。
func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	if !strings.HasSuffix(body, "\n") {
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}
