// SMTP 邮件 Sender 实现（docs/后端架构.md §15.2）：stdlib net/smtp，零新
// 第三方依赖。支持隐式 TLS（465）与明文 + STARTTLS（587 等），AUTH PLAIN
// （凭证复用出站代理行同名字段，见下；是否执行以服务器广告的机制为准）。
//
// Ext 字段口径（接口文档 §5.3 email 行，供 /schema 渲染）：
//   - host = SMTP 服务器地址（endpoint 区块，必填）
//   - port = 端口（endpoint；0 → 默认 587；465 = 隐式 TLS，其余明文连接、
//     服务器支持且未关 STARTTLS 时升级）
//   - from = 发件人地址（basic，非必填；留空回落认证账号 user——多数 SMTP
//     服务认证账号即发件邮箱；RFC 5322 From / MAIL FROM）
//   - sign_name = 发件人名称（credential，非必填；非空时 From 头以
//     RFC 2047 encoded-word 展示名 + 地址，信封 MAIL FROM 恒为纯地址）
//   - user / password = SMTP 认证凭证（credential，必填；复用 §12.1 字段
//     44/45——与出站代理行共用 Ext 字段名，语义按渠道独立，同 host/port 先例）
//   - disable_ssl = 内网自签场景跳过 STARTTLS（policy）
//   - metadata["subject."+tpl] = 标题模板（缺省 "验证码"）
//   - metadata["body."+tpl] = 正文模板（缺省 "您的验证码：{code}"），正文
//     中 {key} 占位符按 params 逐项替换（当前验证码链路 tpl="otp"，见
//     provider/sender.go codeTpl；最小实现，多语言归后续 i18n 卡）
//
// template_code 对本厂商无意义，不消费。
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"slices"
	"strings"

	"authloft/internal/provider"
	"authloft/internal/provider/schemafield"
	"authloft/internal/proxyclient"
)

// Type 渠道类型（§15.2 内置清单）。
const Type = "smtp"

// 默认参数。
const (
	// defaultPort Ext.port 为 0 时的端口（587 = 明文 + STARTTLS）。
	defaultPort = 587
	// tlsPort 隐式 TLS 端口（SMTPS，465）。
	tlsPort = 465
	// ehloDomain 客户端 EHLO 标识（固定值，不暴露部署信息）。
	ehloDomain = "authloft"
	// 默认模板（§15.2：模板内容存 metadata 的最小兜底）。
	defaultSubject = "验证码"
	defaultBody    = "您的验证码：{code}"
)

// 可判别错误。
var (
	// ErrNotConfigured Ext 缺必填项（host / user / password）。
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
// metadata 的 Help 是 SMTP 专属语义（按模板键覆盖标题 / 正文）。
func smtpSchema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 15)
	fields = append(fields, schemafield.ProviderKey(), schemafield.DisplayName())
	fields = append(fields,
		provider.FieldMeta{Key: "host", Label: "admin.schemaField.smtpHostLabel", Type: "text", Section: "endpoint", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "port", Label: "admin.schemaField.smtpPortLabel", Type: "number", Section: "endpoint", Default: "587",
			Help: "admin.schemaField.smtpPortHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "user", Label: "admin.schemaField.smtpUserLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "password", Label: "admin.schemaField.smtpPasswordLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "sign_name", Label: "admin.schemaField.smtpSignNameLabel", Type: "text", Section: "credential", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "from", Label: "admin.schemaField.smtpFromLabel", Type: "text", Section: "credential", Help: "admin.schemaField.smtpFromHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "disable_ssl", Label: "admin.schemaField.smtpDisableSslLabel", Type: "checkbox", Section: "policy",
			Help: "admin.schemaField.smtpDisableSslHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "metadata", Label: "admin.schemaField.metadataLabel", Type: "json", Section: "credential", Advanced: true,
			Help: "admin.schemaField.smtpMetadataHelp", Storage: provider.StorageExt},
	)
	fields = append(fields, schemafield.IconURL(), schemafield.SortOrder(), schemafield.Remark())
	// is_enabled / 登录建号开关是 auth 专属：email 行不声明也不消费
	// （渠道生效实例判定只看 settings 键 → 行命中，provider/sender.go）。
	fields = append(fields, schemafield.ProxyRef())
	return fields
}

// Sender SMTP 客户端（装配期固化连接参数与凭证，运行期只发信）。
type Sender struct {
	host        string
	port        int
	from        string // 发件地址（from 留空时回落 user，构造期已定）
	signName    string // 发件人名称（可空；非空时 From 头带 encoded-word 展示名）
	disableSSL  bool
	user        string
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
		signName:   strings.TrimSpace(p.Ext.GetSignName()),
		disableSSL: p.Ext.GetDisableSsl(),
		user:       strings.TrimSpace(p.Ext.GetUser()),
		password:   p.Ext.GetPassword(),
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
	if s.host == "" || s.user == "" || s.password == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	// from 非必填：留空回落认证账号 user（多数 SMTP 服务认证账号即发件邮箱）。
	if s.from == "" {
		s.from = s.user
	}
	if s.port <= 0 {
		s.port = defaultPort
	}
	return s, nil
}

// New 导出构造入口（§15.5 薄封装总则：兄弟子包 import 基座构造器）：供预设
// 端点形态的消息渠道（如 SES SMTP 接口）复用本包取值口径，凭证装配期取自
// Provider 实例、运行期不回读，与注册表工厂行为完全一致。
func New(p *provider.Provider) (*Sender, error) {
	s, err := newSender(p)
	if err != nil {
		return nil, err
	}
	concrete, ok := s.(*Sender)
	if !ok {
		return nil, fmt.Errorf("smtp: unexpected sender type %T", s)
	}
	return concrete, nil
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
	// AUTH PLAIN：凭据必填（构造期已拦缺项），机制可用性以服务器广告为准——
	// 未广告 AUTH 的免认证 relay（内网自建场景）跳过认证，不硬失败。
	if ok, mechs := cl.Extension("AUTH"); ok && slices.Contains(strings.Fields(mechs), "PLAIN") {
		if err := cl.Auth(smtp.PlainAuth("", s.user, s.password, s.host)); err != nil {
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
	if _, err := w.Write(buildMessage(s.fromHeader(), to, subject, body)); err != nil {
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

// render 取模板并替换变量（§15.2 最小实现）。
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

// fromHeader RFC 5322 From 头值：sign_name 非空时为 RFC 2047 encoded-word
// 展示名 + 尖括号地址，否则纯地址。信封 MAIL FROM 恒为纯地址（见 Send）。
func (s *Sender) fromHeader() string {
	if s.signName == "" {
		return s.from
	}
	return mime.QEncoding.Encode("utf-8", s.signName) + " <" + s.from + ">"
}

// buildMessage 组装 RFC 5322 报文（纯文本 UTF-8；from 为 From 头值——含
// 展示名时由 fromHeader 组好；Subject 用 encoded-word，行结束统一 CRLF）。
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
