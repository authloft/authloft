// SendGrid 邮件 Sender（Mail Send REST v3）薄实现（docs/后端架构.md §15.5）：
// stdlib net/http + encoding/json 直连 JSON API，Bearer API Key 鉴权，零新
// 第三方依赖。请求 / 响应形态以 SendGrid 公开 API（POST /v3/mail/send，
// 成功 HTTP 202）为准。
//
// Ext 字段口径（接口文档 §12.1 编号 59-60 + 复用键，供 /schema 渲染）：
//   - client_secret     = API Key（credential，必填；Bearer 令牌，建议只授
//     Mail Send 权限）
//   - from              = 发件地址 from.email（credential，必填；须为已验证
//     发件人或已认证域名，地址不支持 Unicode）
//   - sign_name         = 发件人显示名 from.name（credential，可选）
//   - template_code     = 动态模板 ID（credential，可选；仅 "d-" 前缀走动态
//     模板轨，其余取值视同无模板）
//   - reply_to          = 回复地址 reply_to.email（endpoint，可选）
//   - sandbox_mode      = mail_settings.sandbox_mode.enable（policy，可选
//     checkbox；true = 厂商返回成功但不真发，联调用）
//   - intranet_endpoint = 覆盖 base URL（endpoint 区块；欧盟区填
//     https://api.eu.sendgrid.com），缺省 https://api.sendgrid.com；仅覆盖
//     基址，路径 /v3/mail/send 固化
//   - metadata["subject."+tpl] / ["body."+tpl] = 无模板时的本地渲染模板
//     （同 smtp / aliyun_dm：{key} 占位在 Send 期替换，tpl 当前为 "otp"）
//
// 模板双轨："d-" 前缀 → params 原样作 personalizations.dynamic_template_data
// （Handlebars {{key}} 引用，值不做本地转义，输出编码由模板侧决定）；非
// "d-"（含空）→ 回落 metadata subject/body 本地渲染，不发 template_id。
// client_id / host / port / user / password / disable_ssl 对本厂商无意义
// （REST 非 SMTP），不声明不消费。
package sendgrid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"

	"authloft/internal/provider"
	"authloft/internal/provider/schemafield"
)

// Type 渠道类型（§15.2 内置清单）。
const Type = "sendgrid"

// 默认参数。
const (
	// defaultBaseURL 公网 API 基址（Ext.intranet_endpoint 存在时优先覆盖）。
	defaultBaseURL = "https://api.sendgrid.com"
	// mailSendPath Mail Send 端点路径（基址覆盖不改路径）。
	mailSendPath = "/v3/mail/send"
	// dynamicTemplatePrefix 动态模板 ID 前缀；仅此前缀走 dynamic_template_data。
	dynamicTemplatePrefix = "d-"
	// contentTypeHTML 正文中缀类型（HTML 是明文的超集，同 smtp/aliyun_dm）。
	contentTypeHTML = "text/html"
	// 默认模板（同 smtp：模板内容存 metadata 的最小兜底）。
	defaultSubject = "验证码"
	defaultBody    = "您的验证码：{code}"
)

// 可判别错误。
var (
	// ErrNotConfigured Ext 缺必填项（API Key / 发件地址）。
	ErrNotConfigured = errors.New("sendgrid: provider not configured")
	// ErrEmptyTo 收件地址为空。
	ErrEmptyTo = errors.New("sendgrid: empty recipient")
)

func init() {
	provider.RegisterSender(Type, provider.SenderMeta{
		Type:        Type,
		DisplayName: "SendGrid",
		Category:    provider.CategoryEmail,
		// Schema 是 /schema 的唯一数据源（表列 + Ext，接口文档 §5.3），属性
		// 与 wire 输出逐字段一致。Label / Help 复用既有 i18n 键（语义一致或
		// 足够中立），专用键归后续 web 卡。
		Schema: schema,
	}, newSender)
}

// schema /schema 唯一数据源：完整字段声明（表列 + Ext）。固化参数不透出
// （端点路径构造期固化，intranet_endpoint 只覆盖基址）；client_id 对本厂商
// 无意义不声明（声明即消费红线）。
func schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 14)
	fields = append(fields, schemafield.ProviderKey(), schemafield.DisplayName())
	fields = append(fields,
		// client_secret 承载 API Key（复用渠道中立密钥文案，专用键归后续
		// web 卡）；client_id 无意义不声明。
		provider.FieldMeta{Key: "client_secret", Label: "admin.schemaField.captchaSecretLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "from", Label: "admin.schemaField.smtpFromLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "sign_name", Label: "admin.schemaField.smtpSignNameLabel", Type: "text", Section: "credential", Storage: provider.StorageExt},
		// 仅 "d-" 前缀走动态模板轨；其余取值视同无模板（回落 metadata）。
		provider.FieldMeta{Key: "template_code", Label: "admin.schemaField.aliyunTemplateCodeLabel", Type: "text", Section: "credential", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "intranet_endpoint", Label: "admin.schemaField.aliyunIntranetEndpointLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "reply_to", Label: "admin.schemaField.replyToLabel", Type: "text", Section: "endpoint",
			Help: "admin.schemaField.replyToHelp", Storage: provider.StorageExt},
		// 沙箱模式：开启进 mail_settings.sandbox_mode.enable，厂商返回成功
		// 但不真发；缺省 false 不进请求体。
		provider.FieldMeta{Key: "sandbox_mode", Label: "admin.schemaField.sandboxModeLabel", Type: "checkbox", Section: "policy",
			Help: "admin.schemaField.sandboxModeHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "metadata", Label: "admin.schemaField.metadataLabel", Type: "json", Section: "credential", Advanced: true,
			Help: "admin.schemaField.smtpMetadataHelp", Storage: provider.StorageExt},
	)
	fields = append(fields, schemafield.IconURL(), schemafield.SortOrder(), schemafield.Remark())
	// is_enabled / 登录建号开关是 auth 专属：email 行不声明也不消费
	// （渠道生效实例判定只看 settings 键 → 行命中，provider/sender.go）。
	fields = append(fields, schemafield.ProxyRef())
	return fields
}

// Sender SendGrid 客户端（装配期固化凭证与可选开关，运行期只发请求）。
type Sender struct {
	baseURL     string
	apiKey      string            // Bearer 令牌（Ext.client_secret）
	from        string            // from.email 发件地址
	fromName    string            // from.name 发件人显示名（可空）
	templateID  string            // 动态模板 ID（仅 "d-" 前缀生效，可空）
	replyTo     string            // reply_to.email（可空）
	sandboxMode bool              // mail_settings.sandbox_mode.enable（缺省 false）
	subjects    map[string]string // metadata["subject."+tpl]
	bodies      map[string]string // metadata["body."+tpl]
	hc          *http.Client
}

// newSender 注册表工厂：从 Provider 实例取 Ext 构造客户端。
func newSender(p *provider.Provider) (provider.Sender, error) {
	return build(p, nil)
}

// build 可注入 http.Client 的构造（生产传 nil 走默认出站 client；测试用
// httptest 拦截请求，不打真实外部服务）。测试注入的 hc 优先；hc 为 nil 时
// Outbound 非 nil 用池化 client（Transport 共享，§15.4），nil（引用键空 =
// 直连）沿用既有 10s 默认直连客户端。引用不可解析在 Loader 装配期已 fail，
// 本层无代理失败路径。
func build(p *provider.Provider, hc *http.Client) (*Sender, error) {
	if p == nil || p.Ext == nil {
		return nil, provider.ErrNilProvider
	}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
		if p.Outbound != nil {
			hc = p.Outbound.HTTPClient(10 * time.Second)
		}
	}
	s := &Sender{
		baseURL:     defaultBaseURL,
		apiKey:      p.Ext.GetClientSecret(),
		from:        strings.TrimSpace(p.Ext.GetFrom()),
		fromName:    strings.TrimSpace(p.Ext.GetSignName()),
		templateID:  strings.TrimSpace(p.Ext.GetTemplateCode()),
		replyTo:     strings.TrimSpace(p.Ext.GetReplyTo()),
		sandboxMode: p.Ext.GetSandboxMode(),
		hc:          hc,
	}
	if e := strings.TrimSpace(p.Ext.GetIntranetEndpoint()); e != "" {
		s.baseURL = strings.TrimSuffix(e, "/")
	}
	for k, v := range p.Ext.GetMetadata() {
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
	// API Key 与发件地址缺一即配置不可用（ErrChannelNotConfigured 上层包装）。
	if s.apiKey == "" || s.from == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	return s, nil
}

// mailAddress v3 邮件地址对象（name 空省略，厂商缺省取发件地址）。
type mailAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

// personalization 收件个性化段（单收件人单段；dynamic_template_data 直传
// params，无变量时省略）。
type personalization struct {
	To                  []mailAddress     `json:"to"`
	DynamicTemplateData map[string]string `json:"dynamic_template_data,omitempty"`
}

// contentBlock 正文段（无模板轨 text/html 单段）。
type contentBlock struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// sandboxModeSetting / mailSettings 沙箱开关（仅开启时进请求体）。
type sandboxModeSetting struct {
	Enable bool `json:"enable"`
}

type mailSettings struct {
	SandboxMode *sandboxModeSetting `json:"sandbox_mode,omitempty"`
}

// mailRequest v3 请求体：subject / content 仅无模板轨下发（动态模板轨由
// 厂商模板自带标题正文）；可选身份 / 联调参数缺省不下发。
type mailRequest struct {
	Personalizations []personalization `json:"personalizations"`
	From             mailAddress       `json:"from"`
	Subject          string            `json:"subject,omitempty"`
	Content          []contentBlock    `json:"content,omitempty"`
	TemplateID       string            `json:"template_id,omitempty"`
	ReplyTo          *mailAddress      `json:"reply_to,omitempty"`
	MailSettings     *mailSettings     `json:"mail_settings,omitempty"`
}

// vendorErrorBody v3 错误响应形态（errors[].message 承载厂商错误消息）。
type vendorErrorBody struct {
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// Send 调用 Mail Send v3（to=收件地址，tpl=模板键，params=模板变量）。
// 失败路径全 fail-closed：HTTP 非 2xx / 响应错误对象 / 非空体 JSON 损坏
// 一律拒绝，厂商错误消息保留进错误串供上层。
func (s *Sender) Send(ctx context.Context, to string, tpl string, params map[string]string) error {
	if to == "" {
		return ErrEmptyTo
	}
	payload := mailRequest{
		From:             mailAddress{Email: s.from, Name: s.fromName},
		Personalizations: []personalization{{To: []mailAddress{{Email: to}}}},
	}
	if strings.HasPrefix(s.templateID, dynamicTemplatePrefix) {
		payload.TemplateID = s.templateID
		if len(params) > 0 {
			payload.Personalizations[0].DynamicTemplateData = params
		}
	} else {
		// 非 "d-"（含空）视同无模板：本地渲染标题正文，不发 template_id。
		subject, body := s.render(tpl, params)
		payload.Subject = subject
		payload.Content = []contentBlock{{Type: contentTypeHTML, Value: body}}
	}
	if s.replyTo != "" {
		payload.ReplyTo = &mailAddress{Email: s.replyTo}
	}
	if s.sandboxMode {
		payload.MailSettings = &mailSettings{SandboxMode: &sandboxModeSetting{Enable: true}}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("sendgrid: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+mailSendPath, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("sendgrid: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	resp, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("sendgrid: request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("sendgrid: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("sendgrid: http %d: %s", resp.StatusCode, vendorErrorMessage(respBody))
	}
	// 2xx：厂商成功响应为空体；非空体仅接受合法 JSON 且无错误对象（损坏
	// 或携带 errors 一律 fail-closed，不静默当成功）。
	if trimmed := strings.TrimSpace(string(respBody)); trimmed != "" {
		var out vendorErrorBody
		if err := json.Unmarshal(respBody, &out); err != nil {
			return fmt.Errorf("sendgrid: decode response: %w", err)
		}
		if msgs := errorMessages(out); len(msgs) > 0 {
			return fmt.Errorf("sendgrid: send failed: %s", strings.Join(msgs, "; "))
		}
	}
	return nil
}

// render 取模板并替换变量（同 smtp 最小实现：占位只替换正文；正文按
// text/html 语义，变量值作用户输入 HTML 转义，模板本身为管理员配置不转义）。
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
		body = strings.ReplaceAll(body, "{"+k+"}", html.EscapeString(val))
	}
	return subject, body
}

// vendorErrorMessage 尽力提取厂商错误消息（errors[].message）保留进错误串
// 供上层排障；非 JSON 错误体回落截断原文。
func vendorErrorMessage(body []byte) string {
	var out vendorErrorBody
	if err := json.Unmarshal(body, &out); err == nil {
		if msgs := errorMessages(out); len(msgs) > 0 {
			return strings.Join(msgs, "; ")
		}
	}
	return truncate(body)
}

// errorMessages 汇总错误对象里的非空 message（无则空切片）。
func errorMessages(out vendorErrorBody) []string {
	msgs := make([]string, 0, len(out.Errors))
	for _, e := range out.Errors {
		if e.Message != "" {
			msgs = append(msgs, e.Message)
		}
	}
	return msgs
}

func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}
