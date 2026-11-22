// 阿里云邮件推送 DirectMail（SingleSendMail，dm 2015-11-23）薄 Sender 实现
// （docs/后端架构.md §15.5）：stdlib 直连 HTTP API + RPC 签名 V1.0，签名经
// 公共包 internal/provider/aliyunrpc（与 sms/aliyun_sms、captcha/aliyun_captcha
// 共用），零新第三方依赖。请求 / 签名格式以阿里云公开 API（RPC 风格）为准。
//
// Ext 字段口径（接口文档 §12.1 编号 61-63 + 复用键，供 /schema 渲染）：
//   - client_id     = AccessKeyId（credential，必填）
//   - client_secret = AccessKeySecret（credential，必填；签名密钥为其值 + "&"）
//   - from          = 发信地址 AccountName（credential，必填；须为控制台已
//     创建 / 验证的发信地址）
//   - address_type  = AddressType（credential，必填 select；wire "0"=随机
//     账号 / "1"=发信地址，决定 AccountName 语义；空值回落 "1"）
//   - sign_name     = FromAlias 发信人昵称（credential，可选）
//   - reply_to_address = ReplyToAddress（endpoint，可选 checkbox；API 要求
//     字符串 "true"/"false" 而非布尔，Sender 构造期转换）
//   - reply_address = ReplyAddress 自定义回信地址（endpoint，可选）
//   - intranet_endpoint = 可选回源 endpoint（endpoint 区块），缺省
//     https://dm.aliyuncs.com
//   - metadata["subject."+tpl] / ["body."+tpl] = 本地渲染模板（同 smtp：
//     DM 服务端不做变量替换，{key} 占位在 Send 期替换，tpl 当前为 "otp"）
//
// template_code 对本厂商无意义（SingleSendMail 无模板 ID 参数），不声明
// 不消费。
package aliyundm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"authloft/internal/provider"
	"authloft/internal/provider/aliyunrpc"
	"authloft/internal/provider/schemafield"
)

// Type 渠道类型（§15.2 内置清单）。
const Type = "aliyun_dm"

// 默认参数。
const (
	// defaultEndpoint 公网网关（Ext.intranet_endpoint 存在时优先回源）。
	defaultEndpoint = "https://dm.aliyuncs.com"
	// rpcVersion SingleSendMail 的 API 版本。
	rpcVersion = "2015-11-23"
	// addressType 取值封闭集（wire "0"=随机账号 / "1"=发信地址）与缺省。
	addressTypeRandom = "0"
	addressTypeSender = "1"
	// 默认模板（同 smtp：模板内容存 metadata 的最小兜底）。
	defaultSubject = "验证码"
	defaultBody    = "您的验证码：{code}"
)

// 可判别错误。
var (
	// ErrNotConfigured Ext 缺必填项（AccessKeyId / AccessKeySecret / 发信
	// 地址）或 address_type 非法。
	ErrNotConfigured = errors.New("aliyun_dm: provider not configured")
	// ErrEmptyTo 收件地址为空。
	ErrEmptyTo = errors.New("aliyun_dm: empty recipient")
)

func init() {
	provider.RegisterSender(Type, provider.SenderMeta{
		Type:        Type,
		DisplayName: "阿里云邮件推送",
		Category:    provider.CategoryEmail,
		// Schema 是 /schema 的唯一数据源（表列 + Ext，接口文档 §5.3），属性
		// 与 wire 输出逐字段一致。Label / Help 全部复用既有 i18n 键——本渠道
		// 语义与既有键一致或足够中立，不新增键。
		Schema: schema,
	}, newSender)
}

// schema /schema 唯一数据源：完整字段声明（表列 + Ext）。固化参数不透出
// （Action / Version / 端点缺省构造期固化）；template_code 无模板 ID 语义
// 不声明（声明即消费红线）。
func schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 14)
	fields = append(fields, schemafield.ProviderKey(), schemafield.DisplayName())
	fields = append(fields,
		// from = 发信地址 AccountName（与短信行同 key 不同语义，复用邮件
		// 侧既有文案键）。
		provider.FieldMeta{Key: "from", Label: "admin.schemaField.smtpFromLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "client_id", Label: "admin.schemaField.aliyunAccessKeyIdLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "client_secret", Label: "admin.schemaField.aliyunAccessKeySecretLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "address_type", Label: "admin.schemaField.addressTypeLabel", Type: "select", Section: "credential", Required: true,
			Options: []string{addressTypeRandom, addressTypeSender}, Default: addressTypeSender,
			Help: "admin.schemaField.addressTypeHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "sign_name", Label: "admin.schemaField.smtpSignNameLabel", Type: "text", Section: "credential", Storage: provider.StorageExt},
		// ReplyToAddress 是布尔语义但 API 要求字符串取值：checkbox 渲染，
		// "true"/"false" 转换在 Sender 构造期完成（防 "True"/"1" 拼写 400）。
		provider.FieldMeta{Key: "reply_to_address", Label: "admin.schemaField.replyToAddressLabel", Type: "checkbox", Section: "endpoint",
			Default: "true", Help: "admin.schemaField.replyToAddressHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "reply_address", Label: "admin.schemaField.replyAddressLabel", Type: "text", Section: "endpoint",
			Help: "admin.schemaField.replyAddressHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "intranet_endpoint", Label: "admin.schemaField.aliyunIntranetEndpointLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "metadata", Label: "admin.schemaField.metadataLabel", Type: "json", Section: "credential", Advanced: true,
			Help: "admin.schemaField.smtpMetadataHelp", Storage: provider.StorageExt},
	)
	fields = append(fields, schemafield.IconURL(), schemafield.SortOrder(), schemafield.Remark())
	// is_enabled / 登录建号开关是 auth 专属：email 行不声明也不消费
	// （渠道生效实例判定只看 settings 键 → 行命中，provider/sender.go）。
	fields = append(fields, schemafield.ProxyRef())
	return fields
}

// Sender 阿里云邮件推送客户端（装配期固化凭证与回信配置，运行期只发请求）。
type Sender struct {
	endpoint        string
	accessKeyID     string
	accessKeySecret string
	from            string // AccountName 发信地址
	addressType     string // "0" / "1"
	signName        string // FromAlias 发信人昵称（可空）
	replyToAddress  bool
	replyAddress    string            // ReplyAddress 自定义回信地址（可空）
	subjects        map[string]string // metadata["subject."+tpl]
	bodies          map[string]string // metadata["body."+tpl]
	nowFunc         func() time.Time  // 时间源（可注入，缺省 time.Now）
	nonceFunc       func() string     // 随机源（缺省 crypto/rand hex）
	hc              *http.Client
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
		endpoint:        defaultEndpoint,
		accessKeyID:     p.Ext.GetClientId(),
		accessKeySecret: p.Ext.GetClientSecret(),
		from:            strings.TrimSpace(p.Ext.GetFrom()),
		addressType:     strings.TrimSpace(p.Ext.GetAddressType()),
		signName:        strings.TrimSpace(p.Ext.GetSignName()),
		replyToAddress:  p.Ext.GetReplyToAddress(),
		replyAddress:    strings.TrimSpace(p.Ext.GetReplyAddress()),
		nowFunc:         time.Now,
		hc:              hc,
	}
	// 随机源缺省走 crypto/rand（兜底时钟取注入的 nowFunc）。
	s.nonceFunc = func() string { return aliyunrpc.NewNonce(s.nowFunc) }
	if e := strings.TrimSpace(p.Ext.GetIntranetEndpoint()); e != "" {
		s.endpoint = e
	}
	// address_type 空值回落 "1"（Schema default 同源）；非封闭集取值
	// fail-closed（决定 AccountName 语义的身份参数，带病出厂即签名错配）。
	if s.addressType == "" {
		s.addressType = addressTypeSender
	}
	if s.addressType != addressTypeRandom && s.addressType != addressTypeSender {
		return nil, fmt.Errorf("%w: provider_key=%q invalid address_type %q", ErrNotConfigured, p.Key, s.addressType)
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
	if s.accessKeyID == "" || s.accessKeySecret == "" || s.from == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	return s, nil
}

// Send 调用 SingleSendMail（to=收件地址，tpl=模板键，params=模板变量）。
// 正文走 HtmlBody：HTML 是明文的超集（无标签文本渲染等价），模板变量值
// 按用户输入转义后替换（review §5.5）。
func (s *Sender) Send(ctx context.Context, to string, tpl string, params map[string]string) error {
	if to == "" {
		return ErrEmptyTo
	}
	subject, body := s.render(tpl, params)

	form := url.Values{}
	form.Set("Action", "SingleSendMail")
	form.Set("Version", rpcVersion)
	form.Set("Format", "JSON")
	form.Set("AccessKeyId", s.accessKeyID)
	form.Set("SignatureMethod", "HMAC-SHA1")
	form.Set("SignatureVersion", "1.0")
	form.Set("SignatureNonce", s.nonceFunc())
	form.Set("Timestamp", s.nowFunc().UTC().Format("2006-01-02T15:04:05Z"))
	form.Set("AccountName", s.from)
	form.Set("AddressType", s.addressType)
	// API 要求字符串 "true"/"false" 而非布尔（构造期已固化布尔值）。
	form.Set("ReplyToAddress", strconv.FormatBool(s.replyToAddress))
	form.Set("ToAddress", to)
	form.Set("Subject", subject)
	form.Set("HtmlBody", body)
	// 可选参数缺省不下发（空值参与签名与请求无意义）。
	if s.signName != "" {
		form.Set("FromAlias", s.signName)
	}
	if s.replyAddress != "" {
		form.Set("ReplyAddress", s.replyAddress)
	}
	form.Set("Signature", aliyunrpc.SignRPCForm(form, s.accessKeySecret))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("aliyun_dm: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := s.hc
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("aliyun_dm: request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("aliyun_dm: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("aliyun_dm: http %d: %s", resp.StatusCode, truncate(respBody))
	}
	// RPC 响应失败形态为顶层 Code / Message（成功形态无 Code，仅 EnvId /
	// RequestId）：HTTP 200 且 Code 缺失才算成功，其余一律 fail-closed。
	var out struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return fmt.Errorf("aliyun_dm: decode response: %w", err)
	}
	if out.Code != "" {
		return fmt.Errorf("aliyun_dm: send failed: code=%s message=%s", out.Code, out.Message)
	}
	return nil
}

// render 取模板并替换变量（同 smtp 最小实现：占位只替换正文；正文按
// HtmlBody 语义，变量值作用户输入 HTML 转义，模板本身为管理员配置不转义）。
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

func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}
