// 阿里云短信（dysmsapi 2017-05-25）Sender 实现（docs/后端架构.md §15.2
// 行 1723、§3.9 行 417）：stdlib 直连 HTTP API + RPC 签名 V1.0（HMAC-SHA1），
// 零新第三方依赖。请求 / 签名格式以阿里云公开 API（RPC 风格）为准。
//
// Ext 字段口径（接口文档 §5.3 行 1236 sms 追加字段 + 凭证区，供 /schema 渲染）：
//   - client_id     = AccessKeyId（credential，必填）
//   - client_secret = AccessKeySecret（credential，必填；签名密钥为其值 + "&"）
//   - sign_name     = 短信签名（credential，必填）
//   - template_code = 默认国内短信模板 ID（credential，Send 时必填）
//   - metadata["template_code."+tpl] 按模板键覆盖 template_code
//     （当前验证码链路 tpl="otp"，见 provider/sender.go codeTpl）
//   - intranet_endpoint = 可选回源 endpoint（endpoint 区块），缺省
//     https://dysmsapi.aliyuncs.com
//
// host / port / disable_ssl / from 对本厂商无意义，不消费。
package aliyunsms

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"authloft/internal/provider"
)

// Type 渠道类型（§15.2 行 1723 内置清单）。
const Type = "aliyun_sms"

// defaultEndpoint 公网网关（Ext.intranet_endpoint 存在时优先回源）。
const defaultEndpoint = "https://dysmsapi.aliyuncs.com"

// 可判别错误。
var (
	// ErrNotConfigured Ext 缺必填项（AccessKeyId / AccessKeySecret / SignName，
	// 或 Send 时模板 ID 为空）。
	ErrNotConfigured = errors.New("aliyun_sms: provider not configured")
	// ErrEmptyTo 收件号码为空。
	ErrEmptyTo = errors.New("aliyun_sms: empty phone number")
)

func init() {
	provider.RegisterSender(Type, provider.SenderMeta{
		Type:        Type,
		DisplayName: "阿里云短信",
		Category:    provider.CategorySMS,
		Fields: []provider.FieldMeta{
			{Key: "client_id", Label: "admin.schemaField.aliyunAccessKeyIdLabel", Type: "text", Section: "credential", Required: true},
			{Key: "client_secret", Label: "admin.schemaField.aliyunAccessKeySecretLabel", Type: "secret", Section: "credential", Required: true},
			{Key: "sign_name", Label: "admin.schemaField.aliyunSignNameLabel", Type: "text", Section: "credential", Required: true},
			{Key: "template_code", Label: "admin.schemaField.aliyunTemplateCodeLabel", Type: "text", Section: "credential", Required: true},
			{Key: "intranet_endpoint", Label: "admin.schemaField.aliyunIntranetEndpointLabel", Type: "text", Section: "endpoint", Advanced: true},
			{Key: "metadata", Label: "admin.schemaField.metadataLabel", Type: "json", Section: "credential", Advanced: true,
				Help: "admin.schemaField.aliyunMetadataHelp"},
		},
	}, newSender)
}

// Sender 阿里云短信客户端（装配期固化凭证，运行期只发请求）。
type Sender struct {
	endpoint        string
	accessKeyID     string
	accessKeySecret string
	signName        string
	templateCode    string // Ext.template_code 默认模板
	metadata        map[string]string
	nowFunc         func() time.Time // 时间源（§22.2 行 1978：可注入，缺省 time.Now）
	nonceFunc       func() string    // 随机源（缺省 crypto/rand hex）
	hc              *http.Client
}

// newSender 注册表工厂：从 Provider 实例取 Ext 构造客户端。
func newSender(p *provider.Provider) (provider.Sender, error) {
	return build(p, nil)
}

// build 可注入 http.Client 的构造（生产传 nil 走默认客户端；测试用
// httptest 拦截请求，不打真实外部服务）。
func build(p *provider.Provider, hc *http.Client) (*Sender, error) {
	if p == nil || p.Ext == nil {
		return nil, provider.ErrNilProvider
	}
	s := &Sender{
		endpoint:        defaultEndpoint,
		accessKeyID:     p.Ext.GetClientId(),
		accessKeySecret: p.Ext.GetClientSecret(),
		signName:        p.Ext.GetSignName(),
		templateCode:    p.Ext.GetTemplateCode(),
		metadata:        p.Ext.GetMetadata(),
		nowFunc:         time.Now,
		hc:              hc,
	}
	// 随机源缺省走 crypto/rand（兜底时钟取注入的 nowFunc，§22.2 行 1978）。
	s.nonceFunc = func() string { return newNonce(s.nowFunc) }
	if e := strings.TrimSpace(p.Ext.GetIntranetEndpoint()); e != "" {
		s.endpoint = e
	}
	if s.accessKeyID == "" || s.accessKeySecret == "" || s.signName == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	return s, nil
}

// Send 调用 SendSms（to=手机号，tpl=模板键，params=模板变量）。
func (s *Sender) Send(ctx context.Context, to string, tpl string, params map[string]string) error {
	if to == "" {
		return ErrEmptyTo
	}
	templateCode := s.templateCode
	if s.metadata != nil {
		if v, ok := s.metadata["template_code."+tpl]; ok && v != "" {
			templateCode = v
		}
	}
	if templateCode == "" {
		return fmt.Errorf("%w: template code empty for tpl %q", ErrNotConfigured, tpl)
	}
	templateParam := "{}"
	if len(params) > 0 {
		raw, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("aliyun_sms: marshal template param: %w", err)
		}
		templateParam = string(raw)
	}

	form := url.Values{}
	form.Set("Action", "SendSms")
	form.Set("Version", "2017-05-25")
	form.Set("Format", "JSON")
	form.Set("AccessKeyId", s.accessKeyID)
	form.Set("SignatureMethod", "HMAC-SHA1")
	form.Set("SignatureVersion", "1.0")
	form.Set("SignatureNonce", s.nonceFunc())
	form.Set("Timestamp", s.nowFunc().UTC().Format("2006-01-02T15:04:05Z"))
	form.Set("PhoneNumbers", to)
	form.Set("SignName", s.signName)
	form.Set("TemplateCode", templateCode)
	form.Set("TemplateParam", templateParam)
	form.Set("Signature", signRPCForm(form, s.accessKeySecret))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("aliyun_sms: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := s.hc
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("aliyun_sms: request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("aliyun_sms: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("aliyun_sms: http %d: %s", resp.StatusCode, truncate(body))
	}
	var out struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("aliyun_sms: decode response: %w", err)
	}
	if out.Code != "OK" {
		return fmt.Errorf("aliyun_sms: send failed: code=%s message=%s", out.Code, out.Message)
	}
	return nil
}

// signRPCForm 阿里云 RPC 签名 V1.0（SHA1 密钥 = AccessKeySecret + "&"）：
// StringToSign = POST & percentEncode("/") & percentEncode(规范化查询串)；
// 规范化串 = 除 Signature 外按 key 升序的 percentEncode(k)=percentEncode(v)。
func signRPCForm(form url.Values, accessKeySecret string) string {
	keys := make([]string, 0, len(form))
	for k := range form {
		if k == "Signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(percentEncode(k))
		b.WriteByte('=')
		b.WriteString(percentEncode(form.Get(k)))
	}
	stringToSign := http.MethodPost + "&" + percentEncode("/") + "&" + percentEncode(b.String())
	mac := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// percentEncode RFC 3986 百分号编码：url.QueryEscape 的空格转 '+' 需改回
// %20，其余（含保留字）一致。
func percentEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func newNonce(now func() time.Time) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败属系统级异常，用纳秒时钟兜底保证唯一性。
		return fmt.Sprintf("%d", now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}
