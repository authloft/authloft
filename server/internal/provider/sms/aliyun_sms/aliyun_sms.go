// 阿里云短信（dysmsapi 2017-05-25）Sender 实现（docs/后端架构.md §15.2、
// §3.9）：stdlib 直连 HTTP API + RPC 签名 V1.0（HMAC-SHA1），零新第三方
// 依赖。请求 / 签名格式以阿里云公开 API（RPC 风格）为准；签名算法经公共包
// internal/provider/aliyunrpc（短信 / 邮件推送 / 验证码渠道共用）。
//
// Ext 字段口径（接口文档 §5.3 sms 追加字段 + 凭证区，供 /schema 渲染）：
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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"authloft/internal/provider"
	"authloft/internal/provider/aliyunrpc"
	"authloft/internal/provider/schemafield"
)

// Type 渠道类型（§15.2 内置清单）。
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
		// Schema 是 /schema 的唯一数据源（表列 + Ext，接口文档 §5.3），属性
		// 与 wire 输出逐字段一致。
		Schema: func() []provider.FieldMeta {
			fields := make([]provider.FieldMeta, 0, 13)
			fields = append(fields, schemafield.ProviderKey(), schemafield.DisplayName())
			fields = append(fields, schemafield.SMSFields()...)
			fields = append(fields, schemafield.IconURL(), schemafield.SortOrder(), schemafield.Remark())
			// is_enabled / 登录建号开关是 auth 专属：sms 行不声明也不消费
			// （渠道生效实例判定只看 settings 键 → 行命中，provider/sender.go）。
			fields = append(fields, schemafield.ProxyRef())
			return fields
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
	nowFunc         func() time.Time // 时间源（可注入，缺省 time.Now）
	nonceFunc       func() string    // 随机源（缺省 crypto/rand hex）
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
		signName:        p.Ext.GetSignName(),
		templateCode:    p.Ext.GetTemplateCode(),
		metadata:        p.Ext.GetMetadata(),
		nowFunc:         time.Now,
		hc:              hc,
	}
	// 随机源缺省走 crypto/rand（兜底时钟取注入的 nowFunc）。
	s.nonceFunc = func() string { return aliyunrpc.NewNonce(s.nowFunc) }
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
	form.Set("Signature", aliyunrpc.SignRPCForm(form, s.accessKeySecret))

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

// truncate 截断厂商响应原文（错误串不落全量 body，防日志膨胀）。
func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}
