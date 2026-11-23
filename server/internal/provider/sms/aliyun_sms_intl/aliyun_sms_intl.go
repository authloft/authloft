// 阿里云国际/港澳台短信（dysmsapi SendMessageToGlobe，2018-05-01）Sender
// 实现（docs/后端架构.md §15.2、§15.5）：stdlib 直连 HTTP API + RPC 签名
// V1.0（HMAC-SHA1），签名经公共包 internal/provider/aliyunrpc（与
// sms/aliyun_sms、email/aliyun_dm 共用），零新第三方依赖。请求 / 响应形态以
// 阿里云公开 API（RPC 风格）为准。
//
// 与国内站 SendSms 是两套 API：本渠道走国际站专用端点、公共参数固定
// RegionId=ap-southeast-1，请求参数为 To / From / Message / Type（无模板 ID
// 与签名名），成功响应顶层判 ResponseCode=="OK"（非国内版的 Code）。
//
// Ext 字段口径（接口文档 §12.1，复用既有编号，不新增 proto 字段）：
//   - client_id     = AccessKeyId（credential，必填）
//   - client_secret = AccessKeySecret（credential，必填；签名密钥为其值 + "&"）
//   - from          = SenderId 发信标识（credential，可选）
//   - intranet_endpoint = 可选回源 endpoint（endpoint 区块），缺省国际站端点
//   - metadata["body."+tpl] = 本地渲染正文模板（API 无模板 ID 参数，
//     {code} 等占位在 Send 期替换；tpl 当前为 "otp"）
//
// sign_name / template_code 对本厂商无意义（国际 API 没有这两个参数），
// 不声明不消费，声明即制造表单死字段。
package aliyunsmsintl

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
const Type = "aliyun_sms_intl"

// 协议常量（SendMessageToGlobe 公开形态）。
const (
	// defaultEndpoint 国际/港澳台短信公网网关（Ext.intranet_endpoint 存在时优先回源）。
	defaultEndpoint = "https://dysmsapi.ap-southeast-1.aliyuncs.com"
	// rpcVersion SendMessageToGlobe 的 API 版本。
	rpcVersion = "2018-05-01"
	// regionID 国际站公共参数，必须固定为 ap-southeast-1。
	regionID = "ap-southeast-1"
	// messageType 本场景固定下发 OTP 验证码。
	messageType = "OTP"
	// 默认正文模板（同 aliyun_dm：模板内容存 metadata 的最小兜底）。
	defaultBody = "您的验证码：{code}"
)

// 可判别错误。
var (
	// ErrNotConfigured Ext 缺必填项（AccessKeyId / AccessKeySecret）。
	ErrNotConfigured = errors.New("aliyun_sms_intl: provider not configured")
	// ErrEmptyTo 收件号码为空。
	ErrEmptyTo = errors.New("aliyun_sms_intl: empty phone number")
)

func init() {
	provider.RegisterSender(Type, provider.SenderMeta{
		Type:        Type,
		DisplayName: "阿里云短信（国际/港澳台）",
		Category:    provider.CategorySMS,
		// Schema 是 /schema 的唯一数据源（表列 + Ext，接口文档 §5.3），属性
		// 与 wire 输出逐字段一致。Label / Help 全部复用既有 i18n 键——本渠道
		// 语义与既有键一致或足够中立，不新增键。
		Schema: schema,
	}, newSender)
}

// schema /schema 唯一数据源：完整字段声明（表列 + Ext）。固化参数（Action /
// Version / RegionId / Type / 端点缺省）构造期固化不透出；sign_name /
// template_code 无对应 API 参数不声明（声明即消费红线）。
func schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 11)
	fields = append(fields, schemafield.ProviderKey(), schemafield.DisplayName())
	fields = append(fields,
		provider.FieldMeta{Key: "client_id", Label: "admin.schemaField.aliyunAccessKeyIdLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "client_secret", Label: "admin.schemaField.aliyunAccessKeySecretLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		// from = Sender ID（可选，复用邮件 / 短信行既有发信人文案键）。
		provider.FieldMeta{Key: "from", Label: "admin.schemaField.smtpFromLabel", Type: "text", Section: "credential", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "intranet_endpoint", Label: "admin.schemaField.aliyunIntranetEndpointLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "metadata", Label: "admin.schemaField.metadataLabel", Type: "json", Section: "credential", Advanced: true,
			Help: "admin.schemaField.aliyunMetadataHelp", Storage: provider.StorageExt},
	)
	fields = append(fields, schemafield.IconURL(), schemafield.SortOrder(), schemafield.Remark())
	// is_enabled / 登录建号开关是 auth 专属：sms 行不声明也不消费
	// （渠道生效实例判定只看 settings 键 → 行命中，provider/sender.go）。
	fields = append(fields, schemafield.ProxyRef())
	return fields
}

// Sender 阿里云国际/港澳台短信客户端（装配期固化凭证、端点与渲染模板，
// 运行期只发请求）。
type Sender struct {
	endpoint        string
	accessKeyID     string
	accessKeySecret string
	from            string            // SenderId 发信标识（可空）
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
		nowFunc:         time.Now,
		hc:              hc,
	}
	// 随机源缺省走 crypto/rand（兜底时钟取注入的 nowFunc）。
	s.nonceFunc = func() string { return aliyunrpc.NewNonce(s.nowFunc) }
	if e := strings.TrimSpace(p.Ext.GetIntranetEndpoint()); e != "" {
		s.endpoint = e
	}
	// 构造期固化正文模板（运行期零配置读取）。
	for k, v := range p.Ext.GetMetadata() {
		if tpl, ok := strings.CutPrefix(k, "body."); ok {
			if s.bodies == nil {
				s.bodies = map[string]string{}
			}
			s.bodies[tpl] = v
		}
	}
	if s.accessKeyID == "" || s.accessKeySecret == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	return s, nil
}

// Send 调用 SendMessageToGlobe（to=E.164 手机号，tpl=模板键，params=模板变量）。
// E.164 的 "+" 前缀须去掉（API 的 To 要求国家码 + 号码、不带 +）；正文本地
// 渲染（API 无模板 ID 参数）。
func (s *Sender) Send(ctx context.Context, to string, tpl string, params map[string]string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return ErrEmptyTo
	}
	to = strings.TrimPrefix(to, "+")
	message := s.render(tpl, params)

	form := url.Values{}
	form.Set("Action", "SendMessageToGlobe")
	form.Set("Version", rpcVersion)
	form.Set("RegionId", regionID)
	form.Set("Format", "JSON")
	form.Set("AccessKeyId", s.accessKeyID)
	form.Set("SignatureMethod", "HMAC-SHA1")
	form.Set("SignatureVersion", "1.0")
	form.Set("SignatureNonce", s.nonceFunc())
	form.Set("Timestamp", s.nowFunc().UTC().Format("2006-01-02T15:04:05Z"))
	form.Set("To", to)
	form.Set("From", s.from)
	form.Set("Type", messageType)
	form.Set("Message", message)
	form.Set("Signature", aliyunrpc.SignRPCForm(form, s.accessKeySecret))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("aliyun_sms_intl: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := s.hc
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("aliyun_sms_intl: request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("aliyun_sms_intl: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("aliyun_sms_intl: http %d: %s", resp.StatusCode, truncate(body))
	}
	var out struct {
		ResponseCode        string `json:"ResponseCode"`
		ResponseDescription string `json:"ResponseDescription"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("aliyun_sms_intl: decode response: %w", err)
	}
	// 成功判定看顶层 ResponseCode（非国内版的 Code）；其余一律 fail-closed。
	if out.ResponseCode != "OK" {
		return fmt.Errorf("aliyun_sms_intl: send failed: response_code=%s description=%s", out.ResponseCode, out.ResponseDescription)
	}
	return nil
}

// render 取正文模板并替换占位（管理员配置模板不转义；变量值为验证码等
// 无 HTML 语义，按明文替换）。
func (s *Sender) render(tpl string, params map[string]string) string {
	body := defaultBody
	if v, ok := s.bodies[tpl]; ok && v != "" {
		body = v
	}
	for k, val := range params {
		body = strings.ReplaceAll(body, "{"+k+"}", val)
	}
	return body
}

// truncate 截断厂商响应原文（错误串不落全量 body，防日志膨胀）。
func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}
