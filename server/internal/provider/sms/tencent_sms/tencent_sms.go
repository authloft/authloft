// 腾讯云短信（云 API 3.0 SendSms，2021-01-11）Sender 实现（docs/后端架构.md
// §15.2、§15.5）：stdlib 直连 HTTP API + TC3-HMAC-SHA256 签名（crypto/hmac +
// crypto/sha256 手工实现规范请求串 → 待签名字符串 → 派生签名密钥 HMAC 链，
// 零新第三方依赖）。请求 / 签名格式以腾讯云公开 API 文档为准（review/02 §1.1
// 行 65-133 摘录）。
//
// Ext 字段口径（接口文档 §12.1 + §15.5，供 /schema 渲染）：
//   - client_id     = SecretId（credential，必填）
//   - client_secret = SecretKey（credential，必填）
//   - sdk_app_id    = SmsSdkAppId（credential，必填；每次发送必填身份参数）
//   - sign_name     = 短信签名内容（credential，必填；是内容而非签名 ID）
//   - template_code = 默认模板 ID（credential，必填）
//   - region        = X-TC-Region 地域（endpoint，必填，default ap-guangzhou）
//   - intranet_endpoint = 可选自定义请求域名（endpoint 区块），缺省
//     https://sms.tencentcloudapi.com
//   - metadata["template_code."+tpl]         按模板键覆盖模板 ID
//   - metadata["template_param_order."+tpl]  位置变量顺序（逗号分隔的参数
//     键序），防 map 展开错位（模板变量是位置数组）
//
// 响应逐条判 SendStatusSet[].Code=="Ok"：整体 HTTP 200 也可能部分失败，只看
// 状态码会漏报。错误按永久 / 瞬时分类返回（SendError.Kind），永久错重试
// 无意义（凭证 / 参数 / 资格类），瞬时错（InternalError 等）可重试。
package tencentsms

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"authloft/internal/provider"
	"authloft/internal/provider/schemafield"
)

// Type 渠道类型（§15.2 内置清单）。
const Type = "tencent_sms"

// 协议常量（云 API 3.0 公共参数）。
const (
	// defaultEndpoint 公网网关（Ext.intranet_endpoint 存在时优先回源）。
	defaultEndpoint = "https://sms.tencentcloudapi.com"
	// apiVersion SendSms 所属 API 版本。
	apiVersion = "2021-01-11"
	// tcService 签名作用域中的产品名（Credential 段 sms）。
	tcService = "sms"
	// tcAlgorithm 签名方法名（Authorization 头前缀）。
	tcAlgorithm = "TC3-HMAC-SHA256"
	// contentType 请求体类型；必须与参与签名的 CanonicalHeaders 逐字符一致。
	contentType = "application/json; charset=utf-8"
	// signedHeaders 参与签名的请求头集合（固定 content-type;host）。
	signedHeaders = "content-type;host"
)

// 可判别错误。
var (
	// ErrNotConfigured Ext 缺必填项（SecretId / SecretKey / SmsSdkAppId /
	// 签名内容 / 模板 ID / 地域）。
	ErrNotConfigured = errors.New("tencent_sms: provider not configured")
	// ErrEmptyTo 收件号码为空。
	ErrEmptyTo = errors.New("tencent_sms: empty phone number")
)

// ErrorKind 厂商错误分类（重试语义）：瞬时错可重试；永久错重试必然同样
// 失败（凭证 / 参数 / 资格类），调用方应直接放弃而非消耗重试预算。
type ErrorKind int

const (
	// KindTransient 瞬时错：网络 / 服务端 / 限流，稍后重试可能成功。
	KindTransient ErrorKind = iota
	// KindPermanent 永久错：参数非法、凭证错误、签名 / 模板未审核、达量
	// 停用等资格类失败。
	KindPermanent
)

// SendError 携带分类的发送失败。Code 为厂商错误码（HTTP / 传输层错误为空，
// 统一按瞬时处理——误判永久会中断验证码下发，代价更高）。
type SendError struct {
	Kind    ErrorKind
	Code    string
	Message string
}

func (e *SendError) Error() string {
	if e.Code == "" {
		return "tencent_sms: " + e.Message
	}
	return fmt.Sprintf("tencent_sms: %s: %s", e.Code, e.Message)
}

// permanentPrefixes 永久错误码前缀（review/02 §1.5：AuthFailure.* /
// InvalidParameterValue / LimitExceeded.* / FailedOperation.* 等资格与参数类
// 失败不要重试）。前缀匹配——厂商错误码形如 "AuthFailure.SecretIdNotFound"。
var permanentPrefixes = []string{
	"AuthFailure.",
	"InvalidParameter",
	"MissingParameter",
	"UnauthorizedOperation",
	"LimitExceeded.",
	"FailedOperation.",
}

// classifyVendorError 按错误码前缀分类；未知码保守按瞬时（重试消耗低，
// 误判永久会中断验证码下发）。
func classifyVendorError(code string) ErrorKind {
	for _, p := range permanentPrefixes {
		if strings.HasPrefix(code, p) {
			return KindPermanent
		}
	}
	return KindTransient
}

func init() {
	provider.RegisterSender(Type, provider.SenderMeta{
		Type:        Type,
		DisplayName: "腾讯云短信",
		Category:    provider.CategorySMS,
		// Schema 是 /schema 的唯一数据源（表列 + Ext，接口文档 §5.3），属性
		// 与 wire 输出逐字段一致。Label / Help 复用既有 i18n 键（新增键需动
		// web/ 语言包，超出本包范围）；sdk_app_id / region 的既有键即为本渠道
		// 语义而设。
		Schema: schema,
	}, newSender)
}

// schema /schema 唯一数据源：完整字段声明（表列 + Ext）。固化参数不透出
// （Action / Version / API 版本 / 缺省域名构造期固化）；is_enabled 等策略
// 开关是 auth 专属，sms 行不声明也不消费。
func schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 14)
	fields = append(fields, schemafield.ProviderKey(), schemafield.DisplayName())
	fields = append(fields,
		provider.FieldMeta{Key: "client_id", Label: "admin.schemaField.aliyunAccessKeyIdLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "client_secret", Label: "admin.schemaField.aliyunAccessKeySecretLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "sdk_app_id", Label: "admin.schemaField.sdkAppIdLabel", Type: "text", Section: "credential", Required: true, Help: "admin.schemaField.sdkAppIdHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "sign_name", Label: "admin.schemaField.aliyunSignNameLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "template_code", Label: "admin.schemaField.aliyunTemplateCodeLabel", Type: "text", Section: "credential", Required: true, Storage: provider.StorageExt},
		// region 进 X-TC-Region 头并锁定发送地域；default 与 pattern 见 §15.5。
		provider.FieldMeta{Key: "region", Label: "admin.schemaField.regionLabel", Type: "text", Section: "endpoint", Required: true,
			Default: "ap-guangzhou", Pattern: "^[a-z]{2}-[a-z]+-[0-9]+$", Help: "admin.schemaField.regionHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "intranet_endpoint", Label: "admin.schemaField.aliyunIntranetEndpointLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "metadata", Label: "admin.schemaField.metadataLabel", Type: "json", Section: "credential", Advanced: true,
			Help: "admin.schemaField.aliyunMetadataHelp", Storage: provider.StorageExt},
	)
	fields = append(fields, schemafield.IconURL(), schemafield.SortOrder(), schemafield.Remark())
	fields = append(fields, schemafield.ProxyRef())
	return fields
}

// Sender 腾讯云短信客户端（装配期固化凭证，运行期只发请求）。
type Sender struct {
	endpoint     string
	host         string // 参与签名的 Host 头值（从 endpoint 解析）
	secretID     string
	secretKey    string
	sdkAppID     string
	signName     string
	templateCode string // Ext.template_code 默认模板
	region       string
	metadata     map[string]string
	nowFunc      func() time.Time // 时间源（可注入，缺省 time.Now）
	hc           *http.Client
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
	endpoint := defaultEndpoint
	if e := strings.TrimSpace(p.Ext.GetIntranetEndpoint()); e != "" {
		endpoint = e
	}
	u, err := url.Parse(endpoint)
	// Host 头是签名输入之一，构造期解析失败属配置错误，fail-fast（发送期
	// 不再兜底猜测）。
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%w: provider_key=%q bad endpoint %q", ErrNotConfigured, p.Key, endpoint)
	}
	s := &Sender{
		endpoint:     endpoint,
		host:         u.Host,
		secretID:     p.Ext.GetClientId(),
		secretKey:    p.Ext.GetClientSecret(),
		sdkAppID:     p.Ext.GetSdkAppId(),
		signName:     p.Ext.GetSignName(),
		templateCode: p.Ext.GetTemplateCode(),
		region:       p.Ext.GetRegion(),
		metadata:     p.Ext.GetMetadata(),
		nowFunc:      time.Now,
		hc:           hc,
	}
	// 六项均必填（§15.5）：凭证 / 身份 / 签名 / 模板 / 地域缺一即构造失败。
	if s.secretID == "" || s.secretKey == "" || s.sdkAppID == "" ||
		s.signName == "" || s.templateCode == "" || s.region == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	return s, nil
}

// sendSmsRequest SendSms 请求体（字段序固定，json.Marshal 按声明序输出，
// 签名对 body 逐字节覆盖）。
type sendSmsRequest struct {
	PhoneNumberSet   []string `json:"PhoneNumberSet"`
	SmsSdkAppId      string   `json:"SmsSdkAppId"`
	SignName         string   `json:"SignName"`
	TemplateId       string   `json:"TemplateId"`
	TemplateParamSet []string `json:"TemplateParamSet,omitempty"`
}

// sendSmsResponse SendSms 响应体（云 API 3.0 统一 Response 包裹）。
type sendSmsResponse struct {
	Response struct {
		SendStatusSet []struct {
			SerialNo    string `json:"SerialNo"`
			PhoneNumber string `json:"PhoneNumber"`
			Code        string `json:"Code"`
			Message     string `json:"Message"`
		} `json:"SendStatusSet"`
		Error *struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
		RequestId string `json:"RequestId"`
	} `json:"Response"`
}

// Send 调用 SendSms（to=手机号，tpl=模板键，params=模板变量）。失败路径
// 全 fail-closed：HTTP 非 200、响应 JSON 损坏、Response.Error 存在、任一条
// SendStatusSet.Code != "Ok" 均拒绝。
func (s *Sender) Send(ctx context.Context, to string, tpl string, params map[string]string) error {
	phone := normalizePhone(to)
	if phone == "" {
		return ErrEmptyTo
	}
	templateCode := s.templateCode
	if s.metadata != nil {
		if v, ok := s.metadata["template_code."+tpl]; ok && v != "" {
			templateCode = v
		}
	}
	paramSet, err := expandTemplateParams(tpl, params, s.metadata)
	if err != nil {
		return err
	}
	body, err := json.Marshal(sendSmsRequest{
		PhoneNumberSet:   []string{phone},
		SmsSdkAppId:      s.sdkAppID,
		SignName:         s.signName,
		TemplateId:       templateCode,
		TemplateParamSet: paramSet,
	})
	if err != nil {
		return &SendError{Kind: KindTransient, Message: "marshal request: " + err.Error()}
	}
	now := s.nowFunc().UTC()
	ts := now.Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return &SendError{Kind: KindTransient, Message: "build request: " + err.Error()}
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-TC-Action", "SendSms")
	req.Header.Set("X-TC-Version", apiVersion)
	req.Header.Set("X-TC-Region", s.region)
	req.Header.Set("X-TC-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("Authorization", tc3Sign(s.secretID, s.secretKey, s.host, ts, body))
	hc := s.hc
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return &SendError{Kind: KindTransient, Message: "request: " + err.Error()}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return &SendError{Kind: KindTransient, Message: "read response: " + err.Error()}
	}
	if resp.StatusCode != http.StatusOK {
		return &SendError{Kind: KindTransient, Message: fmt.Sprintf("http %d: %s", resp.StatusCode, truncate(raw))}
	}
	var out sendSmsResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return &SendError{Kind: KindTransient, Message: "decode response: " + err.Error()}
	}
	if e := out.Response.Error; e != nil && e.Code != "" {
		return &SendError{Kind: classifyVendorError(e.Code), Code: e.Code, Message: e.Message}
	}
	// 逐条判成功：HTTP 200 + 整体成功也可能有单条失败；单号发送只有一条，
	// 批量形态防御性聚合（任一条永久错 → 整体按永久，不消耗重试预算）。
	if len(out.Response.SendStatusSet) == 0 {
		return &SendError{Kind: KindTransient, Message: "empty SendStatusSet"}
	}
	kind := KindTransient
	var firstFailed *struct {
		Code, PhoneNumber, Message string
	}
	for i := range out.Response.SendStatusSet {
		st := out.Response.SendStatusSet[i]
		if st.Code == "Ok" {
			continue
		}
		if firstFailed == nil {
			firstFailed = &struct{ Code, PhoneNumber, Message string }{st.Code, st.PhoneNumber, st.Message}
		}
		if classifyVendorError(st.Code) == KindPermanent {
			kind = KindPermanent
		}
	}
	if firstFailed != nil {
		return &SendError{Kind: kind, Code: firstFailed.Code,
			Message: fmt.Sprintf("send status %s: %s", firstFailed.PhoneNumber, firstFailed.Message)}
	}
	return nil
}

// normalizePhone 号码规整：国内 11 位裸号默认补 +86（E.164 口径）；其余
// 形态（+ / 00 / 86 前缀与国际号码）原样透传，由厂商侧校验。
func normalizePhone(to string) string {
	to = strings.TrimSpace(to)
	if len(to) == 11 && to[0] == '1' {
		digits := true
		for i := 0; i < len(to); i++ {
			if to[i] < '0' || to[i] > '9' {
				digits = false
				break
			}
		}
		if digits {
			return "+86" + to
		}
	}
	return to
}

// expandTemplateParams 位置参数展开：模板变量是位置数组而 Authloft 传 map，
// map 遍历随机，必须按确定序展开防多变量模板错位（§15.5）。顺序来源：
// metadata["template_param_order."+tpl]（逗号分隔键序）；未声明时仅放行
// 验证码链路的单变量 {"code": *}（当前唯一调用方 provider.CodeBridge 只传
// code），多变量不声明顺序直接拒绝——fail-closed 优于按迭代序猜位置。
func expandTemplateParams(tpl string, params map[string]string, metadata map[string]string) ([]string, error) {
	if len(params) == 0 {
		return nil, nil
	}
	order := templateParamOrder(tpl, metadata)
	if order == nil {
		if len(params) == 1 {
			if v, ok := params["code"]; ok {
				return []string{v}, nil
			}
		}
		return nil, &SendError{Kind: KindPermanent,
			Message: fmt.Sprintf("params for tpl %q: declare metadata[template_param_order.%s] to expand positional array", tpl, tpl)}
	}
	seen := make(map[string]bool, len(order))
	out := make([]string, 0, len(order))
	for _, key := range order {
		if seen[key] {
			return nil, &SendError{Kind: KindPermanent,
				Message: fmt.Sprintf("template_param_order.%s duplicates key %q", tpl, key)}
		}
		seen[key] = true
		v, ok := params[key]
		if !ok {
			return nil, &SendError{Kind: KindPermanent,
				Message: fmt.Sprintf("template_param_order.%s key %q missing in params", tpl, key)}
		}
		out = append(out, v)
	}
	if len(seen) != len(params) {
		return nil, &SendError{Kind: KindPermanent,
			Message: fmt.Sprintf("params keys not covered by template_param_order.%s", tpl)}
	}
	return out, nil
}

// templateParamOrder 解析 metadata 中的位置变量顺序；未声明或空白返回 nil。
func templateParamOrder(tpl string, metadata map[string]string) []string {
	raw, ok := metadata["template_param_order."+tpl]
	if !ok || strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// tc3Sign TC3-HMAC-SHA256 签名（云 API 3.0 公共签名规范，stdlib 自实现）：
// CanonicalRequest → StringToSign → 派生签名密钥 HMAC 链 → Authorization 头。
// 返回完整 Authorization 头值。
func tc3Sign(secretID, secretKey, host string, timestamp int64, payload []byte) string {
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	stringToSign := tc3StringToSign(date, timestamp,
		sha256Hex(tc3CanonicalRequest(host, sha256HexBytes(payload))))
	return tcAlgorithm +
		" Credential=" + secretID + "/" + date + "/" + tcService + "/tc3_request" +
		", SignedHeaders=" + signedHeaders +
		", Signature=" + hex.EncodeToString(hmacSHA256(tc3DerivedKey(secretKey, date), stringToSign))
}

// tc3CanonicalRequest 规范请求串：POST JSON 固定 URI=/、查询串空、签名头
// content-type;host。hashedPayloadHex 为请求体的 SHA-256 十六进制。
func tc3CanonicalRequest(host, hashedPayloadHex string) string {
	return "POST" + "\n" +
		"/" + "\n" +
		"" + "\n" +
		"content-type:" + contentType + "\n" +
		"host:" + host + "\n" +
		"\n" +
		signedHeaders + "\n" +
		hashedPayloadHex
}

// tc3StringToSign 待签名字符串：算法名 + 时间戳 + 凭证范围（日期/服务/tc3_request）
// + 规范请求串哈希。
func tc3StringToSign(date string, timestamp int64, hashedCanonicalRequest string) string {
	return tcAlgorithm + "\n" +
		strconv.FormatInt(timestamp, 10) + "\n" +
		date + "/" + tcService + "/tc3_request" + "\n" +
		hashedCanonicalRequest
}

// tc3DerivedKey 派生签名密钥 HMAC 链：TC3+SecretKey → 日期 → 服务名 →
// 固定串 "tc3_request"。
func tc3DerivedKey(secretKey, date string) []byte {
	kDate := hmacSHA256([]byte("TC3"+secretKey), date)
	kService := hmacSHA256(kDate, tcService)
	return hmacSHA256(kService, "tc3_request")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// truncate 截断厂商响应原文（错误串不落全量 body，防日志膨胀）。
func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}
