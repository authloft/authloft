// Twilio Programmable Messaging（Messages 资源，2010-04-01）Sender 实现
// （docs/后端架构.md §15.5）：stdlib 直连 REST + HTTP Basic Auth + form
// urlencode，零新第三方依赖。请求 / 响应形态以 Twilio 公开 API 文档为准
// （review/02 §2 摘录）。
//
// Ext 字段口径（接口文档 §12.1，供 /schema 渲染）：
//   - client_id     = Account SID（credential，必填；Basic Auth 用户名 + URL
//     路径参数同源承载）
//   - client_secret = Auth Token（credential，必填；Basic Auth 密码）
//   - from          = 发信号码 E.164（credential，可选；与 messaging_service_sid
//     二选一，两者都填或都不填构造期拒绝）
//   - messaging_service_sid = Messaging Service SID，MG 前缀（credential，可选）
//   - template_code = 默认 Content SID，HX 前缀（credential，必填；Send 期可被
//     metadata["template_code."+tpl] 按模板键覆盖）
//   - metadata["content_variables_map."+tpl] = 模板变量名 → Content Template
//     序号映射（如 {"code":"1"}）；未配置时按参数键排序自然序兜底
//   - intranet_endpoint = 可选 base URL 覆盖（endpoint 区块），路径段照常拼接
//
// 一期不做 API Key 鉴权（无 account_sid 字段，Basic Auth 由 AccountSid 承载
// 用户名）；sign_name 无签名概念，不声明不消费。发送只走 ContentSid 内容
// 模板轨（无明文 Body 回落）。大陆号码 Best Effort、仅作海外渠道：To 不做
// 国别前缀猜测，E.164 形态由上游保证。
package twilio

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"authloft/internal/provider"
	"authloft/internal/provider/schemafield"
)

// Type 渠道类型（内置清单）。
const Type = "twilio"

// 协议常量（Messages 资源公开形态）。
const (
	// defaultEndpoint 公网 base URL（Ext.intranet_endpoint 存在时优先回源，
	// Messages 路径段照常拼接）。
	defaultEndpoint = "https://api.twilio.com"
	// messagesPath Messages 资源固定路径段，AccountSid 作路径参数。
	messagesPath = "/2010-04-01/Accounts/"
	// contentTypeForm form 提交类型。
	contentTypeForm = "application/x-www-form-urlencoded"
	// idempotencyHeader 幂等键请求头（防 202 后重试重复投递的工程缓解，
	// review/02 §2.5 口径）。
	idempotencyHeader = "Idempotency-Token"
)

// 终态失败 status 集合：intake 响应即落在这些状态说明消息已被厂商拒绝，
// 重试同一内容只会得到同样结果。
var terminalFailureStatus = map[string]bool{
	"failed": true, "undelivered": true, "canceled": true,
}

// 可判别错误。
var (
	// ErrNotConfigured Ext 缺必填项（AccountSid / AuthToken / ContentSid），
	// 或 from 与 messaging_service_sid 未按二选一提供。
	ErrNotConfigured = errors.New("twilio: provider not configured")
	// ErrEmptyTo 收件号码为空。
	ErrEmptyTo = errors.New("twilio: empty phone number")
)

// ErrorKind 厂商错误分类（重试语义）：瞬时错可重试；永久错重试必然同样
// 失败（凭证 / 参数 / 号码资格 / 违规内容类），调用方应直接放弃而非消耗
// 重试预算。
type ErrorKind int

const (
	// KindTransient 瞬时错：网络 / 服务端 / 限流，稍后重试可能成功。
	KindTransient ErrorKind = iota
	// KindPermanent 永久错：凭证、参数、号码资格与违规内容类失败。
	KindPermanent
)

// SendError 携带分类的发送失败。Code 为厂商数字错误码的字符串形态
// （HTTP / 传输层错误为空）。
type SendError struct {
	Kind    ErrorKind
	Code    string
	Message string
}

func (e *SendError) Error() string {
	if e.Code == "" {
		return "twilio: " + e.Message
	}
	return fmt.Sprintf("twilio: %s: %s", e.Code, e.Message)
}

// classifyVendorError 按厂商错误码分类（review/02 §2.5 口径）：20003 鉴权
// 失败、21211 非法号码、21614 座机等 21xxx 号码 / 参数 / 资格类与 30007
// 违规内容为永久；30001 队列溢出等与未知码保守按瞬时（误判永久会中断
// 验证码下发，代价更高）。
func classifyVendorError(code int64) ErrorKind {
	if code == 20003 || code == 30007 {
		return KindPermanent
	}
	if code >= 21200 && code <= 21999 {
		return KindPermanent
	}
	return KindTransient
}

func init() {
	provider.RegisterSender(Type, provider.SenderMeta{
		Type:        Type,
		DisplayName: "Twilio 短信",
		Category:    provider.CategorySMS,
		// Schema 是 /schema 的唯一数据源（表列 + Ext，接口文档 §5.3），属性
		// 与 wire 输出逐字段一致。Label / Help 复用既有 i18n 键（AccountSid /
		// ContentSid / 发信号码的渠道专用键需动 web/ 语言包，超出本包范围）。
		Schema: schema,
	}, newSender)
}

// schema /schema 唯一数据源：完整字段声明（表列 + Ext）。固化参数不透出
// （Messages 路径 / API 版本构造期固化）；sign_name 不消费不声明；from 与
// messaging_service_sid 的二选一交叉校验是跨字段约束，Schema 单字段无法
// 表达，落到构造期 fail-closed。
func schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 14)
	fields = append(fields, schemafield.ProviderKey(), schemafield.DisplayName())
	fields = append(fields,
		// client_id 承载 Account SID（AC 前缀；Basic Auth 用户名 + URL 路径参数）。
		provider.FieldMeta{Key: "client_id", Label: "admin.schemaField.clientIdLabel", Type: "text", Section: "credential", Required: true,
			Pattern: `^AC[0-9a-fA-F]{32}$`, Storage: provider.StorageExt},
		// client_secret 承载 Auth Token（复用渠道中立密钥文案，专用键归
		// 后续 web 卡）。
		provider.FieldMeta{Key: "client_secret", Label: "admin.schemaField.captchaSecretLabel", Type: "secret", Section: "credential", Required: true, Storage: provider.StorageExt},
		// from = 发信号码（E.164）。
		provider.FieldMeta{Key: "from", Label: "admin.schemaField.smtpFromLabel", Type: "text", Section: "credential",
			Pattern: `^\+[1-9][0-9]{1,14}$`, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "messaging_service_sid", Label: "admin.schemaField.messagingServiceSidLabel", Type: "text", Section: "credential",
			Help: "admin.schemaField.messagingServiceSidHelp", Pattern: `^MG[0-9a-fA-F]{32}$`, Storage: provider.StorageExt},
		// template_code 承载 Content SID（HX 前缀）。
		provider.FieldMeta{Key: "template_code", Label: "admin.schemaField.aliyunTemplateCodeLabel", Type: "text", Section: "credential", Required: true,
			Pattern: `^HX[0-9a-fA-F]{32}$`, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "intranet_endpoint", Label: "admin.schemaField.aliyunIntranetEndpointLabel", Type: "text", Section: "endpoint", Advanced: true, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "metadata", Label: "admin.schemaField.metadataLabel", Type: "json", Section: "credential", Advanced: true, Storage: provider.StorageExt},
	)
	fields = append(fields, schemafield.IconURL(), schemafield.SortOrder(), schemafield.Remark())
	fields = append(fields, schemafield.ProxyRef())
	return fields
}

// Sender Twilio 短信客户端（装配期固化凭证与发送身份，运行期只发请求）。
type Sender struct {
	base                string // Messages API base URL（intranet_endpoint 覆盖）
	accountSID          string // Basic Auth 用户名 + URL 路径参数
	authToken           string // Basic Auth 密码
	from                string // 发信号码（与 messagingServiceSID 二选一）
	messagingServiceSID string // Messaging Service SID
	templateCode        string // Ext.template_code 默认 ContentSid
	metadata            map[string]string
	hc                  *http.Client
}

// newSender 注册表工厂：从 Provider 实例取 Ext 构造客户端。
func newSender(p *provider.Provider) (provider.Sender, error) {
	return build(p, nil)
}

// build 可注入 http.Client 的构造（生产传 nil 走默认出站 client；测试用
// httptest 拦截请求，不打真实外部服务）。测试注入的 hc 优先；hc 为 nil 时
// Outbound 非 nil 用池化 client（Transport 共享），nil（引用键空 = 直连）
// 沿用既有 10s 默认直连客户端。引用不可解析在 Loader 装配期已 fail，本层
// 无代理失败路径。
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
		base:                defaultEndpoint,
		accountSID:          p.Ext.GetClientId(),
		authToken:           p.Ext.GetClientSecret(),
		from:                strings.TrimSpace(p.Ext.GetFrom()),
		messagingServiceSID: strings.TrimSpace(p.Ext.GetMessagingServiceSid()),
		templateCode:        p.Ext.GetTemplateCode(),
		metadata:            p.Ext.GetMetadata(),
		hc:                  hc,
	}
	if e := strings.TrimSpace(p.Ext.GetIntranetEndpoint()); e != "" {
		u, err := url.Parse(e)
		// 回源 base 覆盖解析不出 host 属配置错误，fail-fast（发送期不再
		// 兜底猜测）。
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("%w: provider_key=%q bad endpoint %q", ErrNotConfigured, p.Key, e)
		}
		s.base = strings.TrimRight(e, "/")
	}
	// 凭证缺一即构造失败（Basic Auth 两段都不可空）。
	if s.accountSID == "" || s.authToken == "" {
		return nil, fmt.Errorf("%w: provider_key=%q", ErrNotConfigured, p.Key)
	}
	// 发送路由一等身份二选一：都填无法判定以谁为准，都不填请求必然被厂商
	// 拒绝——装配期 fail-closed，不让病配置进入运行期。
	if (s.from == "") == (s.messagingServiceSID == "") {
		return nil, fmt.Errorf("%w: provider_key=%q exactly one of from/messaging_service_sid is required", ErrNotConfigured, p.Key)
	}
	return s, nil
}

// messagesURL Messages 资源完整 URL：base + 固定路径段，AccountSid 作路径
// 参数（与 Basic Auth 用户名同源，均取 Ext.client_id）。
func (s *Sender) messagesURL() string {
	return s.base + messagesPath + url.PathEscape(s.accountSID) + "/Messages.json"
}

// messageResponse Messages 资源响应（成功形如 sid/status/error_code:null；
// 错误体为扁平 code/message/status 形态，两套字段并收以同时覆盖 2xx 成功
// 与非 2xx / 2xx 错误体）。status 两处语义不同：成功体是字符串消息态
// （queued 等），错误体是数字 HTTP 码——按 RawMessage 收取，防止错误体
// 因类型不符整体解析失败而丢失厂商错误码。
type messageResponse struct {
	Sid       string          `json:"sid"`
	Status    json.RawMessage `json:"status"`
	ErrorCode *int64          `json:"error_code"`
	Code      *int64          `json:"code"`
	Message   string          `json:"message"`
}

// messageStatus 提取消息态 status（字符串形态，如 queued / accepted）；
// 缺失、null 或数字 HTTP 码形态返回空串（错误体交由错误码分支判定）。
func (m messageResponse) messageStatus() string {
	if len(m.Status) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(m.Status, &s); err != nil {
		return ""
	}
	return s
}

// Send 调用 Messages 资源（to=E.164 手机号，tpl=模板键，params=模板变量）。
// 失败路径全 fail-closed：HTTP 非 2xx、错误体（error_code / code 非空）、
// JSON 损坏、status 缺失或终态失败均拒绝，厂商错误消息原文保留。
func (s *Sender) Send(ctx context.Context, to string, tpl string, params map[string]string) error {
	to = strings.TrimSpace(to)
	if to == "" {
		return ErrEmptyTo
	}
	templateCode := s.templateCode
	if v, ok := s.metadata["template_code."+tpl]; ok && v != "" {
		templateCode = v
	}
	if templateCode == "" {
		return fmt.Errorf("%w: content sid empty for tpl %q", ErrNotConfigured, tpl)
	}
	contentVars, err := buildContentVariables(tpl, params, s.metadata)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("To", to)
	form.Set("ContentSid", templateCode)
	if s.from != "" {
		form.Set("From", s.from)
	} else {
		form.Set("MessagingServiceSid", s.messagingServiceSID)
	}
	if contentVars != "" {
		form.Set("ContentVariables", contentVars)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.messagesURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return &SendError{Kind: KindTransient, Message: "build request: " + err.Error()}
	}
	req.Header.Set("Content-Type", contentTypeForm)
	req.SetBasicAuth(s.accountSID, s.authToken)
	if token := idempotencyToken(to, tpl, params["code"]); token != "" {
		req.Header.Set(idempotencyHeader, token)
	}
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
	var out messageResponse
	decodeErr := json.Unmarshal(raw, &out)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// 非 2xx 一律拒绝并保留厂商错误消息；可解析出错误码时按码分类
		//（401 携带 20003 即永久，不再盲目重试），否则保守按瞬时。
		if decodeErr == nil && out.Code != nil && *out.Code != 0 {
			return &SendError{Kind: classifyVendorError(*out.Code), Code: strconv.FormatInt(*out.Code, 10),
				Message: fmt.Sprintf("http %d: %s", resp.StatusCode, vendorMessage(out))}
		}
		return &SendError{Kind: KindTransient, Message: fmt.Sprintf("http %d: %s", resp.StatusCode, truncate(raw))}
	}
	if decodeErr != nil {
		return &SendError{Kind: KindTransient, Message: "decode response: " + decodeErr.Error()}
	}
	// 2xx 也可能携带错误体（网关透传 / 厂商语义漂移）：错误码非空即拒绝。
	if out.ErrorCode != nil && *out.ErrorCode != 0 {
		return &SendError{Kind: classifyVendorError(*out.ErrorCode), Code: strconv.FormatInt(*out.ErrorCode, 10), Message: vendorMessage(out)}
	}
	if out.Code != nil && *out.Code != 0 {
		return &SendError{Kind: classifyVendorError(*out.Code), Code: strconv.FormatInt(*out.Code, 10), Message: vendorMessage(out)}
	}
	// intake 成功判定：Send() 成功仅表示厂商已接收，消息态 status 必须非空
	// 且非终态失败（queued / accepted / sent 等均放行）。
	status := out.messageStatus()
	if status == "" {
		return &SendError{Kind: KindTransient, Message: "response missing status"}
	}
	if terminalFailureStatus[status] {
		return &SendError{Kind: KindPermanent, Message: "message status " + status}
	}
	return nil
}

// buildContentVariables 构造 ContentVariables JSON 字符串（变量名 → 序号，
// 如 {"1":"246810"}）：metadata["content_variables_map."+tpl] 声明映射，映射
// 未覆盖的参数键直接拒绝（fail-closed——猜序号会把验证码填进别的变量）；
// 映射声明的多余键忽略（厂商对未提供的变量回退模板默认样例值）。未配置
// 映射时按参数键排序后的自然序兜底（如 {"code"} → 序号 1，review/02 §2.5
// 兜底口径）；键序由 encoding/json 对 map 的排序输出保证稳定。
func buildContentVariables(tpl string, params map[string]string, metadata map[string]string) (string, error) {
	if len(params) == 0 {
		return "", nil
	}
	mapping, err := parseContentVariablesMap(tpl, metadata)
	if err != nil {
		return "", err
	}
	vars := make(map[string]string, len(params))
	if mapping == nil {
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			vars[strconv.Itoa(i+1)] = params[k]
		}
	} else {
		for k, v := range params {
			pos, ok := mapping[k]
			if !ok || pos == "" {
				return "", &SendError{Kind: KindPermanent,
					Message: fmt.Sprintf("params key %q not covered by content_variables_map.%s", k, tpl)}
			}
			vars[pos] = v
		}
	}
	raw, err := json.Marshal(vars)
	if err != nil {
		return "", &SendError{Kind: KindTransient, Message: "marshal content variables: " + err.Error()}
	}
	return string(raw), nil
}

// parseContentVariablesMap 解析 metadata 中的变量名 → 序号映射；未声明或
// 空白返回 nil。声明存在但 JSON 损坏 / 值非字符串属配置错误，永久拒绝。
func parseContentVariablesMap(tpl string, metadata map[string]string) (map[string]string, error) {
	raw, ok := metadata["content_variables_map."+tpl]
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	out := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, &SendError{Kind: KindPermanent,
			Message: fmt.Sprintf("content_variables_map.%s: %v", tpl, err)}
	}
	return out, nil
}

// idempotencyToken 短时效幂等值（review/02 §2.5 工程缓解口径）：对
// to+tpl+code 取 SHA-256。同一逻辑发送（验证码未变）在队列重试间保持同一
// 值供厂商去重；新验证码即新值——短时效由验证码 TTL 承载，无需额外状态。
// code 为空（非验证码链路）返回空串，调用方不下发幂等头：空 code 的键无法
// 区分两次不同发送，误并会吞掉合法新消息。
func idempotencyToken(to, tpl, code string) string {
	if code == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(to + "\x1f" + tpl + "\x1f" + code))
	return hex.EncodeToString(sum[:])
}

// vendorMessage 提取厂商错误消息原文（保留厂商措辞，不吞错误细节）。
func vendorMessage(out messageResponse) string {
	if out.Message != "" {
		return out.Message
	}
	return "vendor error without message"
}

// truncate 截断厂商响应原文（错误串不落全量 body，防日志膨胀）。
func truncate(b []byte) string {
	const max = 200
	if len(b) > max {
		b = b[:max]
	}
	return string(b)
}
