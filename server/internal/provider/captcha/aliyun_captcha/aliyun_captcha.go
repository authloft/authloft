// Package aliyun_captcha 阿里云验证码 CAPTCHA 2.0 人机校验实现（docs/后端架构.md
// §9.1 / §15.5）：协议私有专用 Verifier——RPC VerifyIntelligentCaptcha（AK
// 签名），不能套 captchacore 的 siteverify 骨架：请求是 {CaptchaVerifyParam,
// SceneId}、签名走阿里云 RPC V1.0、判定判 Result.VerifyResult 而非顶层
// Success。RPC form 签名复用公共包 internal/provider/aliyunrpc（短信 /
// 邮件推送 / 验证码渠道共用同一算法，§15.5），本包不带签名与编码逻辑。
//
// token（captchaVerifyParam）原样透传（接口文档 §2.5：禁止解析 / 重组 /
// 修改——V2 架构是 JSON 对象字符串、V3 是紧凑字符串，形态不同，任何一侧
// 的解析重组都会破坏另一形态）；SceneId 从服务端 Ext 读取随请求下发，防
// 前端篡改场景 ID。判定顺序：HTTP 状态 → 顶层 Success / Code → Result.
// VerifyResult。厂商宕机 / 超时按容灾语义可 fail-open，本实现一律
// fail-closed：基础设施错误不映射 captcha_invalid、但校验永不放行（边界
// 行为随用例固化）；正常返回但未通过（Code 非 Success / VerifyResult=
// false，含限流容灾取值）为 provider.ErrInvalid。第三方 token 的一次性由
// 厂商保证，Authloft 侧零存储（§9.2）。
package aliyun_captcha

import (
	"context"
	"encoding/json"
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

// Type 注册类型。字面量暂落实现子包（同 capjs / geetest_v4 先例，
// servicetype.go 常量上移统一另行处理）。
const Type = "aliyun_captcha"

// RPC Action / Version（厂商 OpenAPI captcha 2023-03-05，服务端接入形态
// 以官方文档为准；Version 参与 RPC 签名规范化，错值即 InvalidSignature）。
const (
	apiAction  = "VerifyIntelligentCaptcha"
	apiVersion = "2023-03-05"
)

// 地域 endpoint（region 与 endpoint 必须匹配，否则厂商侧校验失败）。
// ga 为全球加速：就近接入、流量最终路由新加坡，不透出客户端真实 IP；
// 其服务端 endpoint 与 sg 的地域 endpoint 不同，不可互换。
const (
	defaultRegion = "cn"
	endpointCN    = "https://captcha.cn-shanghai.aliyuncs.com"
	endpointSGP   = "https://captcha.ap-southeast-1.aliyuncs.com"
	endpointGA    = "https://captcha-open-ga.aliyuncs.com"
)

// regionEndpoint region → RPC endpoint 映射（region 与 endpoint 必须匹配，
// 未知地域返回 false，由构造期 fail-fast，不猜默认值静默错配）。
func regionEndpoint(region string) (string, bool) {
	switch region {
	case "cn":
		return endpointCN, true
	case "sgp":
		return endpointSGP, true
	case "ga":
		return endpointGA, true
	}
	return "", false
}

// remoteBodyLimit 校验响应体读取上限（64 KiB，防异常端点拖挂，同 geetest_v4）。
const remoteBodyLimit = 1 << 16

// 阿里云验证码弹层为 DOM 渲染、无固定 iframe 域，脚本经 nonce 信任链放行；
// 浏览器侧设备指纹 / 上传域名的 connect-src 放行已随基线取消，本 provider
// 不贡献任何 CSP 源（接口文档 §8）。
func init() {
	provider.RegisterVerifier(Type, provider.Meta{
		DisplayName: "阿里云验证码",
		Category:    provider.CategoryCaptcha,
		Schema:      schema,
	}, newVerifier)
}

// schema /schema 唯一数据源：表列基线与各家一致（schemafield 单一来源），
// Ext 按接口文档 §5.3 aliyun_captcha 行序 client_id(SceneId) / access_key_id /
// client_secret / region / prefix / encrypt_key / endpoint / widget_options。
// region 是服务端 Verifier 的消费字段（决定地域 RPC endpoint）；prefix /
// encrypt_key / widget_options 服务端校验不消费，声明仅为随配置下发（声明
// 即消费红线不破：消费方是前端 adapter，浏览器侧注入）。is_enabled / 登录建号开关
// 是 auth 专属，captcha 类别不下发也不消费（生效实例判定只看 settings 键 →
// 行命中，captcha/catalog.go）。
func schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 13)
	fields = append(fields, schemafield.ProviderKey(), schemafield.DisplayName())
	common := schemafield.CaptchaFields()
	fields = append(fields, common[0],
		provider.FieldMeta{Key: "access_key_id", Label: "admin.schemaField.accessKeyIdLabel", Type: "text", Section: "credential", Required: true,
			Help: "admin.schemaField.accessKeyIdHelp", Storage: provider.StorageExt},
		common[1],
		provider.FieldMeta{Key: "region", Label: "admin.schemaField.regionLabel", Type: "select", Section: "endpoint", Required: true,
			Options: []string{"cn", "sgp", "ga"}, Default: defaultRegion, Storage: provider.StorageExt},
		provider.FieldMeta{Key: "prefix", Label: "admin.schemaField.prefixLabel.aliyunCaptcha", Type: "text", Section: "endpoint",
			Help: "admin.schemaField.prefixHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "encrypt_key", Label: "admin.schemaField.encryptKeyLabel", Type: "secret", Section: "credential", Advanced: true,
			Help: "admin.schemaField.encryptKeyHelp", Storage: provider.StorageExt},
		common[2],
		provider.FieldMeta{Key: "widget_options", Label: "admin.schemaField.widgetOptionsLabel", Type: "text", Section: "display", Advanced: true,
			Help: "admin.schemaField.widgetOptionsHelp", Storage: provider.StorageExt},
	)
	fields = append(fields, schemafield.IconURL(), schemafield.SortOrder(), schemafield.Remark(), schemafield.ProxyRef())
	return fields
}

// Verifier 阿里云验证码专用校验实现：构造期从 Provider 实例固化 SceneId /
// AK 凭证 / 地域 endpoint / 出站连接池，运行期零配置读取（§13.0）。
type Verifier struct {
	verifyURL       string
	sceneID         string
	accessKeyID     string
	accessKeySecret string
	nowFunc         func() time.Time // 时间源（可注入，缺省 time.Now）
	nonceFunc       func() string    // 随机源（缺省 crypto/rand hex）
	hc              *http.Client
}

// newVerifier 注册表工厂：client_id(SceneId) / access_key_id / client_secret
// 缺任一即构造失败——RPC 签名与场景下发都缺不了这三件，属配置残缺，
// fail-fast（同 geetest_v4 / capjs 构造期缺失报错口径），不留到运行期才
// 失败；region 空 = 默认 cn（§15.5），未知地域（Schema select 之外的值）与
// 非法 endpoint 同为构造错误。
func newVerifier(p *provider.Provider) (provider.Verifier, error) {
	if p == nil || p.Ext == nil {
		return nil, fmt.Errorf("captcha: nil provider ext")
	}
	sceneID := strings.TrimSpace(p.Ext.GetClientId())
	accessKeyID := strings.TrimSpace(p.Ext.GetAccessKeyId())
	secret := p.Ext.GetClientSecret()
	if sceneID == "" || accessKeyID == "" || secret == "" {
		return nil, fmt.Errorf("captcha: aliyun_captcha client_id(scene_id)、access_key_id、client_secret(access_key_secret) 均必填")
	}
	region := strings.TrimSpace(p.Ext.GetRegion())
	if region == "" {
		region = defaultRegion
	}
	verifyURL := strings.TrimSpace(p.Ext.GetEndpoint())
	if verifyURL == "" {
		e, ok := regionEndpoint(region)
		if !ok {
			return nil, fmt.Errorf("captcha: aliyun_captcha region %q 无法映射地域 endpoint（可选 cn/sgp/ga）", region)
		}
		verifyURL = e
	}
	if _, err := url.Parse(verifyURL); err != nil {
		return nil, fmt.Errorf("captcha: aliyun_captcha endpoint 非法: %w", err)
	}
	hc := &http.Client{Timeout: 10 * time.Second}
	if p.Outbound != nil {
		hc = p.Outbound.HTTPClient(10 * time.Second)
	}
	v := &Verifier{
		verifyURL:       verifyURL,
		sceneID:         sceneID,
		accessKeyID:     accessKeyID,
		accessKeySecret: secret,
		nowFunc:         time.Now,
		hc:              hc,
	}
	// 随机源缺省走 crypto/rand（兜底时钟取注入的 nowFunc，同 aliyun_sms）。
	v.nonceFunc = func() string { return aliyunrpc.NewNonce(v.nowFunc) }
	return v, nil
}

// Verify 原样透传 token 构造 RPC form（签名经公共包 aliyunrpc）→ POST 地域
// endpoint → 判定 Success / Code / Result.VerifyResult。空 token 不发请求
// 直接判无效；HTTP 非 200 / 响应 JSON 损坏为基础设施错误（fail-closed，
// 永不放行）；顶层 Code 非 Success / Success=false / VerifyResult=false 一律
// ErrInvalid（含厂商限流容灾取值，本实现不做 fail-open 放行）。
func (v *Verifier) Verify(ctx context.Context, _ string, sub provider.Submission) error {
	if sub.Token == "" {
		return fmt.Errorf("%w: empty captcha token", provider.ErrInvalid)
	}
	form := url.Values{}
	form.Set("Action", apiAction)
	form.Set("Version", apiVersion)
	form.Set("Format", "JSON")
	form.Set("AccessKeyId", v.accessKeyID)
	form.Set("SignatureMethod", "HMAC-SHA1")
	form.Set("SignatureVersion", "1.0")
	form.Set("SignatureNonce", v.nonceFunc())
	form.Set("Timestamp", v.nowFunc().UTC().Format("2006-01-02T15:04:05Z"))
	// captchaVerifyParam 原样透传：不解析、不重组、不改写（V2 JSON 字符串 /
	// V3 紧凑字符串两种形态都要能过）。
	form.Set("CaptchaVerifyParam", sub.Token)
	// SceneId 服务端从 Ext 下发，不从前端取（防篡改场景 ID，接口文档 §2.5）。
	form.Set("SceneId", v.sceneID)
	form.Set("Signature", aliyunrpc.SignRPCForm(form, v.accessKeySecret))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("captcha: build aliyun_captcha request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.hc.Do(req)
	if err != nil {
		return fmt.Errorf("captcha: post aliyun_captcha verify: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("captcha: aliyun_captcha verify status %d", resp.StatusCode)
	}
	var out struct {
		Success bool   `json:"Success"`
		Code    string `json:"Code"`
		Message string `json:"Message"`
		Result  struct {
			VerifyResult bool   `json:"VerifyResult"`
			VerifyCode   string `json:"VerifyCode"`
		} `json:"Result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, remoteBodyLimit)).Decode(&out); err != nil {
		return fmt.Errorf("captcha: decode aliyun_captcha response: %w", err)
	}
	// Code 空（部分成功响应省略）视为通过该层；非空非 Success 即 API 级失败，
	// 校验没有发生、按校验不通过拒绝。
	if out.Code != "" && out.Code != "Success" {
		return fmt.Errorf("%w: aliyun_captcha code=%s message=%s", provider.ErrInvalid, out.Code, out.Message)
	}
	if !out.Success {
		return fmt.Errorf("%w: aliyun_captcha success=false code=%s message=%s", provider.ErrInvalid, out.Code, out.Message)
	}
	if !out.Result.VerifyResult {
		return fmt.Errorf("%w: aliyun_captcha verify_result=false verify_code=%q", provider.ErrInvalid, out.Result.VerifyCode)
	}
	return nil
}
