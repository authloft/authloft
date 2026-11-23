// Package geetest_v4 极验行为验证 4 代人机校验实现（docs/后端架构.md §9.1 /
// §15.5）：协议私有专用 Verifier——前端 getValidate() 的四字段
// （lot_number / captcha_output / pass_token / gen_time）整体 JSON 打包进
// Submission.Token（接口文档 §2.5 token 多字段承载口径），本包解包后按
// HMAC-SHA256(captcha_key, lot_number) 服务端生成 sign_token（永不从前端
// 收取），form 编码 POST /validate 判 result=="success"。不能套 captchacore
// 的 siteverify 骨架：签名动态生成、请求多字段、判定判 result 而非 success。
//
// stdlib crypto/hmac 零新依赖；配置取自 Ext（口径 §9.1：captcha_id=client_id、
// captcha_key=client_secret、endpoint=自定义校验地址），代理经 Provider.
// Outbound（§15.4 装配期固化）。正常返回但校验失败 fail-close（provider.
// ErrInvalid）；HTTP / JSON 层异常为基础设施错误。第三方 token 的一次性由
// 厂商保证，Authloft 侧零存储（§9.2）。
package geetest_v4

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"authloft/internal/provider"
	"authloft/internal/provider/schemafield"
)

// Type 注册类型。字面量暂落实现子包（同 capjs / storage s3 先例，
// servicetype.go 常量上移统一另行处理）。
const Type = "geetest_v4"

// defaultVerifyURL 厂商二次校验端点（ext.endpoint 空串时回落，§9.1）；
// captcha_id 放 URL query（厂商服务端部署口径）。
const defaultVerifyURL = "https://gcaptcha4.geetest.com/validate"

// remoteBodyLimit validate 响应体读取上限（64 KiB，防异常端点拖挂）。
const remoteBodyLimit = 1 << 16

// init 注册进统一注册表（§15.3）：Schema 是 /schema 的唯一数据源（表列 +
// Ext + 引用键，接口文档 §5.3 captcha 行），校验走专用 Verifier。
func init() {
	provider.RegisterVerifier(Type, provider.Meta{
		DisplayName: "GeeTest v4",
		Category:    provider.CategoryCaptcha,
		Schema:      schema,
		// CSP 源声明随实现走（§9.4；源值 = 接口文档 §8 参考源清单 geetest_v4
		// 行，不在 csp.go 写死厂商域）：前端 iframe 与 challenge 资源域名。
		CSPSources: map[string][]string{
			"frame-src": {"https://gcaptcha4.geetest.com"},
		},
	}, newVerifier)
}

// schema /schema 唯一数据源：表列基线与三家一致（schemafield 单一来源），
// Ext 按 §15.5 geetest_v4 行序 client_id / client_secret / endpoint /
// widget_product / widget_options——后两者是前端初始化形态（widget_product
// 交互模式三选一 default bind；widget_options JSON 文本原样透传前端），
// 服务端 Verifier 不消费，声明仅为随配置下发（声明即消费红线不破：消费方
// 是前端 adapter，T-089）。is_enabled / 登录建号开关是 auth 专属，captcha
// 类别不下发也不消费（生效实例判定只看 settings 键 → 行命中）。
func schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 12)
	fields = append(fields, schemafield.ProviderKey(), schemafield.DisplayName())
	common := schemafield.CaptchaFields()
	fields = append(fields, common[0], common[1], common[2])
	fields = append(fields,
		provider.FieldMeta{Key: "widget_product", Label: "admin.schemaField.widgetProductLabel", Type: "select", Section: "display",
			Options: []string{"bind", "popup", "float"}, Default: "bind",
			Help: "admin.schemaField.widgetProductHelp", Storage: provider.StorageExt},
		provider.FieldMeta{Key: "widget_options", Label: "admin.schemaField.widgetOptionsLabel", Type: "text", Section: "display", Advanced: true,
			Help: "admin.schemaField.widgetOptionsHelp", Storage: provider.StorageExt},
	)
	fields = append(fields, schemafield.IconURL(), schemafield.SortOrder(), schemafield.Remark(), schemafield.ProxyRef())
	return fields
}

// validateFields token 打包的四字段（接口文档 §2.5 承载口径），缺一即拒。
type validateFields struct {
	LotNumber     string `json:"lot_number"`
	CaptchaOutput string `json:"captcha_output"`
	PassToken     string `json:"pass_token"`
	GenTime       string `json:"gen_time"`
}

// Verifier 极验 v4 专用校验实现：构造期从 Provider 实例固化 captcha_id /
// captcha_key / 校验地址（captcha_id 已并入 query）/ 出站连接池，运行期零
// 配置读取（§13.0）。
type Verifier struct {
	verifyURL  string
	captchaID  string
	captchaKey string
	hc         *http.Client
}

// newVerifier 注册表工厂：client_id / client_secret 缺任一即构造失败——
// 签名与 captcha_id 都没有就无法构造合法校验请求，属配置残缺，fail-fast
// （同 capjs / storage 构造期缺失报错口径），不留到运行期才失败。
func newVerifier(p *provider.Provider) (provider.Verifier, error) {
	if p == nil || p.Ext == nil {
		return nil, fmt.Errorf("captcha: nil provider ext")
	}
	captchaID := strings.TrimSpace(p.Ext.GetClientId())
	captchaKey := p.Ext.GetClientSecret()
	if captchaID == "" || captchaKey == "" {
		return nil, fmt.Errorf("captcha: geetest_v4 client_id(captcha_id) 与 client_secret(captcha_key) 均必填")
	}
	endpoint := strings.TrimSpace(p.Ext.GetEndpoint())
	if endpoint == "" {
		endpoint = defaultVerifyURL
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("captcha: geetest_v4 endpoint 非法: %w", err)
	}
	q := u.Query()
	q.Set("captcha_id", captchaID)
	u.RawQuery = q.Encode()
	hc := &http.Client{Timeout: 10 * time.Second}
	if p.Outbound != nil {
		hc = p.Outbound.HTTPClient(10 * time.Second)
	}
	return &Verifier{verifyURL: u.String(), captchaID: captchaID, captchaKey: captchaKey, hc: hc}, nil
}

// signToken HMAC-SHA256(key=captcha_key, msg=lot_number) 的 hex 小写串
// （厂商服务端二次校验口径；captcha_key 只在服务端，绝不下发前端）。
func signToken(captchaKey, lotNumber string) string {
	mac := hmac.New(sha256.New, []byte(captchaKey))
	mac.Write([]byte(lotNumber))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify 解包 token 四字段 → 签 sign_token → form POST /validate 判
// result=="success"。空 token / 解包失败 / 缺任一字段 / 非-success 一律
// fail-closed 返回 ErrInvalid；HTTP 非 200 / 响应 JSON 损坏为基础设施错误。
func (v *Verifier) Verify(ctx context.Context, _ string, sub provider.Submission) error {
	if sub.Token == "" {
		return fmt.Errorf("%w: empty captcha token", provider.ErrInvalid)
	}
	var fields validateFields
	if err := json.Unmarshal([]byte(sub.Token), &fields); err != nil {
		return fmt.Errorf("%w: geetest_v4 token 非四字段 JSON: %w", provider.ErrInvalid, err)
	}
	if fields.LotNumber == "" || fields.CaptchaOutput == "" || fields.PassToken == "" || fields.GenTime == "" {
		return fmt.Errorf("%w: geetest_v4 token 缺 lot_number/captcha_output/pass_token/gen_time 任一字段", provider.ErrInvalid)
	}
	form := url.Values{}
	form.Set("lot_number", fields.LotNumber)
	form.Set("captcha_output", fields.CaptchaOutput)
	form.Set("pass_token", fields.PassToken)
	form.Set("gen_time", fields.GenTime)
	form.Set("sign_token", signToken(v.captchaKey, fields.LotNumber))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("captcha: build geetest_v4 request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.hc.Do(req)
	if err != nil {
		return fmt.Errorf("captcha: post geetest_v4 validate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("captcha: geetest_v4 validate status %d", resp.StatusCode)
	}
	var out struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, remoteBodyLimit)).Decode(&out); err != nil {
		return fmt.Errorf("captcha: decode geetest_v4 response: %w", err)
	}
	// 只判 result=="success"（厂商口径）：status="error"（宕机/参数错）响应
	// 无 result 或非 success，同归校验不通过。
	if out.Result != "success" {
		return fmt.Errorf("%w: geetest_v4 result=%q", provider.ErrInvalid, out.Result)
	}
	return nil
}
