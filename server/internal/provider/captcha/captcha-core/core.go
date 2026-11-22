// Package captchacore 远程人机校验（turnstile / recaptcha / hcaptcha，及
// 复用本骨架的 capjs）的共用实现（docs/后端架构.md §9.1 阶段三，对齐
// auth/oauthcore 先例）：「secret + response 编码 POST + JSON success 判定」
// 的 siteverify 逻辑与管理后台 Schema 声明沉本包，各 type 子包只声明 type
// 常量与厂商默认端点（方案 §4.1）。三家走 form 编码；capjs（capd）请求/
// 响应与 reCAPTCHA 同构而 Content-Type 为 JSON，经 NewJSON 复用同一验证流程
// 仅切换编码（§15.5）。stdlib net/http 零新依赖；配置取自 Ext（口径 §9.1：
// site_key=client_id、secret=client_secret、endpoint=自定义校验地址），
// 代理经 Provider.Outbound（§15.4 装配期固化、运行期不回读）。
//
// 校验不通过 / 已使用返回 provider.ErrInvalid（可包裹）；其它错误为基础
// 设施错误。第三方 token 的一次性由厂商保证，Authloft 侧零存储（§9.2）。
package captchacore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"authloft/internal/provider"
)

// remoteBodyLimit siteverify 响应体读取上限（64 KiB，防异常端点拖挂）。
const remoteBodyLimit = 1 << 16

// Verifier 三家共用的 siteverify 校验实现：构造期从 Provider 实例固化
// secret / endpoint / 出站连接池，运行期零配置读取（§13.0）。jsonBody 决定
// 请求体编码：false = form（三家），true = JSON body（capjs 的 capd
// siteverify）；两者共享同一响应判定骨架。
type Verifier struct {
	secret    string
	verifyURL string
	jsonBody  bool
	hc        *http.Client
}

// New 从 Provider 实例构造（factory 产物）：endpoint 取 ext.endpoint，
// 空串回落厂商默认（defaultVerifyURL 由各 type 子包声明）；Outbound 非 nil
// 用池化 client（Transport 共享、连接复用），nil 用 10s 超时默认客户端。
func New(p *provider.Provider, defaultVerifyURL string) (*Verifier, error) {
	return newVerifier(p, defaultVerifyURL, false)
}

// NewJSON 同 New 的 JSON body 编码版（capjs 子包工厂专用入口，§15.5）：
// 请求体恰为 {secret, response} 两键、Content-Type application/json，
// 端点解析与响应判定与 form 分支同一骨架。
func NewJSON(p *provider.Provider, defaultVerifyURL string) (*Verifier, error) {
	return newVerifier(p, defaultVerifyURL, true)
}

func newVerifier(p *provider.Provider, defaultVerifyURL string, jsonBody bool) (*Verifier, error) {
	if p == nil || p.Ext == nil {
		return nil, fmt.Errorf("captcha: nil provider ext")
	}
	endpoint := strings.TrimSpace(p.Ext.GetEndpoint())
	if endpoint == "" {
		endpoint = defaultVerifyURL
	}
	hc := &http.Client{Timeout: 10 * time.Second}
	if p.Outbound != nil {
		hc = p.Outbound.HTTPClient(10 * time.Second)
	}
	return &Verifier{secret: p.Ext.GetClientSecret(), verifyURL: endpoint, jsonBody: jsonBody, hc: hc}, nil
}

// Verify secret + response 编码 POST 到 siteverify，JSON success 判定
// （form 编码为三家同一形态 §9.1；capjs 走 JSON 编码 §15.5）。空 token 不发
// 请求直接判无效；HTTP 非 200 / 响应 JSON 损坏一律基础设施错误、success=
// false 判 ErrInvalid——全路径 fail-closed。
func (v *Verifier) Verify(ctx context.Context, _ string, sub provider.Submission) error {
	if sub.Token == "" {
		return fmt.Errorf("%w: empty captcha token", provider.ErrInvalid)
	}
	var req *http.Request
	var err error
	if v.jsonBody {
		body, mErr := json.Marshal(struct {
			Secret   string `json:"secret"`
			Response string `json:"response"`
		}{Secret: v.secret, Response: sub.Token})
		if mErr != nil {
			return fmt.Errorf("captcha: encode siteverify request: %w", mErr)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, bytes.NewReader(body))
	} else {
		form := url.Values{}
		form.Set("secret", v.secret)
		form.Set("response", sub.Token)
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(form.Encode()))
	}
	if err != nil {
		return fmt.Errorf("captcha: build siteverify request: %w", err)
	}
	if v.jsonBody {
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := v.hc.Do(req)
	if err != nil {
		return fmt.Errorf("captcha: post siteverify: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("captcha: siteverify status %d", resp.StatusCode)
	}
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, remoteBodyLimit)).Decode(&out); err != nil {
		return fmt.Errorf("captcha: decode siteverify response: %w", err)
	}
	if !out.Success {
		return provider.ErrInvalid
	}
	return nil
}

// extFields 三家 captcha Ext 字段的单一来源（site_key / secret / 自定义校验
// 地址）；每次返回独立切片，调用方补 Storage 落点不会污染其他调用。
func extFields() []provider.FieldMeta {
	return []provider.FieldMeta{
		{Key: "client_id", Label: "admin.schemaField.captchaSiteKeyLabel", Type: "text", Section: "credential", Required: true},
		{Key: "client_secret", Label: "admin.schemaField.captchaSecretLabel", Type: "secret", Section: "credential", Required: true},
		{Key: "endpoint", Label: "admin.schemaField.captchaEndpointLabel", Type: "text", Section: "endpoint", Advanced: true},
	}
}

// Schema 三家 captcha 共用的完整字段声明（表列 + Ext + 引用键，接口文档
// §5.3），供各 type 子包的 meta 引用，每次调用返回新切片。Ext 复用 fields
// 单一来源并补 Storage 落点，防两份声明漂移；is_enabled / 登录 / 建号 /
// 自动绑定开关是 auth 专属，captcha 类别不下发也不消费（生效实例判定
// 只看 settings 键 → 行命中，captcha/catalog.go）。
func Schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 10)
	fields = append(fields,
		provider.FieldMeta{Key: "provider_key", Label: "admin.schemaField.providerKeyLabel", Type: "text", Section: "basic", Required: true,
			Pattern: "^[a-z0-9_]+$", Help: "admin.schemaField.providerKeyHelp", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "display_name", Label: "admin.schemaField.displayNameLabel", Type: "text", Section: "basic", Required: true, Storage: provider.StorageColumn},
	)
	ext := extFields()
	for i := range ext {
		ext[i].Storage = provider.StorageExt
	}
	fields = append(fields, ext...)
	fields = append(fields,
		provider.FieldMeta{Key: "icon_url", Label: "admin.schemaField.iconUrlLabel", Type: "text", Section: "display",
			Pattern: "^https?://", Help: "admin.schemaField.iconUrlHelp", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "sort_order", Label: "admin.schemaField.sortOrderLabel", Type: "number", Section: "display", Default: "0", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "remark", Label: "admin.schemaField.remarkLabel", Type: "text", Section: "display", Advanced: true, Storage: provider.StorageColumn},
		provider.ProxyRef(),
	)
	return fields
}
