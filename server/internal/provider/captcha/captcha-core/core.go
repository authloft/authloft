// Package captchacore 三家远程人机校验（turnstile / recaptcha / hcaptcha）
// 的共用实现（docs/后端架构.md §9.1 阶段三，对齐 auth/oauthcore 先例）：
// 「secret + response 表单 POST + JSON success 判定」的 siteverify 逻辑与
// 管理后台 Schema 声明沉本包，各 type 子包只声明 type 常量与厂商默认端点
// （方案 §4.1）。stdlib net/http 零新依赖；配置取自 Ext（口径 §9.1：
// site_key=client_id、secret=client_secret、endpoint=自定义校验地址），
// 代理经 Provider.Outbound（§15.4 装配期固化、运行期不回读）。
//
// 校验不通过 / 已使用返回 provider.ErrInvalid（可包裹）；其它错误为基础
// 设施错误。第三方 token 的一次性由厂商保证，Authloft 侧零存储（§9.2）。
package captchacore

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
)

// remoteBodyLimit siteverify 响应体读取上限（64 KiB，防异常端点拖挂）。
const remoteBodyLimit = 1 << 16

// Verifier 三家共用的 siteverify 校验实现：构造期从 Provider 实例固化
// secret / endpoint / 出站连接池，运行期零配置读取（§13.0）。
type Verifier struct {
	secret    string
	verifyURL string
	hc        *http.Client
}

// New 从 Provider 实例构造（factory 产物）：endpoint 取 ext.endpoint，
// 空串回落厂商默认（defaultVerifyURL 由各 type 子包声明）；Outbound 非 nil
// 用池化 client（Transport 共享、连接复用），nil 用 10s 超时默认客户端。
func New(p *provider.Provider, defaultVerifyURL string) (*Verifier, error) {
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
	return &Verifier{secret: p.Ext.GetClientSecret(), verifyURL: endpoint, hc: hc}, nil
}

// Verify secret + response 表单 POST 到 siteverify，JSON success 判定
// （三家厂商同一形态，§9.1）。空 token 不发请求直接判无效。
func (v *Verifier) Verify(ctx context.Context, _ string, sub provider.Submission) error {
	if sub.Token == "" {
		return fmt.Errorf("%w: empty captcha token", provider.ErrInvalid)
	}
	form := url.Values{}
	form.Set("secret", v.secret)
	form.Set("response", sub.Token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("captcha: build siteverify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
		provider.FieldMeta{Key: "ui_group", Label: "admin.schemaField.uiGroupLabel", Type: "select", Section: "display",
			Options: []string{"social", "enterprise", "dev", "other"}, Default: "social", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "sort_order", Label: "admin.schemaField.sortOrderLabel", Type: "number", Section: "display", Default: "0", Storage: provider.StorageColumn},
		provider.FieldMeta{Key: "remark", Label: "admin.schemaField.remarkLabel", Type: "text", Section: "display", Advanced: true, Storage: provider.StorageColumn},
		provider.ProxyRef(),
	)
	return fields
}
