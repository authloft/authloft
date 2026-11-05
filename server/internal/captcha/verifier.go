// verifier.go 是 gate.go Verifier 接口的实装（docs/后端架构.md §9.1
// 行 1085-1090、§9.2）：按 providerKey 分派——builtin_image 不查表直接走
// 内置图形码（接口文档 §2.5 行 515「内置项不是 Provider 表记录」）；
// 其余经 ProviderSource 取行按 type 分派，type=image 同样核 al:cap:{id}
// （§9.2 行 1103，不另写第二条校验路径）。三家第三方均为「secret +
// response 表单 POST + JSON success 判定」（§9.1 行 1088-1090），
// stdlib net/http 零新依赖；可注入 http.Client 与 siteverify 地址覆盖
// （对齐 aliyun_sms 的可测试性模式）。校验不通过 / 已使用返回
// ErrInvalid（可包裹）；其它错误为基础设施错误（Gate 侧映射 failed）。
package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 第三方渠道 type 与 siteverify 默认端点（§9.1 行 1088-1090；type 封闭
// 集合与 gate.go normalize 一致）。
const (
	TypeTurnstile = "turnstile"
	TypeRecaptcha = "recaptcha"
	TypeHcaptcha  = "hcaptcha"

	turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	recaptchaVerifyURL = "https://www.google.com/recaptcha/api/siteverify"
	hcaptchaVerifyURL  = "https://api.hcaptcha.com/siteverify"
)

// remoteBodyLimit siteverify 响应体读取上限（64 KiB，防异常端点拖挂）。
const remoteBodyLimit = 1 << 16

// VerifierOptions 可注入项：HTTPClient 缺省为 10s 超时客户端；VerifyURLs
// 按 type 覆盖 siteverify 地址（测试注入假端点，优先级最高，其次
// ProviderRecord.VerifyURL / Ext.endpoint）。
type VerifierOptions struct {
	HTTPClient *http.Client
	VerifyURLs map[string]string
}

// ServiceVerifier Verifier 实装：不自持 DB / Redis 句柄，行源与图形码
// 存储均经构造注入。
type ServiceVerifier struct {
	source ProviderSource
	images Store
	hc     *http.Client
	urls   map[string]string
}

// NewVerifier 注入 provider 行源（取 type / secret / endpoint）与图形码
// 存储（cache.CaptchaStore，Lua GETDEL 一次性）。
func NewVerifier(source ProviderSource, images Store, opts VerifierOptions) *ServiceVerifier {
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	urls := opts.VerifyURLs
	if urls == nil {
		urls = map[string]string{}
	}
	return &ServiceVerifier{source: source, images: images, hc: hc, urls: urls}
}

// Verify 按 providerKey 分派（gate.go 已保证 providerKey 为当前生效
// 配置项，前端不能任意指定渠道）。
func (v *ServiceVerifier) Verify(ctx context.Context, providerKey string, sub Submission) error {
	if providerKey == BuiltinProviderKey {
		return v.verifyImage(ctx, sub)
	}
	rec, err := v.load(ctx, providerKey)
	if err != nil {
		return err
	}
	switch rec.Type {
	case TypeImage:
		return v.verifyImage(ctx, sub)
	case TypeTurnstile, TypeRecaptcha, TypeHcaptcha:
		return v.verifyRemote(ctx, rec, sub)
	default:
		return fmt.Errorf("captcha: unsupported provider type %q", rec.Type)
	}
}

// load 取 provider 行；无此行按校验不通过处理（ErrInvalid），查询故障为
// 基础设施错误。
func (v *ServiceVerifier) load(ctx context.Context, providerKey string) (*ProviderRecord, error) {
	rec, err := v.source.Find(ctx, providerKey)
	if err != nil {
		return nil, fmt.Errorf("captcha: load provider %q: %w", providerKey, err)
	}
	if rec == nil {
		return nil, fmt.Errorf("%w: provider %q not found", ErrInvalid, providerKey)
	}
	return rec, nil
}

// verifyImage 内置自绘路径：id + answer 核 al:cap:{id}，GETDEL 原子消费
// 由注入的 Store 保证（cache.CaptchaStore，正确 / 错误都消费）。
func (v *ServiceVerifier) verifyImage(ctx context.Context, sub Submission) error {
	if sub.ID == "" {
		return fmt.Errorf("%w: empty captcha id", ErrInvalid)
	}
	ok, err := v.images.Verify(ctx, sub.ID, sub.Answer)
	if err != nil {
		return fmt.Errorf("captcha: verify image store: %w", err)
	}
	if !ok {
		return ErrInvalid
	}
	return nil
}

// verifyRemote 第三方路径：secret + response 表单 POST 到 siteverify，
// JSON success 判定（三家厂商同一形态，§9.1 行 1088-1090）。
func (v *ServiceVerifier) verifyRemote(ctx context.Context, rec *ProviderRecord, sub Submission) error {
	if sub.Token == "" {
		return fmt.Errorf("%w: empty captcha token", ErrInvalid)
	}
	form := url.Values{}
	form.Set("secret", rec.Secret)
	form.Set("response", sub.Token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint(rec), strings.NewReader(form.Encode()))
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
		return ErrInvalid
	}
	return nil
}

// endpoint siteverify 地址优先级：构造注入覆盖（测试）> Ext.endpoint
// （§9.1 行 1083 自定义校验地址）> 厂商默认。
func (v *ServiceVerifier) endpoint(rec *ProviderRecord) string {
	if u, ok := v.urls[rec.Type]; ok && u != "" {
		return u
	}
	if rec.VerifyURL != "" {
		return rec.VerifyURL
	}
	switch rec.Type {
	case TypeTurnstile:
		return turnstileVerifyURL
	case TypeRecaptcha:
		return recaptchaVerifyURL
	default:
		return hcaptchaVerifyURL
	}
}
