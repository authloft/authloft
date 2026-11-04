// aliyun_sms_test.go：阿里云短信 Sender 单测（httptest 拦截请求，不打真实
// 外部服务）：请求形态（Action / PhoneNumbers / SignName / TemplateCode /
// TemplateParam）与 RPC HMAC-SHA1 签名复算、模板键覆盖、厂商错误码、
// 构造期 Ext 校验。
package aliyunsms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

const (
	testAccessKeyID     = "LTAI_test_ak"
	testAccessKeySecret = "test_secret_value"
	testSignName        = "Authloft测试签名"
	testTemplateCode    = "SMS_12345678"
)

// testProvider 构造带完整凭证的 Provider 实例（Ext 唯一编解码出口 repo）。
func testProvider(t *testing.T, mutate func(*providerpb.Ext)) *provider.Provider {
	t.Helper()
	ext := &providerpb.Ext{
		ClientId:     testAccessKeyID,
		ClientSecret: testAccessKeySecret,
		SignName:     testSignName,
		TemplateCode: testTemplateCode,
	}
	if mutate != nil {
		mutate(ext)
	}
	raw, err := repo.MarshalProviderExt(ext)
	if err != nil {
		t.Fatalf("marshal ext: %v", err)
	}
	return &provider.Provider{
		Key:  "sms_main",
		Type: Type,
		Row:  &model.Provider{ProviderKey: "sms_main", Type: Type, IsEnabled: 1, Ext: raw},
		Ext:  ext,
	}
}

// TestBuildRequiresCredentials 构造期校验：AccessKeyId / AccessKeySecret /
// SignName 缺一即 ErrNotConfigured；齐全则 endpoint 回落公网默认。
func TestBuildRequiresCredentials(t *testing.T) {
	if _, err := build(testProvider(t, func(e *providerpb.Ext) { e.ClientId = "" }), nil); !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("missing AccessKeyId err = %v", err)
	}
	if _, err := build(testProvider(t, func(e *providerpb.Ext) { e.SignName = "" }), nil); !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("missing SignName err = %v", err)
	}
	s, err := build(testProvider(t, nil), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if s.endpoint != defaultEndpoint {
		t.Fatalf("endpoint = %q, want default %q", s.endpoint, defaultEndpoint)
	}
	// intranet_endpoint 优先回源（§5.3 行 1236：服务端回源优先使用）。
	s, err = build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = "http://intranet.local" }), nil)
	if err != nil {
		t.Fatalf("build(intranet): %v", err)
	}
	if s.endpoint != "http://intranet.local" {
		t.Fatalf("endpoint = %q, want intranet override", s.endpoint)
	}
}

// TestSendSignsAndPostsCorrectForm 请求形态 + 签名复算：Action / Version /
// 手机号 / 签名 / 模板 / 模板变量逐项断言；服务端按同一算法复算 Signature 必须
// 与请求一致（RPC 签名 V1.0）。
func TestSendSignsAndPostsCorrectForm(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		gotForm = r.Form
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %q", ct)
		}
		_, _ = w.Write([]byte(`{"Code":"OK","BizId":"b1","RequestId":"r1"}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "13800138000", "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	for key, want := range map[string]string{
		"Action":           "SendSms",
		"Version":          "2017-05-25",
		"Format":           "JSON",
		"AccessKeyId":      testAccessKeyID,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"PhoneNumbers":     "13800138000",
		"SignName":         testSignName,
		"TemplateCode":     testTemplateCode,
		"TemplateParam":    `{"code":"246810"}`,
	} {
		if got := gotForm.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	// Timestamp：UTC ISO8601（Z 结尾）。
	if ts := gotForm.Get("Timestamp"); !strings.HasSuffix(ts, "Z") || len(ts) != len("2006-01-02T15:04:05Z") {
		t.Errorf("Timestamp = %q, want UTC ISO8601", ts)
	}
	// SignatureNonce：防重放随机数，必须非空。
	if len(gotForm.Get("SignatureNonce")) == 0 {
		t.Error("SignatureNonce is empty")
	}
	// 签名复算：剔除 Signature 后按同一密钥重算必须一致。
	recomputed := signRPCForm(gotForm, testAccessKeySecret)
	if got := gotForm.Get("Signature"); got != recomputed {
		t.Errorf("Signature = %q, want recomputed %q", got, recomputed)
	}
}

// TestSendKnownSignatureVector 已知签名向量（§22.2 行 1978：时间源/随机源
// 可注入）：固定 now / nonce → 固定 HMAC-SHA1 签名，逐字节比对。期望值
// 独立于 signRPCForm 按阿里云 RPC 签名 V1.0 公开规范预计算，签名算法
// 被改动即红。
func TestSendKnownSignatureVector(t *testing.T) {
	fixedNow := time.Date(2026, time.November, 4, 12, 0, 0, 0, time.UTC)
	const fixedNonce = "fixed-nonce-000"
	const wantSignature = "AhY3raksWTO4KDEdDuLe58qIII8="

	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		_, _ = w.Write([]byte(`{"Code":"OK"}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	s.nowFunc = func() time.Time { return fixedNow }
	s.nonceFunc = func() string { return fixedNonce }
	if err := s.Send(context.Background(), "13800138000", "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if got := gotForm.Get("Timestamp"); got != "2026-11-04T12:00:00Z" {
		t.Errorf("Timestamp = %q, want fixed clock time", got)
	}
	if got := gotForm.Get("SignatureNonce"); got != fixedNonce {
		t.Errorf("SignatureNonce = %q, want injected nonce", got)
	}
	if got := gotForm.Get("Signature"); got != wantSignature {
		t.Errorf("Signature = %q, want known vector %q", got, wantSignature)
	}
	// build 缺省注入时间源/随机源（既有调用方与 bootstrap 装配行为不变）。
	def, err := build(testProvider(t, nil), nil)
	if err != nil || def.nowFunc == nil || def.nonceFunc == nil {
		t.Fatalf("build must default nowFunc/nonceFunc: err=%v", err)
	}
}

// TestSendTemplateKeyOverride 模板键覆盖：metadata["template_code."+tpl]
// 优先于 Ext.template_code（§15.2 行 1725：模板内容存 metadata）。
func TestSendTemplateKeyOverride(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		_, _ = w.Write([]byte(`{"Code":"OK"}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.Metadata = map[string]string{"template_code.otp": "SMS_ OVERRIDE_999", "template_code.marketing": "SMS_999"}
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "13800138000", "otp", map[string]string{"code": "135790"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := gotForm.Get("TemplateCode"); got != "SMS_ OVERRIDE_999" {
		t.Fatalf("TemplateCode = %q, want metadata override", got)
	}
}

// TestSendVendorErrorCode 厂商错误码：Code != OK → 携带 Code / Message 的错误。
func TestSendVendorErrorCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Code":"isv.BUSINESS_LIMIT_CONTROL","Message":"流控限制"}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = s.Send(context.Background(), "13800138000", "otp", map[string]string{"code": "111111"})
	if err == nil || !strings.Contains(err.Error(), "isv.BUSINESS_LIMIT_CONTROL") {
		t.Fatalf("err = %v, want vendor code in message", err)
	}
}

// TestSendHTTPError 非 200 → 错误携带状态码。
func TestSendHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream down"))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "13800138000", "otp", map[string]string{"code": "111111"}); err == nil {
		t.Fatal("Send on http 503 must fail")
	}
}

// TestSendValidation 收件号码为空 / 模板 ID 为空 → 明确错误，不发请求。
func TestSendValidation(t *testing.T) {
	s, err := build(testProvider(t, nil), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "", "otp", nil); err != ErrEmptyTo {
		t.Fatalf("empty to err = %v, want ErrEmptyTo", err)
	}
	noTpl, err := build(testProvider(t, func(e *providerpb.Ext) { e.TemplateCode = "" }), nil)
	if err != nil {
		t.Fatalf("build(no tpl): %v", err)
	}
	if err := noTpl.Send(context.Background(), "13800138000", "otp", map[string]string{"code": "1"}); err == nil ||
		!strings.Contains(err.Error(), "template code empty") {
		t.Fatalf("no template err = %v, want template-not-configured", err)
	}
}

// TestBuildNilExt nil 实例 / nil Ext → ErrNilProvider。
func TestBuildNilExt(t *testing.T) {
	if _, err := build(nil, nil); err != provider.ErrNilProvider {
		t.Fatalf("nil provider err = %v", err)
	}
	if _, err := build(&provider.Provider{Key: "k", Type: Type, Row: &model.Provider{}, Ext: nil}, nil); err != provider.ErrNilProvider {
		t.Fatalf("nil ext err = %v", err)
	}
}

// TestInitRegistersAsSMSVendor init() 已按 §15.3 注册（category=sms，meta
// 声明 Ext 字段口径供 /schema 渲染）。
func TestInitRegistersAsSMSVendor(t *testing.T) {
	meta, ok := provider.LookupSenderMeta(Type)
	if !ok {
		t.Fatal("aliyun_sms not registered in sender registry")
	}
	if meta.Category != provider.CategorySMS {
		t.Fatalf("category = %q, want sms", meta.Category)
	}
	if len(meta.Fields) == 0 {
		t.Fatal("meta.Fields must declare Ext field schema for /schema")
	}
	var hasTemplateCode bool
	for _, f := range meta.Fields {
		if f.Key == "template_code" && f.Section == "credential" {
			hasTemplateCode = true
		}
	}
	if !hasTemplateCode {
		t.Fatal("meta.Fields must include template_code (credential)")
	}
}
