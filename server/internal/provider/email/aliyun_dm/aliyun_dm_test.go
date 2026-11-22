// aliyun_dm_test.go：阿里云邮件推送 Sender 单测（httptest 拦截请求，不打
// 真实外部服务）：请求形态（Action / AccountName / AddressType /
// ReplyToAddress 字符串化）与 RPC HMAC-SHA1 签名复算、本地模板渲染与转义、
// 厂商错误码、构造期 Ext 校验与 fail-closed 路径。签名的可证伪已知向量在
// aliyunrpc 包测试（手写规范串 + 独立 HMAC 复算）。
package aliyundm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/aliyunrpc"
	"authloft/internal/proxyclient"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

const (
	testAccessKeyID     = "LTAI_test_ak"
	testAccessKeySecret = "test_secret_value"
	testFrom            = "no-reply@mail.example.com"
	testAlias           = "Authloft"
)

// testProvider 构造带完整凭证的 Provider 实例（Ext 唯一编解码出口 repo）。
func testProvider(t *testing.T, mutate func(*providerpb.Ext)) *provider.Provider {
	t.Helper()
	ext := &providerpb.Ext{
		ClientId:       testAccessKeyID,
		ClientSecret:   testAccessKeySecret,
		From:           testFrom,
		SignName:       testAlias,
		ReplyToAddress: true, // 表单 checkbox default true 的落库形态
	}
	if mutate != nil {
		mutate(ext)
	}
	raw, err := repo.MarshalProviderExt(ext)
	if err != nil {
		t.Fatalf("marshal ext: %v", err)
	}
	return &provider.Provider{
		Key:  "email_main",
		Type: Type,
		Row:  &model.Provider{ProviderKey: "email_main", Type: Type, IsEnabled: 1, Ext: raw},
		Ext:  ext,
	}
}

// TestBuildRequiresCredentials 构造期校验：AccessKeyId / AccessKeySecret /
// 发信地址缺一即 ErrNotConfigured；address_type 非封闭集取值 fail-closed；
// 空值回落 "1"（Schema default 同源）；endpoint 回落公网默认与内网覆盖。
func TestBuildRequiresCredentials(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*providerpb.Ext)
	}{
		{"missing client_id", func(e *providerpb.Ext) { e.ClientId = "" }},
		{"missing client_secret", func(e *providerpb.Ext) { e.ClientSecret = "" }},
		{"missing from", func(e *providerpb.Ext) { e.From = " " }},
		{"invalid address_type", func(e *providerpb.Ext) { e.AddressType = "2" }},
	} {
		if _, err := build(testProvider(t, tc.mut), nil); err == nil || !strings.Contains(err.Error(), "not configured") {
			t.Fatalf("%s: err = %v, want ErrNotConfigured", tc.name, err)
		}
	}
	s, err := build(testProvider(t, nil), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if s.endpoint != defaultEndpoint {
		t.Fatalf("endpoint = %q, want default %q", s.endpoint, defaultEndpoint)
	}
	if s.addressType != addressTypeSender {
		t.Fatalf("addressType = %q, want default %q", s.addressType, addressTypeSender)
	}
	if !s.replyToAddress {
		t.Fatal("replyToAddress = false, want proto bool passthrough true")
	}
	s, err = build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = "http://intranet.local"
		e.AddressType = addressTypeRandom
		e.ReplyToAddress = false
	}), nil)
	if err != nil {
		t.Fatalf("build(intranet): %v", err)
	}
	if s.endpoint != "http://intranet.local" {
		t.Fatalf("endpoint = %q, want intranet override", s.endpoint)
	}
	if s.addressType != addressTypeRandom {
		t.Fatalf("addressType = %q, want %q", s.addressType, addressTypeRandom)
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

// TestSendSignsAndPostsCorrectForm 请求形态 + 签名复算：Action / Version /
// 发信身份三元组 / 回信字符串化 / 标题正文逐项断言；服务端按同一算法复算
// Signature 必须与请求一致（RPC 签名 V1.0）；可选参数缺省不下发。
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
		_, _ = w.Write([]byte(`{"EnvId":"e1","RequestId":"r1"}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.Metadata = map[string]string{"subject.otp": "您的验证码", "body.otp": "<p>验证码 {code}</p>"}
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "user@example.com", "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	for key, want := range map[string]string{
		"Action":           "SingleSendMail",
		"Version":          rpcVersion,
		"Format":           "JSON",
		"AccessKeyId":      testAccessKeyID,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"AccountName":      testFrom,
		"AddressType":      addressTypeSender,
		"ReplyToAddress":   "true", // 布尔 → API 要求的字符串取值
		"ToAddress":        "user@example.com",
		"Subject":          "您的验证码",
		"HtmlBody":         "<p>验证码 246810</p>",
		"FromAlias":        testAlias,
	} {
		if got := gotForm.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	// Timestamp：UTC ISO8601（Z 结尾）；SignatureNonce：防重放随机数非空。
	if ts := gotForm.Get("Timestamp"); !strings.HasSuffix(ts, "Z") || len(ts) != len("2006-01-02T15:04:05Z") {
		t.Errorf("Timestamp = %q, want UTC ISO8601", ts)
	}
	if len(gotForm.Get("SignatureNonce")) == 0 {
		t.Error("SignatureNonce is empty")
	}
	// 签名复算：剔除 Signature 后按同一密钥重算必须一致。
	recomputed := aliyunrpc.SignRPCForm(gotForm, testAccessKeySecret)
	if got := gotForm.Get("Signature"); got != recomputed {
		t.Errorf("Signature = %q, want recomputed %q", got, recomputed)
	}
}

// TestSendReplyAddressStringification reply_to_address=false → "false"；
// reply_address 非空时随请求下发。
func TestSendReplyAddressStringification(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.SignName = ""
		e.ReplyToAddress = false
		e.ReplyAddress = "reply@example.com"
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "user@example.com", "otp", nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := gotForm.Get("ReplyToAddress"); got != "false" {
		t.Errorf("ReplyToAddress = %q, want %q", got, "false")
	}
	if got := gotForm.Get("ReplyAddress"); got != "reply@example.com" {
		t.Errorf("ReplyAddress = %q, want passthrough", got)
	}
	// 可选参数缺省不下发（FromAlias 空）。
	if _, ok := gotForm["FromAlias"]; ok {
		t.Errorf("empty FromAlias must be omitted, got %q", gotForm.Get("FromAlias"))
	}
}

// TestSendLocalTemplateRender 本地渲染（同 smtp 约定）：metadata 模板优先，
// 缺省回落最小兜底；{code} 占位替换且变量值按用户输入 HTML 转义
// （HtmlBody 语义，防注入）；占位替换仅正文。
func TestSendLocalTemplateRender(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.SignName = ""
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "user@example.com", "otp", map[string]string{"code": "<b>1</b>"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := gotForm.Get("Subject"); got != defaultSubject {
		t.Errorf("Subject = %q, want default %q", got, defaultSubject)
	}
	if got := gotForm.Get("HtmlBody"); got != strings.ReplaceAll(defaultBody, "{code}", "&lt;b&gt;1&lt;/b&gt;") {
		t.Errorf("HtmlBody = %q, want escaped default render", got)
	}
}

// TestSendTemplateKeyOverride 模板键覆盖：metadata["subject."+tpl] /
// ["body."+tpl] 按模板键取用（§15.2：模板内容存 metadata）。
func TestSendTemplateKeyOverride(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.SignName = ""
		e.Metadata = map[string]string{"subject.otp": "登录验证", "body.otp": "code={code}", "subject.other": "x"}
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "user@example.com", "otp", map[string]string{"code": "135790"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotForm.Get("Subject") != "登录验证" || gotForm.Get("HtmlBody") != "code=135790" {
		t.Fatalf("render = %q / %q, want otp templates", gotForm.Get("Subject"), gotForm.Get("HtmlBody"))
	}
}

// TestSendVendorErrorCode 厂商错误码：顶层 Code 非空即失败（成功形态无
// Code），携带 Code / Message。
func TestSendVendorErrorCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Code":"InvalidMailAddress.NotFound","Message":"发信地址未配置"}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL; e.SignName = "" }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = s.Send(context.Background(), "user@example.com", "otp", nil)
	if err == nil || !strings.Contains(err.Error(), "InvalidMailAddress.NotFound") {
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

	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL; e.SignName = "" }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "user@example.com", "otp", nil); err == nil {
		t.Fatal("Send on http 503 must fail")
	}
}

// TestSendInvalidJSONResponse 响应非 JSON → fail-closed（解码失败拒绝，
// 不静默当成功）。
func TestSendInvalidJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL; e.SignName = "" }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = s.Send(context.Background(), "user@example.com", "otp", nil)
	if err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("err = %v, want decode failure", err)
	}
}

// TestSendValidation 收件地址为空 → ErrEmptyTo，不发请求。
func TestSendValidation(t *testing.T) {
	s, err := build(testProvider(t, nil), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "", "otp", nil); err != ErrEmptyTo {
		t.Fatalf("empty to err = %v, want ErrEmptyTo", err)
	}
}

// TestSendKnownSignatureVector 已知签名向量（时间源/随机源可注入）：
// 固定 now / nonce → 固定 HMAC-SHA1 签名，逐字节比对。期望值独立于签名
// 实现按阿里云 RPC 签名 V1.0 公开规范预计算，签名算法被改动即红。
func TestSendKnownSignatureVector(t *testing.T) {
	fixedNow := time.Date(2026, time.November, 4, 12, 0, 0, 0, time.UTC)
	const fixedNonce = "fixed-nonce-000"
	const wantSignature = "q6E0yTlfA7hCjDv0mjoKRGkltiw="

	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.SignName = ""
		e.ReplyToAddress = false
		e.ReplyAddress = "reply@example.com"
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	s.nowFunc = func() time.Time { return fixedNow }
	s.nonceFunc = func() string { return fixedNonce }
	if err := s.Send(context.Background(), "user@example.com", "otp", map[string]string{"code": "246810"}); err != nil {
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

// TestInitRegistersAsEmailVendor init() 已按 §15.3 注册（category=email，
// Schema 声明完整字段口径供 /schema 渲染；template_code 无模板 ID 语义
// 不声明，auth 专属键不下发）。
func TestInitRegistersAsEmailVendor(t *testing.T) {
	meta, ok := provider.LookupSenderMeta(Type)
	if !ok {
		t.Fatal("aliyun_dm not registered in sender registry")
	}
	if meta.Category != provider.CategoryEmail {
		t.Fatalf("category = %q, want email", meta.Category)
	}
	schema := meta.Schema()
	if len(schema) == 0 {
		t.Fatal("meta.Schema() must declare full field schema for /schema")
	}
	byKey := map[string]provider.FieldMeta{}
	for _, f := range schema {
		byKey[f.Key] = f
	}
	at, ok := byKey["address_type"]
	if !ok {
		t.Fatal("meta.Schema() must include address_type (credential)")
	}
	if at.Type != "select" || len(at.Options) != 2 || at.Default != addressTypeSender {
		t.Fatalf("address_type select attrs = %v / %v / %q", at.Type, at.Options, at.Default)
	}
	if f := byKey["from"]; !f.Required {
		t.Error("from (AccountName) must be required")
	}
	if _, ok := byKey["template_code"]; ok {
		t.Error("meta.Schema() must not contain template_code（SingleSendMail 无模板 ID 参数）")
	}
	for _, key := range []string{"provider_key", "display_name", "reply_to_address", "reply_address", "intranet_endpoint", "metadata", provider.ProxyRefKey} {
		if _, found := byKey[key]; !found {
			t.Errorf("meta.Schema() missing %q", key)
		}
	}
	// is_enabled / union_provider 与登录 / 建号 / 自动绑定开关是 auth 专属，
	// email 类别不下发也不消费。
	for _, key := range []string{"is_enabled", "union_provider", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields"} {
		if _, found := byKey[key]; found {
			t.Errorf("meta.Schema() must not contain auth-only key %q", key)
		}
	}
	// 每次调用返回独立切片，调用方改动不得污染后续调用。
	mutated := meta.Schema()
	mutated[0].Key = "mutated"
	if meta.Schema()[0].Key == "mutated" {
		t.Error("meta.Schema() returns a shared slice")
	}
}

// proxyPool 按结构化字段构造单池（测试取池入口，PoolSet 键任意）。
func proxyPool(t *testing.T, scheme, host string, port int32, user, pass string) *proxyclient.Pool {
	t.Helper()
	cfg, err := proxyclient.NewConfig(scheme, host, port, user, pass)
	if err != nil {
		t.Fatal(err)
	}
	return proxyclient.NewPoolSet().Get("test", cfg)
}

// TestSendViaOutboundHTTPProxy http 代理桩实证：Outbound 非 nil 时邮件请求经
// 池化 client 走代理而非直连——目标与代理各自记录命中，代理命中且目标零命中
// 即证流量经代理（§15.4 全 scheme）。
func TestSendViaOutboundHTTPProxy(t *testing.T) {
	var directHits, proxyHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits++
		_, _ = w.Write([]byte(`{}`))
	}))
	defer target.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits++
		_, _ = w.Write([]byte(`{}`))
	}))
	defer proxy.Close()

	u, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	portNum, _ := strconv.Atoi(u.Port())
	p := testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = target.URL; e.SignName = "" })
	p.Outbound = proxyPool(t, "http", u.Hostname(), int32(portNum), "", "")
	s, err := newSender(p)
	if err != nil {
		t.Fatalf("newSender: %v", err)
	}
	if err := s.Send(context.Background(), "user@example.com", "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send via proxy: %v", err)
	}
	if proxyHits != 1 {
		t.Fatalf("代理命中 = %d, want 1（流量须经代理）", proxyHits)
	}
	if directHits != 0 {
		t.Fatalf("直连命中 = %d, want 0（不得绕过代理）", directHits)
	}
}

// TestInjectedClientOverridesProxy 测试注入的 hc 优先于 Outbound 代理配置：
// Outbound 指向不可达端口时仍可经注入 client 成功发送。
func TestInjectedClientOverridesProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer target.Close()

	p := testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = target.URL; e.SignName = "" })
	p.Outbound = proxyPool(t, "http", "127.0.0.1", 1, "", "") // 不可达，须被注入 client 覆盖
	s, err := build(p, target.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "user@example.com", "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("注入 client 应覆盖代理配置: %v", err)
	}
}
