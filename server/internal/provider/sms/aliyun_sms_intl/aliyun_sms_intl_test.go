// aliyun_sms_intl_test.go：阿里云国际/港澳台短信 Sender 单测（httptest
// 拦截请求，不打真实外部服务）：请求动作与公共参数、To 去 "+"、正文本地
// 渲染、ResponseCode 判定、RPC HMAC-SHA1 签名复算与固定向量、构造期校验、
// Schema 字段清单。
package aliyunsmsintl

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
	"authloft/internal/provider/aliyunrpc"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

const (
	testAccessKeyID     = "LTAI_test_ak"
	testAccessKeySecret = "test_secret_value"
	testFrom            = "Authloft"
)

// testProvider 构造带完整凭证的 Provider 实例（Ext 唯一编解码出口 repo）。
func testProvider(t *testing.T, mutate func(*providerpb.Ext)) *provider.Provider {
	t.Helper()
	ext := &providerpb.Ext{
		ClientId:     testAccessKeyID,
		ClientSecret: testAccessKeySecret,
		From:         testFrom,
	}
	if mutate != nil {
		mutate(ext)
	}
	raw, err := repo.MarshalProviderExt(ext)
	if err != nil {
		t.Fatalf("marshal ext: %v", err)
	}
	return &provider.Provider{
		Key:  "sms_intl_main",
		Type: Type,
		Row:  &model.Provider{ProviderKey: "sms_intl_main", Type: Type, IsEnabled: 1, Ext: raw},
		Ext:  ext,
	}
}

// TestBuildRequiresCredentials 构造期校验：AccessKeyId / AccessKeySecret
// 缺一即 ErrNotConfigured；齐备则 endpoint 回落国际站默认，intranet_endpoint
// 存在时优先回源。from 为可选，缺失不阻断构造。
func TestBuildRequiresCredentials(t *testing.T) {
	if _, err := build(testProvider(t, func(e *providerpb.Ext) { e.ClientId = "" }), nil); err == nil ||
		!strings.Contains(err.Error(), "not configured") {
		t.Fatalf("missing AccessKeyId err = %v", err)
	}
	if _, err := build(testProvider(t, func(e *providerpb.Ext) { e.ClientSecret = "" }), nil); err == nil ||
		!strings.Contains(err.Error(), "not configured") {
		t.Fatalf("missing AccessKeySecret err = %v", err)
	}
	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.From = "" }), nil)
	if err != nil {
		t.Fatalf("build without from: %v", err)
	}
	if s.endpoint != defaultEndpoint {
		t.Fatalf("endpoint = %q, want default %q", s.endpoint, defaultEndpoint)
	}
	s, err = build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = "http://intranet.local" }), nil)
	if err != nil {
		t.Fatalf("build(intranet): %v", err)
	}
	if s.endpoint != "http://intranet.local" {
		t.Fatalf("endpoint = %q, want intranet override", s.endpoint)
	}
}

// TestSendSignsAndPostsCorrectForm 请求形态 + 签名复算：Action / Version /
// RegionId / Format / Type / To / From / Message 逐项断言；服务端按同一算法
// 复算 Signature 必须与请求一致（RPC 签名 V1.0）。
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
		_, _ = w.Write([]byte(`{"ResponseCode":"OK","ResponseDescription":"The SMS Send Request was accepted","To":"85200001234"}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.Metadata = map[string]string{"body.otp": "Your code is {code}"}
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// E.164 入参带 "+"：服务端收到的 To 必须去掉前缀。
	if err := s.Send(context.Background(), "+85200001234", "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	for key, want := range map[string]string{
		"Action":           "SendMessageToGlobe",
		"Version":          "2018-05-01",
		"RegionId":         "ap-southeast-1",
		"Format":           "JSON",
		"AccessKeyId":      testAccessKeyID,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"To":               "85200001234",
		"From":             testFrom,
		"Type":             "OTP",
		"Message":          "Your code is 246810",
	} {
		if got := gotForm.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if ts := gotForm.Get("Timestamp"); !strings.HasSuffix(ts, "Z") || len(ts) != len("2006-01-02T15:04:05Z") {
		t.Errorf("Timestamp = %q, want UTC ISO8601", ts)
	}
	if len(gotForm.Get("SignatureNonce")) == 0 {
		t.Error("SignatureNonce is empty")
	}
	recomputed := aliyunrpc.SignRPCForm(gotForm, testAccessKeySecret)
	if got := gotForm.Get("Signature"); got != recomputed {
		t.Errorf("Signature = %q, want recomputed %q", got, recomputed)
	}
}

// TestSendToTrimsPlus 收件号码去 "+"：E.164（+ 开头）与裸号两种入参均得到
// 同一 To（国家码 + 号码、不带 +）；前后空白不影响。
func TestSendToTrimsPlus(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"+85200001234", "85200001234"},
		{"85200001234", "85200001234"},
		{" +85200001234 ", "85200001234"},
	} {
		var gotForm url.Values
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			gotForm = r.Form
			_, _ = w.Write([]byte(`{"ResponseCode":"OK"}`))
		}))
		s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if err := s.Send(context.Background(), tc.in, "otp", map[string]string{"code": "1"}); err != nil {
			t.Fatalf("Send(%q): %v", tc.in, err)
		}
		if got := gotForm.Get("To"); got != tc.want {
			t.Errorf("To(%q) = %q, want %q", tc.in, got, tc.want)
		}
		srv.Close()
	}
}

// TestSendRendersMessage 正文本地渲染：metadata["body."+tpl] 优先于默认模板，
// 占位按 params 明文替换；未配置模板回落默认正文。
func TestSendRendersMessage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata map[string]string
		want     string
	}{
		{"metadata override", map[string]string{"body.otp": "验证码 {code}，请勿泄露"}, "验证码 135790，请勿泄露"},
		{"default fallback", nil, "您的验证码：135790"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotForm url.Values
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				gotForm = r.Form
				_, _ = w.Write([]byte(`{"ResponseCode":"OK"}`))
			}))
			defer srv.Close()
			s, err := build(testProvider(t, func(e *providerpb.Ext) {
				e.IntranetEndpoint = srv.URL
				e.Metadata = tc.metadata
			}), srv.Client())
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			if err := s.Send(context.Background(), "+85200001234", "otp", map[string]string{"code": "135790"}); err != nil {
				t.Fatalf("Send: %v", err)
			}
			if got := gotForm.Get("Message"); got != tc.want {
				t.Fatalf("Message = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSendKnownSignatureVector 已知签名向量（时间源/随机源可注入）：固定
// now / nonce / To / From / Message → 固定 HMAC-SHA1 签名，逐字节比对。
// 期望值独立于签名实现按阿里云 RPC 签名 V1.0 公开规范预计算。
func TestSendKnownSignatureVector(t *testing.T) {
	fixedNow := time.Date(2026, time.November, 4, 12, 0, 0, 0, time.UTC)
	const fixedNonce = "fixed-nonce-000"
	const wantSignature = "G6FVDiX4iKY2F5ewNDNksd+PLoQ="

	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.Form
		_, _ = w.Write([]byte(`{"ResponseCode":"OK"}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.Metadata = map[string]string{"body.otp": "Your code is {code}"}
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	s.nowFunc = func() time.Time { return fixedNow }
	s.nonceFunc = func() string { return fixedNonce }
	if err := s.Send(context.Background(), "+85200001234", "otp", map[string]string{"code": "246810"}); err != nil {
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
	// build 缺省注入时间源/随机源（bootstrap 装配行为不变）。
	def, err := build(testProvider(t, nil), nil)
	if err != nil || def.nowFunc == nil || def.nonceFunc == nil {
		t.Fatalf("build must default nowFunc/nonceFunc: err=%v", err)
	}
}

// TestSendResponseCodeFailure 响应判定：HTTP 200 但 ResponseCode != OK →
// 错误携带厂商 ResponseCode / ResponseDescription（不按国内版的 Code 判成功）。
func TestSendResponseCodeFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ResponseCode":"FAIL","ResponseDescription":"invalid phone number"}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = s.Send(context.Background(), "+85200001234", "otp", map[string]string{"code": "111111"})
	if err == nil || !strings.Contains(err.Error(), "FAIL") {
		t.Fatalf("err = %v, want ResponseCode in message", err)
	}
	if !strings.Contains(err.Error(), "invalid phone number") {
		t.Fatalf("err = %v, want ResponseDescription in message", err)
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
	if err := s.Send(context.Background(), "+85200001234", "otp", map[string]string{"code": "111111"}); err == nil {
		t.Fatal("Send on http 503 must fail")
	}
}

// TestSendEmptyTo 收件号码为空 → ErrEmptyTo，不发请求。
func TestSendEmptyTo(t *testing.T) {
	s, err := build(testProvider(t, nil), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "", "otp", nil); err != ErrEmptyTo {
		t.Fatalf("empty to err = %v, want ErrEmptyTo", err)
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

// TestInitRegistersAsSMSVendor init() 已按 §15.3 注册（category=sms，Schema
// 字段清单供 /schema 渲染）：声明 client_id / client_secret / from /
// intranet_endpoint / metadata，不含 sign_name / template_code 死字段。
func TestInitRegistersAsSMSVendor(t *testing.T) {
	meta, ok := provider.LookupSenderMeta(Type)
	if !ok {
		t.Fatal("aliyun_sms_intl not registered in sender registry")
	}
	if meta.Category != provider.CategorySMS {
		t.Fatalf("category = %q, want sms", meta.Category)
	}
	if meta.DisplayName != "阿里云短信（国际/港澳台）" {
		t.Fatalf("display name = %q", meta.DisplayName)
	}
	schema := meta.Schema()
	wantKeys := map[string]bool{
		"provider_key": true, "display_name": true,
		"client_id": true, "client_secret": true, "from": true,
		"intranet_endpoint": true, "metadata": true,
		"icon_url": true, "sort_order": true, "remark": true,
		provider.ProxyRefKey: true,
	}
	gotKeys := map[string]bool{}
	for _, f := range schema {
		if gotKeys[f.Key] {
			t.Errorf("duplicate schema key %q", f.Key)
		}
		gotKeys[f.Key] = true
	}
	for k := range wantKeys {
		if !gotKeys[k] {
			t.Errorf("meta.Schema() missing %q", k)
		}
	}
	for _, f := range schema {
		if !wantKeys[f.Key] {
			t.Errorf("meta.Schema() has unexpected key %q", f.Key)
		}
	}
	// 国际 API 无签名名与模板 ID 参数，声明即为死字段。
	for _, key := range []string{"sign_name", "template_code", "is_enabled", "union_provider"} {
		if gotKeys[key] {
			t.Errorf("meta.Schema() must not contain %q", key)
		}
	}
	// 每次调用返回独立切片，调用方改动不得污染后续调用。
	mutated := meta.Schema()
	mutated[0].Key = "mutated"
	if meta.Schema()[0].Key == "mutated" {
		t.Error("meta.Schema() returns a shared slice")
	}
}
