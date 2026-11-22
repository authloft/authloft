// tencent_sms_test.go：腾讯云短信 Sender 单测（httptest 拦截请求，不打真实
// 外部服务）：TC3-HMAC-SHA256 签名（规范请求串 / 待签名字符串逐字符断言 +
// 独立预计算已知向量）、请求形态（PhoneNumberSet / SmsSdkAppId / SignName /
// TemplateId / TemplateParamSet 位置展开）、SendStatusSet 逐条判定、厂商
// 错误码分类（永久 / 瞬时）、构造期 Ext 校验。
package tencentsms

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

const (
	testSecretID    = "AKIDzauthlofttestid"
	testSecretKey   = "zauthlofttestsecretkey"
	testSdkAppID    = "1400000000"
	testSignName    = "Authloft签名"
	testTemplateID  = "1234567"
	testRegion      = "ap-guangzhou"
	testBearerPhone = "13800138000" // 国内 11 位裸号
)

// testProvider 构造带完整凭证的 Provider 实例（Ext 唯一编解码出口 repo）。
func testProvider(t *testing.T, mutate func(*providerpb.Ext)) *provider.Provider {
	t.Helper()
	ext := &providerpb.Ext{
		ClientId:     testSecretID,
		ClientSecret: testSecretKey,
		SdkAppId:     testSdkAppID,
		SignName:     testSignName,
		TemplateCode: testTemplateID,
		Region:       testRegion,
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

// TestBuildRequiresCredentials 构造期校验：SecretId / SecretKey / SmsSdkAppId /
// 签名内容 / 模板 ID / 地域缺一即 ErrNotConfigured；齐全则 endpoint 回落公网
// 默认且 host 从 endpoint 解析。
func TestBuildRequiresCredentials(t *testing.T) {
	for _, empty := range []func(*providerpb.Ext){
		func(e *providerpb.Ext) { e.ClientId = "" },
		func(e *providerpb.Ext) { e.ClientSecret = "" },
		func(e *providerpb.Ext) { e.SdkAppId = "" },
		func(e *providerpb.Ext) { e.SignName = "" },
		func(e *providerpb.Ext) { e.TemplateCode = "" },
		func(e *providerpb.Ext) { e.Region = "" },
	} {
		if _, err := build(testProvider(t, empty), nil); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("missing credential err = %v, want ErrNotConfigured", err)
		}
	}
	s, err := build(testProvider(t, nil), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if s.endpoint != defaultEndpoint || s.host != "sms.tencentcloudapi.com" {
		t.Fatalf("endpoint/host = %q/%q, want default %s", s.endpoint, s.host, defaultEndpoint)
	}
	// intranet_endpoint 优先回源（§5.3：服务端回源优先使用），host 随之解析。
	s, err = build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = "http://intranet.local:8443" }), nil)
	if err != nil {
		t.Fatalf("build(intranet): %v", err)
	}
	if s.endpoint != "http://intranet.local:8443" || s.host != "intranet.local:8443" {
		t.Fatalf("endpoint/host = %q/%q, want intranet override", s.endpoint, s.host)
	}
	// 域名解析不出 host（无 scheme / 空 host）→ 构造失败。
	if _, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = "not-a-url" }), nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("bad endpoint err = %v, want ErrNotConfigured", err)
	}
}

// TestBuildNilExt nil 实例 / nil Ext → ErrNilProvider。
func TestBuildNilExt(t *testing.T) {
	if _, err := build(nil, nil); !errors.Is(err, provider.ErrNilProvider) {
		t.Fatalf("nil provider err = %v, want ErrNilProvider", err)
	}
	if _, err := build(&provider.Provider{Type: Type}, nil); !errors.Is(err, provider.ErrNilProvider) {
		t.Fatalf("nil ext err = %v, want ErrNilProvider", err)
	}
}

// TestTC3CanonicalPieces 规范请求串与待签名字符串逐字符断言（POST JSON 固定
// 形态：URI=/、查询串空、签名头 content-type;host），哈希值来自独立预计算。
func TestTC3CanonicalPieces(t *testing.T) {
	const payload = `{"PhoneNumberSet":["+8613800138000"],"SmsSdkAppId":"1400000000","SignName":"Authloft签名","TemplateId":"1234567","TemplateParamSet":["246810"]}`
	const wantHashedPayload = "d5144a5467fb739b9387029816ec1640bd3aa6ff0d747ae3f877f9582c7932d9"
	if got := sha256Hex(payload); got != wantHashedPayload {
		t.Fatalf("hashed payload = %s, want %s", got, wantHashedPayload)
	}
	wantCanonical := "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:sms.tencentcloudapi.com\n\ncontent-type;host\n" + wantHashedPayload
	if got := tc3CanonicalRequest("sms.tencentcloudapi.com", wantHashedPayload); got != wantCanonical {
		t.Fatalf("canonical request =\n%q\nwant\n%q", got, wantCanonical)
	}
	const wantHashedCanonical = "20661d095f3bf8b5ec42b1be6e74f33fe977bd299878bc30acb280b16e219175"
	if got := sha256Hex(tc3CanonicalRequest("sms.tencentcloudapi.com", wantHashedPayload)); got != wantHashedCanonical {
		t.Fatalf("hashed canonical = %s, want %s", got, wantHashedCanonical)
	}
	wantStringToSign := "TC3-HMAC-SHA256\n1796027405\n2026-11-30/sms/tc3_request\n" + wantHashedCanonical
	if got := tc3StringToSign("2026-11-30", 1796027405, wantHashedCanonical); got != wantStringToSign {
		t.Fatalf("string to sign =\n%q\nwant\n%q", got, wantStringToSign)
	}
}

// TestTC3KnownSignatureVector 已知签名向量：固定 SecretId / SecretKey / host /
// 时间戳 / 请求体 → 固定 Authorization 头逐字符比对。期望值按 TC3-HMAC-SHA256
// 公开规范独立预计算（规范请求串 → 待签名字符串 → TC3+SecretKey/日期/服务名/
// tc3_request 派生密钥 HMAC 链），签名链任一环节被改动即红。
func TestTC3KnownSignatureVector(t *testing.T) {
	const fixedPayload = `{"PhoneNumberSet":["+8613800138000"],"SmsSdkAppId":"1400000000","SignName":"Authloft签名","TemplateId":"1234567","TemplateParamSet":["246810"]}`
	const wantAuthorization = "TC3-HMAC-SHA256 Credential=AKIDzauthlofttestid/2026-11-30/sms/tc3_request, " +
		"SignedHeaders=content-type;host, Signature=f4e3b79ce39ece08258e1ca34e60005a53fd7e880292269c236088fa26234058"
	got := tc3Sign(testSecretID, testSecretKey, "sms.tencentcloudapi.com", 1796027405, []byte(fixedPayload))
	if got != wantAuthorization {
		t.Fatalf("authorization =\n%s\nwant\n%s", got, wantAuthorization)
	}
	// 时间戳换日即换凭证范围日期段（date 从 timestamp UTC 推导）。
	got = tc3Sign(testSecretID, testSecretKey, "sms.tencentcloudapi.com", 1796113805, []byte(fixedPayload))
	if !strings.Contains(got, "Credential="+testSecretID+"/2026-12-01/sms/tc3_request") {
		t.Errorf("credential scope date must follow timestamp UTC date: %s", got)
	}
}

// TestSendSignsAndPostsCorrectRequest 请求形态 + 签名复算：公共参数头与请求体
// 逐项断言；服务端按同一算法以捕获到的请求体 / host / 时间戳复算 Authorization
// 必须与请求一致。
func TestSendSignsAndPostsCorrectRequest(t *testing.T) {
	var gotHeaders http.Header
	var gotHost string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotHost = r.Host // Host 头在服务端被移入 r.Host，不在 Header 表内
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"Response":{"SendStatusSet":[{"SerialNo":"s1","PhoneNumber":"+8613800138000","Fee":1,"Code":"Ok","Message":"send success","IsoCode":"cn"}],"RequestId":"r1"}}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), testBearerPhone, "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	for key, want := range map[string]string{
		"X-TC-Action":  "SendSms",
		"X-TC-Version": apiVersion,
		"X-TC-Region":  testRegion,
		"Content-Type": contentType,
	} {
		if got := gotHeaders.Get(key); got != want {
			t.Errorf("header %s = %q, want %q", key, got, want)
		}
	}
	if gotHeaders.Get("X-TC-Timestamp") == "" || gotHeaders.Get("Authorization") == "" {
		t.Error("X-TC-Timestamp / Authorization must be present")
	}
	// 请求体逐字段断言（手机号已补 +86 前缀；TemplateParamSet 位置展开）。
	var req sendSmsRequest
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("unmarshal request body: %v", err)
	}
	if len(req.PhoneNumberSet) != 1 || req.PhoneNumberSet[0] != "+86"+testBearerPhone {
		t.Errorf("PhoneNumberSet = %v, want [+86%s]", req.PhoneNumberSet, testBearerPhone)
	}
	if req.SmsSdkAppId != testSdkAppID || req.SignName != testSignName || req.TemplateId != testTemplateID {
		t.Errorf("identity fields = %q/%q/%q, want %q/%q/%q", req.SmsSdkAppId, req.SignName, req.TemplateId, testSdkAppID, testSignName, testTemplateID)
	}
	if len(req.TemplateParamSet) != 1 || req.TemplateParamSet[0] != "246810" {
		t.Errorf("TemplateParamSet = %v, want [246810]", req.TemplateParamSet)
	}
	// 签名复算：同一密钥 + 捕获的 body / host / 时间戳必须得到同一 Authorization。
	ts, err := strconv.ParseInt(gotHeaders.Get("X-TC-Timestamp"), 10, 64)
	if err != nil {
		t.Fatalf("X-TC-Timestamp = %q: %v", gotHeaders.Get("X-TC-Timestamp"), err)
	}
	recomputed := tc3Sign(testSecretID, testSecretKey, gotHost, ts, gotBody)
	if got := gotHeaders.Get("Authorization"); got != recomputed {
		t.Errorf("Authorization = %q, want recomputed %q", got, recomputed)
	}
}

// TestSendPhoneNormalization 号码规整：国内 11 位裸号补 +86；带 + 前缀原样
// 透传；空号 ErrEmptyTo 不发请求。
func TestSendPhoneNormalization(t *testing.T) {
	if got := normalizePhone("13800138000"); got != "+8613800138000" {
		t.Errorf("bare 11-digit = %q, want +8613800138000", got)
	}
	if got := normalizePhone("+85291234567"); got != "+85291234567" {
		t.Errorf("prefixed = %q, want passthrough", got)
	}
	if got := normalizePhone(" 13800138000 "); got != "+8613800138000" {
		t.Errorf("trimmed = %q, want +8613800138000", got)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("empty phone must not hit the wire")
	}))
	defer srv.Close()
	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "", "otp", nil); !errors.Is(err, ErrEmptyTo) {
		t.Fatalf("empty to err = %v, want ErrEmptyTo", err)
	}
}

// TestSendTemplateKeyOverride 模板键覆盖：metadata["template_code."+tpl]
// 优先于 Ext.template_code（§15.2：模板内容存 metadata）。
func TestSendTemplateKeyOverride(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"Response":{"SendStatusSet":[{"Code":"Ok","Message":"send success"}],"RequestId":"r1"}}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.Metadata = map[string]string{"template_code.otp": "2222222", "template_code.marketing": "3333333"}
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "+8613800138000", "otp", map[string]string{"code": "135790"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	var req sendSmsRequest
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("unmarshal request body: %v", err)
	}
	if req.TemplateId != "2222222" {
		t.Fatalf("TemplateId = %q, want metadata override 2222222", req.TemplateId)
	}
}

// TestExpandTemplateParams 位置参数展开：声明顺序即展开顺序（与 map 迭代序
// 无关）；未声明顺序仅放行单变量 code；多变量未声明 / 键缺失 / 键多余 /
// 键重复一律 fail-closed。
func TestExpandTemplateParams(t *testing.T) {
	// 单变量 code：当前验证码链路的唯一形态，直接展开。
	got, err := expandTemplateParams("otp", map[string]string{"code": "246810"}, nil)
	if err != nil || len(got) != 1 || got[0] != "246810" {
		t.Fatalf("code-only = %v / %v, want [246810] / nil", got, err)
	}
	// 声明顺序 "b,a"：无论 map 迭代序，展开必须为 [b 的值, a 的值]。
	meta := map[string]string{"template_param_order.otp": "b,a"}
	params := map[string]string{"a": "1", "b": "2"}
	for i := 0; i < 20; i++ {
		got, err = expandTemplateParams("otp", params, meta)
		if err != nil || len(got) != 2 || got[0] != "2" || got[1] != "1" {
			t.Fatalf("declared order run %d = %v / %v, want [2 1] / nil", i, got, err)
		}
	}
	// 空参数 → 空数组（无参传空，§1.1 官方参数表）。
	if got, err = expandTemplateParams("otp", nil, meta); err != nil || got != nil {
		t.Fatalf("empty params = %v / %v, want nil / nil", got, err)
	}
	// 多变量未声明顺序 → 拒绝（fail-closed 优于按迭代序猜位置）。
	if _, err = expandTemplateParams("otp", params, nil); err == nil {
		t.Fatal("multi-param without declared order must fail")
	}
	var se *SendError
	if !errors.As(err, &se) || se.Kind != KindPermanent {
		t.Fatalf("undeclared-order err = %v, want permanent SendError", err)
	}
	// 非单变量 code 的参数且未声明顺序 → 拒绝。
	if _, err = expandTemplateParams("otp", map[string]string{"foo": "x"}, nil); err == nil {
		t.Fatal("non-code param without declared order must fail")
	}
	// 顺序声明缺失键 → 拒绝。
	if _, err = expandTemplateParams("otp", map[string]string{"a": "1"}, meta); err == nil {
		t.Fatal("missing declared key must fail")
	}
	// 顺序未覆盖的多余键 → 拒绝。
	if _, err = expandTemplateParams("otp", map[string]string{"a": "1", "b": "2", "c": "3"}, meta); err == nil {
		t.Fatal("extra param key must fail")
	}
	// 顺序重复键 → 拒绝（防重复键悄悄错位）。
	dup := map[string]string{"template_param_order.otp": "a,a,b"}
	if _, err = expandTemplateParams("otp", params, dup); err == nil {
		t.Fatal("duplicate order key must fail")
	}
}

// TestSendStatusSetPerItemVerdict 逐条判定：HTTP 200 也可能单条失败——
// Code != "Ok" 即整体失败并按该条错误码分类（永久 / 瞬时）；批量形态聚合
// 任一条永久错 → 整体按永久。
func TestSendStatusSetPerItemVerdict(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantErr  bool
		wantKind ErrorKind
	}{
		{
			name:    "all Ok",
			body:    `{"Response":{"SendStatusSet":[{"PhoneNumber":"+8613800138000","Code":"Ok","Message":"send success"}],"RequestId":"r"}}`,
			wantErr: false,
		},
		{
			name:     "single permanent item",
			body:     `{"Response":{"SendStatusSet":[{"PhoneNumber":"+8613800138000","Code":"FailedOperation.TemplateIncorrectOrUnapproved","Message":"template not approved"}],"RequestId":"r"}}`,
			wantErr:  true,
			wantKind: KindPermanent,
		},
		{
			name:     "single transient item",
			body:     `{"Response":{"SendStatusSet":[{"PhoneNumber":"+8613800138000","Code":"InternalError.Rest","Message":"server busy"}],"RequestId":"r"}}`,
			wantErr:  true,
			wantKind: KindTransient,
		},
		{
			name:     "mixed items transient first permanent later",
			body:     `{"Response":{"SendStatusSet":[{"PhoneNumber":"+8613800138000","Code":"InternalError.Rest","Message":"busy"},{"PhoneNumber":"+8613800138001","Code":"LimitExceeded.PhoneNumberCountLimit","Message":"too many"}],"RequestId":"r"}}`,
			wantErr:  true,
			wantKind: KindPermanent,
		},
		{
			name:     "empty SendStatusSet fail-closed",
			body:     `{"Response":{"RequestId":"r"}}`,
			wantErr:  true,
			wantKind: KindTransient,
		},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(tc.body))
		}))
		s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
		if err != nil {
			srv.Close()
			t.Fatalf("%s: build: %v", tc.name, err)
		}
		err = s.Send(context.Background(), "+8613800138000", "otp", map[string]string{"code": "1"})
		srv.Close()
		if !tc.wantErr {
			if err != nil {
				t.Fatalf("%s: Send err = %v, want nil", tc.name, err)
			}
			continue
		}
		var se *SendError
		if !errors.As(err, &se) {
			t.Fatalf("%s: err = %v (%T), want *SendError", tc.name, err, err)
		}
		if se.Kind != tc.wantKind {
			t.Fatalf("%s: kind = %d, want %d (code=%s)", tc.name, se.Kind, tc.wantKind, se.Code)
		}
	}
}

// TestVendorErrorClassification 厂商错误码分类：顶层 Response.Error 按前缀
// 分类返回——资格 / 参数类（AuthFailure / InvalidParameter / MissingParameter /
// UnauthorizedOperation / LimitExceeded / FailedOperation）永久；InternalError /
// RequestLimitExceeded 等瞬时；未知码保守瞬时。
func TestVendorErrorClassification(t *testing.T) {
	cases := []struct {
		code     string
		wantKind ErrorKind
	}{
		{"AuthFailure.SecretIdNotFound", KindPermanent},
		{"InvalidParameterValue.PhoneNumber", KindPermanent},
		{"InvalidParameter param", KindPermanent},
		{"MissingParameter.SmsSdkAppId", KindPermanent},
		{"UnauthorizedOperation", KindPermanent},
		{"LimitExceeded.PhoneNumberCountLimit", KindPermanent},
		{"FailedOperation.TemplateParamSetNotMatchApprovedTemplate", KindPermanent},
		{"InternalError.System", KindTransient},
		{"RequestLimitExceeded", KindTransient},
		{"Vendor.Unknown", KindTransient},
	}
	for _, tc := range cases {
		if got := classifyVendorError(tc.code); got != tc.wantKind {
			t.Errorf("classify(%q) = %d, want %d", tc.code, got, tc.wantKind)
		}
	}
	// 顶层错误经 Send 全链路携带分类。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Response":{"Error":{"Code":"AuthFailure.SecretIdNotFound","Message":"not found"},"RequestId":"r"}}`))
	}))
	defer srv.Close()
	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = s.Send(context.Background(), "+8613800138000", "otp", map[string]string{"code": "1"})
	var se *SendError
	if !errors.As(err, &se) || se.Kind != KindPermanent || se.Code != "AuthFailure.SecretIdNotFound" {
		t.Fatalf("top-level error = %v, want permanent SendError with vendor code", err)
	}
}

// TestSendFailClosedPaths HTTP 非 200 / 响应 JSON 损坏 / 传输错误 → 瞬时
// SendError，一律拒绝。
func TestSendFailClosedPaths(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream down"))
	}))
	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer srv.Close()
	err = s.Send(context.Background(), "+8613800138000", "otp", nil)
	var se *SendError
	if !errors.As(err, &se) || se.Kind != KindTransient || se.Code != "" {
		t.Fatalf("http 503 err = %v, want transient code-less SendError", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Response":{"SendStatusSet":[`))
	}))
	defer bad.Close()
	s, err = build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = bad.URL }), bad.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = s.Send(context.Background(), "+8613800138000", "otp", nil)
	if !errors.As(err, &se) || se.Kind != KindTransient || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("corrupt json err = %v, want transient decode SendError", err)
	}
}

// TestInitRegistersAsSMSVendor 注册表断言：init() 自注册 sender 槽（meta +
// category），Schema 完整声明表列与 Ext、不含 auth 专属键，且返回独立切片。
func TestInitRegistersAsSMSVendor(t *testing.T) {
	meta, ok := provider.LookupSenderMeta(Type)
	if !ok {
		t.Fatal("tencent_sms not registered in sender registry")
	}
	if meta.Category != provider.CategorySMS {
		t.Fatalf("category = %q, want sms", meta.Category)
	}
	schema := meta.Schema()
	if len(schema) == 0 {
		t.Fatal("meta.Schema() must declare full field schema for /schema")
	}
	byKey := map[string]provider.FieldMeta{}
	for _, f := range schema {
		byKey[f.Key] = f
	}
	for _, key := range []string{"client_id", "client_secret", "sdk_app_id", "sign_name", "template_code", "region", "intranet_endpoint", "metadata",
		"provider_key", "display_name", "icon_url", "sort_order", "remark", provider.ProxyRefKey} {
		if _, found := byKey[key]; !found {
			t.Errorf("meta.Schema() missing %q", key)
		}
	}
	for _, key := range []string{"client_id", "client_secret", "sdk_app_id", "sign_name", "template_code", "region"} {
		if !byKey[key].Required {
			t.Errorf("meta.Schema() %q must be required", key)
		}
	}
	region := byKey["region"]
	if region.Section != "endpoint" || region.Default != "ap-guangzhou" || region.Pattern != "^[a-z]{2}-[a-z]+-[0-9]+$" {
		t.Fatalf("region attrs = %v / %q / %q", region.Section, region.Default, region.Pattern)
	}
	// is_enabled / union_provider 与登录 / 建号 / 自动绑定开关是 auth 专属，
	// sms 类别不下发也不消费。
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
	// 构造期 fail-fast：最小可用 Ext 走真实 factory 必须成功（同 bootstrap
	// 门禁形态）。
	if _, err := provider.NewSender(testProvider(t, nil), provider.CategorySMS); err != nil {
		t.Errorf("NewSender(tencent_sms): %v——sender factory 槽缺失或实现构造破损", err)
	}
	// build 缺省注入时间源（既有调用方与 bootstrap 装配行为不变）。
	def, err := build(testProvider(t, nil), nil)
	if err != nil || def.nowFunc == nil {
		t.Fatalf("build must default nowFunc: err=%v", err)
	}
}
