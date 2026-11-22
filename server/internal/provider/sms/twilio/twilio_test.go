// twilio_test.go：Twilio 短信 Sender 单测（httptest 拦截请求，不打真实外部
// 服务）：Basic Auth 形态（base64(AccountSid:AuthToken) 逐字符断言）、form
// 请求形态（To / From / MessagingServiceSid / ContentSid / ContentVariables）、
// 变量映射与自然序兜底、幂等键确定性、from/messaging_service_sid 互斥、
// 厂商错误码分类、失败路径 fail-closed、构造期 Ext 校验与注册表断言。
package twilio

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

const (
	testAccountSID = "AC11111111111111111111111111111111"
	testAuthToken  = "zauthlofttestauthtoken"
	testFrom       = "+15550001111"
	testServiceSID = "MG22222222222222222222222222222222"
	testContentSID = "HX33333333333333333333333333333333"
	testPhone      = "+85291234567" // 海外 E.164，透传
)

// testProvider 构造带完整凭证的 Provider 实例（Ext 唯一编解码出口 repo）。
func testProvider(t *testing.T, mutate func(*providerpb.Ext)) *provider.Provider {
	t.Helper()
	ext := &providerpb.Ext{
		ClientId:     testAccountSID,
		ClientSecret: testAuthToken,
		From:         testFrom,
		TemplateCode: testContentSID,
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

// TestBuildRequiresCredentials 构造期校验：AccountSid / AuthToken 缺一即
// ErrNotConfigured；from 与 messaging_service_sid 都不填或都填同样拒绝
// （二选一 fail-closed），恰填一个成功。
func TestBuildRequiresCredentials(t *testing.T) {
	for _, empty := range []func(*providerpb.Ext){
		func(e *providerpb.Ext) { e.ClientId = "" },
		func(e *providerpb.Ext) { e.ClientSecret = "" },
		func(e *providerpb.Ext) { e.From = ""; e.MessagingServiceSid = "" }, // 都不填
		func(e *providerpb.Ext) { e.MessagingServiceSid = testServiceSID },  // 都填
	} {
		if _, err := build(testProvider(t, empty), nil); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("missing/ambiguous config err = %v, want ErrNotConfigured", err)
		}
	}
	s, err := build(testProvider(t, nil), nil)
	if err != nil {
		t.Fatalf("build(from): %v", err)
	}
	if s.base != defaultEndpoint || s.accountSID != testAccountSID || s.authToken != testAuthToken {
		t.Fatalf("base/credentials = %q/%q/%q, want defaults", s.base, s.accountSID, s.authToken)
	}
	// messaging_service_sid 轨道同样可构造。
	if _, err = build(testProvider(t, func(e *providerpb.Ext) { e.From = ""; e.MessagingServiceSid = testServiceSID }), nil); err != nil {
		t.Fatalf("build(messaging_service_sid): %v", err)
	}
	// intranet_endpoint 覆盖 base URL（路径段照常拼接），尾部斜杠规整。
	s, err = build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = "http://intranet.local:8443/" }), nil)
	if err != nil {
		t.Fatalf("build(intranet): %v", err)
	}
	if s.base != "http://intranet.local:8443" || !strings.HasSuffix(s.messagesURL(), "/2010-04-01/Accounts/"+testAccountSID+"/Messages.json") {
		t.Fatalf("intranet base/url = %q / %q, want trimmed base + messages path", s.base, s.messagesURL())
	}
	if !strings.HasPrefix(s.messagesURL(), "http://intranet.local:8443/") {
		t.Fatalf("messages URL must use intranet base: %q", s.messagesURL())
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

// TestSendPostsBasicAuthForm 请求形态：POST form 到 Messages 资源路径，
// Basic Auth 头为 base64(AccountSid:AuthToken)，form 携带 To / ContentSid /
// From / ContentVariables，幂等键随验证码下发；厂商 201 queued 判成功。
func TestSendPostsBasicAuthForm(t *testing.T) {
	var gotURL *url.URL
	var gotHeaders http.Header
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL
		gotHeaders = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sid":"SM44444444444444444444444444444444","status":"queued","error_code":null}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), testPhone, "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := gotURL.Path; got != "/2010-04-01/Accounts/"+testAccountSID+"/Messages.json" {
		t.Errorf("path = %q, want AccountSid path parameter", got)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(testAccountSID+":"+testAuthToken))
	if got := gotHeaders.Get("Authorization"); got != wantAuth {
		t.Errorf("Authorization = %q, want %q", got, wantAuth)
	}
	if got := gotHeaders.Get("Content-Type"); got != contentTypeForm {
		t.Errorf("Content-Type = %q, want %q", got, contentTypeForm)
	}
	if gotHeaders.Get(idempotencyHeader) == "" {
		t.Error("Idempotency-Token must be present for code sends")
	}
	form, err := url.ParseQuery(string(gotBody))
	if err != nil {
		t.Fatalf("parse form body: %v", err)
	}
	if got := form.Get("To"); got != testPhone {
		t.Errorf("To = %q, want %q", got, testPhone)
	}
	if got := form.Get("From"); got != testFrom {
		t.Errorf("From = %q, want %q", got, testFrom)
	}
	if got := form.Get("MessagingServiceSid"); got != "" {
		t.Errorf("MessagingServiceSid = %q, want empty (From 轨道)", got)
	}
	if got := form.Get("ContentSid"); got != testContentSID {
		t.Errorf("ContentSid = %q, want %q", got, testContentSID)
	}
	if got := form.Get("ContentVariables"); got != `{"1":"246810"}` {
		t.Errorf("ContentVariables = %q, want {\"1\":\"246810\"}（未配置映射走自然序兜底）", got)
	}
}

// TestSendMessagingServiceSidTrack messaging_service_sid 轨道：form 带
// MessagingServiceSid、不带 From。
func TestSendMessagingServiceSidTrack(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sid":"SM44444444444444444444444444444444","status":"queued"}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.From = ""
		e.MessagingServiceSid = testServiceSID
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), testPhone, "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	form, err := url.ParseQuery(string(gotBody))
	if err != nil {
		t.Fatalf("parse form body: %v", err)
	}
	if got := form.Get("MessagingServiceSid"); got != testServiceSID {
		t.Errorf("MessagingServiceSid = %q, want %q", got, testServiceSID)
	}
	if got := form.Get("From"); got != "" {
		t.Errorf("From = %q, want empty", got)
	}
}

// TestSendContentVariablesMapping 变量映射：metadata 声明即按映射（键名 →
// 序号），未覆盖键 / 坏 JSON 拒绝，多余映射键忽略；未声明映射按参数键排序
// 自然序兜底；空参数不下发 ContentVariables。
func TestSendContentVariablesMapping(t *testing.T) {
	// 映射 {"a":"2","b":"1"}：params b 的值落序号 1、a 的值落序号 2。
	vars, err := buildContentVariables("otp", map[string]string{"a": "1", "b": "2"},
		map[string]string{"content_variables_map.otp": `{"a":"2","b":"1"}`})
	if err != nil || vars != `{"1":"2","2":"1"}` {
		t.Fatalf("mapped = %q / %v, want {\"1\":\"2\",\"2\":\"1\"} / nil", vars, err)
	}
	// 映射多余键忽略（厂商对未提供变量回退模板默认样例值）。
	vars, err = buildContentVariables("otp", map[string]string{"code": "246810"},
		map[string]string{"content_variables_map.otp": `{"code":"1","name":"2"}`})
	if err != nil || vars != `{"1":"246810"}` {
		t.Fatalf("extra mapping keys = %q / %v, want {\"1\":\"246810\"} / nil", vars, err)
	}
	// 未配置映射 → 排序自然序兜底（键序与 map 迭代序无关）。
	for i := 0; i < 20; i++ {
		vars, err = buildContentVariables("otp", map[string]string{"b": "2", "a": "1"}, nil)
		if err != nil || vars != `{"1":"1","2":"2"}` {
			t.Fatalf("natural order run %d = %q / %v, want {\"1\":\"1\",\"2\":\"2\"} / nil", i, vars, err)
		}
	}
	// 空参数 → 空串（form 不带 ContentVariables 字段）。
	if vars, err = buildContentVariables("otp", nil, nil); err != nil || vars != "" {
		t.Fatalf("empty params = %q / %v, want empty / nil", vars, err)
	}
	// 映射未覆盖的参数键 → 永久拒绝（猜序号会把验证码填进别的变量）。
	_, err = buildContentVariables("otp", map[string]string{"code": "1", "other": "2"},
		map[string]string{"content_variables_map.otp": `{"code":"1"}`})
	var se *SendError
	if !errors.As(err, &se) || se.Kind != KindPermanent {
		t.Fatalf("unmapped key err = %v, want permanent SendError", err)
	}
	// 映射 JSON 损坏 / 值非字符串 → 永久拒绝。
	for _, bad := range []string{`{"code":`, `{"code":1}`} {
		_, err = buildContentVariables("otp", map[string]string{"code": "1"},
			map[string]string{"content_variables_map.otp": bad})
		if !errors.As(err, &se) || se.Kind != KindPermanent {
			t.Fatalf("bad mapping %q err = %v, want permanent SendError", bad, err)
		}
	}
	// 全链路：映射声明下 ContentVariables 精确落 form。
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sid":"SM44444444444444444444444444444444","status":"queued"}`))
	}))
	defer srv.Close()
	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.Metadata = map[string]string{"content_variables_map.otp": `{"code":"1"}`}
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), testPhone, "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	form, err := url.ParseQuery(string(gotBody))
	if err != nil {
		t.Fatalf("parse form body: %v", err)
	}
	if got := form.Get("ContentVariables"); got != `{"1":"246810"}` {
		t.Errorf("ContentVariables = %q, want {\"1\":\"246810\"}", got)
	}
	// 空参数发送不带 ContentVariables 字段。
	s2, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	gotBody = nil
	if err := s2.Send(context.Background(), testPhone, "otp", nil); err != nil {
		t.Fatalf("Send(no params): %v", err)
	}
	form, err = url.ParseQuery(string(gotBody))
	if err != nil {
		t.Fatalf("parse form body: %v", err)
	}
	if _, found := form["ContentVariables"]; found {
		t.Errorf("ContentVariables = %q, want field omitted for empty params", form.Get("ContentVariables"))
	}
}

// TestSendTemplateKeyOverride 模板键覆盖：metadata["template_code."+tpl]
// 优先于 Ext.template_code；两者皆空 Send 期拒绝。
func TestSendTemplateKeyOverride(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sid":"SM44444444444444444444444444444444","status":"queued"}`))
	}))
	defer srv.Close()

	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.Metadata = map[string]string{"template_code.otp": "HX55555555555555555555555555555555"}
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), testPhone, "otp", map[string]string{"code": "135790"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	form, err := url.ParseQuery(string(gotBody))
	if err != nil {
		t.Fatalf("parse form body: %v", err)
	}
	if got := form.Get("ContentSid"); got != "HX55555555555555555555555555555555" {
		t.Fatalf("ContentSid = %q, want metadata override", got)
	}
	// Ext 与 metadata 均无 ContentSid → Send 期拒绝（fail-closed）。
	s, err = build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		e.TemplateCode = ""
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), testPhone, "otp", nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("missing content sid err = %v, want ErrNotConfigured", err)
	}
}

// TestIdempotencyToken 幂等键：同一 to+tpl+code 恒定（队列重试间去重），
// code 变化即变（新验证码即新键）；code 为空返回空串（不下发幂等头，
// 防止空键误并两次不同发送）。
func TestIdempotencyToken(t *testing.T) {
	first := idempotencyToken("+15550001111", "otp", "246810")
	if first == "" || first != idempotencyToken("+15550001111", "otp", "246810") {
		t.Fatalf("token must be deterministic and non-empty: %q", first)
	}
	if first == idempotencyToken("+15550001111", "otp", "135790") {
		t.Fatal("different code must produce different token")
	}
	if first == idempotencyToken("+15550002222", "otp", "246810") {
		t.Fatal("different to must produce different token")
	}
	if got := idempotencyToken("+15550001111", "otp", ""); got != "" {
		t.Fatalf("empty code token = %q, want empty (header omitted)", got)
	}
	// 无 code 参数的发送不携带幂等头。
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sid":"SM44444444444444444444444444444444","status":"queued"}`))
	}))
	defer srv.Close()
	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), testPhone, "otp", nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := gotHeaders.Get(idempotencyHeader); got != "" {
		t.Errorf("Idempotency-Token = %q, want absent for non-code sends", got)
	}
}

// TestSendPhonePassthrough 号码口径：海外渠道不做国别前缀猜测，E.164 原样
// 透传（裸号原样交给厂商判定）；仅去空白；空号不发请求。
func TestSendPhonePassthrough(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sid":"SM44444444444444444444444444444444","status":"queued"}`))
	}))
	defer srv.Close()
	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), " 13800138000 ", "otp", nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	form, err := url.ParseQuery(string(gotBody))
	if err != nil {
		t.Fatalf("parse form body: %v", err)
	}
	if got := form.Get("To"); got != "13800138000" {
		t.Fatalf("To = %q, want trimmed passthrough without country guessing", got)
	}

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("empty phone must not hit the wire")
	}))
	defer empty.Close()
	s, err = build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = empty.URL }), empty.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "   ", "otp", nil); !errors.Is(err, ErrEmptyTo) {
		t.Fatalf("blank to err = %v, want ErrEmptyTo", err)
	}
}

// TestSendFailClosedPaths 失败路径全 fail-closed：非 2xx 带厂商错误体（按
// 码分类、消息保留）/ 非 2xx 纯文本 / 2xx JSON 损坏 / 2xx 错误码体 / status
// 缺失 / 终态失败 status / 传输错误均拒绝。
func TestSendFailClosedPaths(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantKind ErrorKind
		wantCode string
		wantMsg  string
	}{
		{
			name:     "400 landline permanent with vendor message",
			status:   http.StatusBadRequest,
			body:     `{"code":21614,"message":"To number is a landline","status":400}`,
			wantKind: KindPermanent,
			wantCode: "21614",
			wantMsg:  "To number is a landline",
		},
		{
			name:     "401 auth failure permanent",
			status:   http.StatusUnauthorized,
			body:     `{"code":20003,"message":"Authenticate","status":401}`,
			wantKind: KindPermanent,
			wantCode: "20003",
			wantMsg:  "Authenticate",
		},
		{
			name:     "503 plain body transient",
			status:   http.StatusServiceUnavailable,
			body:     "upstream down",
			wantKind: KindTransient,
			wantMsg:  "upstream down",
		},
		{
			name:     "201 corrupt json transient",
			status:   http.StatusCreated,
			body:     `{"sid":"SM`,
			wantKind: KindTransient,
			wantMsg:  "decode response",
		},
		{
			name:     "2xx error body permanent",
			status:   http.StatusCreated,
			body:     `{"sid":"SM44444444444444444444444444444444","status":"failed","error_code":30007}`,
			wantKind: KindPermanent,
			wantCode: "30007",
		},
		{
			name:     "2xx missing status transient",
			status:   http.StatusCreated,
			body:     `{"sid":"SM44444444444444444444444444444444"}`,
			wantKind: KindTransient,
			wantMsg:  "response missing status",
		},
		{
			name:     "2xx terminal failed status permanent",
			status:   http.StatusCreated,
			body:     `{"sid":"SM44444444444444444444444444444444","status":"failed"}`,
			wantKind: KindPermanent,
		},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = srv.URL }), srv.Client())
		if err != nil {
			srv.Close()
			t.Fatalf("%s: build: %v", tc.name, err)
		}
		err = s.Send(context.Background(), testPhone, "otp", map[string]string{"code": "246810"})
		srv.Close()
		var se *SendError
		if !errors.As(err, &se) {
			t.Fatalf("%s: err = %v (%T), want *SendError", tc.name, err, err)
		}
		if se.Kind != tc.wantKind {
			t.Fatalf("%s: kind = %d, want %d", tc.name, se.Kind, tc.wantKind)
		}
		if tc.wantCode != "" && se.Code != tc.wantCode {
			t.Fatalf("%s: code = %q, want %q", tc.name, se.Code, tc.wantCode)
		}
		if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
			t.Fatalf("%s: message = %q, want contains %q", tc.name, err.Error(), tc.wantMsg)
		}
	}
	// 传输错误（服务不可达）→ 瞬时。
	closed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	s, err := build(testProvider(t, func(e *providerpb.Ext) { e.IntranetEndpoint = closed.URL }), closed.Client())
	closed.Close()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	err = s.Send(context.Background(), testPhone, "otp", nil)
	var se *SendError
	if !errors.As(err, &se) || se.Kind != KindTransient || se.Code != "" {
		t.Fatalf("transport err = %v, want transient code-less SendError", err)
	}
}

// TestVendorErrorClassification 厂商错误码分类：20003 鉴权失败、21xxx 号码 /
// 参数 / 资格类（21211 非法号码、21614 座机）与 30007 违规内容永久；
// 30001 队列溢出等瞬时；未知码保守瞬时。
func TestVendorErrorClassification(t *testing.T) {
	cases := []struct {
		code     int64
		wantKind ErrorKind
	}{
		{20003, KindPermanent},
		{21211, KindPermanent},
		{21614, KindPermanent},
		{30007, KindPermanent},
		{30001, KindTransient},
		{20448, KindTransient},
		{50001, KindTransient},
		{0, KindTransient},
	}
	for _, tc := range cases {
		if got := classifyVendorError(tc.code); got != tc.wantKind {
			t.Errorf("classify(%d) = %d, want %d", tc.code, got, tc.wantKind)
		}
	}
}

// TestInitRegistersAsSMSVendor 注册表断言：init() 自注册 sender 槽（meta +
// category），Schema 完整声明表列与 Ext（含二选一两字段）、不含 sign_name
// 与 auth 专属键、pattern 声明在场，且返回独立切片；最小可用 Ext 走真实
// factory 必须成功（同 bootstrap 门禁形态）。
func TestInitRegistersAsSMSVendor(t *testing.T) {
	meta, ok := provider.LookupSenderMeta(Type)
	if !ok {
		t.Fatal("twilio not registered in sender registry")
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
	for _, key := range []string{"client_id", "client_secret", "from", "messaging_service_sid", "template_code", "intranet_endpoint", "metadata",
		"provider_key", "display_name", "icon_url", "sort_order", "remark", provider.ProxyRefKey} {
		if _, found := byKey[key]; !found {
			t.Errorf("meta.Schema() missing %q", key)
		}
	}
	for _, key := range []string{"client_id", "client_secret", "template_code"} {
		if !byKey[key].Required {
			t.Errorf("meta.Schema() %q must be required", key)
		}
	}
	// 二选一两字段均非必填（互斥为跨字段约束，构造期执法）。
	for _, key := range []string{"from", "messaging_service_sid"} {
		if byKey[key].Required {
			t.Errorf("meta.Schema() %q must be optional (mutual exclusion enforced at build)", key)
		}
	}
	patterns := map[string]string{
		"client_id": `^AC[0-9a-fA-F]{32}$`,
		"from":      `^\+[1-9][0-9]{1,14}$`,
	}
	for key, want := range patterns {
		if got := byKey[key].Pattern; got != want {
			t.Errorf("meta.Schema() %q pattern = %q, want %q", key, got, want)
		}
	}
	// sign_name 无签名概念不声明；is_enabled / 登录建号开关是 auth 专属。
	for _, key := range []string{"sign_name", "is_enabled", "union_provider", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields"} {
		if _, found := byKey[key]; found {
			t.Errorf("meta.Schema() must not contain key %q", key)
		}
	}
	// 每次调用返回独立切片，调用方改动不得污染后续调用。
	mutated := meta.Schema()
	mutated[0].Key = "mutated"
	if meta.Schema()[0].Key == "mutated" {
		t.Error("meta.Schema() returns a shared slice")
	}
	// 最小可用 Ext 走真实 factory 必须成功（messaging_service_sid 轨道同验）。
	if _, err := provider.NewSender(testProvider(t, nil), provider.CategorySMS); err != nil {
		t.Errorf("NewSender(twilio): %v——sender factory 槽缺失或实现构造破损", err)
	}
	if _, err := provider.NewSender(testProvider(t, func(e *providerpb.Ext) {
		e.From = ""
		e.MessagingServiceSid = testServiceSID
	}), provider.CategorySMS); err != nil {
		t.Errorf("NewSender(twilio via messaging_service_sid): %v——二选一轨道构造破损", err)
	}
}
