// sendgrid_test.go：SendGrid Sender 单测（httptest 拦截请求，不打真实外部
// 服务）：模板双轨（"d-" 动态直传 / 非 "d-" 回落 metadata 本地渲染）、可选
// 字段消费（reply_to / sandbox_mode 开启才进请求体）、Bearer 鉴权与请求
// 形态、失败路径 fail-closed（非 2xx / 错误对象 / 非空体 JSON 损坏，厂商
// 错误消息保留）、构造期 Ext 校验与注册表 Schema 口径。
package sendgrid

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

const (
	testAPIKey   = "SG.test-api-key"
	testFrom     = "no-reply@mail.example.com"
	testFromName = "Authloft"
)

// testProvider 构造带完整凭证的 Provider 实例（Ext 唯一编解码出口 repo）。
func testProvider(t *testing.T, mutate func(*providerpb.Ext)) *provider.Provider {
	t.Helper()
	ext := &providerpb.Ext{
		ClientSecret: testAPIKey,
		From:         testFrom,
		SignName:     testFromName,
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

// capturedRequest 拦截服务器记录的最近一次请求。
type capturedRequest struct {
	method string
	path   string
	header http.Header
	body   []byte
}

// newTestServer 拦截服务器：记录请求，回写固定 status / body（空 body 合法，
// 厂商成功形态即 202 空体）。
func newTestServer(status int, respBody string) (*httptest.Server, *capturedRequest) {
	cap := &capturedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.method = r.Method
		cap.path = r.URL.Path
		cap.header = r.Header.Clone()
		cap.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	return srv, cap
}

// newTestSender 构造指向拦截服务器的 Sender（缺省仅覆盖 endpoint，其余 Ext
// 走 mutate）。
func newTestSender(t *testing.T, srv *httptest.Server, mutate func(*providerpb.Ext)) *Sender {
	t.Helper()
	s, err := build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = srv.URL
		if mutate != nil {
			mutate(e)
		}
	}), srv.Client())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return s
}

// decodeBody 解码请求体 JSON（对象形态）。
func decodeBody(t *testing.T, cap *capturedRequest) map[string]any {
	t.Helper()
	if len(cap.body) == 0 {
		t.Fatal("request body is empty")
	}
	var m map[string]any
	if err := json.Unmarshal(cap.body, &m); err != nil {
		t.Fatalf("decode request body: %v (body %s)", err, cap.body)
	}
	return m
}

// firstPersonalization 取 personalizations 首段。
func firstPersonalization(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	list, ok := m["personalizations"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("personalizations = %v, want single segment", m["personalizations"])
	}
	p, ok := list[0].(map[string]any)
	if !ok {
		t.Fatalf("personalizations[0] = %T, want object", list[0])
	}
	return p
}

// TestBuildRequiresCredentials 构造期校验：API Key / 发件地址缺一即
// ErrNotConfigured；base URL 回落公网默认；intranet_endpoint 覆盖基址并去
// 尾斜杠；from / template_code / reply_to 构造期 trim。
func TestBuildRequiresCredentials(t *testing.T) {
	for _, tc := range []struct {
		name string
		mut  func(*providerpb.Ext)
	}{
		{"missing client_secret", func(e *providerpb.Ext) { e.ClientSecret = "" }},
		{"missing from", func(e *providerpb.Ext) { e.From = " " }},
	} {
		if _, err := build(testProvider(t, tc.mut), nil); err == nil || !strings.Contains(err.Error(), "not configured") {
			t.Fatalf("%s: err = %v, want ErrNotConfigured", tc.name, err)
		}
	}
	s, err := build(testProvider(t, nil), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if s.baseURL != defaultBaseURL {
		t.Fatalf("baseURL = %q, want default %q", s.baseURL, defaultBaseURL)
	}
	if s.sandboxMode || s.replyTo != "" || s.templateID != "" {
		t.Fatalf("optional fields = %v / %q / %q, want zero values", s.sandboxMode, s.replyTo, s.templateID)
	}
	s, err = build(testProvider(t, func(e *providerpb.Ext) {
		e.IntranetEndpoint = "http://api.eu.sendgrid.com/"
		e.TemplateCode = " d-abc123 "
		e.ReplyTo = " reply@example.com "
	}), nil)
	if err != nil {
		t.Fatalf("build(intranet): %v", err)
	}
	if s.baseURL != "http://api.eu.sendgrid.com" {
		t.Fatalf("baseURL = %q, want intranet override without trailing slash", s.baseURL)
	}
	if s.templateID != "d-abc123" || s.replyTo != "reply@example.com" {
		t.Fatalf("templateID/replyTo = %q / %q, want trimmed", s.templateID, s.replyTo)
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

// TestSendDynamicTemplateTrack 模板轨一："d-" 前缀 → template_id +
// dynamic_template_data 直传（params 原样进 JSON，值不做本地转义，输出编码
// 由模板侧决定）；不发 subject / content。请求形态：POST <base>/v3/mail/send
// + Bearer API Key + application/json；202 空体即成功。
func TestSendDynamicTemplateTrack(t *testing.T) {
	srv, cap := newTestServer(http.StatusAccepted, "")
	defer srv.Close()

	s := newTestSender(t, srv, func(e *providerpb.Ext) { e.TemplateCode = "d-abc123" })
	if err := s.Send(context.Background(), "user@example.com", "otp", map[string]string{"code": "<b>246810</b>"}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if cap.method != http.MethodPost {
		t.Fatalf("method = %q, want POST", cap.method)
	}
	if cap.path != mailSendPath {
		t.Fatalf("path = %q, want %q", cap.path, mailSendPath)
	}
	if got := cap.header.Get("Authorization"); got != "Bearer "+testAPIKey {
		t.Fatalf("authorization = %q, want Bearer API Key", got)
	}
	if got := cap.header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q", got)
	}
	m := decodeBody(t, cap)
	if got := m["template_id"]; got != "d-abc123" {
		t.Fatalf("template_id = %v, want dynamic template ID", got)
	}
	p := firstPersonalization(t, m)
	tos, ok := p["to"].([]any)
	if !ok || len(tos) != 1 {
		t.Fatalf("to = %v, want single recipient", p["to"])
	}
	to, _ := tos[0].(map[string]any)
	if to["email"] != "user@example.com" {
		t.Fatalf("to.email = %v, want recipient", to["email"])
	}
	// 直传：params 值原样进 JSON（含 HTML 特殊字符不本地转义）。
	data, ok := p["dynamic_template_data"].(map[string]any)
	if !ok {
		t.Fatalf("dynamic_template_data = %v, want object", p["dynamic_template_data"])
	}
	if data["code"] != "<b>246810</b>" {
		t.Fatalf("dynamic_template_data.code = %v, want raw param passthrough", data["code"])
	}
	for _, key := range []string{"subject", "content", "reply_to", "mail_settings"} {
		if _, ok := m[key]; ok {
			t.Errorf("%s must be omitted on dynamic template track", key)
		}
	}
}

// TestSendDynamicTemplateNoParams 动态模板轨无变量：dynamic_template_data
// 省略（nil map 直传 null 无意义），template_id 照常下发。
func TestSendDynamicTemplateNoParams(t *testing.T) {
	srv, cap := newTestServer(http.StatusAccepted, "")
	defer srv.Close()

	s := newTestSender(t, srv, func(e *providerpb.Ext) { e.TemplateCode = "d-abc123" })
	if err := s.Send(context.Background(), "user@example.com", "otp", nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	m := decodeBody(t, cap)
	p := firstPersonalization(t, m)
	if _, ok := p["dynamic_template_data"]; ok {
		t.Fatalf("dynamic_template_data must be omitted without params, got %v", p["dynamic_template_data"])
	}
	if m["template_id"] != "d-abc123" {
		t.Fatalf("template_id = %v, want dynamic template ID", m["template_id"])
	}
}

// TestSendLegacyCodeFallsBackToMetadata 模板轨二：非 "d-" code（含老模板
// ID 等任意取值）回落 metadata 本地渲染——下发 subject / content，不发
// template_id；正文 {code} 占位替换且变量值 HTML 转义（text/html 语义）。
func TestSendLegacyCodeFallsBackToMetadata(t *testing.T) {
	srv, cap := newTestServer(http.StatusAccepted, "")
	defer srv.Close()

	s := newTestSender(t, srv, func(e *providerpb.Ext) {
		e.TemplateCode = "100001"
		e.Metadata = map[string]string{"subject.otp": "登录验证", "body.otp": "<p>验证码 {code}</p>"}
	})
	if err := s.Send(context.Background(), "user@example.com", "otp", map[string]string{"code": "<b>1</b>"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	m := decodeBody(t, cap)
	if _, ok := m["template_id"]; ok {
		t.Error("template_id must be omitted on metadata fallback track")
	}
	if got := m["subject"]; got != "登录验证" {
		t.Fatalf("subject = %v, want metadata subject.otp", got)
	}
	contents, ok := m["content"].([]any)
	if !ok || len(contents) != 1 {
		t.Fatalf("content = %v, want single block", m["content"])
	}
	block, _ := contents[0].(map[string]any)
	if block["type"] != contentTypeHTML {
		t.Fatalf("content.type = %v, want %q", block["type"], contentTypeHTML)
	}
	if got := block["value"]; got != "<p>验证码 &lt;b&gt;1&lt;/b&gt;</p>" {
		t.Fatalf("content.value = %v, want escaped render", got)
	}
	if _, ok := firstPersonalization(t, m)["dynamic_template_data"]; ok {
		t.Error("dynamic_template_data must be omitted on metadata fallback track")
	}
}

// TestSendNoTemplateDefaults 无模板无 metadata：回落最小兜底模板（同 smtp
// 约定），保证验证码链路永远有可发送内容。
func TestSendNoTemplateDefaults(t *testing.T) {
	srv, cap := newTestServer(http.StatusAccepted, "")
	defer srv.Close()

	s := newTestSender(t, srv, nil)
	if err := s.Send(context.Background(), "user@example.com", "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	m := decodeBody(t, cap)
	if got := m["subject"]; got != defaultSubject {
		t.Fatalf("subject = %v, want default %q", got, defaultSubject)
	}
	block := m["content"].([]any)[0].(map[string]any)
	if got := block["value"]; got != strings.ReplaceAll(defaultBody, "{code}", "246810") {
		t.Fatalf("content.value = %v, want default render", got)
	}
}

// TestSendTemplateKeyOverride 模板键覆盖：metadata["subject."+tpl] /
// ["body."+tpl] 按模板键取用（§15.2：模板内容存 metadata）。
func TestSendTemplateKeyOverride(t *testing.T) {
	srv, cap := newTestServer(http.StatusAccepted, "")
	defer srv.Close()

	s := newTestSender(t, srv, func(e *providerpb.Ext) {
		e.Metadata = map[string]string{
			"subject.otp": "登录验证", "body.otp": "code={code}",
			"subject.other": "其他", "body.other": "other={code}",
		}
	})
	if err := s.Send(context.Background(), "user@example.com", "other", map[string]string{"code": "135790"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	m := decodeBody(t, cap)
	if m["subject"] != "其他" {
		t.Fatalf("subject = %v, want other-key template", m["subject"])
	}
	block := m["content"].([]any)[0].(map[string]any)
	if block["value"] != "other=135790" {
		t.Fatalf("content.value = %v, want other-key render", block["value"])
	}
}

// TestSendOptionalFieldsConsumed 可选字段开启才进请求体：reply_to →
// reply_to.email，sandbox_mode → mail_settings.sandbox_mode.enable=true。
func TestSendOptionalFieldsConsumed(t *testing.T) {
	srv, cap := newTestServer(http.StatusAccepted, "")
	defer srv.Close()

	s := newTestSender(t, srv, func(e *providerpb.Ext) {
		e.ReplyTo = "support@example.com"
		e.SandboxMode = true
	})
	if err := s.Send(context.Background(), "user@example.com", "otp", map[string]string{"code": "246810"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	m := decodeBody(t, cap)
	reply, ok := m["reply_to"].(map[string]any)
	if !ok || reply["email"] != "support@example.com" {
		t.Fatalf("reply_to = %v, want reply_to.email passthrough", m["reply_to"])
	}
	settings, ok := m["mail_settings"].(map[string]any)
	if !ok {
		t.Fatalf("mail_settings = %v, want object", m["mail_settings"])
	}
	sandbox, ok := settings["sandbox_mode"].(map[string]any)
	if !ok || sandbox["enable"] != true {
		t.Fatalf("sandbox_mode = %v, want enable=true", settings["sandbox_mode"])
	}
}

// TestSendHTTPErrorWithVendorMessage 非 2xx：fail-closed 且厂商错误消息
// （errors[].message）保留进错误串供上层。
func TestSendHTTPErrorWithVendorMessage(t *testing.T) {
	srv, _ := newTestServer(http.StatusUnauthorized,
		`{"errors":[{"message":"The provided authorization grant is invalid, expired, or revoked","field":null}]}`)
	defer srv.Close()

	s := newTestSender(t, srv, nil)
	err := s.Send(context.Background(), "user@example.com", "otp", nil)
	if err == nil {
		t.Fatal("Send on http 401 must fail")
	}
	if !strings.Contains(err.Error(), "http 401") || !strings.Contains(err.Error(), "authorization grant") {
		t.Fatalf("err = %v, want status and vendor message preserved", err)
	}
}

// TestSendHTTPErrorNonJSONBody 非 2xx 非 JSON 错误体：fail-closed，原文
// 截断保留。
func TestSendHTTPErrorNonJSONBody(t *testing.T) {
	srv, _ := newTestServer(http.StatusInternalServerError, "upstream exploded")
	defer srv.Close()

	s := newTestSender(t, srv, nil)
	err := s.Send(context.Background(), "user@example.com", "otp", nil)
	if err == nil || !strings.Contains(err.Error(), "http 500") || !strings.Contains(err.Error(), "upstream exploded") {
		t.Fatalf("err = %v, want http 500 with raw body", err)
	}
}

// TestSendCorruptJSONBodyOn2xx 2xx 非空体 JSON 损坏：拒绝（不静默当成功）。
func TestSendCorruptJSONBodyOn2xx(t *testing.T) {
	srv, _ := newTestServer(http.StatusAccepted, "not-json")
	defer srv.Close()

	s := newTestSender(t, srv, nil)
	err := s.Send(context.Background(), "user@example.com", "otp", nil)
	if err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Fatalf("err = %v, want decode failure", err)
	}
}

// TestSend2xxWithErrorsObject 2xx 携带错误对象（异常形态）：fail-closed。
func TestSend2xxWithErrorsObject(t *testing.T) {
	srv, _ := newTestServer(http.StatusAccepted, `{"errors":[{"message":"sandbox anomaly"}]}`)
	defer srv.Close()

	s := newTestSender(t, srv, nil)
	err := s.Send(context.Background(), "user@example.com", "otp", nil)
	if err == nil || !strings.Contains(err.Error(), "sandbox anomaly") {
		t.Fatalf("err = %v, want error object rejected", err)
	}
}

// TestSendValidation 收件地址为空 → ErrEmptyTo，不发请求。
func TestSendValidation(t *testing.T) {
	s, err := build(testProvider(t, nil), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := s.Send(context.Background(), "", "otp", nil); !errors.Is(err, ErrEmptyTo) {
		t.Fatalf("empty to err = %v, want ErrEmptyTo", err)
	}
}

// TestInitRegistersAsEmailVendor init() 已按 §15.3 注册（category=email，
// Schema 声明完整字段口径供 /schema 渲染；client_id 与 SMTP 专属键不声明，
// auth 专属键不下发）。
func TestInitRegistersAsEmailVendor(t *testing.T) {
	meta, ok := provider.LookupSenderMeta(Type)
	if !ok {
		t.Fatal("sendgrid not registered in sender registry")
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
	cs, ok := byKey["client_secret"]
	if !ok {
		t.Fatal("meta.Schema() must include client_secret（API Key）")
	}
	if cs.Type != "secret" || !cs.Required {
		t.Fatalf("client_secret attrs = %q / %v, want secret + required", cs.Type, cs.Required)
	}
	if f := byKey["from"]; !f.Required {
		t.Error("from must be required")
	}
	if _, ok := byKey["client_id"]; ok {
		t.Error("meta.Schema() must not contain client_id（SendGrid 无意义）")
	}
	if tc := byKey["template_code"]; !ok || tc.Type != "text" {
		t.Fatalf("template_code = %v, want optional text", tc)
	}
	if sm := byKey["sandbox_mode"]; !ok || sm.Type != "checkbox" || sm.Section != "policy" {
		t.Fatalf("sandbox_mode = %v, want checkbox in policy", sm)
	}
	if rt := byKey["reply_to"]; !ok || rt.Section != "endpoint" {
		t.Fatalf("reply_to = %v, want endpoint field", rt)
	}
	for _, key := range []string{"provider_key", "display_name", "intranet_endpoint", "metadata", provider.ProxyRefKey} {
		if _, found := byKey[key]; !found {
			t.Errorf("meta.Schema() missing %q", key)
		}
	}
	// SMTP 专属键对本厂商无意义（REST 非 SMTP），不声明不消费。
	for _, key := range []string{"host", "port", "user", "password", "disable_ssl"} {
		if _, found := byKey[key]; found {
			t.Errorf("meta.Schema() must not contain smtp-only key %q", key)
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
