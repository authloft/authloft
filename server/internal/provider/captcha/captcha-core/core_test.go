// core_test.go 覆盖共用 siteverify 逻辑（docs/后端架构.md §9.1）：请求形态
// （POST + form-urlencoded + 恰好 secret/response 两字段）、success 判定与
// 失败映射（success=false → ErrInvalid；HTTP 500 / 坏 JSON → 基础设施错误）、
// endpoint 优先级（ext.endpoint > 厂商默认）、出站代理经 Outbound 池化 client
// （§15.4）；另覆盖 JSON body 编码分支（capjs/capd，§15.5）及 form / JSON
// 双分支共存互不串扰。httptest 假端点，不打真实厂商。
package captchacore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/proxyclient"
)

const testDefaultURL = "https://default.example/siteverify"

// newCore 构造以 httptest 为 ext.endpoint 的校验器。
func newCore(t *testing.T, endpoint, secret string, outbound *proxyclient.Pool) *Verifier {
	t.Helper()
	p := &provider.Provider{
		Key:      "pk",
		Type:     "turnstile",
		Ext:      &providerpb.Ext{ClientId: "site", ClientSecret: secret, Endpoint: endpoint},
		Outbound: outbound,
	}
	v, err := New(p, testDefaultURL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

// recorder 断言 siteverify 请求形态的假端点。
type recorder struct {
	server   *httptest.Server
	method   string
	ctype    string
	form     map[string]string
	status   int
	body     string
	hitCount int
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	rec := &recorder{status: http.StatusOK}
	rec.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.hitCount++
		rec.method = r.Method
		rec.ctype = r.Header.Get("Content-Type")
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		rec.form = map[string]string{}
		for k, vs := range r.PostForm {
			rec.form[k] = vs[0]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rec.status)
		body := rec.body
		if body == "" {
			body = `{"success":true}`
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(rec.server.Close)
	return rec
}

// TestCoreFormAndSuccess 请求形态与 success 判定（§9.1 三家同一形态）。
func TestCoreFormAndSuccess(t *testing.T) {
	rec := newRecorder(t)
	v := newCore(t, rec.server.URL, "sec-1", nil)
	if err := v.Verify(context.Background(), "pk", provider.Submission{Token: "tok-1"}); err != nil {
		t.Fatalf("success=true = %v, want nil", err)
	}
	if rec.hitCount != 1 || rec.method != http.MethodPost {
		t.Fatalf("hit=%d method=%q, want 1 次 POST", rec.hitCount, rec.method)
	}
	if rec.ctype != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want form-urlencoded", rec.ctype)
	}
	if len(rec.form) != 2 || rec.form["secret"] != "sec-1" || rec.form["response"] != "tok-1" {
		t.Errorf("form = %v, want exactly {secret:sec-1, response:tok-1}", rec.form)
	}
}

// TestCoreFailures 失败映射：success=false → ErrInvalid（可判别）；HTTP 500 /
// 坏 JSON → 基础设施错误；空 token 不发请求直接 ErrInvalid。
func TestCoreFailures(t *testing.T) {
	rec := newRecorder(t)
	rec.body = `{"success":false,"error-codes":["invalid-input-response"]}`
	v := newCore(t, rec.server.URL, "s", nil)
	if err := v.Verify(context.Background(), "pk", provider.Submission{Token: "t"}); !errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("success=false = %v, want ErrInvalid", err)
	}

	rec.status = http.StatusInternalServerError
	if err := newCore(t, rec.server.URL, "s", nil).Verify(context.Background(), "pk", provider.Submission{Token: "t"}); err == nil || errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("HTTP 500 = %v, want infra error", err)
	}

	rec.status = http.StatusOK
	rec.body = "not-json"
	if err := newCore(t, rec.server.URL, "s", nil).Verify(context.Background(), "pk", provider.Submission{Token: "t"}); err == nil || errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("坏 JSON = %v, want infra error", err)
	}

	rec2 := newRecorder(t)
	if err := newCore(t, rec2.server.URL, "s", nil).Verify(context.Background(), "pk", provider.Submission{}); !errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("空 token = %v, want ErrInvalid", err)
	}
	if rec2.hitCount != 0 {
		t.Fatalf("空 token 不应发请求, hits = %d", rec2.hitCount)
	}
}

// TestCoreEndpointPrecedence 地址优先级（§9.1）：ext.endpoint 覆盖厂商默认；
// ext.endpoint 空串回落 type 子包声明的默认端点。
func TestCoreEndpointPrecedence(t *testing.T) {
	rec := newRecorder(t)
	v := newCore(t, rec.server.URL, "s", nil)
	if err := v.Verify(context.Background(), "pk", provider.Submission{Token: "t"}); err != nil {
		t.Fatalf("ext.endpoint 校验 = %v, want nil", err)
	}
	if rec.hitCount != 1 {
		t.Fatalf("ext.endpoint 请求数 = %d, want 1", rec.hitCount)
	}
	fallback, err := New(&provider.Provider{
		Key: "pk", Type: "turnstile",
		Ext: &providerpb.Ext{ClientId: "site", ClientSecret: "s"},
	}, testDefaultURL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if fallback.verifyURL != testDefaultURL {
		t.Fatalf("ext.endpoint 为空回落默认 = %q, want %q", fallback.verifyURL, testDefaultURL)
	}
	if _, err := New(nil, testDefaultURL); err == nil {
		t.Fatal("nil provider ext 应构造失败")
	}
}

// TestCoreViaOutboundProxy http 代理桩实证：siteverify 流量经池化 client 走
// 代理而非直连（§15.4），目标零命中即证 Outbound 固化生效。
func TestCoreViaOutboundProxy(t *testing.T) {
	target := newRecorder(t)
	var proxyHits int
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits++
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer proxy.Close()

	u, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	portNum, _ := strconv.Atoi(u.Port())
	pool := proxyclient.NewPoolSet().Get("test", mustConfig(t, "http", u.Hostname(), int32(portNum)))
	v := newCore(t, target.server.URL, "sec-1", pool)
	if err := v.Verify(context.Background(), "pk", provider.Submission{Token: "tok-1"}); err != nil {
		t.Fatalf("经代理校验 = %v, want nil", err)
	}
	if proxyHits != 1 {
		t.Fatalf("代理命中 = %d, want 1（流量须经代理）", proxyHits)
	}
	if target.hitCount != 0 {
		t.Fatalf("直连目标命中 = %d, want 0（不得绕过代理）", target.hitCount)
	}
}

func mustConfig(t *testing.T, scheme, host string, port int32) proxyclient.Config {
	t.Helper()
	cfg, err := proxyclient.NewConfig(scheme, host, port, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// jsonRecorder 断言 JSON 编码请求形态的假端点：捕获原始 body——form 分支的
// ParseForm 对 JSON 体不生效，须读原文判形态（form 体不是合法 JSON，误走
// form 分支时下方断言必失败，可证伪）。
type jsonRecorder struct {
	server *httptest.Server
	method string
	ctype  string
	raw    []byte
	status int
	body   string
	hits   int
}

func newJSONRecorder(t *testing.T) *jsonRecorder {
	t.Helper()
	rec := &jsonRecorder{status: http.StatusOK}
	rec.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.hits++
		rec.method = r.Method
		rec.ctype = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(io.LimitReader(r.Body, remoteBodyLimit))
		rec.raw = raw
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rec.status)
		body := rec.body
		if body == "" {
			body = `{"success":true}`
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(rec.server.Close)
	return rec
}

func newJSONVerifier(t *testing.T, endpoint string) *Verifier {
	t.Helper()
	p := &provider.Provider{
		Key:  "pk",
		Type: "capjs",
		Ext:  &providerpb.Ext{ClientId: "site", ClientSecret: "s", Endpoint: endpoint},
	}
	v, err := NewJSON(p, testDefaultURL)
	if err != nil {
		t.Fatalf("NewJSON: %v", err)
	}
	return v
}

// TestCoreJSONEncoding JSON 编码分支（capjs/capd，§15.5）：请求体恰为
// {secret, response} 两键、Content-Type application/json；success 判定与
// 失败映射（success=false → ErrInvalid；HTTP 500 / 坏 JSON → 基础设施错误；
// 空 token 不发请求）与 form 分支同骨架；同端点上 New 仍发 form-urlencoded
// ——双编码分支共存且互不串扰（三家 form 行为零变化）。
func TestCoreJSONEncoding(t *testing.T) {
	rec := newJSONRecorder(t)
	v := newJSONVerifier(t, rec.server.URL)
	if err := v.Verify(context.Background(), "pk", provider.Submission{Token: "tok-1"}); err != nil {
		t.Fatalf("JSON success=true = %v, want nil", err)
	}
	if rec.hits != 1 || rec.method != http.MethodPost {
		t.Fatalf("hit=%d method=%q, want 1 次 POST", rec.hits, rec.method)
	}
	if rec.ctype != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", rec.ctype)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.raw, &got); err != nil {
		t.Fatalf("请求体非合法 JSON: %v（原文 %q）", err, rec.raw)
	}
	if len(got) != 2 || got["secret"] != "s" || got["response"] != "tok-1" {
		t.Errorf("JSON body = %v, want exactly {secret:s, response:tok-1}", got)
	}

	rec.body = `{"success":false}`
	if err := newJSONVerifier(t, rec.server.URL).Verify(context.Background(), "pk", provider.Submission{Token: "t"}); !errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("JSON success=false = %v, want ErrInvalid", err)
	}

	rec.status = http.StatusInternalServerError
	if err := newJSONVerifier(t, rec.server.URL).Verify(context.Background(), "pk", provider.Submission{Token: "t"}); err == nil || errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("JSON HTTP 500 = %v, want infra error", err)
	}

	rec.status = http.StatusOK
	rec.body = "not-json"
	if err := newJSONVerifier(t, rec.server.URL).Verify(context.Background(), "pk", provider.Submission{Token: "t"}); err == nil || errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("JSON 坏响应 = %v, want infra error", err)
	}

	rec2 := newJSONRecorder(t)
	if err := newJSONVerifier(t, rec2.server.URL).Verify(context.Background(), "pk", provider.Submission{}); !errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("JSON 空 token = %v, want ErrInvalid", err)
	}
	if rec2.hits != 0 {
		t.Fatalf("JSON 空 token 不应发请求, hits = %d", rec2.hits)
	}

	// 端点优先级与构造防御与 form 分支同口径：ext.endpoint 空回落默认；
	// nil provider ext 构造失败。
	fallback, err := NewJSON(&provider.Provider{
		Key: "pk", Type: "capjs",
		Ext: &providerpb.Ext{ClientId: "site", ClientSecret: "s"},
	}, testDefaultURL)
	if err != nil {
		t.Fatalf("NewJSON fallback: %v", err)
	}
	if fallback.verifyURL != testDefaultURL {
		t.Fatalf("JSON ext.endpoint 为空回落默认 = %q, want %q", fallback.verifyURL, testDefaultURL)
	}
	if _, err := NewJSON(nil, testDefaultURL); err == nil {
		t.Fatal("JSON nil provider ext 应构造失败")
	}

	// 双分支共存：同端点上 form 构造器（三家路径）仍发 form-urlencoded，
	// 未被 JSON 分支波及。
	formRec := newJSONRecorder(t)
	formV := newCore(t, formRec.server.URL, "sec-form", nil)
	if err := formV.Verify(context.Background(), "pk", provider.Submission{Token: "tok-2"}); err != nil {
		t.Fatalf("form 分支回归 = %v, want nil", err)
	}
	if formRec.ctype != "application/x-www-form-urlencoded" {
		t.Fatalf("form 分支 Content-Type = %q, want form-urlencoded（行为零变化）", formRec.ctype)
	}
	formVals, err := url.ParseQuery(string(formRec.raw))
	if err != nil || len(formVals) != 2 || formVals.Get("secret") != "sec-form" || formVals.Get("response") != "tok-2" {
		t.Fatalf("form body = %q, want exactly {secret:sec-form, response:tok-2}", formRec.raw)
	}
}
