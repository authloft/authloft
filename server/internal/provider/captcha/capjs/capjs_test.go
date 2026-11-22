// capjs_test.go 覆盖 capjs 子包装配与校验链路：注册表注册（meta / Schema
// 差异字段 / CSP 登记）、真实 factory（provider.NewVerifier 分派）下的 JSON
// siteverify 请求形态、端点派生（endpoint 优先、widget_api_base + site key
// 回落）与失败路径全 fail-closed。httptest 假端点，不打真实服务。
package capjs

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
)

// recorder 断言 siteverify 请求形态的假端点（捕获原始 body 与路径）。
type recorder struct {
	server *httptest.Server
	method string
	ctype  string
	path   string
	raw    []byte
	status int
	body   string
	hits   int
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	rec := &recorder{status: http.StatusOK}
	rec.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.hits++
		rec.method = r.Method
		rec.ctype = r.Header.Get("Content-Type")
		rec.path = r.URL.Path
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
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

func newProvider(endpoint, apiBase string) *provider.Provider {
	return &provider.Provider{
		Key:  "cap_row",
		Type: Type,
		Ext:  &providerpb.Ext{ClientId: "cap-site", ClientSecret: "sec-1", Endpoint: endpoint, WidgetApiBase: apiBase},
	}
}

// TestCapjsRegistered 注册表断言（§15.3）：meta 缺位即 blank import 被删；
// Schema 差异字段（widget_api_base 必填、widget_script_url 可选 advanced）
// 与 CSP 登记（worker-src blob:）随实现声明。
func TestCapjsRegistered(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok {
		t.Fatalf("注册表缺 type %q——init 自注册未生效", Type)
	}
	if meta.Category != provider.CategoryCaptcha {
		t.Fatalf("category = %q, want %q", meta.Category, provider.CategoryCaptcha)
	}
	if meta.Schema == nil {
		t.Fatal("Schema 未声明（/schema 唯一数据源不得为空）")
	}
	fields := meta.Schema()
	got := make(map[string]provider.FieldMeta, len(fields))
	order := make([]string, 0, len(fields))
	for _, f := range fields {
		if _, dup := got[f.Key]; dup {
			t.Fatalf("字段 %q 重复声明", f.Key)
		}
		got[f.Key] = f
		order = append(order, f.Key)
	}
	wantOrder := []string{
		"provider_key", "display_name",
		"client_id", "client_secret", "widget_api_base", "endpoint", "widget_script_url",
		"icon_url", "sort_order", "remark", "proxy_provider_key",
	}
	if len(order) != len(wantOrder) {
		t.Fatalf("字段数 = %d (%v), want %d", len(order), order, len(wantOrder))
	}
	for i, w := range wantOrder {
		if order[i] != w {
			t.Fatalf("字段序 = %v, want %v（Ext 按 capjs 行序）", order, wantOrder)
		}
	}
	if !got["widget_api_base"].Required || got["widget_api_base"].Storage != provider.StorageExt {
		t.Errorf("widget_api_base = %+v, want 必填且落 Ext", got["widget_api_base"])
	}
	if got["widget_script_url"].Required || !got["widget_script_url"].Advanced {
		t.Errorf("widget_script_url = %+v, want 可选 advanced", got["widget_script_url"])
	}
	if got["endpoint"].Required || !got["endpoint"].Advanced {
		t.Errorf("endpoint = %+v, want 可选 advanced", got["endpoint"])
	}
	if _, ok := got["is_enabled"]; ok {
		t.Error("is_enabled 是 auth 专属开关，captcha 类别不得声明")
	}
	if src := meta.CSPSources["worker-src"]; len(src) != 1 || src[0] != "blob:" {
		t.Errorf("worker-src = %v, want [blob:]（PoW Web Worker）", src)
	}
	if meta.CSPSourcesOf == nil {
		t.Error("CSPSourcesOf 未声明——按行派生源缺失，capd API 会被基线 CSP 拦截")
	}
}

// TestCapjsCSPDerivedConnectSrc 按行派生 connect-src（接口文档 §8 capjs 行 /
// 后端架构 §9.4「按行配置派生源」）：源 = widget_api_base 的 origin——
// scheme 缺省 https 补全、路径与尾斜杠丢弃、显式 scheme 保留；base 空 /
// nil Ext / 无 host 的非法值一律不贡献（返回 nil，未配置行不写入任何域名）。
func TestCapjsCSPDerivedConnectSrc(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok {
		t.Fatalf("注册表缺 type %q", Type)
	}
	cases := []struct {
		name string
		base string
		want string
	}{
		{"https 完整", "https://capd.example.com", "https://capd.example.com"},
		{"路径与尾斜杠丢弃", "https://capd.example.com/prefix/", "https://capd.example.com"},
		{"scheme 缺省 https", "capd.example.com", "https://capd.example.com"},
		{"host:port 缺省 https", "capd.example.com:8443", "https://capd.example.com:8443"},
		{"显式 http 保留", "http://capd.local:8080", "http://capd.local:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := meta.CSPSourcesOf(newProvider("", tc.base))
			if len(got["connect-src"]) != 1 || got["connect-src"][0] != tc.want {
				t.Fatalf("CSPSourcesOf(widget_api_base=%q) = %v, want connect-src [%s]", tc.base, got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		p    *provider.Provider
	}{
		{"base 空不贡献", newProvider("", "")},
		{"nil ext 不贡献", &provider.Provider{Key: "cap_row", Type: Type}},
		{"nil provider 不贡献", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := meta.CSPSourcesOf(tc.p); got != nil {
				t.Fatalf("CSPSourcesOf = %v, want nil（不贡献）", got)
			}
		})
	}
	t.Run("无 host 非法不贡献", func(t *testing.T) {
		if got := meta.CSPSourcesOf(newProvider("", "https://")); got != nil {
			t.Fatalf("CSPSourcesOf(\"https://\") = %v, want nil（非法不贡献）", got)
		}
	})
}

// TestCapjsFactoryJSONSiteverify 真实 factory 分派（provider.NewVerifier）下
// 的 JSON 编码链路：请求体恰为 {secret, response} 两键、Content-Type 为
// application/json；误走 form 分支时原始 body 非合法 JSON，断言必然失败。
func TestCapjsFactoryJSONSiteverify(t *testing.T) {
	rec := newRecorder(t)
	v, err := provider.NewVerifier(newProvider(rec.server.URL, ""))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(context.Background(), "cap_row", provider.Submission{Token: "tok-1"}); err != nil {
		t.Fatalf("success=true = %v, want nil", err)
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
	if len(got) != 2 || got["secret"] != "sec-1" || got["response"] != "tok-1" {
		t.Errorf("JSON body = %v, want exactly {secret:sec-1, response:tok-1}", got)
	}
}

// TestCapjsDerivedEndpoint 端点派生（§9.1 端点带 site key 路径段）：
// ext.endpoint 为空时按 <widget_api_base>/<site key>/siteverify 拼出（base
// 尾部斜杠去除防双斜杠）；ext.endpoint 优先于派生（派生源零请求）。
func TestCapjsDerivedEndpoint(t *testing.T) {
	rec := newRecorder(t)
	v, err := provider.NewVerifier(newProvider("", rec.server.URL+"/"))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(context.Background(), "cap_row", provider.Submission{Token: "t"}); err != nil {
		t.Fatalf("派生端点校验 = %v, want nil", err)
	}
	if rec.hits != 1 || rec.path != "/cap-site/siteverify" {
		t.Fatalf("hit=%d path=%q, want 1 次 POST /cap-site/siteverify", rec.hits, rec.path)
	}

	rec2, derived := newRecorder(t), newRecorder(t)
	v2, err := provider.NewVerifier(newProvider(rec2.server.URL, derived.server.URL))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v2.Verify(context.Background(), "cap_row", provider.Submission{Token: "t"}); err != nil {
		t.Fatalf("endpoint 优先校验 = %v, want nil", err)
	}
	if rec2.hits != 1 || derived.hits != 0 {
		t.Fatalf("endpoint 命中=%d 派生源命中=%d, want 1/0（ext.endpoint 优先）", rec2.hits, derived.hits)
	}
}

// TestCapjsFactoryFailClosed 失败路径全 fail-closed：endpoint 与
// widget_api_base/site key 均缺 → 构造期报错（不留空 URL 校验器）；
// success=false → ErrInvalid；HTTP 500 / 坏 JSON → 基础设施错误；空 token
// 不发请求直接 ErrInvalid。
func TestCapjsFactoryFailClosed(t *testing.T) {
	if _, err := provider.NewVerifier(newProvider("", "")); err == nil {
		t.Fatal("endpoint 与 widget_api_base 均空应构造失败")
	}
	if _, err := provider.NewVerifier(nil); err == nil {
		t.Fatal("nil provider 应构造失败")
	}

	rec := newRecorder(t)
	rec.body = `{"success":false}`
	v, err := provider.NewVerifier(newProvider(rec.server.URL, ""))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(context.Background(), "cap_row", provider.Submission{Token: "t"}); !errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("success=false = %v, want ErrInvalid", err)
	}

	rec.status = http.StatusInternalServerError
	if err := v.Verify(context.Background(), "cap_row", provider.Submission{Token: "t"}); err == nil || errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("HTTP 500 = %v, want infra error", err)
	}

	rec.status = http.StatusOK
	rec.body = "not-json"
	if err := v.Verify(context.Background(), "cap_row", provider.Submission{Token: "t"}); err == nil || errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("坏 JSON = %v, want infra error", err)
	}

	rec2 := newRecorder(t)
	v2, err := provider.NewVerifier(newProvider(rec2.server.URL, ""))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if err := v2.Verify(context.Background(), "cap_row", provider.Submission{}); !errors.Is(err, provider.ErrInvalid) {
		t.Fatalf("空 token = %v, want ErrInvalid", err)
	}
	if rec2.hits != 0 {
		t.Fatalf("空 token 不应发请求, hits = %d", rec2.hits)
	}
}
