// wechat_mp 适配器单测：用 httptest 扮演微信 code2session，
// 经 SDK 的自定义 http.Client 拦截请求（不访问真实微信）；覆盖成功、
// 微信错误码、空 code / 空 openid、未配置凭证、不同 provider 实例使用
// 各自 app_id（证明无硬编码 / 无全局默认），以及 Exchange → FetchUser。
package wechatmp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/proxyclient"
)

// rewriteTransport 把 SDK 的 api.weixin.qq.com 请求改写到 httptest 服务器。
type rewriteTransport struct {
	base *url.URL
	rt   http.RoundTripper
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = t.base.Scheme
	clone.URL.Host = t.base.Host
	return t.rt.RoundTrip(clone)
}

func clientForServer(srv *httptest.Server) *http.Client {
	base, err := url.Parse(srv.URL)
	if err != nil {
		panic(err)
	}
	return &http.Client{Transport: rewriteTransport{base: base, rt: http.DefaultTransport}}
}

func testProvider(key, appID, appSecret string) *provider.Provider {
	return &provider.Provider{
		Key:  key,
		Type: Type,
		Ext:  &providerpb.Ext{AppId: appID, ClientSecret: appSecret},
	}
}

// TestCode2SessionSuccess 验证 code2session 成功路径与请求参数。
func TestCode2SessionSuccess(t *testing.T) {
	var gotAppID, gotSecret, gotCode, gotGrant string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		gotAppID = q.Get("appid")
		gotSecret = q.Get("secret")
		gotCode = q.Get("js_code")
		gotGrant = q.Get("grant_type")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"openid":"o-1","session_key":"session-key","unionid":"u-1"}`)
	}))
	defer srv.Close()

	a, err := build(testProvider("mp", "wx-app", "wx-secret"), clientForServer(srv))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	id, err := a.Code2Session(context.Background(), "code-1")
	if err != nil {
		t.Fatalf("Code2Session: %v", err)
	}
	if id.ProviderKey != "mp" || id.ProviderType != Type || id.OpenID != "o-1" || id.UnionID != "u-1" {
		t.Fatalf("identity = %+v", id)
	}
	if gotAppID != "wx-app" || gotSecret != "wx-secret" || gotCode != "code-1" || gotGrant != "authorization_code" {
		t.Fatalf("query appid=%q secret=%q js_code=%q grant_type=%q", gotAppID, gotSecret, gotCode, gotGrant)
	}
}

// TestCode2SessionWechatError 微信 errcode 非 0 必须作为错误上抛。
func TestCode2SessionWechatError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"errcode":40029,"errmsg":"invalid code"}`)
	}))
	defer srv.Close()

	a, err := build(testProvider("mp", "wx-app", "wx-secret"), clientForServer(srv))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	_, err = a.Code2Session(context.Background(), "bad-code")
	if err == nil || !strings.Contains(err.Error(), "40029") {
		t.Fatalf("err = %v, want wechat errcode 40029", err)
	}
}

// TestCode2SessionEmptyCode / EmptyOpenID 边界。
func TestCode2SessionEmptyCode(t *testing.T) {
	a, err := build(testProvider("mp", "wx-app", "wx-secret"), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := a.Code2Session(context.Background(), ""); !errors.Is(err, ErrEmptyCode) {
		t.Fatalf("err = %v, want ErrEmptyCode", err)
	}
}

func TestCode2SessionEmptyOpenID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"openid":"","session_key":"sk"}`)
	}))
	defer srv.Close()

	a, err := build(testProvider("mp", "wx-app", "wx-secret"), clientForServer(srv))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := a.Code2Session(context.Background(), "code"); !errors.Is(err, ErrEmptyOpenID) {
		t.Fatalf("err = %v, want ErrEmptyOpenID", err)
	}
}

// TestBuildNotConfigured：Ext.app_id / client_secret 为空即未配置（§13.0），
// 不回落全局默认值。
func TestBuildNotConfigured(t *testing.T) {
	for _, p := range []*provider.Provider{
		testProvider("mp", "", "secret"),
		testProvider("mp", "app", ""),
		testProvider("mp", "", ""),
	} {
		if _, err := build(p, nil); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("build(%+v) err = %v, want ErrNotConfigured", p.Ext, err)
		}
	}
}

// TestDifferentProvisionInstancesUseOwnAppID：两个 provider 实例各自携带
// 不同 app_id，请求参数必须分别对应（证明不是硬编码 / 全局默认）。
func TestDifferentProvisionInstancesUseOwnAppID(t *testing.T) {
	var mu sync.Mutex
	var appIDs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		appIDs = append(appIDs, r.URL.Query().Get("appid"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"openid":"o-%s"}`, r.URL.Query().Get("appid"))
	}))
	defer srv.Close()

	first, err := build(testProvider("mp-a", "wx-app-a", "secret-a"), clientForServer(srv))
	if err != nil {
		t.Fatalf("build first: %v", err)
	}
	second, err := build(testProvider("mp-b", "wx-app-b", "secret-b"), clientForServer(srv))
	if err != nil {
		t.Fatalf("build second: %v", err)
	}
	if _, err := first.Code2Session(context.Background(), "c1"); err != nil {
		t.Fatalf("first Code2Session: %v", err)
	}
	if _, err := second.Code2Session(context.Background(), "c2"); err != nil {
		t.Fatalf("second Code2Session: %v", err)
	}
	mu.Lock()
	got := append([]string(nil), appIDs...)
	mu.Unlock()
	if len(got) != 2 || got[0] != "wx-app-a" || got[1] != "wx-app-b" {
		t.Fatalf("appIDs = %v, want [wx-app-a wx-app-b]", got)
	}
}

// TestExchangeThenFetchUser：channel=api 的 Exchange / FetchUser 组合。
func TestExchangeThenFetchUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"openid":"o-1","unionid":"u-1"}`)
	}))
	defer srv.Close()

	a, err := build(testProvider("mp", "wx-app", "wx-secret"), clientForServer(srv))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "code-1"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	id, err := a.FetchUser(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "o-1" || id.UnionID != "u-1" || id.ProviderKey != "mp" {
		t.Fatalf("identity = %+v", id)
	}
	if _, err := a.FetchUser(context.Background(), nil); !errors.Is(err, ErrNilToken) {
		t.Fatalf("nil token err = %v, want ErrNilToken", err)
	}
}

// TestBuildAuthURLNotSupported：channel=api 无跳转流程，明确返回哨兵
// 错误（不返回空串当成功），errors.Is 可命中。
func TestBuildAuthURLNotSupported(t *testing.T) {
	a, err := build(testProvider("mp", "wx-app", "wx-secret"), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got, err := a.BuildAuthURL(&provider.AuthContext{ProviderKey: "mp", RedirectURI: "https://example.com/cb"})
	if got != "" {
		t.Fatalf("BuildAuthURL url = %q, want empty", got)
	}
	if !errors.Is(err, ErrAuthURLNotSupported) {
		t.Fatalf("BuildAuthURL err = %v, want ErrAuthURLNotSupported", err)
	}
}

// TestRegisteredInRegistry：init() 自注册可见，NewAdapter 能构造出 api 适配器。
func TestRegisteredInRegistry(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.Channel != provider.ChannelAPI || meta.Category != "auth" {
		t.Fatalf("Lookup(%q) = (%+v, %v)", Type, meta, ok)
	}
	a, err := provider.NewAdapter(testProvider("mp", "wx-app", "wx-secret"))
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	if a.Channel() != provider.ChannelAPI {
		t.Fatalf("Channel = %q, want api", a.Channel())
	}
}

// TestSchemaKeepSet keep 集收敛回归（§5.3 keep 集表 auth 行，声明即运行期
// 实际消费）：Schema 的 Ext 段恰为 app_id / client_secret（声明序同 §5.3 示例、
// 均必填），引用键 proxy_provider_key 仍由漏斗统一追加；keep 外死字段
// （client_id / cert / scopes / user_mapping / metadata 等）不再下发。
func TestSchemaKeepSet(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok {
		t.Fatalf("Lookup(%q) 未注册", Type)
	}
	full := meta.Schema()
	// 声明序即渲染序：basic(3) → Ext(2，app_id 在前) → display(3) → policy(5)
	// → 引用键(1)。
	wantOrder := []string{"provider_key", "display_name", "union_provider",
		"app_id", "client_secret",
		"icon_url", "sort_order", "remark",
		"is_enabled", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields",
		provider.ProxyRefKey}
	if len(full) != len(wantOrder) {
		t.Fatalf("schema fields = %d, want %d（3+2+3+5+1）", len(full), len(wantOrder))
	}
	byKey := make(map[string]provider.FieldMeta, len(wantOrder))
	for i, f := range full {
		if f.Key != wantOrder[i] {
			t.Fatalf("schema[%d].Key = %q, want %q（声明序）", i, f.Key, wantOrder[i])
		}
		byKey[f.Key] = f
	}
	for _, k := range []string{"app_id", "client_secret"} {
		f := byKey[k]
		if !f.Required {
			t.Errorf("%s required = false, want true（凭证缺失即构造失败）", k)
		}
		if f.Storage != provider.StorageExt {
			t.Errorf("%s Storage = %q, want ext（写入键集按 Storage 派生）", k, f.Storage)
		}
	}
	if f := byKey["app_id"]; f.Advanced {
		t.Errorf("app_id advanced = true, want false（必填主凭证不折叠）")
	}
	// 死字段不再下发。
	for _, dead := range []string{"client_id", "cert", "scopes", "provider_url",
		"custom_auth_url", "custom_token_url", "custom_user_info_url", "user_mapping", "metadata"} {
		if f, ok := byKey[dead]; ok {
			t.Errorf("死字段 %q 仍在 Schema: %+v", dead, f)
		}
	}
	// 引用键由 SchemaFor 漏斗追加：末位、endpoint / select / dynamic。
	ref := full[len(full)-1]
	if ref.Key != provider.ProxyRefKey || ref.Section != "endpoint" ||
		ref.Type != "select" || ref.Kind != provider.FieldDynamicOptions {
		t.Fatalf("引用键 = %+v, want 末位 endpoint/select/dynamic %q", ref, provider.ProxyRefKey)
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

// TestNewAdapterOutboundTransport 验证构造期按装配固化的 Outbound 池构造出站
// client：非 nil 时经 WithHttpClient 注入 SDK 的 client 持有池的代理 Transport
// （§15.4），nil（引用键空 = 直连）注入 10s 超时的直连 client。经包内 hc 钩子
// 读取注入的 client，不新增生产导出。
func TestNewAdapterOutboundTransport(t *testing.T) {
	cases := []struct {
		name      string
		outbound  *proxyclient.Pool
		wantProxy bool
	}{
		{name: "http proxy", outbound: proxyPool(t, "http", "127.0.0.1", 8080, "user", "pass"), wantProxy: true},
		{name: "socks5 proxy", outbound: proxyPool(t, "socks5", "127.0.0.1", 1080, "", ""), wantProxy: true},
		{name: "nil Outbound direct", outbound: nil, wantProxy: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testProvider("mp", "wx-app", "wx-secret")
			p.Outbound = tc.outbound
			a, err := newAdapter(p)
			if err != nil {
				t.Fatalf("newAdapter: %v", err)
			}
			adapter, ok := a.(*Adapter)
			if !ok || adapter == nil {
				t.Fatalf("adapter = %T, want *Adapter", a)
			}
			if adapter.hc == nil {
				t.Fatal("injected client is nil, want client constructed at build time")
			}
			if adapter.hc.Timeout != 10*time.Second {
				t.Errorf("Timeout = %v, want 10s", adapter.hc.Timeout)
			}
			if !tc.wantProxy {
				if adapter.hc.Transport != nil {
					t.Fatalf("direct transport = %T, want nil", adapter.hc.Transport)
				}
				return
			}
			tr, ok := adapter.hc.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("proxy transport = %T, want *http.Transport", adapter.hc.Transport)
			}
			if tr.Proxy == nil && tr.DialContext == nil {
				t.Fatal("proxy transport has neither Proxy (http/https) nor DialContext (socks5)")
			}
		})
	}
}

// TestBuildInjectedClientPriority 验证测试经 build 注入的 client 优先于
// Outbound 代理配置，测试注入口径保持不变。
func TestBuildInjectedClientPriority(t *testing.T) {
	injected := &http.Client{}
	p := testProvider("mp", "wx-app", "wx-secret")
	p.Outbound = proxyPool(t, "http", "127.0.0.1", 8080, "", "")
	a, err := build(p, injected)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if a.hc != injected {
		t.Fatalf("injected client = %p, want %p (test injection must win over outbound pool)", a.hc, injected)
	}
}
