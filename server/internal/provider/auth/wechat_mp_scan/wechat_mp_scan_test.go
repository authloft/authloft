// wechat_mp_scan 适配器单测：httptest 扮演微信侧（code2session、
// stable_token、getwxacodeunlimit 三端点），覆盖扫码通道特有面——
// FetchQrcode 成功（scene 参数断言 + 图片字节回传）、微信 errcode 上抛、
// 未配置拒绝、注册表 channel=qrcode、共享 access_token 缓存桥接。
// code2session 与 wechat_mp 同构部分只做代表性回归。
package wechatmpscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/proxyclient"
)

// rewriteTransport 把 SDK 的 api.weixin.qq.com 请求改写到 httptest 服务器
// （与 wechat_mp 测试同款）。
type rewriteTransport struct {
	base string
	rt   http.RoundTripper
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = t.base
	return t.rt.RoundTrip(clone)
}

func clientForServer(srv *httptest.Server) *http.Client {
	return &http.Client{Transport: rewriteTransport{base: strings.TrimPrefix(srv.URL, "http://"), rt: http.DefaultTransport}}
}

func testProvider(key, appID, appSecret string) *provider.Provider {
	return &provider.Provider{
		Key:  key,
		Type: Type,
		Ext:  &providerpb.Ext{AppId: appID, ClientSecret: appSecret},
	}
}

// TestRegistryRegistered 注册表形态：channel=qrcode、category=auth、
// Schema 按 keep 集收敛为五键（凭证两键 + 扫码三字段，后者随 metadata 撤除
// 移至 Ext 段尾、相对顺序不变）；storage_provider 为动态 select。
func TestRegistryRegistered(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok {
		t.Fatalf("Lookup(%q) 未注册", Type)
	}
	if meta.Channel != provider.ChannelQRCode || meta.Category != "auth" {
		t.Fatalf("meta = %+v, want qrcode/auth", meta)
	}
	full := meta.Schema()
	// 声明序即渲染序：basic(3) → Ext(8，凭证两键 + 扫码六字段在段尾、相对顺序
	// 不变) → display(4) → policy(5) → 引用键(1)。
	wantOrder := []string{"provider_key", "display_name", "union_provider",
		"app_id", "client_secret", "qrcode_auto_delete", "storage_provider", "storage_path",
		"qrcode_mode", "qrcode_format", "qrcode_tip",
		"icon_url", "ui_group", "sort_order", "remark",
		"is_enabled", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields",
		provider.ProxyRefKey}
	if len(full) != len(wantOrder) {
		t.Fatalf("schema fields = %d, want %d（3+8+4+5+1）", len(full), len(wantOrder))
	}
	byKey := make(map[string]provider.FieldMeta, len(wantOrder))
	for i, f := range full {
		if f.Key != wantOrder[i] {
			t.Fatalf("schema[%d].Key = %q, want %q（声明序、扫码字段在段尾且相对顺序不变）", i, f.Key, wantOrder[i])
		}
		byKey[f.Key] = f
	}
	for _, k := range []string{"app_id", "client_secret"} {
		f := byKey[k]
		if !f.Required {
			t.Errorf("%s required = false, want true（凭证缺失即构造失败）", k)
		}
		if f.Storage != provider.StorageExt {
			t.Errorf("%s Storage = %q, want ext", k, f.Storage)
		}
	}
	if f := byKey["app_id"]; f.Advanced {
		t.Errorf("app_id advanced = true, want false（必填主凭证不折叠）")
	}
	// storage_provider 动态 select：候选 storage 类 provider_key 由 handler
	// 按此 DynamicKey 查库注入，声明侧不下发候选值。
	sp := byKey["storage_provider"]
	if sp.Type != "select" || sp.Kind != provider.FieldDynamicOptions ||
		sp.DynamicKey != "storage_provider_keys" {
		t.Fatalf("storage_provider = %+v, want select + dynamic + DynamicKey=storage_provider_keys", sp)
	}
	if len(sp.Options) != 0 {
		t.Errorf("storage_provider options = %v, want 空（候选运行时注入）", sp.Options)
	}
	for _, k := range []string{"qrcode_auto_delete", "storage_path"} {
		if f := byKey[k]; f.Storage != provider.StorageExt {
			t.Errorf("扫码字段 %q Storage = %q, want ext（Ext 写入键集按 Storage 派生）", k, f.Storage)
		}
	}
	// 拉码模式三字段（§5.3 type 行）：endpoint 区块、Ext 落点、label / help
	// 恒为前端 i18n 键（键名钉死，文案落地随前端语言包）；qrcode_mode 的
	// options 恒为 wire 取值，default 仅作表单初值；qrcode_tip 用 textarea
	// 承载多行 HTML 原文。
	wantKeys := map[string]struct{ typ, label, help string }{
		"qrcode_mode":   {"select", "admin.schemaField.qrcodeModeLabel", "admin.schemaField.qrcodeModeHelp"},
		"qrcode_format": {"text", "admin.schemaField.qrcodeFormatLabel", "admin.schemaField.qrcodeFormatHelp"},
		"qrcode_tip":    {"textarea", "admin.schemaField.qrcodeTipLabel", "admin.schemaField.qrcodeTipHelp"},
	}
	for k, w := range wantKeys {
		f, ok := byKey[k]
		if !ok {
			t.Fatalf("拉码模式字段 %q 未声明", k)
		}
		if f.Type != w.typ || f.Section != "endpoint" || f.Storage != provider.StorageExt {
			t.Errorf("%s = (type=%q section=%q storage=%q), want (%q endpoint ext)", k, f.Type, f.Section, f.Storage, w.typ)
		}
		if f.Label != w.label || f.Help != w.help {
			t.Errorf("%s = (label=%q help=%q), want (%q %q)", k, f.Label, f.Help, w.label, w.help)
		}
	}
	if qm := byKey["qrcode_mode"]; strings.Join(qm.Options, ",") != "ticket,base64,url" || qm.Default != "url" {
		t.Errorf("qrcode_mode = (options=%v default=%q), want [ticket base64 url]/url", qm.Options, qm.Default)
	}
	// 死字段不再下发（metadata 等 keep 外键）。
	for _, dead := range []string{"client_id", "cert", "scopes", "provider_url",
		"custom_auth_url", "custom_token_url", "custom_user_info_url", "user_mapping", "metadata"} {
		if f, ok := byKey[dead]; ok {
			t.Errorf("死字段 %q 仍在 Schema: %+v", dead, f)
		}
	}
	// 引用键由 SchemaFor 漏斗追加：末位、endpoint / select / dynamic。
	if ref := full[len(full)-1]; ref.Key != provider.ProxyRefKey ||
		ref.Section != "endpoint" || ref.Kind != provider.FieldDynamicOptions {
		t.Fatalf("引用键 = %+v, want 末位 endpoint/dynamic", ref)
	}
	a, err := provider.NewAdapter(testProvider("scan", "wx-app", "wx-secret"))
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	if a.Channel() != provider.ChannelQRCode {
		t.Fatalf("Channel = %q, want qrcode", a.Channel())
	}
}

// TestCode2Session code2session 同构回归：参数（appid/js_code）与身份组装。
func TestCode2Session(t *testing.T) {
	var gotAppID, gotCode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		gotAppID = q.Get("appid")
		gotCode = q.Get("js_code")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"openid":"o-scan","unionid":"u-1"}`)
	}))
	defer srv.Close()

	a, err := build(testProvider("scan", "wx-app", "wx-secret"), clientForServer(srv))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	id, err := a.Code2Session(context.Background(), "code-9")
	if err != nil {
		t.Fatalf("Code2Session: %v", err)
	}
	if id.OpenID != "o-scan" || id.UnionID != "u-1" || id.ProviderKey != "scan" || id.ProviderType != Type {
		t.Fatalf("identity = %+v", id)
	}
	if gotAppID != "wx-app" || gotCode != "code-9" {
		t.Fatalf("query appid=%q js_code=%q", gotAppID, gotCode)
	}
}

// TestFetchQrcodeSuccess 拉码成功：scene=拉码入参（承载 ticket_id）、
// 图片字节原样回传、check_path=false。
func TestFetchQrcodeSuccess(t *testing.T) {
	var gotScene string
	var gotCheckPath bool
	var gotTokenParam string
	pngBody := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 1, 2, 3}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/stable_token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok-1","expires_in":7200}`)
		case "/wxa/getwxacodeunlimit":
			gotTokenParam = r.URL.Query().Get("access_token")
			// SDK 以 JSON body 提交码图参数（PostWithBody）。
			var body struct {
				Scene     string `json:"scene"`
				CheckPath bool   `json:"check_path"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotScene = body.Scene
			gotCheckPath = !body.CheckPath
			w.Header().Set("Content-Type", "image/png")
			w.Write(pngBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, err := build(testProvider("scan", "wx-app", "wx-secret"), clientForServer(srv))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	body, err := a.FetchQrcode(context.Background(), "c7Kx9ticketid0123456")
	if err != nil {
		t.Fatalf("FetchQrcode: %v", err)
	}
	if string(body) != string(pngBody) {
		t.Fatalf("body = %v, want 原样回传 %v", body, pngBody)
	}
	if gotScene != "c7Kx9ticketid0123456" {
		t.Errorf("scene = %q, want ticket_id", gotScene)
	}
	if !gotCheckPath {
		t.Errorf("check_path 应为 false（不依赖小程序发布状态）")
	}
	if gotTokenParam != "tok-1" {
		t.Errorf("access_token = %q, want tok-1", gotTokenParam)
	}
}

// TestFetchQrcodeWechatError 微信 errcode（JSON 应答）必须上抛，不当空图
// 返回。
func TestFetchQrcodeWechatError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/stable_token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"tok-1","expires_in":7200}`)
		case "/wxa/getwxacodeunlimit":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"errcode":41030,"errmsg":"invalid page"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, err := build(testProvider("scan", "wx-app", "wx-secret"), clientForServer(srv))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	_, err = a.FetchQrcode(context.Background(), "t-1")
	if err == nil || !strings.Contains(err.Error(), "41030") {
		t.Fatalf("err = %v, want wechat errcode 41030", err)
	}
}

// TestFetchQrcodeEmptyScene 空 scene 哨兵。
func TestFetchQrcodeEmptyScene(t *testing.T) {
	a, err := build(testProvider("scan", "wx-app", "wx-secret"), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := a.FetchQrcode(context.Background(), ""); !errors.Is(err, ErrEmptyScene) {
		t.Fatalf("err = %v, want ErrEmptyScene", err)
	}
}

// TestBuildNotConfigured Ext.app_id / client_secret 为空即未配置（§13.0）；
// nil Provider / nil Ext 走注册表 ErrNilProvider 哨兵。
func TestBuildNotConfigured(t *testing.T) {
	for _, p := range []*provider.Provider{
		testProvider("scan", "", "secret"),
		testProvider("scan", "app", ""),
	} {
		if _, err := build(p, nil); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("build(%+v) err = %v, want ErrNotConfigured", p.Ext, err)
		}
	}
	if _, err := build(&provider.Provider{Key: "scan", Type: Type, Ext: nil}, nil); !errors.Is(err, provider.ErrNilProvider) {
		t.Fatalf("build(nil ext) err = %v, want provider.ErrNilProvider", err)
	}
}

// TestBuildAuthURLNotSupported channel=qrcode 无跳转流程。
func TestBuildAuthURLNotSupported(t *testing.T) {
	a, err := build(testProvider("scan", "wx-app", "wx-secret"), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := a.BuildAuthURL(&provider.AuthContext{ProviderKey: "scan"}); !errors.Is(err, ErrAuthURLNotSupported) {
		t.Fatalf("err = %v, want ErrAuthURLNotSupported", err)
	}
}

// fakeTokenCache AccessTokenCache fake：记录 Set、按预置值 Get。
type fakeTokenCache struct {
	mu   sync.Mutex
	set  map[string]string
	ttls map[string]time.Duration
	get  string
}

func (f *fakeTokenCache) Get(context.Context, string) (string, bool) {
	if f.get != "" {
		return f.get, true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.set["k"], len(f.set) > 0
}

func (f *fakeTokenCache) Set(_ context.Context, _, val string, ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.set == nil {
		f.set = map[string]string{}
		f.ttls = map[string]time.Duration{}
	}
	f.set["k"] = val
	f.ttls["k"] = ttl
}

// TestSharedAccessTokenCacheBridge 注入共享缓存后：SDK 取 token 走缓存
// （不再请求 stable_token 端点）、TTL 原样透传、桥接只收 string。
func TestSharedAccessTokenCacheBridge(t *testing.T) {
	var tokenFetches int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cgi-bin/stable_token" {
			tokenFetches++
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"fresh","expires_in":7200}`)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		fmt.Fprint(w, "img")
	}))
	defer srv.Close()

	cacheFake := &fakeTokenCache{get: "cached-tok"}
	SetAccessTokenCache(cacheFake)
	defer SetAccessTokenCache(nil)

	a, err := build(testProvider("scan", "wx-app", "wx-secret"), clientForServer(srv))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := a.FetchQrcode(context.Background(), "t-1"); err != nil {
		t.Fatalf("FetchQrcode: %v", err)
	}
	if tokenFetches != 0 {
		t.Fatalf("共享缓存命中时不应回源微信 stable_token, fetches = %d", tokenFetches)
	}

	// 缓存未命中（get 清空）→ 回源一次并写缓存 + TTL 透传。
	cacheFake.get = ""
	if _, err := a.FetchQrcode(context.Background(), "t-2"); err != nil {
		t.Fatalf("FetchQrcode: %v", err)
	}
	if tokenFetches != 1 {
		t.Fatalf("缓存未命中应恰好回源一次, fetches = %d", tokenFetches)
	}
	cacheFake.mu.Lock()
	got, ttl := cacheFake.set["k"], cacheFake.ttls["k"]
	cacheFake.mu.Unlock()
	if got != "fresh" || ttl != 7200*time.Second {
		t.Fatalf("缓存写入 = (%q, %v), want (fresh, 7200s)", got, ttl)
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
			p := testProvider("scan", "wx-app", "wx-secret")
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
// Outbound 代理配置，测试注入口径保持不变；共享 access_token 缓存注入仍生效。
func TestBuildInjectedClientPriority(t *testing.T) {
	injected := &http.Client{}
	p := testProvider("scan", "wx-app", "wx-secret")
	p.Outbound = proxyPool(t, "http", "127.0.0.1", 8080, "", "")
	a, err := build(p, injected)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if a.hc != injected {
		t.Fatalf("injected client = %p, want %p (test injection must win over outbound pool)", a.hc, injected)
	}
}
