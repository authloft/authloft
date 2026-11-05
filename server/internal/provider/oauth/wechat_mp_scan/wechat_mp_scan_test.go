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

// TestRegistryRegistered 注册表形态：channel=qrcode、category=oauth、
// 扫码三追加字段在 /schema meta 中。
func TestRegistryRegistered(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok {
		t.Fatalf("Lookup(%q) 未注册", Type)
	}
	if meta.Channel != provider.ChannelQRCode || meta.Category != "oauth" {
		t.Fatalf("meta = %+v, want qrcode/oauth", meta)
	}
	keys := map[string]bool{}
	for _, f := range meta.Fields {
		keys[f.Key] = true
	}
	for _, want := range []string{"qrcode_auto_delete", "storage_provider", "storage_path"} {
		if !keys[want] {
			t.Errorf("Fields 缺少 %q", want)
		}
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
