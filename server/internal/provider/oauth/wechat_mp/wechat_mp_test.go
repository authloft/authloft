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

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
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
	if !ok || meta.Channel != provider.ChannelAPI || meta.Category != "oauth" {
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
