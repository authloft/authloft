// baidu 适配器单测：httptest 扮演百度开放平台端点，覆盖
// state 校验、code→token（请求参数断言）、getInfo 抽取（openid /
// username / portrait 拼接）、user_mapping 覆盖、错误映射、注册表装配。
package baidu

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

func testProvider(key, id, secret string) *provider.Provider {
	return &provider.Provider{Key: key, Type: Type, Ext: &providerpb.Ext{ClientId: id, ClientSecret: secret}}
}

func TestBuildAuthURL(t *testing.T) {
	a, err := build(testProvider("bd", "bd-id", "bd-secret"), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// 端点断言（独立字面量，与生产常量解耦）：能抓
	// authURL 常量本身写错（先前笔误即由自比对断言漏掉），防的是
	// 「BuildAuthURL 输出 ≠ 百度官方授权端点」；不防其他两端点与真实端点
	// 的互通性（httptest 无法覆盖，真机联调未覆盖）。
	const wantAuthURL = "https://openapi.baidu.com/oauth/2.0/authorize"
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-bd", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, _ := url.Parse(got)
	if u.Scheme+"://"+u.Host+u.Path != wantAuthURL {
		t.Fatalf("endpoint = %q, want %q", u.Scheme+"://"+u.Host+u.Path, wantAuthURL)
	}
	q := u.Query()
	if q.Get("state") != "l-bd" || q.Get("client_id") != "bd-id" || q.Get("response_type") != "code" {
		t.Fatalf("query = %v", q)
	}
	if q.Get("scope") != defaultScopes {
		t.Fatalf("scope = %q, want %q", q.Get("scope"), defaultScopes)
	}
	if _, err := a.BuildAuthURL(&provider.AuthContext{}); !errors.Is(err, oauthcore.ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
}

func TestExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "bd-code" ||
			r.Form.Get("client_id") != "bd-id" || r.Form.Get("client_secret") != "bd-secret" {
			t.Errorf("form = %v", r.Form)
		}
		fmt.Fprint(w, `{"access_token":"bd-at","refresh_token":"bd-rt","expires_in":2592000,"scope":"basic"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("bd", "bd-id", "bd-secret"), oauthcore.NewRewriteClient(srv.URL))
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "bd-code"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "bd-at" || tok.RefreshToken != "bd-rt" || tok.ExpiresIn != 2592000 {
		t.Fatalf("token = %+v", tok)
	}
	// 空 code → 哨兵。
	if _, err := a.Exchange(context.Background(), provider.ExchangeInput{}); !errors.Is(err, oauthcore.ErrEmptyCode) {
		t.Fatalf("err = %v, want ErrEmptyCode", err)
	}
}

func TestExchangeProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Invalid authorization code"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("bd", "bd-id", "bd-secret"), oauthcore.NewRewriteClient(srv.URL))
	_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "bad"})
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Code != "invalid_grant" || pe.Desc != "Invalid authorization code" {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "bd-secret") {
		t.Fatalf("错误串泄漏凭证: %v", err)
	}
}

func TestFetchUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("access_token") != "bd-at" {
			t.Errorf("query = %v", r.URL.Query())
		}
		fmt.Fprint(w, `{"openid":"bd-open-1","username":"baidu_user","portrait":"tx1.123"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("bd", "bd-id", "bd-secret"), oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "bd-at"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.ProviderKey != "bd" || id.ProviderType != Type || id.OpenID != "bd-open-1" {
		t.Fatalf("id = %+v", id)
	}
	if id.Username != "baidu_user" || id.Nickname != "baidu_user" {
		t.Fatalf("id = %+v", id)
	}
	if id.AvatarURL != avatarPrefix+"tx1.123" {
		t.Fatalf("avatar = %q, want portrait 拼接", id.AvatarURL)
	}
	// Raw 只落用户信息响应，不含令牌。
	if id.Raw == nil || id.Raw["openid"] != "bd-open-1" {
		t.Fatalf("Raw = %v", id.Raw)
	}
	if _, ok := id.Raw["access_token"]; ok {
		t.Fatalf("Raw 不应含 access_token")
	}
	// 无 portrait → 头像为空。
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"openid":"o-2","username":"u2"}`)
	}))
	defer srv2.Close()
	a2, _ := build(testProvider("bd", "bd-id", "bd-secret"), oauthcore.NewRewriteClient(srv2.URL))
	id2, err := a2.FetchUser(context.Background(), &provider.Token{AccessToken: "at"})
	if err != nil || id2.AvatarURL != "" {
		t.Fatalf("id = %+v err = %v", id2, err)
	}
}

func TestFetchUserMappingOverride(t *testing.T) {
	// user_mapping 覆盖 avatar_url 时以映射结果优先（渠道拼接不覆盖）。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"openid":"o-3","username":"u3","portrait":"tx.9"}`)
	}))
	defer srv.Close()
	a, _ := build(&provider.Provider{Key: "bd", Type: Type, Ext: &providerpb.Ext{
		ClientId: "id", ClientSecret: "s",
		UserMapping: map[string]string{"avatar_url": "$.username"},
	}}, oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "at"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.AvatarURL != "u3" {
		t.Fatalf("avatar = %q, want mapping 覆盖为 u3", id.AvatarURL)
	}
	// nil token → 哨兵。
	if _, err := a.FetchUser(context.Background(), nil); !errors.Is(err, oauthcore.ErrNilToken) {
		t.Fatalf("err = %v, want ErrNilToken", err)
	}
}

func TestNotConfigured(t *testing.T) {
	if _, err := build(&provider.Provider{Key: "bd", Type: Type,
		Ext: &providerpb.Ext{ClientId: "id"}}, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if _, err := build(nil, nil); !errors.Is(err, provider.ErrNilProvider) {
		t.Fatalf("err = %v, want ErrNilProvider", err)
	}
}

func TestRegistry(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "百度" || meta.Category != "oauth" || meta.Channel != provider.ChannelRedirect {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	adapter, err := provider.NewAdapter(testProvider("bd", "id", "secret"))
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	if adapter.Channel() != provider.ChannelRedirect {
		t.Fatalf("channel = %q", adapter.Channel())
	}
}
