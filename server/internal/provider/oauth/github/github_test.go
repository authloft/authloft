// github 适配器单测：httptest 扮演 GitHub 端点（改写客户端），
// 覆盖 state 校验、授权码换令牌（请求参数断言）、拉取用户信息、provider
// 侧错误映射、未配置凭证与注册表装配。
package github

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

// TestBuildAuthURL state 必填透传、scope 缺省、client_id 携带。
func TestBuildAuthURL(t *testing.T) {
	a, err := build(testProvider("gh", "gh-id", "gh-secret"), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-xyz"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, _ := url.Parse(got)
	q := u.Query()
	if q.Get("state") != "l-xyz" || q.Get("client_id") != "gh-id" || q.Get("response_type") != "code" {
		t.Fatalf("query = %v", q)
	}
	if q.Get("scope") != defaultScopes {
		t.Fatalf("scope = %q, want %q", q.Get("scope"), defaultScopes)
	}
	// state 为空 → 哨兵（透传校验，§12.4）。
	if _, err := a.BuildAuthURL(&provider.AuthContext{}); !errors.Is(err, oauthcore.ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
	// Ext.scopes 覆盖缺省。
	a2, _ := build(&provider.Provider{Key: "gh", Type: Type,
		Ext: &providerpb.Ext{ClientId: "id", ClientSecret: "s", Scopes: "read:user"}}, nil)
	got, _ = a2.BuildAuthURL(&provider.AuthContext{State: "s"})
	if !strings.Contains(got, "scope=read") {
		t.Fatalf("scope override: %q", got)
	}
}

// TestExchange 授权码换令牌：POST form 参数断言 + Accept 头 + JSON 解析。
func TestExchange(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		gotAccept = r.Header.Get("Accept")
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "c-1" ||
			r.Form.Get("client_id") != "gh-id" || r.Form.Get("client_secret") != "gh-secret" {
			t.Errorf("form = %v", r.Form)
		}
		fmt.Fprint(w, `{"access_token":"gh-at","token_type":"bearer","scope":"read:user"}`)
	}))
	defer srv.Close()

	a, err := build(testProvider("gh", "gh-id", "gh-secret"), oauthcore.NewRewriteClient(srv.URL))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c-1"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "gh-at" {
		t.Fatalf("token = %+v", tok)
	}
	if gotAccept != "application/json" {
		t.Fatalf("Accept = %q", gotAccept)
	}
	// 空 code → 哨兵。
	if _, err := a.Exchange(context.Background(), provider.ExchangeInput{}); !errors.Is(err, oauthcore.ErrEmptyCode) {
		t.Fatalf("err = %v, want ErrEmptyCode", err)
	}
}

// TestExchangeProviderError GitHub 错误体（bad_verification_code）映射。
func TestExchangeProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired."}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("gh", "gh-id", "gh-secret"), oauthcore.NewRewriteClient(srv.URL))
	_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "bad"})
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Code != "bad_verification_code" || pe.Desc == "" {
		t.Fatalf("err = %v, want ProviderError bad_verification_code", err)
	}
	if strings.Contains(err.Error(), "gh-secret") {
		t.Fatalf("错误串泄漏凭证: %v", err)
	}
}

// TestFetchUser 拉取用户信息：Bearer 头、id 数字键整数化、字段抽取。
func TestFetchUser(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, `{"id":12345678,"login":"octocat","name":"Octo Cat","email":"octo@example.com","avatar_url":"https://a/b.png"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("gh", "gh-id", "gh-secret"), oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "gh-at"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if gotAuth != "Bearer gh-at" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if id.ProviderKey != "gh" || id.ProviderType != Type || id.OpenID != "12345678" {
		t.Fatalf("id = %+v", id)
	}
	if id.Username != "octocat" || id.Nickname != "Octo Cat" || id.Email != "octo@example.com" || id.AvatarURL != "https://a/b.png" {
		t.Fatalf("id = %+v", id)
	}
	// Raw 落用户信息响应，不含令牌。
	if id.Raw == nil || id.Raw["login"] != "octocat" {
		t.Fatalf("Raw = %v", id.Raw)
	}
	// nil token → 哨兵。
	if _, err := a.FetchUser(context.Background(), nil); !errors.Is(err, oauthcore.ErrNilToken) {
		t.Fatalf("err = %v, want ErrNilToken", err)
	}
}

// TestFetchUserMapping user_mapping 覆盖抽取（JSONata 表达式）。
func TestFetchUserMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":1,"login":"u","name":"raw-name"}`)
	}))
	defer srv.Close()

	a, _ := build(&provider.Provider{Key: "gh", Type: Type, Ext: &providerpb.Ext{
		ClientId: "id", ClientSecret: "s",
		UserMapping: map[string]string{"nickname": "$.login", "email": "$.missing"},
	}}, oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "at"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.Nickname != "u" {
		t.Fatalf("nickname = %q, want mapping 覆盖为 u", id.Nickname)
	}
	if id.Email != "" {
		t.Fatalf("空值表达式应跳过，email = %q", id.Email)
	}
}

// TestNotConfigured 凭证缺失视为未配置（§13.0）。
func TestNotConfigured(t *testing.T) {
	if _, err := build(&provider.Provider{Key: "gh", Type: Type,
		Ext: &providerpb.Ext{ClientId: "id"}}, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if _, err := build(nil, nil); !errors.Is(err, provider.ErrNilProvider) {
		t.Fatalf("err = %v, want ErrNilProvider", err)
	}
}

// TestRegistry 注册表装配：Lookup 元信息 / NewAdapter 工厂 / Channel。
func TestRegistry(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "GitHub" || meta.Category != "oauth" || meta.Channel != provider.ChannelRedirect {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	adapter, err := provider.NewAdapter(testProvider("gh", "id", "secret"))
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	if adapter.Channel() != provider.ChannelRedirect {
		t.Fatalf("channel = %q", adapter.Channel())
	}
}
