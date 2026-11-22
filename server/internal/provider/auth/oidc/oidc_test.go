// oidc 通用兜底适配器单测：httptest 扮演 IdP（discovery + token +
// userinfo 三端点），覆盖 discovery 构造、state 校验、code→token、userinfo
// 抽取、错误映射、配置缺失与 schema 字段裁剪。
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/auth/oauthcore"
	"authloft/internal/provider/schemafield"
)

func testProvider(key, id, secret, issuer string) *provider.Provider {
	return &provider.Provider{Key: key, Type: Type, Ext: &providerpb.Ext{ClientId: id, ClientSecret: secret, ProviderUrl: issuer}}
}

// newIdP 拟一个三端点 IdP；discovery 文档经闭包在请求期引用 srv.URL。
func newIdP(t *testing.T, tokenHandler, userHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"authorization_endpoint":%q,"token_endpoint":%q,"userinfo_endpoint":%q}`,
			srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/userinfo")
	})
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/userinfo", userHandler)
	srv = httptest.NewServer(mux)
	return srv
}

func TestBuildAndExchangeAndFetchUser(t *testing.T) {
	tokenOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "o-code" ||
			r.Form.Get("client_id") != "o-id" || r.Form.Get("client_secret") != "o-secret" {
			t.Errorf("form = %v", r.Form)
		}
		fmt.Fprint(w, `{"access_token":"o-at","id_token":"o-jwt","expires_in":3600}`)
	})
	userOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer o-at" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		fmt.Fprint(w, `{"sub":"sub-1","name":"IdP User","email":"idp@example.com","picture":"https://p/1.png"}`)
	})
	srv := newIdP(t, tokenOK, userOK)
	defer srv.Close()

	a, err := build(testProvider("op", "o-id", "o-secret", srv.URL+"/"), nil, srv.URL+"/")
	if err != nil {
		t.Fatalf("build (discovery): %v", err)
	}
	if a.authURL != srv.URL+"/authorize" || a.tokenURL != srv.URL+"/token" || a.userInfoURL != srv.URL+"/userinfo" {
		t.Fatalf("endpoints = %q %q %q", a.authURL, a.tokenURL, a.userInfoURL)
	}
	// state 校验 + scope 缺省。
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-oidc"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	if !strings.Contains(got, "state=l-oidc") || !strings.Contains(got, "scope="+url.QueryEscape(defaultScopes)) {
		t.Fatalf("url = %q", got)
	}
	if _, err := a.BuildAuthURL(&provider.AuthContext{}); !errors.Is(err, oauthcore.ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
	// code→token。
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "o-code"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "o-at" || tok.IDToken != "o-jwt" {
		t.Fatalf("token = %+v", tok)
	}
	// userinfo 抽取。
	id, err := a.FetchUser(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "sub-1" || id.Nickname != "IdP User" || id.Email != "idp@example.com" || id.AvatarURL != "https://p/1.png" {
		t.Fatalf("id = %+v", id)
	}
}

func TestDiscoveryError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if _, err := build(testProvider("op", "o-id", "o-secret", srv.URL), nil, srv.URL); err == nil {
		t.Fatalf("discovery 404 want error")
	}
	// provider_url 缺失 → 未配置。
	if _, err := build(testProvider("op", "o-id", "o-secret", ""), nil, ""); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestExchangeProviderError(t *testing.T) {
	bad := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error":"access_denied","error_description":"user denied"}`)
	})
	srv := newIdP(t, bad, func(w http.ResponseWriter, r *http.Request) {})
	defer srv.Close()

	a, err := build(testProvider("op", "o-id", "o-secret", srv.URL), nil, srv.URL)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	_, err = a.Exchange(context.Background(), provider.ExchangeInput{Code: "x"})
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Code != "access_denied" {
		t.Fatalf("err = %v", err)
	}
}

func TestRegistry(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "OIDC（标准协议）" || meta.Channel != provider.ChannelRedirect {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	// custom_* 手工端点已从 schema 移除；provider_url 必填。
	for _, f := range meta.Schema() {
		switch f.Key {
		case "custom_auth_url", "custom_token_url", "custom_user_info_url":
			t.Fatalf("custom 端点 %q 不应出现在 oidc schema", f.Key)
		case "provider_url":
			if !f.Required {
				t.Fatalf("provider_url 应必填")
			}
		}
	}
}

// TestSchemaKeepSet Schema 键集收敛（接口文档 §5.3 keep 集表 auth 行）：注册表
// Schema() 恰为表列基线 + keep 集（标准四件套 + provider_url，基线序）+ 引用键
// proxy_provider_key，keep 外键（app_id / cert / custom_* / metadata）不再下发；
// provider_url 置必填并换 oidc 专用 Help，其余字段属性与 schemafield 基线逐项
// 一致（裁剪只删键不改属性），声明序即 wire 序。
func TestSchemaKeepSet(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok {
		t.Fatalf("type %q 未注册", Type)
	}
	schema := meta.Schema()
	wantKeys := []string{
		"provider_key", "display_name", "union_provider",
		"client_id", "client_secret", "scopes", "provider_url", "user_mapping",
		"icon_url", "sort_order", "remark",
		"is_enabled", "enable_signin", "enable_signup", "auto_bind", "auto_bind_fields",
		provider.ProxyRefKey,
	}
	if len(schema) != len(wantKeys) {
		var got []string
		for _, f := range schema {
			got = append(got, f.Key)
		}
		t.Fatalf("schema keys = %v, want %v", got, wantKeys)
	}
	for i, k := range wantKeys {
		if schema[i].Key != k {
			t.Fatalf("schema[%d].Key = %q, want %q（声明序即 wire 序）", i, schema[i].Key, k)
		}
	}
	baseline := map[string]provider.FieldMeta{}
	for _, f := range schemafield.OAuthCredentials() {
		baseline[f.Key] = f
	}
	for _, f := range schema {
		if f.Key == "provider_url" {
			// discovery 唯一入口，必填 + oidc 专用 Help。
			if !f.Required || f.Help != "admin.schemaField.oidcProviderUrlHelp" {
				t.Errorf("provider_url Required/Help = %v/%q, want true/admin.schemaField.oidcProviderUrlHelp", f.Required, f.Help)
			}
			continue
		}
		if b, ok := baseline[f.Key]; ok && !reflect.DeepEqual(f, b) {
			t.Errorf("字段 %q = %+v, want 基线 %+v（裁剪只删键不改属性）", f.Key, f, b)
		}
	}
}

// TestNewInjectionURL 薄封装构造入口（§15.5）：providerURL 由调用方构造期
// 固化注入，与 Ext.provider_url 相互独立——薄封装 Schema 不声明该键，实例
// 配置恒空，注入值是 discovery 唯一真源；注入空值仍 fail-closed 不回退 Ext。
func TestNewInjectionURL(t *testing.T) {
	tokenOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("code") != "d-code" || r.Form.Get("client_id") != "d-id" || r.Form.Get("client_secret") != "d-secret" {
			t.Errorf("form = %v", r.Form)
		}
		fmt.Fprint(w, `{"access_token":"d-at","expires_in":3600}`)
	})
	userOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer d-at" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		fmt.Fprint(w, `{"sub":"sub-d","name":"Injected User","email":"d@example.com"}`)
	})
	srv := newIdP(t, tokenOK, userOK)
	defer srv.Close()

	// Ext.provider_url 留空（薄封装形态）：注入值独立生效，发现 / 授权 /
	// 换令牌 / 用户信息全流程可用。
	p := &provider.Provider{Key: "dp", Type: "discord", Ext: &providerpb.Ext{ClientId: "d-id", ClientSecret: "d-secret"}}
	a, err := New(p, srv.URL)
	if err != nil {
		t.Fatalf("New (injected URL): %v", err)
	}
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-dsc"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	if !strings.Contains(got, srv.URL+"/authorize") || !strings.Contains(got, "state=l-dsc") {
		t.Fatalf("url = %q", got)
	}
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "d-code"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	id, err := a.FetchUser(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "sub-d" || id.Email != "d@example.com" || id.ProviderType != "discord" {
		t.Fatalf("id = %+v", id)
	}
	// 注入空 URL：ErrNotConfigured fail-closed，不回退 Ext。
	if _, err := New(p, ""); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

// TestNewInjectionOverridesExt 注入值优先：Ext 残值（历史脏数据）不得改变
// discovery 目标——若 Ext 值被采用，构造必因端点不可达而失败。
func TestNewInjectionOverridesExt(t *testing.T) {
	srv := newIdP(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"x-at"}`)
	}, func(w http.ResponseWriter, r *http.Request) {})
	defer srv.Close()
	a, err := New(testProvider("op", "o-id", "o-secret", "https://stale.invalid"), srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.authURL != srv.URL+"/authorize" {
		t.Fatalf("authURL = %q, want 注入值端点 %q", a.authURL, srv.URL+"/authorize")
	}
}

// TestProviderTypeFromProvider 身份类型固化 p.Type（单一真源）：薄封装以
// discord / telegram 注册本 type，身份 ProviderType 不得错标 oidc；基线路径
// （p.Type=oidc）行为不变。
func TestProviderTypeFromProvider(t *testing.T) {
	srv := newIdP(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"t-at"}`)
	}, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"sub":"sub-1"}`)
	})
	defer srv.Close()
	fetchType := func(p *provider.Provider) string {
		t.Helper()
		a, err := build(p, nil, srv.URL)
		if err != nil {
			t.Fatalf("build %s: %v", p.Type, err)
		}
		id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "t-at"})
		if err != nil {
			t.Fatalf("FetchUser %s: %v", p.Type, err)
		}
		return id.ProviderType
	}
	for _, typ := range []string{"discord", "telegram"} {
		p := &provider.Provider{Key: "p1", Type: typ, Ext: &providerpb.Ext{ClientId: "id", ClientSecret: "secret"}}
		if got := fetchType(p); got != typ {
			t.Fatalf("ProviderType = %q, want %q（身份错标）", got, typ)
		}
	}
	if got := fetchType(testProvider("p2", "id", "secret", srv.URL)); got != Type {
		t.Fatalf("ProviderType = %q, want %q（基线路径行为变化）", got, Type)
	}
}
