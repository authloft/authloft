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
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
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

	a, err := build(testProvider("op", "o-id", "o-secret", srv.URL+"/"), nil)
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
	if _, err := build(testProvider("op", "o-id", "o-secret", srv.URL), nil); err == nil {
		t.Fatalf("discovery 404 want error")
	}
	// provider_url 缺失 → 未配置。
	if _, err := build(testProvider("op", "o-id", "o-secret", ""), nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestExchangeProviderError(t *testing.T) {
	bad := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error":"access_denied","error_description":"user denied"}`)
	})
	srv := newIdP(t, bad, func(w http.ResponseWriter, r *http.Request) {})
	defer srv.Close()

	a, err := build(testProvider("op", "o-id", "o-secret", srv.URL), nil)
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
	for _, f := range meta.Fields {
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
