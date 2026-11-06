// google 适配器单测：httptest 扮演 Google 端点，覆盖 state 校验、
// code→token（redirect_uri 透传断言）、OIDC userinfo 抽取、错误映射。
package google

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

func testProvider(key, id, secret string) *provider.Provider {
	return &provider.Provider{Key: key, Type: Type, Ext: &providerpb.Ext{ClientId: id, ClientSecret: secret}}
}

func TestBuildAuthURL(t *testing.T) {
	a, _ := build(testProvider("g", "g-id", "g-secret"), nil)
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-s", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, _ := url.Parse(got)
	q := u.Query()
	if q.Get("state") != "l-s" || q.Get("scope") != defaultScopes || q.Get("redirect_uri") != "https://app/cb" {
		t.Fatalf("query = %v", q)
	}
	if _, err := a.BuildAuthURL(nil); !errors.Is(err, oauthcore.ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
}

func TestExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("code") != "g-code" || r.Form.Get("redirect_uri") != "https://app/cb" {
			t.Errorf("form = %v", r.Form)
		}
		fmt.Fprint(w, `{"access_token":"g-at","refresh_token":"g-rt","expires_in":3599,"id_token":"jwt-1"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("g", "g-id", "g-secret"), oauthcore.NewRewriteClient(srv.URL))
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "g-code", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "g-at" || tok.IDToken != "jwt-1" || tok.ExpiresIn != 3599 {
		t.Fatalf("token = %+v", tok)
	}
}

func TestExchangeProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Code was already redeemed."}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("g", "g-id", "g-secret"), oauthcore.NewRewriteClient(srv.URL))
	_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "x"})
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Code != "invalid_grant" || pe.Desc != "Code was already redeemed." {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer g-at" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		fmt.Fprint(w, `{"sub":"110169484474386276334","name":"G User","email":"g@example.com","email_verified":true,"picture":"https://p/1.jpg"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("g", "g-id", "g-secret"), oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "g-at"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "110169484474386276334" || id.Email != "g@example.com" || !id.EmailVerified ||
		id.AvatarURL != "https://p/1.jpg" || id.Nickname != "G User" {
		t.Fatalf("id = %+v", id)
	}
}

func TestNotConfigured(t *testing.T) {
	if _, err := build(&provider.Provider{Key: "g", Type: Type, Ext: &providerpb.Ext{ClientId: "id"}}, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestRegistry(t *testing.T) {
	if _, ok := provider.Lookup(Type); !ok {
		t.Fatalf("Lookup(%q) 未注册", Type)
	}
	if _, err := provider.NewAdapter(testProvider("g", "id", "s")); err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
}
