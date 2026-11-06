// gitee 适配器单测：httptest 扮演 Gitee 端点，覆盖 state 校验、
// code→token、拉取用户信息、provider 错误映射、注册表装配。
package gitee

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
	a, err := build(testProvider("gee", "gee-id", "gee-secret"), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-abc"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, _ := url.Parse(got)
	q := u.Query()
	if q.Get("state") != "l-abc" || q.Get("client_id") != "gee-id" || q.Get("scope") != defaultScopes {
		t.Fatalf("query = %v", q)
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
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "g-c" ||
			r.Form.Get("client_id") != "gee-id" || r.Form.Get("client_secret") != "gee-secret" {
			t.Errorf("form = %v", r.Form)
		}
		fmt.Fprint(w, `{"access_token":"gee-at","refresh_token":"gee-rt","expires_in":86400,"scope":"user_info"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("gee", "gee-id", "gee-secret"), oauthcore.NewRewriteClient(srv.URL))
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "g-c"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "gee-at" || tok.RefreshToken != "gee-rt" || tok.ExpiresIn != 86400 {
		t.Fatalf("token = %+v", tok)
	}
}

func TestExchangeProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"client unauthorized"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("gee", "gee-id", "gee-secret"), oauthcore.NewRewriteClient(srv.URL))
	_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "x"})
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Code != "invalid_client" || pe.Status != 401 {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gee-at" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		fmt.Fprint(w, `{"id":4242,"login":"geeker","name":"Gee Ker","email":"gee@example.com","avatar_url":"https://av/1.png"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("gee", "gee-id", "gee-secret"), oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "gee-at"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "4242" || id.Username != "geeker" || id.Nickname != "Gee Ker" ||
		id.Email != "gee@example.com" || id.AvatarURL != "https://av/1.png" {
		t.Fatalf("id = %+v", id)
	}
	// 无 id 字段 → ErrEmptyOpenID。
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"login":"noid"}`)
	}))
	defer srv2.Close()
	a2, _ := build(testProvider("gee", "gee-id", "gee-secret"), oauthcore.NewRewriteClient(srv2.URL))
	if _, err := a2.FetchUser(context.Background(), &provider.Token{AccessToken: "at"}); !errors.Is(err, oauthcore.ErrEmptyOpenID) {
		t.Fatalf("err = %v, want ErrEmptyOpenID", err)
	}
}

func TestNotConfigured(t *testing.T) {
	if _, err := build(&provider.Provider{Key: "gee", Type: Type, Ext: &providerpb.Ext{}}, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestRegistry(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "Gitee" || meta.Channel != provider.ChannelRedirect {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	if _, err := provider.NewAdapter(testProvider("gee", "id", "s")); err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
}
