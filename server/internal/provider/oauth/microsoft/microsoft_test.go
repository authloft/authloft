// microsoft 适配器单测：httptest 扮演 Microsoft 端点（tenant 注入
// 断言），覆盖 state 校验、code→token、OIDC userinfo 抽取、错误映射。
package microsoft

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

func testProvider(key, id, secret, tenant string) *provider.Provider {
	return &provider.Provider{Key: key, Type: Type, Ext: &providerpb.Ext{ClientId: id, ClientSecret: secret, ProviderUrl: tenant}}
}

// TestBuildAuthURLTenant tenant 缺省 common、provider_url 覆盖。
func TestBuildAuthURLTenant(t *testing.T) {
	a, _ := build(testProvider("ms", "ms-id", "ms-secret", ""), nil)
	if a.tenant != "common" {
		t.Fatalf("tenant = %q, want common", a.tenant)
	}
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-ms"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	if !strings.Contains(got, "login.microsoftonline.com/common/oauth2/v2.0/authorize") {
		t.Fatalf("url = %q", got)
	}
	if !strings.Contains(got, "state=l-ms") || !strings.Contains(got, "scope="+url.QueryEscape(defaultScope)) {
		t.Fatalf("url = %q", got)
	}
	if _, err := a.BuildAuthURL(&provider.AuthContext{}); !errors.Is(err, oauthcore.ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}

	b, _ := build(testProvider("ms", "ms-id", "ms-secret", "9188040d-xxxx-xxxx-xxxx-270d1c0d"), nil)
	if got, _ := b.BuildAuthURL(&provider.AuthContext{State: "s"}); !strings.Contains(got, "/9188040d-xxxx-xxxx-xxxx-270d1c0d/oauth2/v2.0/authorize") {
		t.Fatalf("tenant override url = %q", got)
	}
}

func TestExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/common/oauth2/v2.0/token") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("code") != "ms-code" || r.Form.Get("client_id") != "ms-id" {
			t.Errorf("form = %v", r.Form)
		}
		fmt.Fprint(w, `{"access_token":"ms-at","expires_in":3600}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("ms", "ms-id", "ms-secret", ""), oauthcore.NewRewriteClient(srv.URL))
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "ms-code"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "ms-at" {
		t.Fatalf("token = %+v", tok)
	}
}

func TestExchangeProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error":"authorization_pending","error_description":"authorization pending"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("ms", "ms-id", "ms-secret", ""), oauthcore.NewRewriteClient(srv.URL))
	_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "x"})
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Code != "authorization_pending" {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"sub":"AAAAAAAAAAAAAAAAAAAAA","name":"MS User","email":"ms@example.com","email_verified":true}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("ms", "ms-id", "ms-secret", ""), oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "ms-at"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "AAAAAAAAAAAAAAAAAAAAA" || id.Nickname != "MS User" || id.Email != "ms@example.com" || !id.EmailVerified {
		t.Fatalf("id = %+v", id)
	}
}

func TestNotConfigured(t *testing.T) {
	if _, err := build(&provider.Provider{Key: "ms", Type: Type, Ext: &providerpb.Ext{ClientId: "id"}}, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestRegistry(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "Microsoft" {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	// provider_url 标签改写为 Tenant 的 i18n 键（文案在前端语言包）。
	found := false
	for _, f := range meta.Fields {
		if f.Key == "provider_url" {
			found = f.Label == "admin.schemaField.microsoftTenantLabel" &&
				f.Help == "admin.schemaField.microsoftTenantHelp"
		}
	}
	if !found {
		t.Fatalf("provider_url Label / Help 未改写为 i18n 键")
	}
	if _, err := provider.NewAdapter(testProvider("ms", "id", "s", "")); err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
}
