// oauth2 通用兜底适配器单测：httptest 扮演手工端点三件套，覆盖
// 配置缺失（端点 / user_mapping.open_id）、state 校验、code→token、
// user_mapping 全量映射、错误映射与 schema 必填声明。
package oauth2

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

func testProvider(auth, token, user string, mapping map[string]string) *provider.Provider {
	return &provider.Provider{Key: "gen", Type: Type, Ext: &providerpb.Ext{
		ClientId:          "g-id",
		ClientSecret:      "g-secret",
		Scopes:            "profile",
		CustomAuthUrl:     auth,
		CustomTokenUrl:    token,
		CustomUserInfoUrl: user,
		UserMapping:       mapping,
	}}
}

func TestBuildAuthURL(t *testing.T) {
	a, err := build(testProvider("https://idp/auth", "https://idp/token", "https://idp/me",
		map[string]string{"open_id": "$.id"}), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-gen"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, _ := url.Parse(got)
	q := u.Query()
	if q.Get("state") != "l-gen" || q.Get("client_id") != "g-id" || q.Get("scope") != "profile" {
		t.Fatalf("query = %v", q)
	}
	if _, err := a.BuildAuthURL(&provider.AuthContext{}); !errors.Is(err, oauthcore.ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
}

func TestExchangeAndFetchUserMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse form: %v", err)
			}
			if r.Form.Get("code") != "g-code" || r.Form.Get("client_id") != "g-id" {
				t.Errorf("form = %v", r.Form)
			}
			fmt.Fprint(w, `{"access_token":"g-at","expires_in":3600}`)
		case "/me":
			fmt.Fprint(w, `{"id":99,"display_name":"Gen User","mail":"gen@example.com","pic":"https://p/g.png"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, err := build(testProvider(srv.URL+"/auth", srv.URL+"/token", srv.URL+"/me", map[string]string{
		"open_id":    "$.id",
		"nickname":   "$.display_name",
		"email":      "$.mail",
		"avatar_url": "$.pic",
	}), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "g-code"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "g-at" {
		t.Fatalf("token = %+v", tok)
	}
	id, err := a.FetchUser(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "99" || id.Nickname != "Gen User" || id.Email != "gen@example.com" || id.AvatarURL != "https://p/g.png" {
		t.Fatalf("id = %+v", id)
	}
}

func TestFetchUserEmptyOpenID(t *testing.T) {
	// openid 表达式空值（响应缺 id）→ ErrEmptyOpenID。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"name":"no-id"}`)
	}))
	defer srv.Close()
	a, _ := build(testProvider("https://a", srv.URL+"/token", srv.URL+"/me",
		map[string]string{"open_id": "$.id"}), nil)
	if _, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "at"}); !errors.Is(err, oauthcore.ErrEmptyOpenID) {
		t.Fatalf("err = %v, want ErrEmptyOpenID", err)
	}
}

func TestNotConfigured(t *testing.T) {
	// 三端点与 user_mapping.open_id 任一缺失均视为未配置。
	cases := []*providerpb.Ext{
		{ClientId: "id", ClientSecret: "s", UserMapping: map[string]string{"open_id": "$.id"}},
		{ClientId: "id", ClientSecret: "s", CustomAuthUrl: "https://a",
			UserMapping: map[string]string{"open_id": "$.id"}},
		{ClientId: "id", ClientSecret: "s", CustomAuthUrl: "https://a", CustomTokenUrl: "https://t",
			UserMapping: map[string]string{"open_id": "$.id"}},
		{ClientId: "id", ClientSecret: "s", CustomAuthUrl: "https://a", CustomTokenUrl: "https://t",
			CustomUserInfoUrl: "https://u", UserMapping: map[string]string{"nickname": "$.n"}},
	}
	for i, ext := range cases {
		p := &provider.Provider{Key: "gen", Type: Type, Ext: ext}
		if _, err := build(p, nil); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("case %d: err = %v, want ErrNotConfigured", i, err)
		}
	}
}

func TestRegistrySchema(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "OAuth2（标准协议）" || meta.Channel != provider.ChannelRedirect {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	required := map[string]bool{}
	for _, f := range meta.Fields {
		if strings.HasPrefix(f.Key, "custom_") || f.Key == "user_mapping" {
			required[f.Key] = f.Required
		}
		if f.Key == "provider_url" {
			t.Fatalf("provider_url 不应出现在 oauth2 schema（不做 discovery）")
		}
	}
	for _, k := range []string{"custom_auth_url", "custom_token_url", "custom_user_info_url", "user_mapping"} {
		if !required[k] {
			t.Fatalf("%s 应必填", k)
		}
	}
	if _, err := provider.NewAdapter(testProvider("https://a", "https://t", "https://u",
		map[string]string{"open_id": "$.id"})); err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
}
