// weibo 适配器单测：httptest 扮演微博端点，覆盖 state 校验、
// code→token（uid 随令牌返回）、show.json 拉取（uid 参数断言）、抽取与
// 错误映射。
package weibo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

func testProvider(id, secret string) *provider.Provider {
	return &provider.Provider{Key: "wb", Type: Type, Ext: &providerpb.Ext{ClientId: id, ClientSecret: secret}}
}

func TestBuildAuthURL(t *testing.T) {
	a, _ := build(testProvider("wb-id", "wb-secret"), nil)
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-wb"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	if got != "https://api.weibo.com/oauth2/authorize?client_id=wb-id&response_type=code&state=l-wb" {
		t.Fatalf("url = %q", got)
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
		if r.Form.Get("code") != "wb-code" || r.Form.Get("client_id") != "wb-id" {
			t.Errorf("form = %v", r.Form)
		}
		fmt.Fprint(w, `{"access_token":"wb-at","remind_in":"157679999","expires_in":157679999,"uid":"17481221"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("wb-id", "wb-secret"), oauthcore.NewRewriteClient(srv.URL))
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "wb-code"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "wb-at" || tok.Raw["uid"] != "17481221" {
		t.Fatalf("token = %+v", tok)
	}
}

func TestFetchUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("access_token") != "wb-at" || q.Get("uid") != "17481221" {
			t.Errorf("query = %v", q)
		}
		fmt.Fprint(w, `{"id":17481221,"idstr":"17481221","screen_name":"微博用户","profile_image_url":"https://av/s.jpg","avatar_hd":"https://av/h.jpg"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("wb-id", "wb-secret"), oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{
		AccessToken: "wb-at",
		Raw:         map[string]any{"uid": "17481221"},
	})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "17481221" || id.Nickname != "微博用户" || id.AvatarURL != "https://av/h.jpg" {
		t.Fatalf("id = %+v", id)
	}
	// Raw 落用户信息响应（show.json），不含令牌响应。
	if id.Raw == nil || id.Raw["idstr"] != "17481221" {
		t.Fatalf("Raw = %v", id.Raw)
	}
	if _, ok := id.Raw["access_token"]; ok {
		t.Fatalf("Raw 不应含 access_token")
	}
}

func TestFetchUserError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"auth header is absent","error_code":21332}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("wb-id", "wb-secret"), oauthcore.NewRewriteClient(srv.URL))
	_, err := a.FetchUser(context.Background(), &provider.Token{
		AccessToken: "bad", Raw: map[string]any{"uid": "1"},
	})
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Status != 403 {
		t.Fatalf("err = %v", err)
	}
}

func TestNotConfigured(t *testing.T) {
	if _, err := build(&provider.Provider{Key: "wb", Type: Type, Ext: &providerpb.Ext{ClientId: "id"}}, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestRegistry(t *testing.T) {
	if _, ok := provider.Lookup(Type); !ok {
		t.Fatalf("Lookup(%q) 未注册", Type)
	}
	if _, err := provider.NewAdapter(testProvider("id", "s")); err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
}
