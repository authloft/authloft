// qq 适配器单测：httptest 扮演 QQ 互联端点，覆盖 state 校验、
// GET 查询串换令牌（form 编码响应）、JSONP /me 剥壳、get_user_info
// （oauth_consumer_key / openid 参数断言、ret != 0）、错误 JSONP 映射。
package qq

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

func testProvider(id, secret string) *provider.Provider {
	return &provider.Provider{Key: "qq", Type: Type, Ext: &providerpb.Ext{ClientId: id, ClientSecret: secret}}
}

func TestBuildAuthURL(t *testing.T) {
	a, _ := build(testProvider("qq-id", "qq-secret"), nil)
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-qq"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, _ := url.Parse(got)
	q := u.Query()
	if q.Get("state") != "l-qq" || q.Get("client_id") != "qq-id" || q.Get("scope") != defaultScopes {
		t.Fatalf("query = %v", q)
	}
	if _, err := a.BuildAuthURL(&provider.AuthContext{}); !errors.Is(err, oauthcore.ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
}

func TestExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != "qq-id" || q.Get("client_secret") != "qq-secret" ||
			q.Get("code") != "qq-code" || q.Get("grant_type") != "authorization_code" {
			t.Errorf("query = %v", q)
		}
		fmt.Fprint(w, "access_token=qq-at&expires_in=7776000&refresh_token=qq-rt")
	}))
	defer srv.Close()

	a, _ := build(testProvider("qq-id", "qq-secret"), oauthcore.NewRewriteClient(srv.URL))
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "qq-code", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "qq-at" || tok.ExpiresIn != 7776000 || tok.RefreshToken != "qq-rt" {
		t.Fatalf("token = %+v", tok)
	}
}

// TestFetchUser 两步链路：/me JSONP 剥壳取 openid → get_user_info。
func TestFetchUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2.0/me":
			if r.URL.Query().Get("access_token") != "qq-at" {
				t.Errorf("me query = %v", r.URL.Query())
			}
			fmt.Fprint(w, `callback( {"client_id":"qq-id","openid":"O-QQ-1","unionid":"U-QQ-1"} ); `)
		case "/user/get_user_info":
			q := r.URL.Query()
			if q.Get("access_token") != "qq-at" || q.Get("oauth_consumer_key") != "qq-id" || q.Get("openid") != "O-QQ-1" {
				t.Errorf("userinfo query = %v", q)
			}
			fmt.Fprint(w, `{"ret":0,"nickname":"QQ用户","figureurl_qq_1":"https://q/50.jpg","figureurl_qq_2":"https://q/100.jpg"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, _ := build(testProvider("qq-id", "qq-secret"), oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "qq-at"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "O-QQ-1" || id.UnionID != "U-QQ-1" || id.Nickname != "QQ用户" || id.AvatarURL != "https://q/100.jpg" {
		t.Fatalf("id = %+v", id)
	}
	// Raw 落两步用户侧合并（含 /me openid），不含 access_token。
	if id.Raw == nil || id.Raw["openid"] != "O-QQ-1" || id.Raw["nickname"] != "QQ用户" {
		t.Fatalf("Raw = %v", id.Raw)
	}
	if _, ok := id.Raw["access_token"]; ok {
		t.Fatalf("Raw 不应含 access_token")
	}
}

// TestFetchUserErrors /me 错误 JSONP 与 get_user_info ret != 0 两条错误路径。
func TestFetchUserErrors(t *testing.T) {
	// /me 错误 JSONP（error 字段）。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `cb( {"error":100016,"error_description":"access token expired"} );`)
	}))
	defer srv.Close()
	a, _ := build(testProvider("qq-id", "qq-secret"), oauthcore.NewRewriteClient(srv.URL))
	_, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "bad"})
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Code != "100016" || pe.Desc != "access token expired" {
		t.Fatalf("err = %v", err)
	}

	// /me 未返回 openid。
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `callback( {"client_id":"qq-id"} );`)
	}))
	defer srv2.Close()
	a2, _ := build(testProvider("qq-id", "qq-secret"), oauthcore.NewRewriteClient(srv2.URL))
	if _, err := a2.FetchUser(context.Background(), &provider.Token{AccessToken: "at"}); !errors.Is(err, ErrEmptyOpenID) {
		t.Fatalf("err = %v, want ErrEmptyOpenID", err)
	}

	// get_user_info ret != 0。
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2.0/me":
			fmt.Fprint(w, `callback( {"client_id":"qq-id","openid":"O-1"} );`)
		default:
			fmt.Fprint(w, `{"ret":1002,"msg":"invalid openid"}`)
		}
	}))
	defer srv3.Close()
	a3, _ := build(testProvider("qq-id", "qq-secret"), oauthcore.NewRewriteClient(srv3.URL))
	_, err = a3.FetchUser(context.Background(), &provider.Token{AccessToken: "at"})
	pe, ok = oauthcore.AsProviderError(err)
	if !ok || pe.Code != "1002" {
		t.Fatalf("err = %v", err)
	}
}

func TestNotConfigured(t *testing.T) {
	if _, err := build(&provider.Provider{Key: "qq", Type: Type, Ext: &providerpb.Ext{}}, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestRegistry(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "QQ" {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	if _, err := provider.NewAdapter(testProvider("id", "s")); err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
}
