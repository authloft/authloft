// wechat 适配器单测：httptest 扮演微信开放平台端点，覆盖
// qrconnect URL（appid / 尾锚 / snsapi_login）、GET 查询串换令牌
// （openid / unionid）、userinfo（openid 参数断言）、errcode 错误映射。
package wechat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

func testProvider(id, secret string) *provider.Provider {
	return &provider.Provider{Key: "wx", Type: Type, Ext: &providerpb.Ext{ClientId: id, ClientSecret: secret}}
}

func TestBuildAuthURL(t *testing.T) {
	a, _ := build(testProvider("wx-appid", "wx-secret"), nil)
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-wx", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	if !strings.Contains(got, "open.weixin.qq.com/connect/qrconnect?") {
		t.Fatalf("url = %q", got)
	}
	if !strings.Contains(got, "appid=wx-appid") || !strings.Contains(got, "scope=snsapi_login") ||
		!strings.Contains(got, "state=l-wx") || !strings.HasSuffix(got, "#wechat_redirect") {
		t.Fatalf("url = %q", got)
	}
	// ctx.Scope 优先。
	if got, _ = a.BuildAuthURL(&provider.AuthContext{State: "s", Scope: "snsapi_base"}); !strings.Contains(got, "scope=snsapi_base") {
		t.Fatalf("url = %q", got)
	}
	if _, err := a.BuildAuthURL(nil); !errors.Is(err, oauthcore.ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
}

func TestExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("appid") != "wx-appid" || q.Get("secret") != "wx-secret" ||
			q.Get("code") != "wx-code" || q.Get("grant_type") != "authorization_code" {
			t.Errorf("query = %v", q)
		}
		fmt.Fprint(w, `{"access_token":"wx-at","expires_in":7200,"refresh_token":"wx-rt","openid":"o-wx-1","unionid":"u-wx-1","scope":"snsapi_login"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("wx-appid", "wx-secret"), oauthcore.NewRewriteClient(srv.URL))
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "wx-code"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "wx-at" || tok.Raw["openid"] != "o-wx-1" || tok.Raw["unionid"] != "u-wx-1" {
		t.Fatalf("token = %+v", tok)
	}
}

func TestExchangeWechatError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"errcode":40029,"errmsg":"invalid code"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("wx-appid", "wx-secret"), oauthcore.NewRewriteClient(srv.URL))
	_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "bad"})
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Code != "40029" || pe.Desc != "invalid code" {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("access_token") != "wx-at" || q.Get("openid") != "o-wx-1" {
			t.Errorf("query = %v", q)
		}
		fmt.Fprint(w, `{"openid":"o-wx-1","nickname":"微信用户","headimgurl":"https://wx/h.jpg","unionid":"u-wx-1"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("wx-appid", "wx-secret"), oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{
		AccessToken: "wx-at",
		Raw:         map[string]any{"openid": "o-wx-1", "unionid": "u-wx-1"},
	})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "o-wx-1" || id.UnionID != "u-wx-1" || id.Nickname != "微信用户" || id.AvatarURL != "https://wx/h.jpg" {
		t.Fatalf("id = %+v", id)
	}
	// Raw 只落 userinfo 响应。
	if _, ok := id.Raw["access_token"]; ok {
		t.Fatalf("Raw 不应含 access_token")
	}
}

func TestNotConfigured(t *testing.T) {
	if _, err := build(&provider.Provider{Key: "wx", Type: Type, Ext: &providerpb.Ext{ClientId: "id"}}, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestRegistry(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "微信开放平台" {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	if _, err := provider.NewAdapter(testProvider("id", "s")); err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
}
