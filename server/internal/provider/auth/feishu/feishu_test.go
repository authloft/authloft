// feishu 适配器单测：httptest 扮演飞书端点，覆盖 state 校验、
// code→token、userinfo 抽取（open_id / sub 双键）、错误映射。
package feishu

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/auth/oauthcore"
	"authloft/internal/provider/schemafield"
)

func testProvider(id, secret string) *provider.Provider {
	return &provider.Provider{Key: "fs", Type: Type, Ext: &providerpb.Ext{ClientId: id, ClientSecret: secret}}
}

func TestBuildAuthURL(t *testing.T) {
	a, err := build(testProvider("fs-id", "fs-secret"), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-fs", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	if !strings.Contains(got, "passport.feishu.cn/suite/passport/oauth2/authorize") ||
		!strings.Contains(got, "state=l-fs") || !strings.Contains(got, "client_id=fs-id") {
		t.Fatalf("url = %q", got)
	}
	// 无渠道缺省 scope：不携带。
	if strings.Contains(got, "scope=") {
		t.Fatalf("url 不应携带 scope: %q", got)
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
		if r.Form.Get("code") != "fs-code" || r.Form.Get("client_id") != "fs-id" || r.Form.Get("client_secret") != "fs-secret" {
			t.Errorf("form = %v", r.Form)
		}
		fmt.Fprint(w, `{"access_token":"fs-at","refresh_token":"fs-rt","expires_in":7200}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("fs-id", "fs-secret"), oauthcore.NewRewriteClient(srv.URL))
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "fs-code"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "fs-at" || tok.ExpiresIn != 7200 {
		t.Fatalf("token = %+v", tok)
	}
}

func TestExchangeProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"code expired"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("fs-id", "fs-secret"), oauthcore.NewRewriteClient(srv.URL))
	_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "x"})
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Code != "invalid_grant" || pe.Desc != "code expired" {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fs-at" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		fmt.Fprint(w, `{"sub":"ou-1","name":"FS User","picture_url":"https://p/fs.png","email":"fs@example.com"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("fs-id", "fs-secret"), oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "fs-at"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "ou-1" || id.Nickname != "FS User" || id.AvatarURL != "https://p/fs.png" || id.Email != "fs@example.com" {
		t.Fatalf("id = %+v", id)
	}

	// open_id 键优先于 sub。
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"open_id":"ou-2","sub":"s-2","name":"n"}`)
	}))
	defer srv2.Close()
	a2, _ := build(testProvider("fs-id", "fs-secret"), oauthcore.NewRewriteClient(srv2.URL))
	id2, err := a2.FetchUser(context.Background(), &provider.Token{AccessToken: "at"})
	if err != nil || id2.OpenID != "ou-2" {
		t.Fatalf("id = %+v err = %v", id2, err)
	}
}

func TestNotConfigured(t *testing.T) {
	if _, err := build(&provider.Provider{Key: "fs", Type: Type, Ext: &providerpb.Ext{}}, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestRegistry(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "飞书" || meta.Channel != provider.ChannelRedirect {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	if _, err := provider.NewAdapter(testProvider("id", "s")); err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
}

// TestSchemaKeepSet Schema 键集收敛（接口文档 §5.3 keep 集表 auth 行）：注册表
// Schema() 恰为表列基线 + keep 集（client_id / client_secret / scopes /
// user_mapping，基线序）+ 引用键 proxy_provider_key，keep 外键（app_id / cert /
// provider_url / custom_* / metadata）不再下发；保留字段属性与 schemafield
// 基线逐项一致（裁剪只删键不改属性），声明序即 wire 序。
func TestSchemaKeepSet(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok {
		t.Fatalf("type %q 未注册", Type)
	}
	schema := meta.Schema()
	wantKeys := []string{
		"provider_key", "display_name", "union_provider",
		"client_id", "client_secret", "scopes", "user_mapping",
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
		if b, ok := baseline[f.Key]; ok && !reflect.DeepEqual(f, b) {
			t.Errorf("字段 %q = %+v, want 基线 %+v（裁剪只删键不改属性）", f.Key, f, b)
		}
	}
}
