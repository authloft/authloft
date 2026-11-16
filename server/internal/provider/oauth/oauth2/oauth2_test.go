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
	"reflect"
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
	"authloft/internal/provider/schemafield"
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
	for _, f := range meta.Schema() {
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

// TestSchemaKeepSet Schema 键集收敛（接口文档 §5.3 keep 集表 oauth 行）：注册表
// Schema() 恰为表列基线 + keep 集（标准四件套 + 三端点，基线序）+ 引用键
// proxy_provider_key，keep 外键（app_id / cert / provider_url / metadata）不再
// 下发；三端点与 user_mapping 置必填、user_mapping 换 oauth2 专用 Help，其余
// 字段属性与 schemafield 基线逐项一致（裁剪只删键不改属性），声明序即 wire 序。
func TestSchemaKeepSet(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok {
		t.Fatalf("type %q 未注册", Type)
	}
	schema := meta.Schema()
	wantKeys := []string{
		"provider_key", "display_name", "union_provider",
		"client_id", "client_secret", "scopes",
		"custom_auth_url", "custom_token_url", "custom_user_info_url", "user_mapping",
		"icon_url", "ui_group", "sort_order", "remark",
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
		switch f.Key {
		case "custom_auth_url", "custom_token_url", "custom_user_info_url":
			// 无渠道缺省知识，端点必填。
			if !f.Required {
				t.Errorf("%s 应必填", f.Key)
			}
		case "user_mapping":
			// 必填 + oauth2 专用 Help。
			if !f.Required || f.Help != "admin.schemaField.oauth2UserMappingHelp" {
				t.Errorf("user_mapping Required/Help = %v/%q, want true/admin.schemaField.oauth2UserMappingHelp", f.Required, f.Help)
			}
		default:
			if b, ok := baseline[f.Key]; ok && !reflect.DeepEqual(f, b) {
				t.Errorf("字段 %q = %+v, want 基线 %+v（裁剪只删键不改属性）", f.Key, f, b)
			}
		}
	}
}
