// discord 薄封装单测：Schema 收窄与预设值、固化常量、工厂 fail-closed，以及
// 经导出的 oidc.New 注入 mock 基址复现生产 factory 数据流（factory 与生产
// 唯一差异是 providerURL 参数值，不影响身份类型与预设消费）——真实端点
// 本机不可达，测试一律本地 mock。
package discord

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/auth/oidc"
)

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

// TestRegistry Schema 收窄与预设值：keep 集 = 表列基线 + 标准四件套 + 引用键；
// 固化 provider_url 不透出（可证伪：误声明即红）；scopes / user_mapping 预设
// 随字段 default 下发。
func TestRegistry(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "Discord" || meta.Channel != provider.ChannelRedirect {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	want := map[string]bool{
		"provider_key": true, "display_name": true, "union_provider": true,
		"client_id": true, "client_secret": true, "scopes": true, "user_mapping": true,
		"icon_url": true, "sort_order": true, "remark": true,
		"is_enabled": true, "enable_signin": true, "enable_signup": true, "auto_bind": true, "auto_bind_fields": true,
		provider.ProxyRefKey: true,
	}
	schema := meta.Schema()
	if len(schema) != len(want) {
		var keys []string
		for _, f := range schema {
			keys = append(keys, f.Key)
		}
		t.Fatalf("schema keys = %v, want 恰为 keep 集 %v", keys, want)
	}
	for _, f := range schema {
		if !want[f.Key] {
			t.Fatalf("schema 出现 keep 外键 %q", f.Key)
		}
		switch f.Key {
		case "scopes":
			if f.Default != defaultScopes {
				t.Fatalf("scopes default = %q, want %q", f.Default, defaultScopes)
			}
		case "user_mapping":
			if f.Default != defaultUserMapping {
				t.Fatalf("user_mapping default = %q, want 预设拼接表达式", f.Default)
			}
		case "client_id", "client_secret":
			if !f.Required {
				t.Fatalf("%s 应必填", f.Key)
			}
		}
	}
}

// TestProviderURLFixed 固化 discovery 基址：常量被误改即红。
func TestProviderURLFixed(t *testing.T) {
	if ProviderURL != "https://discord.com" {
		t.Fatalf("ProviderURL = %q, want https://discord.com", ProviderURL)
	}
}

// TestFactoryNotConfigured 工厂走 oidc 基座校验链：凭证缺失 fail-closed，
// 不发起 discovery（零网络）。
func TestFactoryNotConfigured(t *testing.T) {
	_, err := newAdapter(&provider.Provider{Key: "d1", Type: Type, Ext: &providerpb.Ext{}})
	if !errors.Is(err, oidc.ErrNotConfigured) {
		t.Fatalf("err = %v, want oidc.ErrNotConfigured", err)
	}
}

// TestFetchUserFlow 注入 mock 基址的全流程：发现 / 授权 / 换令牌 / 用户信息，
// 身份 ProviderType 取 p.Type（错标回归），预设 user_mapping 的头像 CDN
// 拼接真实生效。Ext 预填预设值 = 生产形态（预设随 Schema 字段 default 下发，
// 表单按 default 提交进 Ext，适配器照常消费）。
func TestFetchUserFlow(t *testing.T) {
	tokenOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("code") != "d-code" || r.Form.Get("client_id") != "d-id" || r.Form.Get("client_secret") != "d-secret" {
			t.Errorf("form = %v", r.Form)
		}
		fmt.Fprint(w, `{"access_token":"d-at","expires_in":604800}`)
	})
	userOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer d-at" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		fmt.Fprint(w, `{"id":"80351110224678912","username":"jane","global_name":"Jane Doe","discriminator":"0","avatar":"8342729096ea3675442027381ff50dfe","email":"jane@example.com","verified":true}`)
	})
	srv := newIdP(t, tokenOK, userOK)
	defer srv.Close()

	// 预设 user_mapping 是 JSON 文本字段，反序列化失败即预设表达式损坏（可证伪）。
	var mapping map[string]string
	if err := json.Unmarshal([]byte(defaultUserMapping), &mapping); err != nil {
		t.Fatalf("预设 user_mapping 非法 JSON: %v", err)
	}
	// 生产 factory 形态：Type=discord，Ext 无 provider_url（Schema 不声明）；
	// 测试经 oidc.New 注入 mock 基址（生产为固化 ProviderURL）。
	p := &provider.Provider{Key: "d1", Type: Type, Ext: &providerpb.Ext{
		ClientId: "d-id", ClientSecret: "d-secret", Scopes: defaultScopes, UserMapping: mapping,
	}}
	a, err := oidc.New(p, srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-dsc"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	if !strings.Contains(got, "scope="+url.QueryEscape(defaultScopes)) {
		t.Fatalf("url 缺预设 scope = %q", got)
	}
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "d-code"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	id, err := a.FetchUser(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.ProviderType != Type {
		t.Fatalf("ProviderType = %q, want %q（身份错标）", id.ProviderType, Type)
	}
	if id.OpenID != "80351110224678912" || id.Username != "jane" || id.Nickname != "Jane Doe" || id.Email != "jane@example.com" {
		t.Fatalf("id = %+v", id)
	}
	wantAvatar := "https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png"
	if id.AvatarURL != wantAvatar {
		t.Fatalf("AvatarURL = %q, want 预设拼接 %q", id.AvatarURL, wantAvatar)
	}
}
