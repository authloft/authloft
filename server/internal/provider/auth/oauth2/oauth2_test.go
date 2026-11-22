// oauth2 通用兜底适配器单测：httptest 扮演手工端点三件套，覆盖
// 配置缺失（端点 / user_mapping.open_id）、state 校验、code→token、
// user_mapping 全量映射、错误映射与 schema 必填声明；差异开关（GET 令牌
// 端点 / query 传 token userinfo / PKCE S256）各带可证伪用例：stub 端
// 校验 method、参数与 challenge-verifier 配对，实现偏差即拒绝路径。
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
	"authloft/internal/provider/auth/oauthcore"
	"authloft/internal/provider/schemafield"
)

func testProvider(auth, token, user string, mapping map[string]string, md ...map[string]string) *provider.Provider {
	ext := &providerpb.Ext{
		ClientId:          "g-id",
		ClientSecret:      "g-secret",
		Scopes:            "profile",
		CustomAuthUrl:     auth,
		CustomTokenUrl:    token,
		CustomUserInfoUrl: user,
		UserMapping:       mapping,
	}
	if len(md) > 0 {
		ext.Metadata = md[0]
	}
	return &provider.Provider{Key: "gen", Type: Type, Ext: ext}
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

// TestPKCEFlow pkce=s256 全链路配对校验（可证伪）：授权 URL 的 challenge
// 必须等于派生 verifier 的 S256，令牌端点 stub 复算收到的 code_verifier
// 比对——verifier 缺失 / 两侧派生不一致即拒绝；缺省关闭时不携带任何
// PKCE 参数（标准形态回归锁定）。
func TestPKCEFlow(t *testing.T) {
	const redirect = "https://root/sso/oauth/callback/gen"
	wantVerifier := pkceVerifier("g-secret", "gen", redirect)
	wantChallenge := s256Challenge(wantVerifier)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse form: %v", err)
			}
			cv := r.Form.Get("code_verifier")
			if cv == "" || s256Challenge(cv) != wantChallenge {
				t.Errorf("verifier/challenge 不配对: cv=%q", cv)
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"invalid_grant","error_description":"pkce mismatch"}`)
				return
			}
			fmt.Fprint(w, `{"access_token":"g-at","expires_in":3600}`)
		case "/me":
			fmt.Fprint(w, `{"id":99,"name":"PKCE User"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, err := build(testProvider(srv.URL+"/auth", srv.URL+"/token", srv.URL+"/me",
		map[string]string{"open_id": "$.id"}, map[string]string{"pkce": "s256"}), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-gen", RedirectURI: redirect})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	q, _ := url.Parse(got)
	if qp := q.Query(); qp.Get("code_challenge_method") != "S256" || qp.Get("code_challenge") != wantChallenge {
		t.Fatalf("challenge = %v, want S256/%s", qp, wantChallenge)
	}
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "g-code", RedirectURI: redirect})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "g-at" {
		t.Fatalf("token = %+v", tok)
	}
	if id, err := a.FetchUser(context.Background(), tok); err != nil || id.OpenID != "99" {
		t.Fatalf("FetchUser = %+v, %v", id, err)
	}

	// 缺省关闭：无 code_challenge / 无 code_verifier。
	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.Form.Get("code_verifier") != "" {
			t.Errorf("缺省不应携带 code_verifier: %q", r.Form.Get("code_verifier"))
		}
		fmt.Fprint(w, `{"access_token":"g-at"}`)
	}))
	defer off.Close()
	a2, err := build(testProvider(off.URL+"/auth", off.URL+"/token", srv.URL+"/me",
		map[string]string{"open_id": "$.id"}), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got2, err := a2.BuildAuthURL(&provider.AuthContext{State: "l-gen", RedirectURI: redirect})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u2, _ := url.Parse(got2)
	if qp := u2.Query(); qp.Get("code_challenge") != "" || qp.Get("code_challenge_method") != "" {
		t.Fatalf("缺省不应携带 PKCE 参数: %v", qp)
	}
	if _, err := a2.Exchange(context.Background(), provider.ExchangeInput{Code: "g-code", RedirectURI: redirect}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
}

// TestTokenMethodGet token_method=get（可证伪）：令牌端点 stub 校验方法与
// 必备 query 参数，错方法 / 缺参数即拒绝；GET 形态不带 grant_type（按目标
// 渠道文档组装）。PKCE 同开时 code_verifier 改随 query 携带。
func TestTokenMethodGet(t *testing.T) {
	const redirect = "https://root/sso/oauth/callback/gen"
	newStub := func(t *testing.T, wantVerifier string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/token":
				if r.Method != http.MethodGet {
					t.Errorf("method = %s, want GET", r.Method)
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				q := r.URL.Query()
				if q.Get("code") != "g-code" || q.Get("client_id") != "g-id" ||
					q.Get("client_secret") != "g-secret" || q.Get("redirect_uri") != redirect {
					t.Errorf("query = %v", q)
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprint(w, `{"error":"invalid_request"}`)
					return
				}
				if q.Get("grant_type") != "" {
					t.Errorf("GET 形态不应携带 grant_type: %v", q)
				}
				if q.Get("code_verifier") != wantVerifier {
					t.Errorf("code_verifier = %q, want %q", q.Get("code_verifier"), wantVerifier)
				}
				fmt.Fprint(w, `{"access_token":"g-at"}`)
			case "/me":
				fmt.Fprint(w, `{"id":7}`)
			default:
				http.NotFound(w, r)
			}
		}))
	}

	srv := newStub(t, "")
	defer srv.Close()
	a, err := build(testProvider(srv.URL+"/auth", srv.URL+"/token", srv.URL+"/me",
		map[string]string{"open_id": "$.id"}, map[string]string{"token_method": "get"}), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "g-code", RedirectURI: redirect})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "g-at" {
		t.Fatalf("token = %+v", tok)
	}

	// GET + PKCE 组合：verifier 随 query 携带，challenge 与派生值配对。
	wantVerifier := pkceVerifier("g-secret", "gen", redirect)
	srv2 := newStub(t, wantVerifier)
	defer srv2.Close()
	a2, err := build(testProvider(srv2.URL+"/auth", srv2.URL+"/token", srv2.URL+"/me",
		map[string]string{"open_id": "$.id"}, map[string]string{"token_method": "get", "pkce": "s256"}), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got, err := a2.BuildAuthURL(&provider.AuthContext{State: "l-gen", RedirectURI: redirect})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, _ := url.Parse(got)
	if got := u.Query().Get("code_challenge"); got != s256Challenge(wantVerifier) {
		t.Fatalf("code_challenge = %q, want %q", got, s256Challenge(wantVerifier))
	}
	if _, err := a2.Exchange(context.Background(), provider.ExchangeInput{Code: "g-code", RedirectURI: redirect}); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
}

// TestUserInfoTokenInQuery userinfo_token_in=query（可证伪）：access_token
// 走查询串且不带 Authorization 头（stub 见头即记错）；错 token 走错误体
// → ProviderError 拒绝路径。缺省仍为 Bearer 头、查询串不带 token。
func TestUserInfoTokenInQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("不应携带 Authorization 头: %q", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("access_token") != "g-at" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid_token","message":"bad access_token"}`)
			return
		}
		fmt.Fprint(w, `{"id":88,"name":"Query User"}`)
	}))
	defer srv.Close()

	a, err := build(testProvider("https://a", srv.URL+"/token", srv.URL+"/me",
		map[string]string{"open_id": "$.id"}, map[string]string{"userinfo_token_in": "query"}), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "g-at"})
	if err != nil || id.OpenID != "88" {
		t.Fatalf("FetchUser = %+v, %v", id, err)
	}
	_, err = a.FetchUser(context.Background(), &provider.Token{AccessToken: "bad"})
	if _, ok := oauthcore.AsProviderError(err); !ok {
		t.Fatalf("err = %v, want ProviderError", err)
	}

	// 缺省：Bearer 头携带、查询串不带 access_token。
	def := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer g-at" {
			t.Errorf("Authorization = %q, want Bearer g-at", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("access_token") != "" {
			t.Errorf("缺省不应在查询串携带 access_token")
		}
		fmt.Fprint(w, `{"id":1}`)
	}))
	defer def.Close()
	a2, err := build(testProvider("https://a", def.URL+"/token", def.URL+"/me",
		map[string]string{"open_id": "$.id"}), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := a2.FetchUser(context.Background(), &provider.Token{AccessToken: "g-at"}); err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
}

// TestInvalidMetadataOption 差异开关未知取值装配期 fail-closed（可证伪）：
// 拼错取值不得静默回落标准形态，否则登录期才暴露、难排查。
func TestInvalidMetadataOption(t *testing.T) {
	cases := []map[string]string{
		{"token_method": "PUT"},
		{"userinfo_token_in": "cookie"},
		{"pkce": "plain"},
	}
	for i, md := range cases {
		if _, err := build(testProvider("https://a", "https://t", "https://u",
			map[string]string{"open_id": "$.id"}, md), nil); !errors.Is(err, ErrInvalidOption) {
			t.Fatalf("case %d: err = %v, want ErrInvalidOption", i, err)
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

// TestSchemaKeepSet Schema 键集收敛（接口文档 §5.3 keep 集表 auth 行）：注册表
// Schema() 恰为表列基线 + keep 集（标准四件套 + 三端点 + metadata，基线序）+
// 引用键 proxy_provider_key，keep 外键（app_id / cert / provider_url）不再
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
		"custom_auth_url", "custom_token_url", "custom_user_info_url", "user_mapping", "metadata",
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
