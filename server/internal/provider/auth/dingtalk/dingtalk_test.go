// dingtalk 适配器单测：httptest 扮演钉钉开放平台端点，覆盖 authCode 回调
// 取参、JSON body 令牌交换（区别于 form）、自定义 Header userinfo（非
// Bearer）、refreshToken 刷新（TokenRefresher）、openId / unionId 双落、
// user_mapping 覆盖、失败路径 fail-closed（网络错 / JSON 损坏 / errcode
// 非零 / 缺 openId）、注册表装配与 Schema 键集。
package dingtalk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func testProvider(key, id, secret string) *provider.Provider {
	return &provider.Provider{Key: key, Type: Type, Ext: &providerpb.Ext{ClientId: id, ClientSecret: secret}}
}

func TestParseCallback(t *testing.T) {
	cb, err := ParseCallback(url.Values{"authCode": {"ac-1"}, "state": {"l-dt"}})
	if err != nil || cb.AuthCode != "ac-1" || cb.State != "l-dt" {
		t.Fatalf("cb = %+v, err = %v", cb, err)
	}
	// 钉钉回调参数名是 authCode 而非 code：标准 code 参数不认（fail-closed）。
	if _, err := ParseCallback(url.Values{"code": {"ac-1"}, "state": {"s"}}); !errors.Is(err, ErrCallbackInvalid) {
		t.Fatalf("err = %v, want ErrCallbackInvalid（code 参数名不认）", err)
	}
	if _, err := ParseCallback(url.Values{"authCode": {"ac-1"}}); !errors.Is(err, ErrCallbackInvalid) {
		t.Fatalf("err = %v, want ErrCallbackInvalid（state 缺失）", err)
	}
	if _, err := ParseCallback(nil); !errors.Is(err, ErrCallbackInvalid) {
		t.Fatalf("err = %v, want ErrCallbackInvalid", err)
	}
}

func TestBuildAuthURL(t *testing.T) {
	a, err := build(testProvider("dt", "dt-id", "dt-secret"), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// 端点断言（独立字面量，与生产常量解耦）：防「BuildAuthURL 输出 ≠
	// 钉钉官方授权端点」；不防与真实端点的互通性（httptest 无法覆盖，
	// 真机联调未覆盖）。
	const wantAuthURL = "https://login.dingtalk.com/oauth2/auth"
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-dt", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, _ := url.Parse(got)
	if u.Scheme+"://"+u.Host+u.Path != wantAuthURL {
		t.Fatalf("endpoint = %q, want %q", u.Scheme+"://"+u.Host+u.Path, wantAuthURL)
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != "dt-id" || q.Get("state") != "l-dt" {
		t.Fatalf("query = %v", q)
	}
	if q.Get("redirect_uri") != "https://app/cb" {
		t.Fatalf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if q.Get("scope") != defaultScopes {
		t.Fatalf("scope = %q, want %q", q.Get("scope"), defaultScopes)
	}
	if q.Get("prompt") != "consent" {
		t.Fatalf("prompt = %q, want consent（钉钉确认页固定参数）", q.Get("prompt"))
	}
	if _, err := a.BuildAuthURL(&provider.AuthContext{}); !errors.Is(err, oauthcore.ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
}

func TestExchange(t *testing.T) {
	// JSON body 交换（区别于 form）：请求必须是 application/json 且字段
	// 驼峰（clientId / clientSecret / code / grantType），不得出现 form 形态
	// 的 grant_type / client_secret 键。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1.0/oauth2/userAccessToken" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q, want application/json", ct)
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("body 非 JSON: %s (%v)", body, err)
		}
		if req["clientId"] != "dt-id" || req["clientSecret"] != "dt-secret" ||
			req["code"] != "dt-authcode" || req["grantType"] != "authorization_code" {
			t.Errorf("body = %v", req)
		}
		if _, ok := req["grant_type"]; ok {
			t.Errorf("body 不应含 form 形态键 grant_type: %v", req)
		}
		if _, ok := req["redirect_uri"]; ok {
			t.Errorf("body 不应含 redirect_uri（钉钉令牌端点不要求）: %v", req)
		}
		// 官方驼峰响应形态。
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"expireIn":7200,"accessToken":"dt-at","refreshToken":"dt-rt","corpId":"corp-1"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("dt", "dt-id", "dt-secret"), oauthcore.NewRewriteClient(srv.URL))
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "dt-authcode"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "dt-at" || tok.RefreshToken != "dt-rt" || tok.ExpiresIn != 7200 {
		t.Fatalf("token = %+v", tok)
	}
	// 空 code → 哨兵。
	if _, err := a.Exchange(context.Background(), provider.ExchangeInput{}); !errors.Is(err, oauthcore.ErrEmptyCode) {
		t.Fatalf("err = %v, want ErrEmptyCode", err)
	}

	// 兼容旧式下划线响应形态。
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"expires_in":7200,"access_token":"at2","refresh_token":"rt2"}`)
	}))
	defer srv2.Close()
	a2, _ := build(testProvider("dt", "dt-id", "dt-secret"), oauthcore.NewRewriteClient(srv2.URL))
	tok2, err := a2.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
	if err != nil || tok2.AccessToken != "at2" || tok2.RefreshToken != "rt2" || tok2.ExpiresIn != 7200 {
		t.Fatalf("token = %+v, err = %v", tok2, err)
	}
}

func TestExchangeFailClosed(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		resp     string
		wantCode string
	}{
		{"errcode 非零（2xx 错误体）", http.StatusOK, `{"errcode":400,"errmsg":"bad code"}`, "400"},
		{"v1.0 网关错误体（HTTP 400）", http.StatusBadRequest, `{"code":"InvalidGrant","message":"invalid authorization code"}`, "InvalidGrant"},
		{"JSON 损坏", http.StatusOK, `{"accessToken":`, "unparsable_token_response"},
		{"缺 accessToken", http.StatusOK, `{"expireIn":7200}`, "empty_access_token"},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			fmt.Fprint(w, tc.resp)
		}))
		a, _ := build(testProvider("dt", "dt-id", "dt-secret"), oauthcore.NewRewriteClient(srv.URL))
		_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "bad"})
		pe, ok := oauthcore.AsProviderError(err)
		if !ok || pe.Code != tc.wantCode {
			t.Errorf("%s: err = %v, want ProviderError code %q", tc.name, err, tc.wantCode)
		}
		if err != nil && strings.Contains(err.Error(), "dt-secret") {
			t.Errorf("%s: 错误串泄漏凭证: %v", tc.name, err)
		}
		srv.Close()
	}
}

func TestFetchUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Header 形态：accessToken 走自定义 Header（非 Bearer、不进 query）。
		if r.Method != http.MethodGet || r.URL.Path != "/v1.0/contact/users/me" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if h := r.Header.Get("x-acs-dingtalk-access-token"); h != "dt-at" {
			t.Errorf("header = %q, want dt-at", h)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("authorization = %q, want 空（非 Bearer）", r.Header.Get("Authorization"))
		}
		if q := r.URL.Query(); len(q) != 0 {
			t.Errorf("query = %v, want 空（token 不进 query）", q)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"nick":"张三","avatarUrl":"https://img.example/1.png","mobile":"13800000000","openId":"dt-open-1","unionId":"dt-union-1","email":"zhang@example.com"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("dt", "dt-id", "dt-secret"), oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "dt-at"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	// openId / unionId 双落。
	if id.ProviderKey != "dt" || id.ProviderType != Type || id.OpenID != "dt-open-1" || id.UnionID != "dt-union-1" {
		t.Fatalf("id = %+v", id)
	}
	if id.Nickname != "张三" || id.Email != "zhang@example.com" || id.Phone != "13800000000" ||
		id.AvatarURL != "https://img.example/1.png" {
		t.Fatalf("id = %+v", id)
	}
	// Raw 只落用户信息响应，不含令牌。
	if id.Raw == nil || id.Raw["openId"] != "dt-open-1" {
		t.Fatalf("Raw = %v", id.Raw)
	}
	if _, ok := id.Raw["access_token"]; ok {
		t.Fatalf("Raw 不应含 access_token")
	}
}

func TestFetchUserFailClosed(t *testing.T) {
	a0, _ := build(testProvider("dt", "dt-id", "dt-secret"), nil)
	if _, err := a0.FetchUser(context.Background(), nil); !errors.Is(err, oauthcore.ErrNilToken) {
		t.Fatalf("err = %v, want ErrNilToken", err)
	}
	if _, err := a0.FetchUser(context.Background(), &provider.Token{}); !errors.Is(err, ErrEmptyAccessToken) {
		t.Fatalf("err = %v, want ErrEmptyAccessToken", err)
	}
	cases := []struct {
		name     string
		status   int
		resp     string
		wantCode string
	}{
		{"errcode 非零", http.StatusOK, `{"errcode":60121,"errmsg":"no permission"}`, "60121"},
		{"HTTP 403 v1.0 错误体", http.StatusForbidden, `{"code":"Forbidden","message":"Contact.User.Read required"}`, "Forbidden"},
		{"JSON 损坏", http.StatusOK, `{"openId":`, "unparsable_user_info"},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			fmt.Fprint(w, tc.resp)
		}))
		a2, _ := build(testProvider("dt", "dt-id", "dt-secret"), oauthcore.NewRewriteClient(srv.URL))
		_, err := a2.FetchUser(context.Background(), &provider.Token{AccessToken: "at"})
		pe, ok := oauthcore.AsProviderError(err)
		if !ok || pe.Code != tc.wantCode {
			t.Errorf("%s: err = %v, want ProviderError code %q", tc.name, err, tc.wantCode)
		}
		srv.Close()
	}
	// 缺 openId → ErrEmptyOpenID（fail-closed：不给无唯一标识的登录）。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"nick":"n"}`)
	}))
	defer srv.Close()
	a3, _ := build(testProvider("dt", "dt-id", "dt-secret"), oauthcore.NewRewriteClient(srv.URL))
	if _, err := a3.FetchUser(context.Background(), &provider.Token{AccessToken: "at"}); !errors.Is(err, oauthcore.ErrEmptyOpenID) {
		t.Fatalf("err = %v, want ErrEmptyOpenID", err)
	}
}

func TestRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("body 非 JSON: %s (%v)", body, err)
		}
		if req["clientId"] != "dt-id" || req["clientSecret"] != "dt-secret" ||
			req["refreshToken"] != "dt-rt-old" || req["grantType"] != "refresh_token" {
			t.Errorf("body = %v", req)
		}
		if _, ok := req["code"]; ok {
			t.Errorf("刷新请求不应携带 code: %v", req)
		}
		fmt.Fprint(w, `{"expireIn":7200,"accessToken":"dt-at-new","refreshToken":"dt-rt-new"}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider("dt", "dt-id", "dt-secret"), oauthcore.NewRewriteClient(srv.URL))
	// 经 TokenRefresher 接口调用：证明适配器满足刷新契约。
	var ref TokenRefresher = a
	tok, err := ref.Refresh(context.Background(), &provider.Token{RefreshToken: "dt-rt-old"})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tok.AccessToken != "dt-at-new" || tok.RefreshToken != "dt-rt-new" || tok.ExpiresIn != 7200 {
		t.Fatalf("token = %+v", tok)
	}
	// 空 refreshToken / nil 入参 → fail-closed。
	if _, err := ref.Refresh(context.Background(), &provider.Token{}); !errors.Is(err, ErrEmptyRefreshToken) {
		t.Fatalf("err = %v, want ErrEmptyRefreshToken", err)
	}
	if _, err := ref.Refresh(context.Background(), nil); !errors.Is(err, ErrEmptyRefreshToken) {
		t.Fatalf("err = %v, want ErrEmptyRefreshToken", err)
	}

	// 刷新失败路径（errcode 非零）fail-closed。
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"errcode":400,"errmsg":"refresh token expired"}`)
	}))
	defer srv2.Close()
	a2, _ := build(testProvider("dt", "dt-id", "dt-secret"), oauthcore.NewRewriteClient(srv2.URL))
	_, err = a2.Refresh(context.Background(), &provider.Token{RefreshToken: "rt"})
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Code != "400" {
		t.Fatalf("err = %v, want ProviderError code 400", err)
	}
}

func TestUserMappingOverride(t *testing.T) {
	// user_mapping 覆盖渠道抽取值（映射结果优先）。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"nick":"n","openId":"o-3","unionId":"u-3","email":"m@example.com"}`)
	}))
	defer srv.Close()
	a, _ := build(&provider.Provider{Key: "dt", Type: Type, Ext: &providerpb.Ext{
		ClientId: "id", ClientSecret: "s",
		UserMapping: map[string]string{"nickname": "$.email"},
	}}, oauthcore.NewRewriteClient(srv.URL))
	id, err := a.FetchUser(context.Background(), &provider.Token{AccessToken: "at"})
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.Nickname != "m@example.com" {
		t.Fatalf("nickname = %q, want mapping 覆盖为 m@example.com", id.Nickname)
	}
}

func TestNotConfigured(t *testing.T) {
	if _, err := build(&provider.Provider{Key: "dt", Type: Type,
		Ext: &providerpb.Ext{ClientId: "id"}}, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if _, err := build(&provider.Provider{Key: "dt", Type: Type,
		Ext: &providerpb.Ext{ClientSecret: "s"}}, nil); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if _, err := build(nil, nil); !errors.Is(err, provider.ErrNilProvider) {
		t.Fatalf("err = %v, want ErrNilProvider", err)
	}
}

func TestRegistry(t *testing.T) {
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "钉钉" || meta.Category != "auth" || meta.Channel != provider.ChannelRedirect {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	adapter, err := provider.NewAdapter(testProvider("dt", "id", "secret"))
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	if adapter.Channel() != provider.ChannelRedirect {
		t.Fatalf("channel = %q", adapter.Channel())
	}
}

// TestSchemaKeepSet Schema 键集收敛（接口文档 §5.3 keep 集表 auth 行）：注册表
// Schema() 恰为表列基线 + 标准四键（client_id / client_secret / scopes /
// user_mapping，基线序）+ 引用键 proxy_provider_key，keep 外键（app_id / cert /
// provider_url / custom_* / metadata）不再下发；scopes / user_mapping 的预设
// 值随字段 default 下发（§15.5 收窄边界），保留字段其余属性与 schemafield
// 基线逐项一致。
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
		b, ok := baseline[f.Key]
		if !ok {
			continue
		}
		switch f.Key {
		case "scopes":
			if f.Default != defaultScopes {
				t.Errorf("scopes default = %q, want %q", f.Default, defaultScopes)
			}
			f.Default = b.Default
		case "user_mapping":
			if f.Default != defaultUserMapping {
				t.Errorf("user_mapping default = %q, want 预设映射", f.Default)
			}
			f.Default = b.Default
		}
		if !reflect.DeepEqual(f, b) {
			t.Errorf("字段 %q = %+v, want 基线 %+v（裁剪只删键不改属性）", f.Key, f, b)
		}
	}
}
