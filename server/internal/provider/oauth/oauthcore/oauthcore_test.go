// oauthcore 单测：令牌响应解析（JSON / form / 错误体）、字段
// 拍平、统一身份抽取与 user_mapping 覆盖、BuildAuthURL state 校验、
// GetUserInfo 两种鉴权形态与错误归一、OIDC discovery、Meta 基线。
package oauthcore

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

	"authloft/internal/provider"
)

// TestParseTokenBodyJSONSuccess JSON 令牌响应：数字与字符串 expires_in。
func TestParseTokenBodyJSONSuccess(t *testing.T) {
	tok, err := parseTokenBody(200, []byte(`{"access_token":"at-1","refresh_token":"rt-1","expires_in":7200}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tok.AccessToken != "at-1" || tok.RefreshToken != "rt-1" || tok.ExpiresIn != 7200 {
		t.Fatalf("token = %+v", tok)
	}
	if v, _ := tok.Raw["access_token"].(string); v != "at-1" {
		t.Fatalf("Raw access_token = %v", tok.Raw["access_token"])
	}

	tok, err = parseTokenBody(200, []byte(`{"access_token":"at-2","expires_in":"3600"}`))
	if err != nil || tok.ExpiresIn != 3600 {
		t.Fatalf("string expires_in: tok=%+v err=%v", tok, err)
	}
}

// TestParseTokenBodyFormFallback QQ 旧式 form 编码响应回退解析。
func TestParseTokenBodyFormFallback(t *testing.T) {
	tok, err := parseTokenBody(200, []byte("access_token=at-3&expires_in=7776000&refresh_token=rt-3"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tok.AccessToken != "at-3" || tok.RefreshToken != "rt-3" || tok.ExpiresIn != 7776000 {
		t.Fatalf("token = %+v", tok)
	}
}

// TestParseTokenBodyError 错误体归一：2xx 错误字段、非 2xx、微信 errcode
// 数字键、无 access_token、不可解析。
func TestParseTokenBodyError(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantCode string
		wantDesc string
	}{
		{"2xx error 字段", 200, `{"error":"invalid_grant","error_description":"bad code"}`, "invalid_grant", "bad code"},
		{"非 2xx JSON", 400, `{"error":"invalid_client","error_description":"client mismatch"}`, "invalid_client", "client mismatch"},
		{"非 2xx 纯文本", 500, "oops", "http_500", "oops"},
		{"微信 errcode", 200, `{"errcode":40029,"errmsg":"invalid code"}`, "40029", "invalid code"},
		{"空 access_token", 200, `{"foo":"bar"}`, "empty_access_token", `{"foo":"bar"}`},
		{"不可解析", 200, "\x00\x01", "unparsable_token_response", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTokenBody(tc.status, []byte(tc.body))
			pe, ok := AsProviderError(err)
			if !ok {
				t.Fatalf("err = %v, want ProviderError", err)
			}
			if pe.Code != tc.wantCode {
				t.Fatalf("code = %q, want %q", pe.Code, tc.wantCode)
			}
			if tc.wantDesc != "" && pe.Desc != tc.wantDesc {
				t.Fatalf("desc = %q, want %q", pe.Desc, tc.wantDesc)
			}
		})
	}
}

// TestBuildAuthURL state 必填透传、scope 缺省、redirect_uri、extra 参数。
func TestBuildAuthURL(t *testing.T) {
	got, err := BuildAuthURL("https://idp.example.com/authorize", "cid-1",
		&provider.AuthContext{State: "l-abc", RedirectURI: "https://app.example.com/cb"}, "openid profile",
		map[string]string{"foo": "bar", "empty": ""})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse %q: %v", got, err)
	}
	q := u.Query()
	if q.Get("state") != "l-abc" || q.Get("client_id") != "cid-1" || q.Get("response_type") != "code" {
		t.Fatalf("query = %v", q)
	}
	if q.Get("redirect_uri") != "https://app.example.com/cb" || q.Get("scope") != "openid profile" || q.Get("foo") != "bar" || q.Has("empty") {
		t.Fatalf("query = %v", q)
	}

	// AuthContext.Scope 优先于渠道默认。
	got, _ = BuildAuthURL("https://idp.example.com/authorize", "cid-1",
		&provider.AuthContext{State: "s", Scope: "custom"}, "openid", nil)
	if !strings.Contains(got, "scope=custom") {
		t.Fatalf("scope override: %q", got)
	}

	// state 为空 → 哨兵。
	if _, err := BuildAuthURL("https://x.example.com/a", "cid", &provider.AuthContext{}, "", nil); !errors.Is(err, ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
	if _, err := BuildAuthURL("https://x.example.com/a", "cid", nil, "", nil); !errors.Is(err, ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
	// 端点缺失 → 哨兵。
	if _, err := BuildAuthURL("", "cid", &provider.AuthContext{State: "s"}, "", nil); !errors.Is(err, ErrMissingEndpoint) {
		t.Fatalf("err = %v, want ErrMissingEndpoint", err)
	}
	// 已带 query 的端点用 & 拼接。
	got, _ = BuildAuthURL("https://x.example.com/a?k=v", "cid", &provider.AuthContext{State: "s"}, "", nil)
	if !strings.Contains(got, "a?k=v&") {
		t.Fatalf("join: %q", got)
	}
}

// TestGetUserInfo Bearer 头 / access_token 查询串两形态与错误归一。
func TestGetUserInfo(t *testing.T) {
	var gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.Query().Get("access_token")
		fmt.Fprint(w, `{"id":42,"name":"n"}`)
	}))
	defer srv.Close()

	m, err := GetUserInfo(context.Background(), nil, srv.URL, "at-1", true, nil, nil)
	if err != nil {
		t.Fatalf("bearer: %v", err)
	}
	if gotAuth != "Bearer at-1" || gotQuery != "" {
		t.Fatalf("auth=%q query=%q", gotAuth, gotQuery)
	}
	if m["name"] != "n" {
		t.Fatalf("m = %v", m)
	}

	m, err = GetUserInfo(context.Background(), nil, srv.URL, "at-2", false,
		url.Values{"openid": {"o-1"}}, nil)
	if err != nil {
		t.Fatalf("query style: %v", err)
	}
	if gotAuth != "" || gotQuery != "at-2" {
		t.Fatalf("auth=%q query=%q", gotAuth, gotQuery)
	}
	if _, ok := m["id"]; !ok {
		t.Fatalf("m = %v", m)
	}

	// 非 2xx JSON 错误体。
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_token","error_description":"token expired"}`)
	}))
	defer srv2.Close()
	_, err = GetUserInfo(context.Background(), nil, srv2.URL, "bad", true, nil, nil)
	pe, ok := AsProviderError(err)
	if !ok || pe.Code != "invalid_token" || pe.Desc != "token expired" || pe.Status != 401 {
		t.Fatalf("err = %v", err)
	}

	// QQ get_user_info：HTTP 200 但 ret != 0。
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ret":1002,"msg":"invalid openid"}`)
	}))
	defer srv3.Close()
	_, err = GetUserInfo(context.Background(), nil, srv3.URL, "at", false, nil, nil)
	pe, ok = AsProviderError(err)
	if !ok || pe.Code != "1002" || pe.Desc != "invalid openid" {
		t.Fatalf("err = %v", err)
	}

	// 端点缺失哨兵。
	if _, err := GetUserInfo(context.Background(), nil, "", "at", true, nil, nil); !errors.Is(err, ErrMissingEndpoint) {
		t.Fatalf("err = %v, want ErrMissingEndpoint", err)
	}
}

// TestExtractIdentity 声明式抽取 + user_mapping 覆盖 + Raw 不含令牌响应。
func TestExtractIdentity(t *testing.T) {
	tok := &provider.Token{AccessToken: "secret-at", Raw: map[string]any{
		"access_token": "secret-at",
		"uid":          "u-100",
		"openid":       "tok-openid",
	}}
	user := map[string]any{
		"idstr":  "from-user",
		"name":   "alice",
		"nested": map[string]any{"k": "v"},
	}
	spec := IdentitySpec{
		OpenID:   []string{"idstr", "uid"}, // 用户信息优先，令牌兜底
		UnionID:  []string{"unionid"},
		Nickname: []string{"name"},
	}
	id, err := ExtractIdentity("pk", "test", spec, tok, user, nil)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if id.ProviderKey != "pk" || id.ProviderType != "test" || id.OpenID != "from-user" {
		t.Fatalf("id = %+v", id)
	}
	if id.Nickname != "alice" {
		t.Fatalf("nickname = %q", id.Nickname)
	}
	// Raw 只含用户信息响应，绝不含令牌响应（凭证禁入 extra）。
	if _, ok := id.Raw["access_token"]; ok {
		t.Fatalf("Raw 不应含 access_token: %v", id.Raw)
	}
	if _, ok := id.Raw["uid"]; ok {
		t.Fatalf("Raw 不应含令牌响应键 uid: %v", id.Raw)
	}

	// 令牌兜底路径（用户信息无 idstr）。
	id, err = ExtractIdentity("pk", "test", IdentitySpec{OpenID: []string{"idstr", "uid"}}, tok,
		map[string]any{"name": "bob"}, nil)
	if err != nil || id.OpenID != "u-100" {
		t.Fatalf("fallback: id=%+v err=%v", id, err)
	}
}

// TestExtractIdentityMapping user_mapping 覆盖：正常表达式生效、空值跳过、
// 未知字段报错、openid 兜底哨兵。
func TestExtractIdentityMapping(t *testing.T) {
	tok := &provider.Token{Raw: map[string]any{}}
	user := map[string]any{"uid": "77", "nickname": "nick-raw", "email": "a@b.c"}

	// 正常覆盖 + 令牌/用户字段可引用。
	id, err := ExtractIdentity("pk", "test", IdentitySpec{OpenID: []string{"uid"}},
		tok, user, map[string]string{"open_id": "$.uid", "nickname": "$.email"})
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if id.OpenID != "77" || id.Nickname != "a@b.c" {
		t.Fatalf("id = %+v", id)
	}

	// 表达式空值（undefined）→ 跳过保留抽取值；非法表达式 → 报错。
	id, err = ExtractIdentity("pk", "test", IdentitySpec{OpenID: []string{"uid"}, Nickname: []string{"nickname"}},
		tok, user, map[string]string{"nickname": "$.missing"})
	if err != nil {
		t.Fatalf("empty expr: %v", err)
	}
	if id.Nickname != "nick-raw" {
		t.Fatalf("nickname = %q, want 保留 nick-raw", id.Nickname)
	}
	_, err = ExtractIdentity("pk", "test", IdentitySpec{OpenID: []string{"uid"}},
		tok, user, map[string]string{"nickname": "$$.bad[["})
	if err == nil {
		t.Fatalf("illegal expr want error")
	}
	// 未知 Authloft 字段 → 配置错误。
	_, err = ExtractIdentity("pk", "test", IdentitySpec{OpenID: []string{"uid"}},
		tok, user, map[string]string{"hacker": "$.uid"})
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field err = %v", err)
	}
	// openid 为空 → 哨兵。
	_, err = ExtractIdentity("pk", "test", IdentitySpec{}, tok, user, nil)
	if !errors.Is(err, ErrEmptyOpenID) {
		t.Fatalf("err = %v, want ErrEmptyOpenID", err)
	}
	// nil token → 哨兵。
	if _, err := ExtractIdentity("pk", "test", IdentitySpec{}, nil, user, nil); !errors.Is(err, ErrNilToken) {
		t.Fatalf("err = %v, want ErrNilToken", err)
	}
}

// TestFlatten 顶层标量拍平：数字整数化、布尔、对象 JSON 串、nil 跳过。
func TestFlatten(t *testing.T) {
	out := Flatten(map[string]any{
		"id":      float64(123456789),
		"big":     float64(1.5),
		"flag":    true,
		"obj":     map[string]any{"a": "b"},
		"nothing": nil,
		"s":       "str",
	})
	if out["id"] != "123456789" {
		t.Fatalf("id = %q, want 123456789（整数化无科学计数）", out["id"])
	}
	if out["big"] != "1.5" || out["flag"] != "true" || out["s"] != "str" {
		t.Fatalf("out = %v", out)
	}
	if _, ok := out["nothing"]; ok {
		t.Fatalf("nil 应跳过: %v", out)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(out["obj"]), &obj); err != nil || obj["a"] != "b" {
		t.Fatalf("obj = %q err = %v", out["obj"], err)
	}
}

// TestDiscoverOIDC discovery 文档解析与缺端点报错。
func TestDiscoverOIDC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"authorization_endpoint":"https://idp/a","token_endpoint":"https://idp/t","userinfo_endpoint":"https://idp/u"}`)
	}))
	defer srv.Close()

	auth, tok, ui, err := DiscoverOIDC(context.Background(), nil, srv.URL+"/")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if auth != "https://idp/a" || tok != "https://idp/t" || ui != "https://idp/u" {
		t.Fatalf("endpoints = %q %q %q", auth, tok, ui)
	}
	// 缺 userinfo_endpoint → 不支持。
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"authorization_endpoint":"https://idp/a","token_endpoint":"https://idp/t"}`)
	}))
	defer srv2.Close()
	if _, _, _, err := DiscoverOIDC(context.Background(), nil, srv2.URL); err == nil {
		t.Fatalf("missing userinfo_endpoint want error")
	}
	// 空 provider_url → 哨兵。
	if _, _, _, err := DiscoverOIDC(context.Background(), nil, " "); !errors.Is(err, ErrMissingEndpoint) {
		t.Fatalf("err = %v, want ErrMissingEndpoint", err)
	}
}

// TestNewMetaBaseline oauth 基线 11 字段（§5.3 行 1257 oauth 追加 + 行
// 1261 metadata），section 归属与 wechat_mp 同款。
func TestNewMetaBaseline(t *testing.T) {
	m := NewMeta("test_oauth", "测试", provider.ChannelRedirect)
	if m.Type != "test_oauth" || m.DisplayName != "测试" || m.Category != "oauth" || m.Channel != provider.ChannelRedirect {
		t.Fatalf("meta = %+v", m)
	}
	wantKeys := []string{
		"client_id", "client_secret", "app_id", "cert", "scopes", "provider_url",
		"custom_auth_url", "custom_token_url", "custom_user_info_url", "user_mapping", "metadata",
	}
	if len(m.Fields) != len(wantKeys) {
		t.Fatalf("fields = %d, want %d", len(m.Fields), len(wantKeys))
	}
	for i, k := range wantKeys {
		if m.Fields[i].Key != k {
			t.Fatalf("fields[%d].Key = %q, want %q", i, m.Fields[i].Key, k)
		}
		if m.Fields[i].Section == "" {
			t.Fatalf("fields[%d].Section 为空（每个字段都必须带 section）", i)
		}
	}
}

// TestProviderErrorNoCredential 错误串不含本地凭证（安全口径）：请求携带
// 的 client_secret 只进 form，绝不进错误串。
func TestProviderErrorNoCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"client authentication failed"}`)
	}))
	defer srv.Close()

	_, err := ExchangePostForm(context.Background(), nil, srv.URL, "cid", "super-secret",
		provider.ExchangeInput{Code: "c-1"}, nil, nil)
	if err == nil {
		t.Fatalf("want error")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("错误串泄漏本地凭证: %v", err)
	}
	pe, ok := AsProviderError(err)
	if !ok || pe.Status != 400 || pe.Code != "invalid_client" {
		t.Fatalf("err = %v", err)
	}
}
