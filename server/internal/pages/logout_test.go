// logout_test.go GET /sso/logout 测试（§2.9 行 753-765、§11.2）：
// 清 Cookie Set-Cookie 断言、单域 / 多域跳转链（真实 builder + 接收端逐跳）、
// post_logout 白名单两分支、id_token_hint 非法拒绝。
package pages

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	clientpb "authloft/gen/go/client"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

// setCookieHeader 取第一个 Set-Cookie 头。
func setCookieHeader(rec *httptest.ResponseRecorder) string {
	return rec.Header().Get("Set-Cookie")
}

// TestLogoutClearsCookieAndDefault 单域（sso_domains 空）：Set-Cookie 清
// al_session（同名 Max-Age=0）+ 302 落 al_root（§2.9）。
func TestLogoutClearsCookieAndDefault(t *testing.T) {
	f := newFixture(t)
	rec := doGet(t, f.engine(t), "/sso/logout")

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://auth.example.com" {
		t.Errorf("Location = %q, want al_root 默认页", loc)
	}
	ck := setCookieHeader(rec)
	if !strings.HasPrefix(ck, "al_session=;") {
		t.Errorf("Set-Cookie = %q, want al_session=; 开头（清值）", ck)
	}
	if !strings.Contains(ck, "Max-Age=0") {
		t.Errorf("Set-Cookie = %q, want Max-Age=0（立即删除）", ck)
	}
	if !strings.Contains(ck, "Path=/") || !strings.Contains(ck, "HttpOnly") || !strings.Contains(ck, "Secure") {
		t.Errorf("Set-Cookie = %q, want Path=/ + HttpOnly + Secure（session.Cookie 属性）", ck)
	}
	if !strings.Contains(ck, "Domain=auth.example.com") {
		t.Errorf("Set-Cookie = %q, want Domain=根域（同名同域覆盖到要删的那枚）", ck)
	}
}

// TestLogoutPostLogoutSameOrigin 无 hint：仅允许 al_root 同源路径
// （相对路径按 al_root 解析同源；跨源 / 协议相对拒绝）。
func TestLogoutPostLogoutSameOrigin(t *testing.T) {
	f := newFixture(t)
	r := f.engine(t)

	cases := []struct {
		target string
		want   string
	}{
		{"/sso/logout?post_logout_redirect_uri=/logged-out", "https://auth.example.com/logged-out"},
		{"/sso/logout?post_logout_redirect_uri=https%3A%2F%2Fauth.example.com%2Fgoodbye", "https://auth.example.com/goodbye"},
		{"/sso/logout?post_logout_redirect_uri=https%3A%2F%2Fevil.example%2Fx", "https://auth.example.com"},
		{"/sso/logout?post_logout_redirect_uri=%2F%2Fevil.example%2Fx", "https://auth.example.com"},
	}
	for _, tc := range cases {
		rec := doGet(t, r, tc.target)
		if rec.Code != http.StatusFound {
			t.Fatalf("%s: status = %d, want 302", tc.target, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != tc.want {
			t.Errorf("%s: Location = %q, want %q", tc.target, loc, tc.want)
		}
	}
}

// TestLogoutIdTokenHintWhitelist 有 id_token_hint：验签解析 aud=client_id →
// 该 OIDC 客户端 redirect_uris 白名单整段匹配（含 * 通配，§12.3）。
func TestLogoutIdTokenHintWhitelist(t *testing.T) {
	f := newFixture(t)
	uris, err := repo.MarshalClientRedirectUris(&clientpb.ClientRedirectUris{
		Uris: []string{"https://app.example/cb", "https://*.trusted.example/cb"},
	})
	if err != nil {
		t.Fatalf("marshal redirect uris: %v", err)
	}
	f.clients = fakeClients{c: &model.OidcClient{
		ClientID:     "oidc_app",
		RedirectURIs: uris,
		IsEnabled:    1,
	}}
	f.deps.Clients = f.clients
	f.jwt.claims = jwt.MapClaims{"aud": "oidc_app"}
	r := f.engine(t)

	cases := []struct {
		target string
		want   string
	}{
		{"https://app.example/cb", "https://app.example/cb"},             // 整段字面
		{"https://x.trusted.example/cb", "https://x.trusted.example/cb"}, // * 通配
		{"https://app.example/cb/extra", "https://auth.example.com"},     // 子串 ≠ 整段
		{"https://evil.example/cb", "https://auth.example.com"},          // 白名单外
	}
	for _, tc := range cases {
		rec := doGet(t, r, "/sso/logout?id_token_hint=valid.hint&post_logout_redirect_uri="+tc.target)
		if rec.Code != http.StatusFound {
			t.Fatalf("%s: status = %d, want 302", tc.target, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != tc.want {
			t.Errorf("target %s: Location = %q, want %q", tc.target, loc, tc.want)
		}
	}
}

// TestLogoutHintAudArray aud 为数组形态（多 audience id_token）。
func TestLogoutHintAudArray(t *testing.T) {
	f := newFixture(t)
	uris, _ := repo.MarshalClientRedirectUris(&clientpb.ClientRedirectUris{Uris: []string{"https://app.example/cb"}})
	f.clients = fakeClients{c: &model.OidcClient{ClientID: "oidc_app", RedirectURIs: uris, IsEnabled: 1}}
	f.deps.Clients = f.clients
	f.jwt.claims = jwt.MapClaims{"aud": []any{"other", "oidc_app"}}

	rec := doGet(t, f.engine(t), "/sso/logout?id_token_hint=h&post_logout_redirect_uri=https://app.example/cb")
	if loc := rec.Header().Get("Location"); loc != "https://app.example/cb" {
		t.Errorf("Location = %q, want 白名单命中（aud 数组含 oidc_app）", loc)
	}
}

// TestLogoutHintInvalid id_token_hint 非法（验签失败 / 客户端不存在）：
// 拒绝 post_logout_redirect_uri 回落默认页；登出本身照常（Set-Cookie 仍在）。
func TestLogoutHintInvalid(t *testing.T) {
	f := newFixture(t)
	f.jwt.err = errors.New("jwt: signature is invalid")
	r := f.engine(t)

	rec := doGet(t, r, "/sso/logout?id_token_hint=bad.hint&post_logout_redirect_uri=https://app.example/cb")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302（hint 非法不阻断登出）", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://auth.example.com" {
		t.Errorf("Location = %q, want 默认页（hint 非法拒绝）", loc)
	}
	if ck := setCookieHeader(rec); !strings.HasPrefix(ck, "al_session=;") {
		t.Errorf("Set-Cookie = %q, want 清 Cookie 照常", ck)
	}

	// hint 有效但客户端查无此行 → 同样拒绝。
	f.jwt.err = nil
	f.jwt.claims = jwt.MapClaims{"aud": "ghost"}
	rec = doGet(t, r, "/sso/logout?id_token_hint=h&post_logout_redirect_uri=https://app.example/cb")
	if loc := rec.Header().Get("Location"); loc != "https://auth.example.com" {
		t.Errorf("客户端不存在: Location = %q, want 默认页", loc)
	}
}

// TestLogoutMultiDomainChain 多域跳转链（§11.2）：logout 302 首跳 →
// 接收端逐跳（写 Cookie + 重封 302）→ 末跳 302 final；登出载荷值空 TTL "0"，
// 每跳 Set-Cookie 均为清除形态。
func TestLogoutMultiDomainChain(t *testing.T) {
	f := newFixture(t)
	f.settings.m[settings.KeySsoDomains] = []string{"https://a.example", "https://b.example"}
	r := f.engine(t)

	// 发起端：清本域 Cookie + 302 首跳（带载荷）。
	rec := doGet(t, r, "/sso/logout?post_logout_redirect_uri=/done")
	if rec.Code != http.StatusFound {
		t.Fatalf("logout status = %d, want 302", rec.Code)
	}
	if ck := setCookieHeader(rec); !strings.Contains(ck, "Max-Age=0") {
		t.Errorf("发起端 Set-Cookie = %q, want Max-Age=0", ck)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://a.example/sso/sync_cookie?") {
		t.Fatalf("首跳 Location = %q, want a.example/sso/sync_cookie?{payload}", loc)
	}

	// 逐跳：a → b（重封载荷）→ final。
	hops := []string{loc}
	for i := 0; i < 2; i++ {
		rec = doGet(t, r, hops[i])
		if rec.Code != http.StatusFound {
			t.Fatalf("hop %d: status = %d, want 302", i, rec.Code)
		}
		if ck := setCookieHeader(rec); !strings.HasPrefix(ck, "al_session=;") || !strings.Contains(ck, "Max-Age=0") {
			t.Errorf("hop %d Set-Cookie = %q, want 登出清除形态", i, ck)
		}
		hops = append(hops, rec.Header().Get("Location"))
	}
	if !strings.HasPrefix(hops[1], "https://b.example/sso/sync_cookie?") {
		t.Errorf("第二跳 = %q, want b.example（顺序推进）", hops[1])
	}
	// 末跳 302 final：不带载荷、不回本端点。
	if hops[2] != "https://auth.example.com/done" {
		t.Errorf("末跳 = %q, want final /done（post_logout 同源相对地址）", hops[2])
	}
}

// TestLogoutSingleDomainSkip sso_domains 未配置 → 直接 302 final（无同步链）。
func TestLogoutSingleDomainSkip(t *testing.T) {
	f := newFixture(t)
	rec := doGet(t, f.engine(t), "/sso/logout?post_logout_redirect_uri=/x")
	if loc := rec.Header().Get("Location"); loc != "https://auth.example.com/x" {
		t.Errorf("Location = %q, want 直接回跳（同源解析为绝对地址）", loc)
	}
}
