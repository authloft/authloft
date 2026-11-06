// thirdparty_wiring_test.go 三方渠道装配接线断言：① 注册表覆盖
// §12.2 内置清单全量 14 type（渠道包 blank import 等价 bootstrap.go 装配，
// 触发 init() 自注册）；② Authorize 组装的跳转 URL 携带 redirect_uri
// （{root}/sso/oauth/callback/{key}，§2.7.3 行 614）与 scope（Ext.scopes，
// 空则适配器渠道默认）；③ 实例化覆盖标准渠道（gitee）与通用兜底（oauth2）
// 两形态（真实注册表链 provider.NewAdapter，不经 fake）。
package service

import (
	"context"
	"net/url"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/gen/go/token"
	"authloft/internal/provider"
	"authloft/internal/repo/model"
	"authloft/internal/security"

	_ "authloft/internal/provider/oauth/alipay"
	_ "authloft/internal/provider/oauth/baidu"
	_ "authloft/internal/provider/oauth/feishu"
	_ "authloft/internal/provider/oauth/gitee"
	_ "authloft/internal/provider/oauth/github"
	_ "authloft/internal/provider/oauth/google"
	_ "authloft/internal/provider/oauth/microsoft"
	_ "authloft/internal/provider/oauth/oauth2"
	_ "authloft/internal/provider/oauth/oidc"
	_ "authloft/internal/provider/oauth/qq"
	_ "authloft/internal/provider/oauth/wechat"
	_ "authloft/internal/provider/oauth/wechat_mp"
	_ "authloft/internal/provider/oauth/wechat_mp_scan"
	_ "authloft/internal/provider/oauth/weibo"
)

// TestThirdpartyAdapterRegistryComplete 注册表含 §12.2 内置清单全量
// 14 type（bootstrap.go blank import 的等价口径：任一 type 缺失即装配缺口，
// 此前仅 wechat_mp / wechat_mp_scan 两 type 在册）。
func TestThirdpartyAdapterRegistryComplete(t *testing.T) {
	want := []string{
		"alipay", "baidu", "feishu", "gitee", "github", "google",
		"microsoft", "oauth2", "oidc", "qq", "wechat", "wechat_mp",
		"wechat_mp_scan", "weibo",
	}
	got := provider.Types()
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("provider 注册表缺 type %q（在册 %v）", w, got)
		}
	}
}

// tpCaptureAdapter 捕获型 fake：在 tpAdapter 基础上记录 Exchange 入参，
// 用于断言 redirect_uri 透传到令牌交换（与授权时一致）。
type tpCaptureAdapter struct {
	tpAdapter
	lastExchange provider.ExchangeInput
}

func (a *tpCaptureAdapter) Exchange(ctx context.Context, in provider.ExchangeInput) (*provider.Token, error) {
	a.lastExchange = in
	return a.tpAdapter.Exchange(ctx, in)
}

// TestAuthorizeWiringRedirectURIScope 标准渠道（gitee，真实适配器）：
// Authorize URL 含 redirect_uri（root 尾斜杠归一）与 scope=Ext.scopes；
// Ext.scopes 未配置时回落渠道默认（gitee defaultScopes=user_info）；
// LoginOauth Exchange 入参携带同一 redirect_uri；RootOrigin 未注入时
// 不携带（旧装配兼容）。
func TestAuthorizeWiringRedirectURIScope(t *testing.T) {
	ctx := context.Background()

	t.Run("gitee 配置 scope + 尾斜杠归一", func(t *testing.T) {
		e := newTPEnv(t)
		e.svc.deps.NewAdapter = provider.NewAdapter
		e.svc.deps.RootOrigin = "https://uc.example.com/"
		p := e.addProvider("gee", func(row *model.Provider) { row.Type = "gitee" })
		p.Ext = &providerpb.Ext{ClientId: "gee-id", ClientSecret: "gee-secret", Scopes: "user_info emails"}

		out, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "gee"})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		q := parseQuery(t, out.AuthorizeURL)
		if got := q.Get("redirect_uri"); got != "https://uc.example.com/sso/oauth/callback/gee" {
			t.Errorf("redirect_uri = %q", got)
		}
		if got := q.Get("scope"); got != "user_info emails" {
			t.Errorf("scope = %q, want Ext.scopes", got)
		}
		if got := q.Get("state"); got == "" {
			t.Error("state 应非空")
		}
	})

	t.Run("gitee 未配置 scope → 渠道默认", func(t *testing.T) {
		e := newTPEnv(t)
		e.svc.deps.NewAdapter = provider.NewAdapter
		e.svc.deps.RootOrigin = "https://uc.example.com"
		p := e.addProvider("gee", func(row *model.Provider) { row.Type = "gitee" })
		p.Ext = &providerpb.Ext{ClientId: "gee-id", ClientSecret: "gee-secret"}

		out, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "gee"})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		q := parseQuery(t, out.AuthorizeURL)
		if got := q.Get("scope"); got != "user_info" {
			t.Errorf("scope = %q, want gitee 渠道默认 user_info", got)
		}
	})

	t.Run("oauth2 通用兜底", func(t *testing.T) {
		e := newTPEnv(t)
		e.svc.deps.NewAdapter = provider.NewAdapter
		e.svc.deps.RootOrigin = "https://uc.example.com"
		p := e.addProvider("generic", func(row *model.Provider) {
			row.Type = "oauth2"
			row.DisplayName = "自建 IdP"
		})
		p.Ext = &providerpb.Ext{
			ClientId:          "g-id",
			ClientSecret:      "g-secret",
			CustomAuthUrl:     "https://idp.example.com/authorize",
			CustomTokenUrl:    "https://idp.example.com/token",
			CustomUserInfoUrl: "https://idp.example.com/userinfo",
			UserMapping:       map[string]string{"open_id": "$.id"},
			Scopes:            "openid profile",
		}

		out, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "generic"})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		u, err := url.Parse(out.AuthorizeURL)
		if err != nil {
			t.Fatalf("parse %q: %v", out.AuthorizeURL, err)
		}
		if u.Host != "idp.example.com" || u.Path != "/authorize" {
			t.Errorf("授权端点 = %s%s, want idp.example.com/authorize", u.Host, u.Path)
		}
		q := u.Query()
		if got := q.Get("redirect_uri"); got != "https://uc.example.com/sso/oauth/callback/generic" {
			t.Errorf("redirect_uri = %q", got)
		}
		if got := q.Get("scope"); got != "openid profile" {
			t.Errorf("scope = %q, want Ext.scopes", got)
		}
	})

	t.Run("Exchange 携带同一 redirect_uri（端到端）", func(t *testing.T) {
		e := newTPEnv(t)
		cap := &tpCaptureAdapter{tpAdapter: *e.adapter}
		e.svc.deps.NewAdapter = func(*provider.Provider) (provider.AuthAdapter, error) { return cap, nil }
		e.svc.deps.RootOrigin = "https://uc.example.com"
		e.addProvider("qq", nil)
		e.binds.rows[key("qq", "openid_1")] = model.UserThirdpartyBind{UserID: 7, ProviderKey: "qq", OpenID: "openid_1"}
		e.users.byID[7] = &model.User{ID: 7, UserStatus: 1, MfaRequired: 0}

		auth, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "qq"})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if got := cap.lastCtx.RedirectURI; got != "https://uc.example.com/sso/oauth/callback/qq" {
			t.Fatalf("Authorize redirect_uri = %q", got)
		}
		payload, err := security.Open[token.LoginStatePayload](e.svc.deps.CookieCodec, security.PurposeCookie, auth.Cookie.Value)
		if err != nil {
			t.Fatalf("Open state cookie: %v", err)
		}
		out := e.svc.LoginOauth(ctx, OauthInput{
			ProviderKey: "qq", Code: "authcode",
			State: payload.GetState(), StateCookie: auth.Cookie.Value,
		})
		if out.Envelope.GetStatus() != "success" {
			t.Fatalf("status = %q (resp %+v)", out.Envelope.GetStatus(), out.Envelope)
		}
		if got := cap.lastExchange.RedirectURI; got != "https://uc.example.com/sso/oauth/callback/qq" {
			t.Errorf("Exchange redirect_uri = %q, want 与授权一致", got)
		}
	})

	t.Run("RootOrigin 未注入 → 不携带", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		p := e.loader.byKey["qq"]
		p.Ext = &providerpb.Ext{Scopes: "user_info"}

		out, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "qq"})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if got := e.adapter.lastCtx.RedirectURI; got != "" {
			t.Errorf("redirect_uri = %q, want 空（未注入 RootOrigin）", got)
		}
		if got := e.adapter.lastCtx.Scope; got != "user_info" {
			t.Errorf("scope = %q, want Ext.scopes 仍透传", got)
		}
		if out.AuthorizeURL == "" {
			t.Error("authorize_url 应非空")
		}
	})
}

// parseQuery 解析 URL 查询串（失败即 Fatal）。
func parseQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Query()
}
