// thirdparty_sso_test.go 三方链路应用上下文（接口文档 §2.7.2 / §2.7.4、
// 后端架构 §12.4 / §11.6.2）：al_login_state 携带 sso_client_id、LoginOauth
// 从 Cookie 解出按首签口径解析快照并按 §2.1 应用级过滤表校验 Provider 放行、
// login_token.sso 首签携带；Cookie 无值（直登 / 既有客户端链路）行为回归。
package thirdparty

import (
	"context"
	"testing"

	"authloft/gen/go/token"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
	"authloft/internal/service/ssoapp"
	ticketsvc "authloft/internal/service/ticket"
)

// tpSsoResolver ThirdpartySsoResolver 的 fake：固定快照 / 错误，记录调用
// 入参（无 sso_client_id 请求不应触达解析器）。
type tpSsoResolver struct {
	snap  *token.Sso
	err   error
	calls []string
}

func (f *tpSsoResolver) Snapshot(_ context.Context, id string) (*token.Sso, error) {
	f.calls = append(f.calls, id)
	if f.err != nil {
		return nil, f.err
	}
	return f.snap, nil
}

// withSsoResolver 给 env 注入快照解析器 fake。
func (e *tpEnv) withSsoResolver(r *tpSsoResolver) {
	e.svc.deps.SsoApps = r
}

// stateCookieSso 签一枚携带 sso_client_id 的 al_login_state 值（其余形态与
// stateCookie 一致：l 前缀 state、uid=0、未过期）。
func (e *tpEnv) stateCookieSso(t *testing.T, state, ssoClientID string) string {
	t.Helper()
	codec := e.svc.deps.CookieCodec
	payload := &token.LoginStatePayload{
		State:       state,
		Iat:         e.now.Unix(),
		Exp:         e.now.Add(loginStateTTL).Unix(),
		SsoClientId: ssoClientID,
	}
	v, err := codec.Seal(security.PurposeCookie, payload)
	if err != nil {
		t.Fatalf("Seal cookie: %v", err)
	}
	return v
}

// ssoApp 组装一份放行 qq 的应用快照（methods 冻结集含 thirdparty）。
func ssoApp() *token.Sso {
	return &token.Sso{ClientId: "app-1", Methods: []string{"password", "thirdparty"}, Providers: []string{"qq"}}
}

// TestAuthorizeLoginStateSsoClientID al_login_state 携带口径（§2.7.2）：
// 登录场景请求携带的 sso_client_id 装入 Cookie 载荷；scene=bind 不携带
// （绑定流程不读应用配置）。
func TestAuthorizeLoginStateSsoClientID(t *testing.T) {
	ctx := context.Background()

	t.Run("login 场景装入 Cookie", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		out, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "qq", SsoClientID: "app-1"})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		payload, err := security.Open[token.LoginStatePayload](e.svc.deps.CookieCodec, security.PurposeCookie, out.Cookie.Value)
		if err != nil {
			t.Fatalf("Open cookie: %v", err)
		}
		if payload.GetSsoClientId() != "app-1" {
			t.Errorf("Cookie 载荷 sso_client_id = %q, want app-1", payload.GetSsoClientId())
		}
	})

	t.Run("bind 场景不携带", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		out, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "qq", Scene: "bind", UID: 9, SsoClientID: "app-1"})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		payload, err := security.Open[token.LoginStatePayload](e.svc.deps.CookieCodec, security.PurposeCookie, out.Cookie.Value)
		if err != nil {
			t.Fatalf("Open cookie: %v", err)
		}
		if payload.GetSsoClientId() != "" {
			t.Errorf("bind 场景 sso_client_id = %q, want 空（§2.7.2 bind 不携带）", payload.GetSsoClientId())
		}
		if payload.GetUid() != 9 {
			t.Errorf("bind 场景 uid = %d, want 9", payload.GetUid())
		}
	})
}

// TestLoginOauthSsoFirstSign 首签快照写入 login_token（§2.7.4：通过则
// login_token 首签携带快照）：未绑定 → binding_required 信封 token 带
// Sso；已绑定启用 MFA → mfa_required 信封 token 带 Sso；解析器只被
// 首签触达一次。
func TestLoginOauthSsoFirstSign(t *testing.T) {
	ctx := context.Background()

	t.Run("binding_required 中间态 token 带快照", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		resolver := &tpSsoResolver{snap: ssoApp()}
		e.withSsoResolver(resolver)
		state := StatePrefixLogin + "abc"
		in := OauthInput{ProviderKey: "qq", Code: "authcode", State: state,
			StateCookie: e.stateCookieSso(t, state, "app-1")}

		out := e.svc.LoginOauth(ctx, in)
		if out.Envelope.GetStatus() != orchestrator.StatusBindingRequired {
			t.Fatalf("status = %q, want binding_required", out.Envelope.GetStatus())
		}
		lt, err := security.Open[token.LoginTokenPayload](e.loginC, security.PurposeLogin, out.Envelope.GetLoginToken())
		if err != nil {
			t.Fatalf("Open login_token: %v", err)
		}
		if lt.GetSso() == nil || lt.GetSso().GetClientId() != "app-1" {
			t.Fatalf("login_token.sso = %+v, want clientId app-1", lt.GetSso())
		}
		if got := lt.GetSso().GetProviders(); len(got) != 1 || got[0] != "qq" {
			t.Errorf("快照 providers = %v, want [qq]", got)
		}
		if len(resolver.calls) != 1 || resolver.calls[0] != "app-1" {
			t.Errorf("解析器调用 = %v, want [app-1]（首签一次）", resolver.calls)
		}
	})

	t.Run("mfa_required 中间态 token 带快照", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		e.binds.rows[key("qq", "openid_1")] = model.UserThirdpartyBind{UserID: 3, ProviderKey: "qq", OpenID: "openid_1"}
		e.users.byID[3] = &model.User{ID: 3, UserStatus: 1, MfaRequired: 1}
		e.creds.byKind["totp"] = &model.UserCredential{UserID: 3, Kind: "totp", IsEnabled: 1}
		resolver := &tpSsoResolver{snap: ssoApp()}
		e.withSsoResolver(resolver)
		state := StatePrefixLogin + "abc"
		in := OauthInput{ProviderKey: "qq", Code: "authcode", State: state,
			StateCookie: e.stateCookieSso(t, state, "app-1")}

		out := e.svc.LoginOauth(ctx, in)
		if out.Envelope.GetStatus() != orchestrator.StatusMFARequired {
			t.Fatalf("status = %q, want mfa_required", out.Envelope.GetStatus())
		}
		lt, err := security.Open[token.LoginTokenPayload](e.loginC, security.PurposeLogin, out.Envelope.GetLoginToken())
		if err != nil {
			t.Fatalf("Open login_token: %v", err)
		}
		if lt.GetSso() == nil || lt.GetSso().GetClientId() != "app-1" {
			t.Fatalf("login_token.sso = %+v, want clientId app-1", lt.GetSso())
		}
	})
}

// TestLoginOauthSsoProviderGate Provider ∈ 快照校验（§2.1 应用级过滤表，
// 不在 → 既有 provider_disabled，不新增取值）：白名单不含该 provider、
// 应用 login_methods 关闭 thirdparty 整体、快照 providers 空集（全局关）
// 三形态均拒绝且删 Cookie；行级可用性（is_enabled / enable_signin）不受
// 快照放行豁免，仍现查现判。
func TestLoginOauthSsoProviderGate(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		snap *token.Sso
	}{
		{"provider 不在白名单", &token.Sso{ClientId: "app-1", Methods: []string{"thirdparty"}, Providers: []string{"other"}}},
		{"应用 login_methods 关闭 thirdparty", &token.Sso{ClientId: "app-1", Methods: []string{"password"}, Providers: []string{"qq"}}},
		{"快照 providers 空集（全局 thirdparty 关）", &token.Sso{ClientId: "app-1", Methods: []string{"password"}, Providers: []string{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTPEnv(t)
			e.addProvider("qq", nil)
			e.withSsoResolver(&tpSsoResolver{snap: tc.snap})
			state := StatePrefixLogin + "abc"
			in := OauthInput{ProviderKey: "qq", Code: "authcode", State: state,
				StateCookie: e.stateCookieSso(t, state, "app-1")}

			out := e.svc.LoginOauth(ctx, in)
			if out.Envelope.GetStatus() != StatusProviderDisabled {
				t.Fatalf("status = %q, want provider_disabled", out.Envelope.GetStatus())
			}
			if out.Cookie == nil || out.Cookie.MaxAge != -1 {
				t.Errorf("Cookie = %+v, want 删除（回调终态即删）", out.Cookie)
			}
		})
	}

	t.Run("快照放行不豁免行级可用性（enable_signin=0 现查现判）", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", func(row *model.Provider) { row.EnableSignin = 0 })
		e.withSsoResolver(&tpSsoResolver{snap: ssoApp()})
		state := StatePrefixLogin + "abc"
		in := OauthInput{ProviderKey: "qq", Code: "authcode", State: state,
			StateCookie: e.stateCookieSso(t, state, "app-1")}

		out := e.svc.LoginOauth(ctx, in)
		if out.Envelope.GetStatus() != StatusProviderDisabled {
			t.Fatalf("status = %q, want provider_disabled", out.Envelope.GetStatus())
		}
	})
}

// TestLoginOauthSsoClientInvalid 快照解析业务拒绝（§2.2 首签口径）：
// 查无行 / 行不可用 → invalid_request，不降级直登；解析器缺位（装配缺陷）
// 同样 fail-closed。
func TestLoginOauthSsoClientInvalid(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name       string
		resolver   *tpSsoResolver
		wantStatus string
	}{
		{"查无行", &tpSsoResolver{err: ssoapp.ErrClientNotFound}, orchestrator.StatusInvalidRequest},
		{"行不可用", &tpSsoResolver{err: ssoapp.ErrClientDisabled}, orchestrator.StatusInvalidRequest},
		{"解析器缺位", nil, orchestrator.StatusInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTPEnv(t)
			e.addProvider("qq", nil)
			if tc.resolver != nil {
				e.withSsoResolver(tc.resolver)
			}
			state := StatePrefixLogin + "abc"
			in := OauthInput{ProviderKey: "qq", Code: "authcode", State: state,
				StateCookie: e.stateCookieSso(t, state, "app-1")}

			out := e.svc.LoginOauth(ctx, in)
			if out.Envelope.GetStatus() != tc.wantStatus {
				t.Fatalf("status = %q, want %s", out.Envelope.GetStatus(), tc.wantStatus)
			}
			if out.Cookie == nil || out.Cookie.MaxAge != -1 {
				t.Errorf("Cookie = %+v, want 删除", out.Cookie)
			}
		})
	}
}

// TestLoginOauthSsoCookieAbsentRegression Cookie 无 sso_client_id（直登 /
// 既有客户端链路）行为与现状一致：解析器不被触达、全链路照旧（已绑定
// 无 MFA → success 建会话）。
func TestLoginOauthSsoCookieAbsentRegression(t *testing.T) {
	ctx := context.Background()
	e := newTPEnv(t)
	e.addProvider("qq", nil)
	e.binds.rows[key("qq", "openid_1")] = model.UserThirdpartyBind{UserID: 7, ProviderKey: "qq", OpenID: "openid_1"}
	e.users.byID[7] = &model.User{ID: 7, UserStatus: 1, MfaRequired: 0}
	resolver := &tpSsoResolver{snap: ssoApp()}
	e.withSsoResolver(resolver)

	// Cookie 载荷不带 sso_client_id（stateCookie 既有形态）。
	in := e.oauthRequest(t, StatePrefixLogin+"abc", 0)
	out := e.svc.LoginOauth(ctx, in)
	if out.Envelope.GetStatus() != orchestrator.StatusSuccess {
		t.Fatalf("status = %q, want success（回归）", out.Envelope.GetStatus())
	}
	if len(resolver.calls) != 0 {
		t.Errorf("解析器不应被触达, calls = %v", resolver.calls)
	}
	if e.sessions.gotUID != 7 {
		t.Errorf("会话 uid = %d, want 7", e.sessions.gotUID)
	}
}

// TestLoginOauthTicketSsoFromPayload 扫码提交（带 ticketId）的应用上下文
// 取票据载荷（§2.7.4：CreateQrcode 已校验并装载，本侧不读 Cookie）：MFA
// 用户 → mfa_required 信封 token 首签带票据载荷内的快照；解析器不被触达。
func TestLoginOauthTicketSsoFromPayload(t *testing.T) {
	ctx := context.Background()
	e := newScanEnv(t, ticketsvc.SceneLogin)
	e.binds.rows[key("wxscan", "openid_1")] = model.UserThirdpartyBind{UserID: 3, ProviderKey: "wxscan", OpenID: "openid_1"}
	e.users.byID[3] = &model.User{ID: 3, UserStatus: 1, MfaRequired: 1}
	e.creds.byKind["totp"] = &model.UserCredential{UserID: 3, Kind: "totp", IsEnabled: 1}
	e.payloads.snapshots["tid-1"].Sso = &token.Sso{ClientId: "app-1", Methods: []string{"thirdparty"}, Providers: []string{"wxscan"}}
	resolver := &tpSsoResolver{snap: ssoApp()}
	e.withSsoResolver(resolver)

	out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Code: "c", TicketID: "tid-1"})
	if out.Envelope.GetStatus() != orchestrator.StatusMFARequired {
		t.Fatalf("status = %q, want mfa_required", out.Envelope.GetStatus())
	}
	lt, err := security.Open[token.LoginTokenPayload](e.loginC, security.PurposeLogin, out.Envelope.GetLoginToken())
	if err != nil {
		t.Fatalf("Open login_token: %v", err)
	}
	if lt.GetSso() == nil || lt.GetSso().GetClientId() != "app-1" {
		t.Fatalf("login_token.sso = %+v, want 票据载荷快照 app-1", lt.GetSso())
	}
	if len(resolver.calls) != 0 {
		t.Errorf("扫码提交不应读 Cookie 快照, calls = %v", resolver.calls)
	}
}
