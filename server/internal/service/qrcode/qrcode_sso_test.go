// qrcode_sso_test.go 扫码链路应用上下文（接口文档 §2.8、后端架构 §11.6.4）：
// CreateQrcode 携带 sso_client_id 时按首签口径解析快照并按 §2.1 应用级过滤
// 表校验 Provider 放行，快照装 TicketPayload.sso；GetLoginTicket 完成登录
// 把票据载荷内的快照写入 login_token.sso（needs_step_up / binding_required /
// 建会话三出口）；缺省行为回归。
package qrcode

import (
	"context"
	"errors"
	"testing"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
	"authloft/internal/service/ssoapp"
	ticketsvc "authloft/internal/service/ticket"
)

// qrSsoApps QRCodeSsoResolver 的 fake：固定快照 / 错误，记录调用入参
// （无 sso_client_id 请求不应触达解析器）。
type qrSsoApps struct {
	snap  *token.Sso
	err   error
	calls []string
}

func (f *qrSsoApps) Snapshot(_ context.Context, id string) (*token.Sso, error) {
	f.calls = append(f.calls, id)
	if f.err != nil {
		return nil, f.err
	}
	return f.snap, nil
}

// ssoApp 组装一份放行 scan 的应用快照（methods 冻结集含 thirdparty）。
func ssoApp() *token.Sso {
	return &token.Sso{ClientId: "app-1", Methods: []string{"password", "thirdparty"}, Providers: []string{"scan"}}
}

// TestCreateQrcodeSsoSnapshotIntoPayload 携带 sso_client_id 的拉码：快照
// 装进 TicketPayload.sso 并随加密 ticket 与 al:ticket:payload 快照键落存
// （§2.8、§11.6.4）；解析器按首签触达一次。
func TestCreateQrcodeSsoSnapshotIntoPayload(t *testing.T) {
	ctx := context.Background()
	e := newQrEnv(t)
	e.addScanProvider("scan", nil)
	apps := &qrSsoApps{snap: ssoApp()}
	e.svc.deps.SsoApps = apps

	out, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{
		ProviderKey: "scan", Captcha: validCaptcha(), SsoClientID: "app-1",
	})
	if err != nil {
		t.Fatalf("CreateQrcode: %v", err)
	}
	stored := e.payloads.snapshots[out.TicketID]
	if stored == nil || stored.GetSso() == nil || stored.GetSso().GetClientId() != "app-1" {
		t.Fatalf("快照键载荷 sso = %+v, want clientId app-1", stored.GetSso())
	}
	// 加密 ticket 内载荷同样携带（轮询侧凭 ticket 解出，§11.6.4）。
	sealed, err := security.Open[token.TicketPayload](e.ticketC, security.PurposeTicket, out.Ticket)
	if err != nil {
		t.Fatalf("Open ticket: %v", err)
	}
	if sealed.GetSso() == nil || sealed.GetSso().GetClientId() != "app-1" {
		t.Fatalf("ticket 载荷 sso = %+v, want clientId app-1", sealed.GetSso())
	}
	if len(apps.calls) != 1 || apps.calls[0] != "app-1" {
		t.Errorf("解析器调用 = %v, want [app-1]（首签一次）", apps.calls)
	}
}

// TestCreateQrcodeSsoProviderGate Provider ∈ 快照校验（§2.1 应用级过滤表，
// 不在 → 既有 provider_disabled 哨兵，不新增取值）：白名单不含该 provider、
// 应用 login_methods 关闭 thirdparty 整体、快照 providers 空集三形态均拒绝。
func TestCreateQrcodeSsoProviderGate(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		snap *token.Sso
	}{
		{"provider 不在白名单", &token.Sso{ClientId: "app-1", Methods: []string{"thirdparty"}, Providers: []string{"other"}}},
		{"应用 login_methods 关闭 thirdparty", &token.Sso{ClientId: "app-1", Methods: []string{"password"}, Providers: []string{"scan"}}},
		{"快照 providers 空集（全局 thirdparty 关）", &token.Sso{ClientId: "app-1", Methods: []string{"password"}, Providers: []string{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newQrEnv(t)
			e.addScanProvider("scan", nil)
			e.svc.deps.SsoApps = &qrSsoApps{snap: tc.snap}

			_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{
				ProviderKey: "scan", Captcha: validCaptcha(), SsoClientID: "app-1",
			})
			if !errors.Is(err, ErrQrcodeProviderDisabled) {
				t.Fatalf("err = %v, want ErrQrcodeProviderDisabled", err)
			}
		})
	}

	t.Run("快照放行不豁免行级可用性（enable_signin=0 现查现判）", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", func(r *model.Provider) { r.EnableSignin = 0 })
		e.svc.deps.SsoApps = &qrSsoApps{snap: ssoApp()}

		_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{
			ProviderKey: "scan", Captcha: validCaptcha(), SsoClientID: "app-1",
		})
		if !errors.Is(err, ErrQrcodeProviderDisabled) {
			t.Fatalf("err = %v, want ErrQrcodeProviderDisabled", err)
		}
	})
}

// TestCreateQrcodeSsoClientInvalid 快照解析业务拒绝（§2.2 首签口径）：
// 查无行 / 行不可用 → invalid_request 哨兵，不降级直登；解析器缺位（装配
// 缺陷）同样 fail-closed。
func TestCreateQrcodeSsoClientInvalid(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name     string
		wireApps bool
		apps     *qrSsoApps
	}{
		{"查无行", true, &qrSsoApps{err: ssoapp.ErrClientNotFound}},
		{"行不可用", true, &qrSsoApps{err: ssoapp.ErrClientDisabled}},
		{"解析器缺位", false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newQrEnv(t)
			e.addScanProvider("scan", nil)
			if tc.wireApps {
				e.svc.deps.SsoApps = tc.apps
			}
			_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{
				ProviderKey: "scan", Captcha: validCaptcha(), SsoClientID: "app-1",
			})
			if !errors.Is(err, ticketsvc.ErrQrcodeInvalidRequest) {
				t.Fatalf("err = %v, want invalid_request 哨兵", err)
			}
		})
	}
}

// TestCreateQrcodeSsoSceneScope scene 携带口径（§2.8：仅 scene=login 携带）：
// bind 场景请求携带也剥离——解析器不触达、载荷无快照；缺省（直登 /
// 应用未配置）行为与现状一致。
func TestCreateQrcodeSsoSceneScope(t *testing.T) {
	ctx := context.Background()

	t.Run("bind 场景不携带", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		apps := &qrSsoApps{snap: ssoApp()}
		e.svc.deps.SsoApps = apps

		out, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{
			ProviderKey: "scan", Scene: ticketsvc.SceneBind, UID: 9,
			Captcha: validCaptcha(), SsoClientID: "app-1",
		})
		if err != nil {
			t.Fatalf("CreateQrcode: %v", err)
		}
		if stored := e.payloads.snapshots[out.TicketID]; stored.GetSso() != nil {
			t.Errorf("bind 场景快照键载荷 sso = %+v, want nil", stored.GetSso())
		}
		if len(apps.calls) != 0 {
			t.Errorf("解析器不应被触达, calls = %v", apps.calls)
		}
	})

	t.Run("无 sso_client_id 回归", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		apps := &qrSsoApps{snap: ssoApp()}
		e.svc.deps.SsoApps = apps

		out, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
		if err != nil {
			t.Fatalf("CreateQrcode: %v", err)
		}
		if stored := e.payloads.snapshots[out.TicketID]; stored.GetSso() != nil {
			t.Errorf("无 sso_client_id 载荷 sso = %+v, want nil（现状回归）", stored.GetSso())
		}
		if len(apps.calls) != 0 {
			t.Errorf("解析器不应被触达, calls = %v", apps.calls)
		}
	})
}

// TestGetLoginTicketSsoIntoLoginToken 完成登录把票据载荷内的快照写入
// login_token.sso（§11.6.4：MFA 下发过滤与终点回跳随之生效）：
// needs_step_up 与 binding_required 两出口的签发 token 显式断言；建会话
// 出口载荷随 Terminal.Complete 消费（成功流回归）。
func TestGetLoginTicketSsoIntoLoginToken(t *testing.T) {
	ctx := context.Background()

	t.Run("needs_step_up 出口 token 带快照", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		e.tickets.res["tid123"] = &token.TicketResult{
			V: 1, Status: ticketsvc.TicketStatusMFAPending, Scene: "login", ProviderKey: "scan",
			LoginResult: &token.LoginResult{Uid: 9},
		}
		in := pollInputSso(t, e)
		in.OIDC = &token.Oidc{ClientId: "client-1", RedirectUri: "https://rp.example/cb", State: "st-1"}
		out := e.svc.GetLoginTicket(ctx, in)
		if out.Envelope.GetStatus() != statusNeedsStepUp {
			t.Fatalf("status = %q, want needs_step_up", out.Envelope.GetStatus())
		}
		p, err := e.state.Parse(out.Envelope.GetLoginToken())
		if err != nil {
			t.Fatalf("解析 loginToken: %v", err)
		}
		if p.GetSso() == nil || p.GetSso().GetClientId() != "app-1" {
			t.Fatalf("login_token.sso = %+v, want clientId app-1", p.GetSso())
		}
	})

	t.Run("binding_required 出口 token 带快照", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", func(r *model.Provider) { r.DisplayName = "微信扫码" })
		e.tickets.res["tid123"] = &token.TicketResult{
			V: 1, Status: ticketsvc.TicketStatusSuccess, Scene: "login", ProviderKey: "scan",
			LoginResult:        &token.LoginResult{Uid: 0, BindingRequired: true},
			ThirdpartyIdentity: &token.ThirdpartyIdentity{OpenId: "o-1", Nickname: "微信用户", AvatarUrl: "https://wx.cn/a.png"},
		}
		out := e.svc.GetLoginTicket(ctx, pollInputSso(t, e))
		inner := out.Envelope.GetLogin()
		if inner == nil || inner.GetStatus() != orchestrator.StatusBindingRequired {
			t.Fatalf("login = %+v, want binding_required", inner)
		}
		lt, err := security.Open[token.LoginTokenPayload](e.loginC, security.PurposeLogin, inner.GetLoginToken())
		if err != nil {
			t.Fatalf("Open login_token: %v", err)
		}
		if lt.GetSso() == nil || lt.GetSso().GetClientId() != "app-1" {
			t.Fatalf("login_token.sso = %+v, want clientId app-1", lt.GetSso())
		}
		if e.writer.gotUID != 0 {
			t.Fatalf("binding_required 不应建会话, got uid %d", e.writer.gotUID)
		}
	})

	t.Run("success 建会话出口回归", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		e.tickets.res["tid123"] = &token.TicketResult{
			V: 1, Status: ticketsvc.TicketStatusSuccess, Scene: "login", ProviderKey: "scan",
			LoginResult: &token.LoginResult{Uid: 9},
		}
		out := e.svc.GetLoginTicket(ctx, pollInputSso(t, e))
		if out.Envelope.GetStatus() != ticketsvc.TicketStatusSuccess ||
			out.Envelope.GetLogin().GetStatus() != orchestrator.StatusSuccess {
			t.Fatalf("信封 = %+v, want success（快照在场不改变建会话流）", out.Envelope)
		}
		if e.writer.gotUID != 9 {
			t.Errorf("建会话 uid = %d, want 9", e.writer.gotUID)
		}
	})
}

// TestGetLoginTicketSsoReachesTerminalComplete 建会话出口载荷 Sso 的可观测
// 断言：票据快照配置默认回跳时，pollResult 传入 Terminal.Complete 的载荷
// 携带 Sso，终点据此填 redirectTo（接口文档 §1.3）；Sso 未随行时 redirectTo
// 为空，断言必红。
func TestGetLoginTicketSsoReachesTerminalComplete(t *testing.T) {
	ctx := context.Background()
	e := newQrEnv(t)
	e.addScanProvider("scan", nil)
	e.tickets.res["tid123"] = &token.TicketResult{
		V: 1, Status: ticketsvc.TicketStatusSuccess, Scene: "login", ProviderKey: "scan",
		LoginResult: &token.LoginResult{Uid: 9},
	}
	snap := ssoApp()
	snap.DefaultRedirectUri = "https://app.example/after"
	ticket := e.sealTicket(t, &token.TicketPayload{
		TicketId:    "tid123",
		ProviderKey: "scan",
		Scene:       "login",
		Iat:         e.now.Unix(),
		Exp:         e.now.Add(600 * time.Second).Unix(),
		Sso:         snap,
	})
	out := e.svc.GetLoginTicket(ctx, GetLoginTicketInput{Ticket: ticket})
	inner := out.Envelope.GetLogin()
	if inner == nil || inner.GetStatus() != orchestrator.StatusSuccess {
		t.Fatalf("login = %+v, want success", inner)
	}
	if inner.GetRedirectTo() != "https://app.example/after" {
		t.Fatalf("redirectTo = %q, want 应用默认回跳地址（pollResult 载荷 Sso 未随行）", inner.GetRedirectTo())
	}
}

// pollInputSso 轮询入参变体：签一枚携带应用快照的 ticket（形态同
// pollInput，多装 sso——CreateQrcode 携带 sso_client_id 时的载荷形态）。
func pollInputSso(t *testing.T, e *qrEnv) GetLoginTicketInput {
	t.Helper()
	ticket := e.sealTicket(t, &token.TicketPayload{
		TicketId:    "tid123",
		ProviderKey: "scan",
		Scene:       "login",
		Iat:         e.now.Unix(),
		Exp:         e.now.Add(600 * time.Second).Unix(),
		Sso:         ssoApp(),
	})
	return GetLoginTicketInput{Ticket: ticket}
}
