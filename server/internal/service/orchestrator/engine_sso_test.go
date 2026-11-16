// engine_sso_test.go SSO 应用首签快照与主因子交集放行的引擎级用例
// （docs/接口文档.md §2.2 首签口径、§2.1 交集口径；docs/后端架构.md §11.6.2）：
// 快照放行 / 快照拒绝 method_disabled / 无快照走全局回归 / 查无行与内部故障
// 的信封口径 / 续步重签保留快照。
package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/repo/model"
	"authloft/internal/service/ssoapp"
	"authloft/internal/settings"
)

// fakeSsoResolver 固定快照 / 错误的解析器 Fake，记录调用与入参。
type fakeSsoResolver struct {
	snap  *token.Sso
	err   error
	calls int
	gotID string
}

func (f *fakeSsoResolver) Snapshot(_ context.Context, id string) (*token.Sso, error) {
	f.calls++
	f.gotID = id
	return f.snap, f.err
}

// ssoPasswordDeps 装配 password 可登录的最小依赖集。
func ssoPasswordDeps(t *testing.T, at time.Time, global []string, ssoApp *fakeSsoResolver) (*testEngineDeps, *Engine, *State) {
	t.Helper()
	deps := newTestDeps(t, at)
	deps.settings.slices[settings.KeyLoginMethods] = global
	deps.registry.factors[factor.FactorPassword] = passwordFactor(7)
	if ssoApp != nil {
		deps.ssoApp = ssoApp
	}
	state := testState(t, at)
	return deps, deps.engine(state), state
}

// TestEngineSsoSnapshotGovernsPrimary 快照放行：快照声明的方式即便全局已关
// 也放行——首签时快照已与全局取过交集，放行判定只看快照成员（§2.2 第 2 步）。
func TestEngineSsoSnapshotGovernsPrimary(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	ssoApp := &fakeSsoResolver{snap: &token.Sso{ClientId: "app-1", Methods: []string{"password"}}}
	// 全局已关闭 password：放行与否完全由快照决定。
	_, e, _ := ssoPasswordDeps(t, at, []string{"otp_email"}, ssoApp)

	got := e.Submit(context.Background(), "login", Request{
		Method: "password", Step: "verify",
		Payload: &factor.Payload{Username: "u", Password: "p"}, SSOClientID: "app-1",
	})
	if got.Status != StatusSuccess {
		t.Fatalf("status = %q, want %q（快照在场且含 password）", got.Status, StatusSuccess)
	}
	if ssoApp.calls != 1 || ssoApp.gotID != "app-1" {
		t.Fatalf("resolver calls = %d id = %q, want 首签恰好一次", ssoApp.calls, ssoApp.gotID)
	}
}

// TestEngineSsoSnapshotRejectsMethodDisabled 快照拒绝：快照不含的方式按
// method_disabled 拒绝，即便全局开关仍启用（§2.1 交集硬生效）。
func TestEngineSsoSnapshotRejectsMethodDisabled(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	ssoApp := &fakeSsoResolver{snap: &token.Sso{ClientId: "app-1", Methods: []string{"otp_email"}}}
	_, e, _ := ssoPasswordDeps(t, at, []string{"password", "otp_email"}, ssoApp)

	got := e.Submit(context.Background(), "login", Request{
		Method: "password", Step: "verify",
		Payload: &factor.Payload{Username: "u", Password: "p"}, SSOClientID: "app-1",
	})
	if got.Status != StatusMethodDisabled {
		t.Fatalf("status = %q, want %q（快照不含 password）", got.Status, StatusMethodDisabled)
	}
	if got.LoginToken != "" {
		t.Fatalf("login_token = %q, want 空（拒绝态不签发流程态）", got.LoginToken)
	}
}

// TestEngineNoSnapshotFollowsGlobal 无快照走全局回归：应用未配置（解析器返回
// nil 快照）时放行回到全局 login_methods，行为与直登完全一致。
func TestEngineNoSnapshotFollowsGlobal(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	ssoApp := &fakeSsoResolver{snap: nil}
	// 全局只留 otp_email：password 被全局关闭。
	_, e, _ := ssoPasswordDeps(t, at, []string{"otp_email"}, ssoApp)

	got := e.Submit(context.Background(), "login", Request{
		Method: "password", Step: "verify",
		Payload: &factor.Payload{Username: "u", Password: "p"}, SSOClientID: "app-1",
	})
	if got.Status != StatusMethodDisabled {
		t.Fatalf("status = %q, want %q（nil 快照走全局）", got.Status, StatusMethodDisabled)
	}

	// 全局放行 otp_email：nil 快照下正常推进。
	deps2 := newTestDeps(t, at)
	deps2.settings.slices[settings.KeyLoginMethods] = []string{"otp_email"}
	deps2.registry.factors[factor.FactorOTPEmail] = otpEmailFactor()
	deps2.users.user = &model.User{ID: 42, MfaRequired: 0}
	deps2.ssoApp = ssoApp
	e2 := deps2.engine(testState(t, at))
	got = e2.Submit(context.Background(), "login", Request{
		Method: "otp_email", Step: "challenge", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Email: "a@b.com"}, SSOClientID: "app-1",
	})
	if got.Status != StatusNext {
		t.Fatalf("status = %q, want %q", got.Status, StatusNext)
	}
	p, err := testState(t, at).Parse(got.LoginToken)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.GetSso() != nil {
		t.Fatalf("payload sso = %+v, want nil（nil 快照不写载荷）", p.GetSso())
	}
}

// TestEngineSsoNotFoundInvalidRequest 查无行 / 行不可用 → invalid_request 信封，
// 不降级直登（§2.2 首签口径）。
func TestEngineSsoNotFoundInvalidRequest(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	for _, sentinel := range []error{ssoapp.ErrClientNotFound, ssoapp.ErrClientDisabled} {
		_, e, _ := ssoPasswordDeps(t, at, []string{"password"}, &fakeSsoResolver{err: sentinel})
		got := e.Submit(context.Background(), "login", Request{
			Method: "password", Step: "verify",
			Payload: &factor.Payload{Username: "u", Password: "p"}, SSOClientID: "app-1",
		})
		if got.Status != StatusInvalidRequest {
			t.Fatalf("err %v: status = %q, want %q", sentinel, got.Status, StatusInvalidRequest)
		}
		if got.LoginToken != "" {
			t.Fatalf("err %v: login_token = %q, want 空（不降级直登）", sentinel, got.LoginToken)
		}
	}
}

// TestEngineSsoInternalErrorFailed 解析器内部故障（非哨兵）按既有内部失败
// 出口走 failed 并记日志，不误报客户端 invalid_request。
func TestEngineSsoInternalErrorFailed(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	ssoApp := &fakeSsoResolver{err: errors.New("db down")}
	_, e, _ := ssoPasswordDeps(t, at, []string{"password"}, ssoApp)
	got := e.Submit(context.Background(), "login", Request{
		Method: "password", Step: "verify",
		Payload: &factor.Payload{Username: "u", Password: "p"}, SSOClientID: "app-1",
	})
	if got.Status != StatusFailed {
		t.Fatalf("status = %q, want %q", got.Status, StatusFailed)
	}
}

// TestEngineSsoResolverMissingFailClosed 解析器缺位（装配缺陷）时携带
// sso_client_id 的首签 fail-closed，绝不降级直登。
func TestEngineSsoResolverMissingFailClosed(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	// ssoApp 不装配（nil）。
	_, e, _ := ssoPasswordDeps(t, at, []string{"password"}, nil)
	got := e.Submit(context.Background(), "login", Request{
		Method: "password", Step: "verify",
		Payload: &factor.Payload{Username: "u", Password: "p"}, SSOClientID: "app-1",
	})
	if got.Status != StatusInvalidRequest {
		t.Fatalf("status = %q, want %q", got.Status, StatusInvalidRequest)
	}
}

// TestEngineSsoSnapshotPreservedOnRenew 续步重签保留快照：首签载荷带 sso，
// 续步请求不再携带 sso_client_id（续步忽略），重签后原样保留（§11.6.2）。
func TestEngineSsoSnapshotPreservedOnRenew(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	ssoApp := &fakeSsoResolver{snap: &token.Sso{
		ClientId: "app-1", Methods: []string{"otp_email"},
		Providers: []string{"wework"}, DefaultRedirectUri: "https://app.example/cb",
	}}
	deps := newTestDeps(t, at)
	deps.settings.slices[settings.KeyLoginMethods] = []string{"otp_email"}
	deps.registry.factors[factor.FactorOTPEmail] = otpEmailFactor()
	// MFA 启用：verify 落 mfa_required 信封（success 不回传 login_token，§1.3），
	// 续签令牌可从响应解析断言快照保留。
	deps.users.user = &model.User{ID: 42, MfaRequired: 1}
	deps.creds.creds["totp"] = &model.UserCredential{UserID: 42, Kind: "totp", IsEnabled: 1}
	deps.ssoApp = ssoApp
	state := testState(t, at)
	e := deps.engine(state)

	resp := e.Submit(context.Background(), "login", Request{
		Method: "otp_email", Step: "challenge", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Email: "a@b.com"}, SSOClientID: "app-1",
	})
	if resp.Status != StatusNext {
		t.Fatalf("challenge status = %q, want %q", resp.Status, StatusNext)
	}
	p, err := state.Parse(resp.LoginToken)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.GetSso() == nil || p.GetSso().GetClientId() != "app-1" ||
		!equalSlice(p.GetSso().GetMethods(), []string{"otp_email"}) {
		t.Fatalf("首签 payload sso = %+v", p.GetSso())
	}

	// 续步：不带 SSOClientID（续步忽略），重签后快照原样保留。
	resp = e.Submit(context.Background(), "login", Request{
		LoginToken: resp.LoginToken, Method: "otp_email", Step: "verify",
		Payload: &factor.Payload{Email: "a@b.com", Code: "123456"},
	})
	if resp.Status != StatusMFARequired || resp.LoginToken == "" {
		t.Fatalf("verify resp = %+v, want mfa_required 且回传续签令牌", resp)
	}
	if ssoApp.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1（续步不回读配置）", ssoApp.calls)
	}
	p, err = state.Parse(resp.LoginToken)
	if err != nil {
		t.Fatalf("Parse renewed: %v", err)
	}
	snap := p.GetSso()
	if snap == nil || snap.GetClientId() != "app-1" ||
		!equalSlice(snap.GetMethods(), []string{"otp_email"}) ||
		!equalSlice(snap.GetProviders(), []string{"wework"}) ||
		snap.GetDefaultRedirectUri() != "https://app.example/cb" {
		t.Fatalf("renewed payload sso = %+v, want 原样保留", snap)
	}
}

// TestEngineSsoRegisterFirstSign 注册首签同样装载快照（§2.3：注册不读应用级
// 方式开关，快照仅随载荷供终点回跳消费）。
func TestEngineSsoRegisterFirstSign(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	ssoApp := &fakeSsoResolver{snap: &token.Sso{ClientId: "app-1", Methods: []string{"password"}}}
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorOTPEmail] = otpEmailFactor()
	deps.ssoApp = ssoApp
	e := deps.engine(testState(t, at))

	resp := e.Submit(context.Background(), "register", Request{
		Method: "otp_email", Step: "challenge", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Email: "a@b.com"}, SSOClientID: "app-1",
	})
	if resp.Status != StatusNext {
		t.Fatalf("status = %q, want %q", resp.Status, StatusNext)
	}
	p, err := testState(t, at).Parse(resp.LoginToken)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.GetFlow() != "register" || p.GetSso() == nil || p.GetSso().GetClientId() != "app-1" {
		t.Fatalf("register payload = %+v, want flow=register 且 sso 在场", p)
	}
}

func equalSlice(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
