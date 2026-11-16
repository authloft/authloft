package ssoapp

import (
	"context"
	"errors"
	"testing"

	"gorm.io/gorm"

	"authloft/gen/go/client"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

// fakeClientRows sso_client 行查询 Fake：固定行与错误，记录调用次数。
type fakeClientRows struct {
	row   *model.SsoClient
	err   error
	calls int
}

func (f *fakeClientRows) FindSsoClientByClientID(context.Context, string) (*model.SsoClient, error) {
	f.calls++
	return f.row, f.err
}

// fakeSettings 固定切片的 settings Fake。
type fakeSettings struct {
	slices map[string][]string
}

func (f *fakeSettings) GetStringSlice(key string) ([]string, bool) {
	v, ok := f.slices[key]
	return v, ok
}

func testRow(loginMethods, oauthProviders []string) (*model.SsoClient, error) {
	row := &model.SsoClient{ClientID: "app", IsEnabled: 1, DefaultRedirectURI: ""}
	var err error
	if loginMethods != nil {
		row.LoginMethods, err = repo.MarshalClientLoginMethods(&client.ClientLoginMethods{Methods: loginMethods})
		if err != nil {
			return nil, err
		}
	}
	if oauthProviders != nil {
		row.OauthProviders, err = repo.MarshalClientOauthProviders(&client.ClientOauthProviders{Providers: oauthProviders})
		if err != nil {
			return nil, err
		}
	}
	return row, nil
}

func testResolver(rows *fakeClientRows) *Resolver {
	return NewResolver(rows, &fakeSettings{slices: map[string][]string{
		settings.KeyLoginMethods: {"password", "otp_sms", "otp_email", "webauthn", "thirdparty"},
	}})
}

// TestSnapshotEmptyClientID 直登 / OIDC 链路（§2.2）：空标识零查询返回 nil 快照。
func TestSnapshotEmptyClientID(t *testing.T) {
	rows := &fakeClientRows{err: errors.New("must not be queried")}
	got, err := testResolver(rows).Snapshot(context.Background(), "")
	if got != nil || err != nil {
		t.Fatalf("Snapshot(\"\") = %+v, %v, want nil/nil", got, err)
	}
	if rows.calls != 0 {
		t.Fatalf("calls = %d, want 0", rows.calls)
	}
}

// TestSnapshotClientNotFound 查无行 → 显式哨兵错误（§2.2：不降级直登）。
func TestSnapshotClientNotFound(t *testing.T) {
	rows := &fakeClientRows{err: gorm.ErrRecordNotFound}
	_, err := testResolver(rows).Snapshot(context.Background(), "app")
	if !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("err = %v, want ErrClientNotFound", err)
	}
}

// TestSnapshotClientDisabled 行不可用（is_enabled≠1）→ 显式哨兵错误。
func TestSnapshotClientDisabled(t *testing.T) {
	row, err := testRow([]string{"password"}, nil)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	row.IsEnabled = 0
	_, err = testResolver(&fakeClientRows{row: row}).Snapshot(context.Background(), "app")
	if !errors.Is(err, ErrClientDisabled) {
		t.Fatalf("err = %v, want ErrClientDisabled", err)
	}
}

// TestSnapshotEmptyConfigFollowsGlobal 应用完全未配置（两列空 + 默认回跳空）
// → nil 快照：链路与无快照直登完全一致（§2.1 空 = 跟随全局）。
func TestSnapshotEmptyConfigFollowsGlobal(t *testing.T) {
	row, err := testRow(nil, nil)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	got, err := testResolver(&fakeClientRows{row: row}).Snapshot(context.Background(), "app")
	if got != nil || err != nil {
		t.Fatalf("Snapshot = %+v, %v, want nil/nil", got, err)
	}
}

// TestSnapshotDefaultOnlyCarriesRedirect 仅配置默认回跳（两列空）→ 非 nil
// 快照携带 client_id 与默认回跳，方式集冻结全局生效副本。
func TestSnapshotDefaultOnlyCarriesRedirect(t *testing.T) {
	row, err := testRow(nil, nil)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	row.DefaultRedirectURI = "https://app.example/callback"
	got, err := testResolver(&fakeClientRows{row: row}).Snapshot(context.Background(), "app")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got == nil {
		t.Fatal("Snapshot = nil, want non-nil（默认回跳需随快照送达终点）")
	}
	if got.GetClientId() != "app" || got.GetDefaultRedirectUri() != "https://app.example/callback" {
		t.Fatalf("snapshot = %+v", got)
	}
	want := []string{"password", "otp_sms", "otp_email", "webauthn", "thirdparty"}
	if !equalStrings(got.GetMethods(), want) {
		t.Fatalf("methods = %v, want 全局生效副本 %v", got.GetMethods(), want)
	}
	if got.GetProviders() != nil {
		t.Fatalf("providers = %v, want nil（跟随全局）", got.GetProviders())
	}
}

// TestSnapshotMethodsIntersectGlobal 交集边界（§2.1 第一行）：应用声明 ∩
// 全局开关；全局未启用 + 应用启用 = 关；未知取值不扩集；交集结果保持全局序。
func TestSnapshotMethodsIntersectGlobal(t *testing.T) {
	row, err := testRow([]string{"otp_sms", "password", "totp", "otp_sms"}, nil)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	got, err := testResolver(&fakeClientRows{row: row}).Snapshot(context.Background(), "app")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// totp 不在全局 login_methods（不可主登）被滤掉；otp_sms 重复声明去重。
	want := []string{"password", "otp_sms"}
	if !equalStrings(got.GetMethods(), want) {
		t.Fatalf("methods = %v, want %v", got.GetMethods(), want)
	}
	if got.GetProviders() != nil {
		t.Fatalf("providers = %v, want nil", got.GetProviders())
	}
}

// TestSnapshotMethodsGlobalOffWins 全局关闭 + 应用启用 = 关：应用声明的方式
// 全部被滤掉 → 生效集为空（快照非 nil，放行判定空集全拒，fail-closed）。
func TestSnapshotMethodsGlobalOffWins(t *testing.T) {
	row, err := testRow([]string{"password"}, nil)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	rows := &fakeClientRows{row: row}
	resolver := NewResolver(rows, &fakeSettings{slices: map[string][]string{
		settings.KeyLoginMethods: {"otp_email"},
	}})
	got, err := resolver.Snapshot(context.Background(), "app")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got == nil || len(got.GetMethods()) != 0 {
		t.Fatalf("snapshot = %+v, want 非 nil 且 methods 空集", got)
	}
}

// TestSnapshotProvidersFollowGlobalWhitelist providers 交集（§2.1）：应用未
// 配置 → nil（无应用限制）；全局 thirdparty 开启 → 应用白名单原样携带；
// 全局 thirdparty 关闭 → 空集全拒。
func TestSnapshotProvidersFollowGlobalWhitelist(t *testing.T) {
	row, err := testRow([]string{"password"}, []string{"wework", "dingtalk"})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	got, err := testResolver(&fakeClientRows{row: row}).Snapshot(context.Background(), "app")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !equalStrings(got.GetProviders(), []string{"wework", "dingtalk"}) {
		t.Fatalf("providers = %v, want 应用白名单", got.GetProviders())
	}
	if !equalStrings(got.GetMethods(), []string{"password"}) {
		t.Fatalf("methods = %v, want [password]", got.GetMethods())
	}

	// 全局 thirdparty 关闭 → providers 空集（非 nil）。
	resolver := NewResolver(&fakeClientRows{row: row}, &fakeSettings{slices: map[string][]string{
		settings.KeyLoginMethods: {"password", "otp_email"},
	}})
	got, err = resolver.Snapshot(context.Background(), "app")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if got.GetProviders() == nil || len(got.GetProviders()) != 0 {
		t.Fatalf("providers = %v, want 空集（全局 thirdparty 关闭）", got.GetProviders())
	}
}

// TestSnapshotBadColumnsDecodeError 列解码失败按内部故障报错，不产出半截快照。
func TestSnapshotBadColumnsDecodeError(t *testing.T) {
	row := &model.SsoClient{ClientID: "app", IsEnabled: 1, LoginMethods: []byte{0xff, 0xfe}}
	_, err := testResolver(&fakeClientRows{row: row}).Snapshot(context.Background(), "app")
	if err == nil || errors.Is(err, ErrClientNotFound) || errors.Is(err, ErrClientDisabled) {
		t.Fatalf("err = %v, want 非哨兵的解码错误", err)
	}
}

// TestSnapshotSettingsMissingFallsBackDefaults settings 缺键回落默认表：与
// 放行侧同口径，快照冻结值与无快照直登路径同一来源。
func TestSnapshotSettingsMissingFallsBackDefaults(t *testing.T) {
	row, err := testRow(nil, []string{"wework"})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	resolver := NewResolver(&fakeClientRows{row: row}, &fakeSettings{})
	got, err := resolver.Snapshot(context.Background(), "app")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	def, _ := settings.Defaults()[settings.KeyLoginMethods].([]string)
	if !equalStrings(got.GetMethods(), def) {
		t.Fatalf("methods = %v, want 默认表 %v", got.GetMethods(), def)
	}
	if !equalStrings(got.GetProviders(), []string{"wework"}) {
		t.Fatalf("providers = %v, want [wework]", got.GetProviders())
	}
}

func equalStrings(got, want []string) bool {
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
