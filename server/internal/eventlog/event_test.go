package eventlog

import (
	"reflect"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

// TestEventConstantsMatchArchitecture 锚定事件常量与 §4.6 行 770 枚举
// 一一对应（含 §4.6 行 792 的 system 事件 oidc_authorize_no_state）。
func TestEventConstantsMatchArchitecture(t *testing.T) {
	want := map[string]string{
		"EventLoginSuccess":         "login_success",
		"EventChangePassword":       "change_password",
		"EventResetPassword":        "reset_password",
		"EventBindPhone":            "bind_phone",
		"EventBindEmail":            "bind_email",
		"EventEnableMFA":            "enable_mfa",
		"EventDisableMFA":           "disable_mfa",
		"EventWebAuthnRegister":     "webauthn_register",
		"EventWebAuthnDelete":       "webauthn_delete",
		"EventThirdpartyBind":       "thirdparty_bind",
		"EventThirdpartyUnbind":     "thirdparty_unbind",
		"EventAdminDisableUser":     "admin_disable_user",
		"EventAdminResetPassword":   "admin_reset_password",
		"EventProviderCreate":       "provider_create",
		"EventProviderUpdate":       "provider_update",
		"EventSettingsUpdate":       "settings_update",
		"EventOIDCAuthorizeNoState": "oidc_authorize_no_state",
	}

	got := map[string]string{
		"EventLoginSuccess":         EventLoginSuccess,
		"EventChangePassword":       EventChangePassword,
		"EventResetPassword":        EventResetPassword,
		"EventBindPhone":            EventBindPhone,
		"EventBindEmail":            EventBindEmail,
		"EventEnableMFA":            EventEnableMFA,
		"EventDisableMFA":           EventDisableMFA,
		"EventWebAuthnRegister":     EventWebAuthnRegister,
		"EventWebAuthnDelete":       EventWebAuthnDelete,
		"EventThirdpartyBind":       EventThirdpartyBind,
		"EventThirdpartyUnbind":     EventThirdpartyUnbind,
		"EventAdminDisableUser":     EventAdminDisableUser,
		"EventAdminResetPassword":   EventAdminResetPassword,
		"EventProviderCreate":       EventProviderCreate,
		"EventProviderUpdate":       EventProviderUpdate,
		"EventSettingsUpdate":       EventSettingsUpdate,
		"EventOIDCAuthorizeNoState": EventOIDCAuthorizeNoState,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("事件常量与 §4.6 枚举不一致:\n got=%v\nwant=%v", got, want)
	}

	if ActorTypeUser != "user" || ActorTypeAdmin != "admin" || ActorTypeSystem != "system" {
		t.Errorf("actor_type 常量与 §4.6 行 771 不一致: %q %q %q",
			ActorTypeUser, ActorTypeAdmin, ActorTypeSystem)
	}
}

// decodeDetail 断言 detail 非 nil 且可被 msgpack 解码到目标结构。
func decodeDetail[T any](t *testing.T, detail []byte) T {
	t.Helper()
	if detail == nil {
		t.Fatal("detail is nil, want msgpack bytes")
	}
	var v T
	if err := msgpack.Unmarshal(detail, &v); err != nil {
		t.Fatalf("msgpack.Unmarshal: %v", err)
	}
	return v
}

// TestDetailLoginSuccess 校验 §4.6 行 798 的四个字段名与取值；空值也必须
// 保留键（管理后台视图按固定字段渲染）。
func TestDetailLoginSuccess(t *testing.T) {
	type loginDetail struct {
		Factor     string `msgpack:"factor"`
		MFAFactor  string `msgpack:"mfa_factor"`
		SessionID  string `msgpack:"session_id"`
		DeviceHint string `msgpack:"device_hint"`
	}

	got := decodeDetail[loginDetail](t, DetailLoginSuccess("pwd", "otp", "sid-1", "Chrome"))
	if got != (loginDetail{Factor: "pwd", MFAFactor: "otp", SessionID: "sid-1", DeviceHint: "Chrome"}) {
		t.Errorf("login_success detail = %+v", got)
	}

	empty := decodeDetail[loginDetail](t, DetailLoginSuccess("", "", "", ""))
	if empty != (loginDetail{}) {
		t.Errorf("空值 detail = %+v, want zero-value", empty)
	}
}

// TestDetailPwdEpoch 校验 change_password / reset_password（§4.6 行 799）。
func TestDetailPwdEpoch(t *testing.T) {
	type pwdDetail struct {
		PwdEpoch int64 `msgpack:"pwd_epoch"`
	}
	got := decodeDetail[pwdDetail](t, DetailPwdEpoch(7))
	if got.PwdEpoch != 7 {
		t.Errorf("pwd_epoch = %d, want 7", got.PwdEpoch)
	}
}

// TestDetailTargetMasked 校验 bind_phone / bind_email（§4.6 行 800）。
func TestDetailTargetMasked(t *testing.T) {
	type targetDetail struct {
		TargetMasked string `msgpack:"target_masked"`
	}
	got := decodeDetail[targetDetail](t, DetailTargetMasked("138****0000"))
	if got.TargetMasked != "138****0000" {
		t.Errorf("target_masked = %q", got.TargetMasked)
	}
}

// TestDetailMFAMethods 校验 enable_mfa / disable_mfa（§4.6 行 801），并
// 覆盖 nil 归一为空数组。
func TestDetailMFAMethods(t *testing.T) {
	type mfaDetail struct {
		Methods []string `msgpack:"methods"`
	}
	got := decodeDetail[mfaDetail](t, DetailMFAMethods([]string{"totp", "webauthn"}))
	if want := []string{"totp", "webauthn"}; !reflect.DeepEqual(got.Methods, want) {
		t.Errorf("methods = %v, want %v", got.Methods, want)
	}

	empty := decodeDetail[mfaDetail](t, DetailMFAMethods(nil))
	if len(empty.Methods) != 0 {
		t.Errorf("nil methods = %v, want empty array", empty.Methods)
	}
}

// TestDetailThirdpartyBind 校验 thirdparty_bind / thirdparty_unbind（§4.6
// 行 802）。
func TestDetailThirdpartyBind(t *testing.T) {
	type thirdpartyDetail struct {
		ProviderKey string `msgpack:"provider_key"`
		OpenID      string `msgpack:"open_id"`
	}
	got := decodeDetail[thirdpartyDetail](t, DetailThirdpartyBind("wechat", "openid-1"))
	if got.ProviderKey != "wechat" || got.OpenID != "openid-1" {
		t.Errorf("thirdparty detail = %+v", got)
	}
}

// TestDetailProviderChanged 校验 provider_create / provider_update（§4.6
// 行 803）。
func TestDetailProviderChanged(t *testing.T) {
	type providerDetail struct {
		ProviderKey   string   `msgpack:"provider_key"`
		ChangedFields []string `msgpack:"changed_fields"`
	}
	got := decodeDetail[providerDetail](t, DetailProviderChanged("github", []string{"client_secret", "enabled"}))
	if got.ProviderKey != "github" {
		t.Errorf("provider_key = %q", got.ProviderKey)
	}
	if want := []string{"client_secret", "enabled"}; !reflect.DeepEqual(got.ChangedFields, want) {
		t.Errorf("changed_fields = %v, want %v", got.ChangedFields, want)
	}
}

// TestDetailSettingsUpdate 校验 settings_update（§4.6 行 804）：keys /
// before / after 三键，仅变更项。
func TestDetailSettingsUpdate(t *testing.T) {
	type settingsDetail struct {
		Keys   []string          `msgpack:"keys"`
		Before map[string]string `msgpack:"before"`
		After  map[string]string `msgpack:"after"`
	}
	got := decodeDetail[settingsDetail](t, DetailSettingsUpdate(
		[]string{"login_methods"},
		map[string]any{"login_methods": "pwd"},
		map[string]any{"login_methods": "pwd,otp"},
	))
	if want := []string{"login_methods"}; !reflect.DeepEqual(got.Keys, want) {
		t.Errorf("keys = %v, want %v", got.Keys, want)
	}
	if want := map[string]string{"login_methods": "pwd"}; !reflect.DeepEqual(got.Before, want) {
		t.Errorf("before = %v, want %v", got.Before, want)
	}
	if want := map[string]string{"login_methods": "pwd,otp"}; !reflect.DeepEqual(got.After, want) {
		t.Errorf("after = %v, want %v", got.After, want)
	}
}
