package orchestrator

import (
	"context"
	"testing"

	"authloft/internal/captcha"
	"authloft/internal/settings"
)

type fakeProviders struct{ list []ThirdPartyProvider }

func (f fakeProviders) ListLoginProviders(context.Context) ([]ThirdPartyProvider, error) {
	return f.list, nil
}

func TestMethodsLoginFiltersAndOrders(t *testing.T) {
	s := &testSettings{
		ints: map[string]int64{settings.KeyOtpResendInterval: 60, settings.KeyOtpTtl: 300},
		bools: map[string]bool{
			settings.KeyAllowRegistration:  true,
			settings.KeyAllowPasswordReset: true,
		},
		slices: map[string][]string{settings.KeyLoginMethods: {"thirdparty", "otp_email", "password"}},
	}
	gate := captcha.NewGate(s, fakeCatalog{p: &captcha.Provider{ProviderKey: "turnstile-1", Type: "turnstile", SiteKey: "site-1"}}, &fakeCaptchaGate{})
	providers := fakeProviders{list: []ThirdPartyProvider{
		{ProviderKey: "wechat", DisplayName: "微信", Channel: "qrcode", SortOrder: 20},
		{ProviderKey: "qq", DisplayName: "QQ", Channel: "redirect", SortOrder: 10},
	}}
	b := NewMethodsBuilder(s, gate, providers)

	snap, err := b.BuildMethodsSnapshot(context.Background(), "client-1", "login")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !snap.Flags.Registration || !snap.Flags.PasswordReset {
		t.Fatalf("flags = %+v", snap.Flags)
	}
	if snap.Captcha.ProviderKey != "turnstile-1" || snap.Captcha.SiteKey != "site-1" {
		t.Fatalf("captcha = %+v", snap.Captcha)
	}
	if len(snap.Methods) != 3 {
		t.Fatalf("methods = %+v", snap.Methods)
	}
	var methods []string
	for _, m := range snap.Methods {
		methods = append(methods, m.Method)
	}
	if methods[0] != "password" || methods[1] != "otp_email" || methods[2] != "thirdparty" {
		t.Fatalf("order = %v", methods)
	}
	otp := snap.Methods[1]
	if otp.CodeLength != 6 || otp.ResendAfter != 60 || otp.ExpiresIn != 300 {
		t.Fatalf("otp spec = %+v", otp)
	}
	if len(otp.ChallengeFields) != 1 || otp.ChallengeFields[0].Name != "email" {
		t.Fatalf("otp challenge fields = %+v", otp.ChallengeFields)
	}
	tp := snap.Methods[2]
	if len(tp.Providers) != 2 || tp.Providers[0].ProviderKey != "qq" || tp.Providers[1].ProviderKey != "wechat" {
		t.Fatalf("providers order = %+v", tp.Providers)
	}
}

func TestMethodsRegisterOnlyReadsSignupSwitches(t *testing.T) {
	s := &testSettings{
		bools: map[string]bool{
			settings.KeyAllowRegistration:   true,
			settings.KeyAllowSignupPassword: false,
			settings.KeyAllowSignupPhone:    true,
			settings.KeyAllowSignupEmail:    false,
		},
		// login_methods 只含 password，但 register 不应读取它。
		slices: map[string][]string{settings.KeyLoginMethods: {"password"}},
	}
	b := NewMethodsBuilder(s, nil, nil)

	snap, err := b.BuildMethodsSnapshot(context.Background(), "", "register")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !snap.Flags.Registration {
		t.Fatalf("registration flag = %v", snap.Flags.Registration)
	}
	if len(snap.Methods) != 1 || snap.Methods[0].Method != "otp_sms" {
		t.Fatalf("register methods = %+v", snap.Methods)
	}
	if snap.Captcha.ProviderKey != captcha.BuiltinProviderKey || snap.Captcha.Type != captcha.TypeImage {
		t.Fatalf("captcha default = %+v", snap.Captcha)
	}
}

func TestMethodsRegisterDisabled(t *testing.T) {
	s := &testSettings{bools: map[string]bool{
		settings.KeyAllowRegistration:   false,
		settings.KeyAllowSignupPassword: true,
		settings.KeyAllowSignupPhone:    true,
		settings.KeyAllowSignupEmail:    true,
	}}
	snap, err := NewMethodsBuilder(s, nil, nil).BuildMethodsSnapshot(context.Background(), "", "register")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if snap.Flags.Registration || len(snap.Methods) != 0 {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestMethodsResetSwitch(t *testing.T) {
	s := &testSettings{
		bools:  map[string]bool{settings.KeyAllowPasswordReset: false},
		slices: map[string][]string{settings.KeyLoginMethods: {"password", "otp_sms", "otp_email"}},
	}
	snap, err := NewMethodsBuilder(s, nil, nil).BuildMethodsSnapshot(context.Background(), "", "reset")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if snap.Flags.PasswordReset || len(snap.Methods) != 0 {
		t.Fatalf("reset snapshot = %+v", snap)
	}

	s.bools[settings.KeyAllowPasswordReset] = true
	snap, err = NewMethodsBuilder(s, nil, nil).BuildMethodsSnapshot(context.Background(), "", "reset")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var methods []string
	for _, m := range snap.Methods {
		methods = append(methods, m.Method)
	}
	if len(methods) != 2 || methods[0] != "otp_sms" || methods[1] != "otp_email" {
		t.Fatalf("reset methods = %v", methods)
	}
	for _, m := range snap.Methods {
		if len(m.Usage) != 1 || m.Usage[0] != "primary" {
			t.Fatalf("reset usage = %+v, want primary only", m.Usage)
		}
	}
}

func TestMethodsThirdPartyOmittedWhenNoProviders(t *testing.T) {
	s := &testSettings{
		slices: map[string][]string{settings.KeyLoginMethods: {"thirdparty"}},
	}
	providers := fakeProviders{}
	snap, err := NewMethodsBuilder(s, nil, providers).BuildMethodsSnapshot(context.Background(), "", "login")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(snap.Methods) != 0 {
		t.Fatalf("methods = %+v", snap.Methods)
	}
}
