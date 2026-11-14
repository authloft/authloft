// policy_test.go mfapolicy 单测：判定式为「系统已开放 ∧ user.mfa_required=1 ∧
// 存在可用因子（白名单 ∩ 已绑定）」——覆盖白名单空 / 未绑定 / 已绑定 /
// 开关关闭 / 系统总开关关闭 / 依赖故障 fail-closed。
package mfapolicy

import (
	"context"
	"errors"
	"testing"

	"gorm.io/gorm"

	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

// fakeUsers UserReader 的 fake。
type fakeUsers struct {
	byID map[int64]*model.User
	err  error
}

func (f *fakeUsers) FindByID(_ context.Context, id int64) (*model.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	if u, ok := f.byID[id]; ok {
		return u, nil
	}
	return nil, gorm.ErrRecordNotFound
}

// fakeCreds CredentialReader 的 fake（按 kind 命中，未命中按 repo 口径）。
type fakeCreds struct {
	byKind map[string]*model.UserCredential
	err    error
}

func (f *fakeCreds) FindByUserAndKind(_ context.Context, _ int64, kind string) (*model.UserCredential, error) {
	if f.err != nil {
		return nil, f.err
	}
	if c, ok := f.byKind[kind]; ok {
		return c, nil
	}
	return nil, gorm.ErrRecordNotFound
}

// fakeSettings SettingsReader 的 fake。
type fakeSettings struct {
	enabled    bool
	enabledSet bool
	methods    []string
	methodsSet bool
}

func (f *fakeSettings) GetBool(key string) (bool, bool) {
	if key == settings.KeyMfaEnabled {
		return f.enabled, f.enabledSet
	}
	return false, false
}

func (f *fakeSettings) GetStringSlice(key string) ([]string, bool) {
	if key == settings.KeyMfaMethods {
		return f.methods, f.methodsSet
	}
	return nil, false
}

func newDeps(users *fakeUsers, creds *fakeCreds, st *fakeSettings) Deps {
	return Deps{Users: users, Creds: creds, Settings: st}
}

func TestSystemEnabled(t *testing.T) {
	if !SystemEnabled(nil) {
		t.Error("nil reader 应按缺省 true")
	}
	if !SystemEnabled(&fakeSettings{}) {
		t.Error("键缺失应按缺省 true")
	}
	if SystemEnabled(&fakeSettings{enabled: false, enabledSet: true}) {
		t.Error("mfa_enabled=false 应关闭")
	}
}

func TestAllowedMethods(t *testing.T) {
	if got := AllowedMethods(nil); got != nil {
		t.Errorf("nil reader = %v, want nil", got)
	}
	if got := AllowedMethods(&fakeSettings{methods: []string{}, methodsSet: true}); got != nil {
		t.Errorf("空白名单 = %v, want nil", got)
	}
	got := AllowedMethods(&fakeSettings{
		methods:    []string{"totp", "", "otp_sms", "totp", "webauthn"},
		methodsSet: true,
	})
	want := []string{"totp", "otp_sms", "webauthn"}
	if len(got) != len(want) {
		t.Fatalf("methods = %v, want %v（去重 + 保持顺序）", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("methods[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// 封闭值域：recovery_code 随 totp 生效、不单列；未知值丢弃而非报错。
	closed := []struct {
		name string
		in   []string
		want []string
	}{
		{"recovery_code 丢弃", []string{"recovery_code"}, nil},
		{"未知因子丢弃", []string{"totp", "sms"}, []string{"totp"}},
		{"totp + recovery_code 只保留 totp", []string{"totp", "recovery_code"}, []string{"totp"}},
	}
	for _, tc := range closed {
		got := AllowedMethods(&fakeSettings{methods: tc.in, methodsSet: true})
		if len(got) != len(tc.want) {
			t.Fatalf("%s: methods = %v, want %v", tc.name, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("%s: methods[%d] = %q, want %q", tc.name, i, got[i], tc.want[i])
			}
		}
	}
}

func TestUsableFactors(t *testing.T) {
	phone, email := "13800000000", "a@example.com"
	boundUser := &model.User{ID: 42, MfaRequired: 1, Phone: &phone, Email: &email}
	emptyUser := &model.User{ID: 42, MfaRequired: 1}

	cases := []struct {
		name    string
		deps    Deps
		want    []string
		wantErr bool
	}{
		{
			name: "白名单为空 → 无可用因子",
			deps: newDeps(&fakeUsers{byID: map[int64]*model.User{42: boundUser}}, &fakeCreds{}, &fakeSettings{}),
		},
		{
			name: "用户未绑定任何因子",
			deps: newDeps(&fakeUsers{byID: map[int64]*model.User{42: emptyUser}}, &fakeCreds{}, &fakeSettings{
				methods: []string{"totp", "otp_sms"}, methodsSet: true,
			}),
		},
		{
			name: "totp 已绑定 → 随附 recovery_code",
			deps: newDeps(&fakeUsers{byID: map[int64]*model.User{42: emptyUser}}, &fakeCreds{byKind: map[string]*model.UserCredential{
				"totp": {Kind: "totp", IsEnabled: 1},
			}}, &fakeSettings{methods: []string{"totp", "otp_sms"}, methodsSet: true}),
			want: []string{"totp", "recovery_code"},
		},
		{
			name: "白名单只写 recovery_code → 无可用因子",
			deps: newDeps(&fakeUsers{byID: map[int64]*model.User{42: emptyUser}}, &fakeCreds{byKind: map[string]*model.UserCredential{
				"recovery_code": {Kind: "recovery_code", IsEnabled: 1},
			}}, &fakeSettings{methods: []string{"recovery_code"}, methodsSet: true}),
		},
		{
			name: "白名单 totp + recovery_code → 结果不重复",
			deps: newDeps(&fakeUsers{byID: map[int64]*model.User{42: emptyUser}}, &fakeCreds{byKind: map[string]*model.UserCredential{
				"totp": {Kind: "totp", IsEnabled: 1},
			}}, &fakeSettings{methods: []string{"totp", "recovery_code"}, methodsSet: true}),
			want: []string{"totp", "recovery_code"},
		},
		{
			name: "otp_sms / otp_email 走联系方式",
			deps: newDeps(&fakeUsers{byID: map[int64]*model.User{42: boundUser}}, &fakeCreds{}, &fakeSettings{
				methods: []string{"otp_sms", "otp_email"}, methodsSet: true,
			}),
			want: []string{"otp_sms", "otp_email"},
		},
		{
			name: "白名单外因子不计入",
			deps: newDeps(&fakeUsers{byID: map[int64]*model.User{42: boundUser}}, &fakeCreds{byKind: map[string]*model.UserCredential{
				"webauthn": {Kind: "webauthn", IsEnabled: 1},
			}}, &fakeSettings{methods: []string{"totp"}, methodsSet: true}),
		},
		{
			name: "凭证行读取故障 fail-closed",
			deps: newDeps(&fakeUsers{byID: map[int64]*model.User{42: emptyUser}}, &fakeCreds{
				err: errors.New("credential repo: connection refused"),
			}, &fakeSettings{methods: []string{"totp"}, methodsSet: true}),
			wantErr: true,
		},
		{
			name: "用户行读取故障 fail-closed",
			deps: newDeps(&fakeUsers{err: errors.New("user repo: connection refused")}, &fakeCreds{}, &fakeSettings{
				methods: []string{"totp"}, methodsSet: true,
			}),
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := UsableFactors(context.Background(), tc.deps, 42)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UsableFactors: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("factors = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("factors[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestRequired(t *testing.T) {
	on := &fakeSettings{enabled: true, enabledSet: true, methods: []string{"totp"}, methodsSet: true}
	withTotp := &fakeCreds{byKind: map[string]*model.UserCredential{"totp": {Kind: "totp", IsEnabled: 1}}}

	cases := []struct {
		name    string
		deps    Deps
		uid     int64
		want    bool
		wantErr bool
	}{
		{"开关开启且有可用因子", newDeps(&fakeUsers{byID: map[int64]*model.User{42: {ID: 42, MfaRequired: 1}}}, withTotp, on), 42, true, false},
		{"开关关闭", newDeps(&fakeUsers{byID: map[int64]*model.User{42: {ID: 42, MfaRequired: 0}}}, withTotp, on), 42, false, false},
		{"无可用因子兜底", newDeps(&fakeUsers{byID: map[int64]*model.User{42: {ID: 42, MfaRequired: 1}}}, &fakeCreds{}, on), 42, false, false},
		{"系统总开关关闭", newDeps(&fakeUsers{byID: map[int64]*model.User{42: {ID: 42, MfaRequired: 1}}}, withTotp,
			&fakeSettings{enabled: false, enabledSet: true, methods: []string{"totp"}, methodsSet: true}), 42, false, false},
		{"uid=0 无判定输入", newDeps(&fakeUsers{byID: map[int64]*model.User{42: {ID: 42, MfaRequired: 1}}}, withTotp, on), 0, false, false},
		{"用户行读取故障", newDeps(&fakeUsers{err: errors.New("user repo: connection refused")}, withTotp, on), 42, false, true},
		{"凭证行读取故障", newDeps(&fakeUsers{byID: map[int64]*model.User{42: {ID: 42, MfaRequired: 1}}},
			&fakeCreds{err: errors.New("credential repo: connection refused")}, on), 42, false, true},
		{"白名单只写 recovery_code 不构成可用因子",
			newDeps(&fakeUsers{byID: map[int64]*model.User{42: {ID: 42, MfaRequired: 1}}},
				&fakeCreds{byKind: map[string]*model.UserCredential{"recovery_code": {Kind: "recovery_code", IsEnabled: 1}}},
				&fakeSettings{enabled: true, enabledSet: true, methods: []string{"recovery_code"}, methodsSet: true}), 42, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Required(context.Background(), tc.deps, tc.uid)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error（fail-closed）")
				}
				return
			}
			if err != nil {
				t.Fatalf("Required: %v", err)
			}
			if got != tc.want {
				t.Errorf("Required = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDepsUnavailable 判定依赖缺一即装配缺陷：Required / UsableFactors
// 必须返回 ErrDepsUnavailable，不得静默回退成「无需二次验证」；
// uid<=0 表示无主体，仍返回 (false, nil) / (nil, nil)。
func TestDepsUnavailable(t *testing.T) {
	users := &fakeUsers{byID: map[int64]*model.User{42: {ID: 42, MfaRequired: 1}}}
	creds := &fakeCreds{}
	settings := &fakeSettings{enabled: true, enabledSet: true, methods: []string{"totp"}, methodsSet: true}

	cases := []struct {
		name string
		deps Deps
	}{
		{"Users 缺失", Deps{Creds: creds, Settings: settings}},
		{"Creds 缺失", Deps{Users: users, Settings: settings}},
		{"Settings 缺失", Deps{Users: users, Creds: creds}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := UsableFactors(context.Background(), tc.deps, 42); !errors.Is(err, ErrDepsUnavailable) {
				t.Errorf("UsableFactors err = %v, want ErrDepsUnavailable", err)
			}
			got, err := Required(context.Background(), tc.deps, 42)
			if !errors.Is(err, ErrDepsUnavailable) {
				t.Errorf("Required err = %v, want ErrDepsUnavailable", err)
			}
			if got {
				t.Error("Required = true, want false")
			}
			if got, err := Required(context.Background(), tc.deps, 0); err != nil || got {
				t.Errorf("Required(uid=0) = (%v, %v), want (false, nil)", got, err)
			}
			if factors, err := UsableFactors(context.Background(), tc.deps, 0); err != nil || factors != nil {
				t.Errorf("UsableFactors(uid=0) = (%v, %v), want (nil, nil)", factors, err)
			}
		})
	}
}
