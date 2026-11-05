// setpass_test.go 覆盖：直通注册（captcha 必经 +
// captcha_invalid 拦截）、otp 注册全链、signup_disabled 四开关、
// username_taken / target_taken / password_weak / 用户名规则、建号同事务
// credential 失败回滚、reset 全链（含 pwdep 递增与审计断言）、
// reset_disabled、未验后直达拒绝、login 流 set_password 拒绝、无 password
// 行补建。全部走 fake，不连 DB / Redis。
package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

// signupUsers 是 SignupUsers 的计数型 fake。
type signupUsers struct {
	byID       map[int64]*model.User
	byUsername map[string]*model.User
	byEmail    map[string]*model.User
	byPhone    map[string]*model.User
	created    []*model.User
	incEpoch   []int64
	nextID     int64
	nextEpoch  int16
	createErr  error
	creds      *signupCreds
}

func (u *signupUsers) FindByID(_ context.Context, id int64) (*model.User, error) {
	if m, ok := u.byID[id]; ok {
		return m, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (u *signupUsers) FindByUsername(_ context.Context, username string) (*model.User, error) {
	if m, ok := u.byUsername[username]; ok {
		return m, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (u *signupUsers) FindByPhone(_ context.Context, phone string) (*model.User, error) {
	if m, ok := u.byPhone[phone]; ok {
		return m, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (u *signupUsers) FindByEmail(_ context.Context, email string) (*model.User, error) {
	if m, ok := u.byEmail[email]; ok {
		return m, nil
	}
	return nil, gorm.ErrRecordNotFound
}

// CreateWithCredential 模拟同事务建号（§7.4 行 1025）：事务内 user INSERT
// 回填 ID 与 default tag，再 credential INSERT；后者失败整体回滚——user
// 行不落库（自增 ID 与真库一致已消耗不回退；m.ID 回填不撤销，gorm 真库
// 同口径，service 失败路径不读它）。
func (u *signupUsers) CreateWithCredential(ctx context.Context, m *model.User, c *model.UserCredential) error {
	if u.createErr != nil {
		return u.createErr
	}
	u.nextID++
	m.ID = u.nextID
	// 模拟 GORM default tag 回填（model.User 注释：零值字段被 tag 值显式
	// 写入并回填 struct，user_status=1 / mfa_required=0）。
	if m.UserStatus == 0 {
		m.UserStatus = 1
	}
	c.UserID = m.ID
	if err := u.creds.Create(ctx, c); err != nil {
		return err
	}
	u.created = append(u.created, m)
	return nil
}

func (u *signupUsers) IncEpoch(_ context.Context, id int64) (int16, error) {
	u.incEpoch = append(u.incEpoch, id)
	u.nextEpoch++
	return u.nextEpoch, nil
}

// signupCreds 是 SignupCredentials 的计数型 fake（按 uid 存 password 行）；
// createErr 非空时 Create 失败（注入 credential 写失败验证回滚）。
type signupCreds struct {
	rows      map[int64]*model.UserCredential
	created   []int64
	updated   []int64
	createErr error
}

func (c *signupCreds) FindByUserAndKind(_ context.Context, userID int64, _ string) (*model.UserCredential, error) {
	if m, ok := c.rows[userID]; ok {
		return m, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (c *signupCreds) Create(_ context.Context, m *model.UserCredential) error {
	if c.createErr != nil {
		return c.createErr
	}
	c.created = append(c.created, m.UserID)
	c.rows[m.UserID] = m
	return nil
}

func (c *signupCreds) Update(_ context.Context, m *model.UserCredential) error {
	c.updated = append(c.updated, m.UserID)
	c.rows[m.UserID] = m
	return nil
}

// fakeEpochSync 记录 Sync 收到的 (uid, epoch)。
type fakeEpochSync struct {
	got []epochSyncCall
	err error
}

type epochSyncCall struct {
	uid   int64
	epoch int16
}

func (f *fakeEpochSync) Sync(_ context.Context, uid int64, epoch int16) error {
	f.got = append(f.got, epochSyncCall{uid: uid, epoch: epoch})
	return f.err
}

// fakeAudit 记录 RecordReset 收到的事件。
type fakeAudit struct {
	got []resetAuditEvent
}

type resetAuditEvent struct {
	uid   int64
	epoch int16
	amr   []string
}

func (f *fakeAudit) RecordReset(_ context.Context, uid int64, epoch int16, amr []string) {
	f.got = append(f.got, resetAuditEvent{uid: uid, epoch: epoch, amr: amr})
}

// otpEmailRegisterFactor register 语义的 otp_email 因子：verify 通过不带
// uid（用户尚未建号，建号在 set_password 步）。
func otpEmailRegisterFactor() *fakeFactor {
	return &fakeFactor{
		kind:   factor.FactorOTPEmail,
		usages: []factor.Usage{factor.UsagePrimary, factor.UsageSecondary},
		steps:  []factor.StepKind{factor.StepChallenge, factor.StepForm},
		verify: func(*factor.FactorContext) (*factor.VerifyResult, error) {
			return &factor.VerifyResult{Passed: true}, nil
		},
	}
}

// passwordOnlyFactor 直通注册仅需注册表内存在 password 因子（不执行 verify）。
func passwordOnlyFactor() *fakeFactor {
	return &fakeFactor{
		kind:   factor.FactorPassword,
		usages: []factor.Usage{factor.UsagePrimary},
		steps:  []factor.StepKind{factor.StepForm},
	}
}

// newSetPassDeps 汇总 set_password 步的全 fake 依赖。
type setPassFakes struct {
	users *signupUsers
	creds *signupCreds
	epoch *fakeEpochSync
	audit *fakeAudit
}

func newSetPassFakes() *setPassFakes {
	f := &setPassFakes{
		users: &signupUsers{
			byID:       map[int64]*model.User{},
			byUsername: map[string]*model.User{},
			byEmail:    map[string]*model.User{},
			byPhone:    map[string]*model.User{},
		},
		creds: &signupCreds{rows: map[int64]*model.UserCredential{}},
		epoch: &fakeEpochSync{},
		audit: &fakeAudit{},
	}
	// 建号同事务 fake：signupUsers.CreateWithCredential 委托 signupCreds
	// 写 credential 行（真库语义：单事务两跳，credential 失败整体回滚）。
	f.users.creds = f.creds
	return f
}

func (f *setPassFakes) deps(s SettingsReader) *SetPassDeps {
	return &SetPassDeps{
		Users:       f.users,
		Credentials: f.creds,
		Epoch:       f.epoch,
		Audit:       f.audit,
		Settings:    s,
	}
}

const (
	testStrongPassword = "Str0ngPassw0rd"
	testWeakPassword   = "123456"
)

// TestRegisterDirectCaptchaRequiredAndInvalid 直通入口 captcha 必经
// （§2.3 行 450-451）：缺失 → captcha_required；渠道不符 → captcha_invalid。
func TestRegisterDirectCaptchaRequiredAndInvalid(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorPassword] = passwordOnlyFactor()
	fk := newSetPassFakes()
	e := deps.engine(testState(t, at))
	e.setpass = fk.deps(deps.settings)

	got := e.Submit(context.Background(), "register", Request{
		Method: "password", Step: "set_password",
		Payload: &factor.Payload{Username: "alice01", Password: testStrongPassword},
	})
	if got.Status != "captcha_required" {
		t.Fatalf("status = %q, want captcha_required", got.Status)
	}
	if got.Captcha == nil || got.Captcha.ProviderKey != "builtin_image" {
		t.Fatalf("captcha = %+v, want builtin_image config", got.Captcha)
	}

	bogus := captchaSubmission()
	bogus.ProviderKey = "other"
	got = e.Submit(context.Background(), "register", Request{
		Method: "password", Step: "set_password", Captcha: bogus,
		Payload: &factor.Payload{Username: "alice01", Password: testStrongPassword},
	})
	if got.Status != "captcha_invalid" {
		t.Fatalf("status = %q, want captcha_invalid", got.Status)
	}
	if len(fk.users.created) != 0 {
		t.Fatalf("created = %d, want 0（captcha 拦截不建号）", len(fk.users.created))
	}
}

// TestRegisterDirectSuccess 直通注册：合规 username / password + captcha →
// success + 建号（无 phone/email）+ password credential + 会话。
func TestRegisterDirectSuccess(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorPassword] = passwordOnlyFactor()
	fk := newSetPassFakes()
	e := deps.engine(testState(t, at))
	e.setpass = fk.deps(deps.settings)

	got := e.Submit(context.Background(), "register", Request{
		Method: "password", Step: "set_password", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Username: "alice01", Password: testStrongPassword},
	})
	if got.Status != StatusSuccess {
		t.Fatalf("status = %q, want success", got.Status)
	}
	if got.LoginToken != "" {
		t.Fatalf("success must not return login_token, got %q", got.LoginToken)
	}
	if len(fk.users.created) != 1 {
		t.Fatalf("created users = %d, want 1", len(fk.users.created))
	}
	u := fk.users.created[0]
	if u.Username != "alice01" || u.Phone != nil || u.Email != nil || u.UserStatus != 1 {
		t.Fatalf("created user = %+v", u)
	}
	if len(fk.creds.created) != 1 || fk.creds.created[0] != u.ID {
		t.Fatalf("created creds = %v, want [%d]", fk.creds.created, u.ID)
	}
	if row := fk.creds.rows[u.ID]; row.Kind != "password" || row.IsEnabled != 1 || len(row.Secret) == 0 {
		t.Fatalf("credential row = %+v", row)
	}
	if deps.sessions.calls != 1 {
		t.Fatalf("session writes = %d, want 1", deps.sessions.calls)
	}
	if got.UserId != u.ID {
		t.Fatalf("userId = %d, want %d", got.UserId, u.ID)
	}
}

// TestRegisterCredentialFailureRollsBackUser 建号同事务（§7.4 行 1025）：
// credential 写失败时整体回滚——user 行不落库（不残留无凭证 username 占位
// 号）、无 credential 行、无会话、failed。
func TestRegisterCredentialFailureRollsBackUser(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorPassword] = passwordOnlyFactor()
	fk := newSetPassFakes()
	fk.creds.createErr = errors.New("credential insert failed")
	e := deps.engine(testState(t, at))
	e.setpass = fk.deps(deps.settings)

	got := e.Submit(context.Background(), "register", Request{
		Method: "password", Step: "set_password", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Username: "alice01", Password: testStrongPassword},
	})
	if got.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if len(fk.users.created) != 0 {
		t.Fatalf("created users = %d, want 0（credential 失败整体回滚，user 行不落库）", len(fk.users.created))
	}
	if len(fk.creds.created) != 0 {
		t.Fatalf("created creds = %v, want none", fk.creds.created)
	}
	if deps.sessions.calls != 0 {
		t.Fatalf("session writes = %d, want 0", deps.sessions.calls)
	}
}

// TestRegisterOTPFullChain otp_email 注册全链：challenge → verify（next 指向
// set_password，ch.target 保留、uid=0）→ set_password → success + 建号
// （email 落库且 verified=1）+ 会话。
func TestRegisterOTPFullChain(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	state := testState(t, at)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorOTPEmail] = otpEmailRegisterFactor()
	fk := newSetPassFakes()
	e := deps.engine(state)
	e.setpass = fk.deps(deps.settings)

	email := "alice@example.com"
	// challenge：目标不存在（注册入口）→ 发码 + next。
	resp := e.Submit(context.Background(), "register", Request{
		Method: "otp_email", Step: "challenge", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Email: email},
	})
	if resp.Status != StatusNext {
		t.Fatalf("challenge resp = %+v", resp)
	}

	// verify：通过 → next，next_step 指向 set_password（endpoint=Register）。
	resp = e.Submit(context.Background(), "register", Request{
		LoginToken: resp.LoginToken, Method: "otp_email", Step: "verify",
		Payload: &factor.Payload{Code: "123456"},
	})
	if resp.Status != StatusNext {
		t.Fatalf("verify resp = %+v", resp)
	}
	if resp.NextStep == nil || resp.NextStep.Kind != "form" ||
		resp.NextStep.Endpoint != endpointRegister || resp.NextStep.Method != "otp_email" {
		t.Fatalf("next_step = %+v", resp.NextStep)
	}
	var hasUsername, hasPassword bool
	for _, f := range resp.NextStep.Fields {
		if f.Name == "username" {
			hasUsername = true
		}
		if f.Name == "password" {
			hasPassword = true
		}
	}
	if !hasUsername || !hasPassword {
		t.Fatalf("next_step fields = %+v, want username+password", resp.NextStep.Fields)
	}
	p, err := state.Parse(resp.LoginToken)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.GetUid() != 0 || len(p.GetPassed()) != 1 || p.GetPassed()[0] != "otp_email" {
		t.Fatalf("verify token = %+v（uid 应为 0：register 未建号）", p)
	}
	if p.GetCh().GetTarget() != email || p.GetCh().GetPurpose() != "register" {
		t.Fatalf("challenge 保留 = %+v, want target=%s purpose=register", p.GetCh(), email)
	}

	// set_password：成功建号 + 直接登录。
	resp = e.Submit(context.Background(), "register", Request{
		LoginToken: resp.LoginToken, Method: "otp_email", Step: "set_password",
		Payload: &factor.Payload{Username: "alice01", Password: testStrongPassword},
	})
	if resp.Status != StatusSuccess {
		t.Fatalf("set_password resp = %+v", resp)
	}
	if len(fk.users.created) != 1 {
		t.Fatalf("created users = %d, want 1", len(fk.users.created))
	}
	u := fk.users.created[0]
	if u.Email == nil || *u.Email != email || u.EmailVerified != 1 {
		t.Fatalf("created user email = %+v, want %s verified=1", u.Email, email)
	}
	if len(fk.creds.created) != 1 || deps.sessions.calls != 1 {
		t.Fatalf("creds=%v sessions=%d", fk.creds.created, deps.sessions.calls)
	}
}

// TestRegisterSignupDisabledSwitches 注册四开关（§2.3 行 453、§1.6 行 257）。
func TestRegisterSignupDisabledSwitches(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		req   Request
		setup func(*fakeRegistry)
	}{
		{
			name: "allow_registration=false 直通",
			key:  settings.KeyAllowRegistration,
			req:  Request{Method: "password", Step: "set_password", Captcha: captchaSubmission(), Payload: &factor.Payload{Username: "alice01", Password: testStrongPassword}},
			setup: func(r *fakeRegistry) { r.factors[factor.FactorPassword] = passwordOnlyFactor() },
		},
		{
			name: "allow_signup_password=false 直通",
			key:  settings.KeyAllowSignupPassword,
			req:  Request{Method: "password", Step: "set_password", Captcha: captchaSubmission(), Payload: &factor.Payload{Username: "alice01", Password: testStrongPassword}},
			setup: func(r *fakeRegistry) { r.factors[factor.FactorPassword] = passwordOnlyFactor() },
		},
		{
			name: "allow_signup_phone=false otp_sms challenge",
			key:  settings.KeyAllowSignupPhone,
			req:  Request{Method: "otp_sms", Step: "challenge", Captcha: captchaSubmission(), Payload: &factor.Payload{Phone: "13800138000"}},
			setup: func(r *fakeRegistry) { r.factors[factor.FactorOTPSMS] = otpSMSFactor() },
		},
		{
			name: "allow_signup_email=false otp_email challenge",
			key:  settings.KeyAllowSignupEmail,
			req:  Request{Method: "otp_email", Step: "challenge", Captcha: captchaSubmission(), Payload: &factor.Payload{Email: "a@b.com"}},
			setup: func(r *fakeRegistry) { r.factors[factor.FactorOTPEmail] = otpEmailRegisterFactor() },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at := time.Unix(1_700_000_000, 0)
			deps := newTestDeps(t, at)
			tc.setup(deps.registry)
			fk := newSetPassFakes()
			e := deps.engine(testState(t, at))
			e.setpass = fk.deps(deps.settings)

			deps.settings.bools[tc.key] = false
			got := e.Submit(context.Background(), "register", tc.req)
			if got.Status != StatusSignupDisabled {
				t.Fatalf("status = %q, want signup_disabled", got.Status)
			}
			if len(fk.users.created) != 0 {
				t.Fatalf("created = %d, want 0", len(fk.users.created))
			}
		})
	}
}

// TestRegisterUsernameTaken 用户名占用 → username_taken（§1.6 行 256）。
func TestRegisterUsernameTaken(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorPassword] = passwordOnlyFactor()
	fk := newSetPassFakes()
	fk.users.byUsername["alice01"] = &model.User{ID: 9, Username: "alice01"}
	e := deps.engine(testState(t, at))
	e.setpass = fk.deps(deps.settings)

	got := e.Submit(context.Background(), "register", Request{
		Method: "password", Step: "set_password", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Username: "alice01", Password: testStrongPassword},
	})
	if got.Status != StatusUsernameTaken {
		t.Fatalf("status = %q, want username_taken", got.Status)
	}
	if len(fk.users.created) != 0 {
		t.Fatalf("created = %d, want 0", len(fk.users.created))
	}
}

// TestRegisterUsernameRule 用户名规则 ^[A-Za-z0-9_]{5,20}$ 违规 →
// invalid_request（§2.3 行 449 唯一定义处）。
func TestRegisterUsernameRule(t *testing.T) {
	for _, username := range []string{"ab", "a!b", "汉字用户名", "overlong_username_xyz"} {
		at := time.Unix(1_700_000_000, 0)
		deps := newTestDeps(t, at)
		deps.registry.factors[factor.FactorPassword] = passwordOnlyFactor()
		fk := newSetPassFakes()
		e := deps.engine(testState(t, at))
		e.setpass = fk.deps(deps.settings)

		got := e.Submit(context.Background(), "register", Request{
			Method: "password", Step: "set_password", Captcha: captchaSubmission(),
			Payload: &factor.Payload{Username: username, Password: testStrongPassword},
		})
		if got.Status != StatusInvalidRequest {
			t.Fatalf("username %q: status = %q, want invalid_request", username, got.Status)
		}
	}
}

// TestRegisterPasswordWeak 弱密码 → password_weak（§1.6 行 255、§5.6）。
func TestRegisterPasswordWeak(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorPassword] = passwordOnlyFactor()
	fk := newSetPassFakes()
	e := deps.engine(testState(t, at))
	e.setpass = fk.deps(deps.settings)

	got := e.Submit(context.Background(), "register", Request{
		Method: "password", Step: "set_password", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Username: "alice01", Password: testWeakPassword},
	})
	if got.Status != StatusPasswordWeak {
		t.Fatalf("status = %q, want password_weak", got.Status)
	}
	if len(fk.users.created) != 0 {
		t.Fatalf("created = %d, want 0", len(fk.users.created))
	}
}

// TestRegisterTargetTaken 注册目标（email）占用于他人 → target_taken
// （§1.6 行 256）。
func TestRegisterTargetTaken(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	state := testState(t, at)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorOTPEmail] = otpEmailRegisterFactor()
	fk := newSetPassFakes()
	e := deps.engine(state)
	e.setpass = fk.deps(deps.settings)

	// 造一个验后 token（ch.target = 已被占用的 email）。
	email := "taken@example.com"
	tok, err := state.Issue(&token.LoginTokenPayload{
		Tid: "tid-1", Flow: "register", Factor: "otp_email", Passed: []string{"otp_email"},
		Ch: &token.Challenge{Purpose: "register", Target: email},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	fk.users.byEmail[email] = &model.User{ID: 9, Email: &email}

	got := e.Submit(context.Background(), "register", Request{
		LoginToken: tok, Method: "otp_email", Step: "set_password",
		Payload: &factor.Payload{Username: "alice01", Password: testStrongPassword},
	})
	if got.Status != StatusTargetTaken {
		t.Fatalf("status = %q, want target_taken", got.Status)
	}
	if len(fk.users.created) != 0 {
		t.Fatalf("created = %d, want 0", len(fk.users.created))
	}
}

// TestResetFullChain reset 全链（已绑定且已验证目标）：challenge → verify →
// set_password → success + credential 更新 + IncEpoch + epoch 同步 + 审计
// + 会话（§2.4、§10.4 行 1532）。
func TestResetFullChain(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	state := testState(t, at)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorOTPEmail] = otpEmailFactor() // verify 带 UID=42
	fk := newSetPassFakes()
	e := deps.engine(state)
	e.setpass = fk.deps(deps.settings)

	email := "alice@example.com"
	fk.users.byEmail[email] = &model.User{ID: 42, Username: "alice", Email: &email, EmailVerified: 1}
	fk.users.byID[42] = fk.users.byEmail[email]
	fk.creds.rows[42] = &model.UserCredential{ID: 7, UserID: 42, Kind: "password", Secret: []byte("old-hash"), IsEnabled: 1}

	// challenge：已绑定且已验证 → 发码 + next。
	resp := e.Submit(context.Background(), "reset", Request{
		Method: "otp_email", Step: "challenge", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Email: email},
	})
	if resp.Status != StatusNext {
		t.Fatalf("challenge resp = %+v", resp)
	}

	// verify：通过 → next（next_step 指向 set_password，endpoint=ResetPassword）。
	resp = e.Submit(context.Background(), "reset", Request{
		LoginToken: resp.LoginToken, Method: "otp_email", Step: "verify",
		Payload: &factor.Payload{Code: "123456"},
	})
	if resp.Status != StatusNext {
		t.Fatalf("verify resp = %+v", resp)
	}
	if resp.NextStep == nil || resp.NextStep.Kind != "form" || resp.NextStep.Endpoint != endpointReset {
		t.Fatalf("next_step = %+v", resp.NextStep)
	}
	for _, f := range resp.NextStep.Fields {
		if f.Name == "username" {
			t.Fatalf("reset next_step fields = %+v, want password only", resp.NextStep.Fields)
		}
	}

	// set_password：成功 + credential 更新 + epoch 递增同步 + 审计 + 会话。
	resp = e.Submit(context.Background(), "reset", Request{
		LoginToken: resp.LoginToken, Method: "otp_email", Step: "set_password",
		Payload: &factor.Payload{Password: "RenewedPassw0rd"},
	})
	if resp.Status != StatusSuccess {
		t.Fatalf("set_password resp = %+v", resp)
	}
	if len(fk.creds.updated) != 1 || fk.creds.updated[0] != 42 {
		t.Fatalf("updated creds = %v, want [42]", fk.creds.updated)
	}
	row := fk.creds.rows[42]
	if string(row.Secret) == "old-hash" || row.IsEnabled != 1 {
		t.Fatalf("credential row = %+v, want new secret enabled", row)
	}
	if len(fk.users.incEpoch) != 1 || fk.users.incEpoch[0] != 42 {
		t.Fatalf("incEpoch = %v, want [42]", fk.users.incEpoch)
	}
	if len(fk.epoch.got) != 1 || fk.epoch.got[0].uid != 42 || fk.epoch.got[0].epoch != 1 {
		t.Fatalf("epoch sync = %+v, want (42,1)", fk.epoch.got)
	}
	if len(fk.audit.got) != 1 || fk.audit.got[0].uid != 42 || fk.audit.got[0].epoch != 1 {
		t.Fatalf("audit = %+v", fk.audit.got)
	}
	if deps.sessions.calls != 1 || resp.UserId != 42 {
		t.Fatalf("sessions=%d userId=%d, want 1/42", deps.sessions.calls, resp.UserId)
	}
}

// TestResetDisabled allow_password_reset=false 时 challenge 与后续各 step
// 一律 reset_disabled（§2.4 行 471：不发码、不校验）。
func TestResetDisabled(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	state := testState(t, at)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorOTPEmail] = otpEmailFactor()
	fk := newSetPassFakes()
	e := deps.engine(state)
	e.setpass = fk.deps(deps.settings)
	deps.settings.bools[settings.KeyAllowPasswordReset] = false

	got := e.Submit(context.Background(), "reset", Request{
		Method: "otp_email", Step: "challenge", Captcha: captchaSubmission(),
		Payload: &factor.Payload{Email: "alice@example.com"},
	})
	if got.Status != StatusResetDisabled {
		t.Fatalf("challenge status = %q, want reset_disabled", got.Status)
	}

	// 验后 token 的 set_password 同样 reset_disabled。
	tok, err := state.Issue(&token.LoginTokenPayload{
		Tid: "tid-1", Flow: "reset", Factor: "otp_email", Uid: 42, Passed: []string{"otp_email"},
		Ch: &token.Challenge{Purpose: "reset", Target: "alice@example.com"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got = e.Submit(context.Background(), "reset", Request{
		LoginToken: tok, Method: "otp_email", Step: "set_password",
		Payload: &factor.Payload{Password: "RenewedPassw0rd"},
	})
	if got.Status != StatusResetDisabled {
		t.Fatalf("set_password status = %q, want reset_disabled", got.Status)
	}
	if len(fk.users.incEpoch) != 0 {
		t.Fatalf("incEpoch = %v, want none（不校验不落库）", fk.users.incEpoch)
	}
}

// TestResetAndLoginRejectInvalidSetPassword 未验后直达 set_password 与
// login 流 set_password 均拒绝（§1.4 行 165 注册 / 重置专用；防跳过验证）。
func TestResetAndLoginRejectInvalidSetPassword(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorOTPEmail] = otpEmailFactor()
	fk := newSetPassFakes()
	e := deps.engine(testState(t, at))
	e.setpass = fk.deps(deps.settings)

	// reset 无 token（未过 challenge / verify）直达 set_password。
	got := e.Submit(context.Background(), "reset", Request{
		Method: "otp_email", Step: "set_password",
		Payload: &factor.Payload{Password: "RenewedPassw0rd"},
	})
	if got.Status != StatusStepInvalid {
		t.Fatalf("reset direct status = %q, want step_invalid", got.Status)
	}

	// login 流不接受 set_password。
	got = e.Submit(context.Background(), "login", Request{
		Method: "otp_email", Step: "set_password",
		Payload: &factor.Payload{Password: "RenewedPassw0rd"},
	})
	if got.Status != StatusStepInvalid {
		t.Fatalf("login set_password status = %q, want step_invalid", got.Status)
	}
}

// TestResetNoCredentialRowCreates 无 password 行（如三方免密建号）时按
// 「设置密码」同构补建（docs 未明说该分支，默认口径，待定）。
func TestResetNoCredentialRowCreates(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	state := testState(t, at)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorOTPEmail] = otpEmailFactor()
	fk := newSetPassFakes()
	email := "alice@example.com"
	fk.users.byID[42] = &model.User{ID: 42, Username: "alice", Email: &email, EmailVerified: 1}
	e := deps.engine(state)
	e.setpass = fk.deps(deps.settings)

	tok, err := state.Issue(&token.LoginTokenPayload{
		Tid: "tid-1", Flow: "reset", Factor: "otp_email", Uid: 42, Passed: []string{"otp_email"}, Amr: []string{"otp_email"},
		Ch: &token.Challenge{Purpose: "reset", Target: email},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	got := e.Submit(context.Background(), "reset", Request{
		LoginToken: tok, Method: "otp_email", Step: "set_password",
		Payload: &factor.Payload{Password: "RenewedPassw0rd"},
	})
	if got.Status != StatusSuccess {
		t.Fatalf("resp = %+v, want success", got)
	}
	if len(fk.creds.created) != 1 || fk.creds.created[0] != 42 || len(fk.creds.updated) != 0 {
		t.Fatalf("creds created=%v updated=%v, want created=[42]", fk.creds.created, fk.creds.updated)
	}
}
