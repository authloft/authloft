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
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/repo"
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
// 同口径，service 失败路径不读它）。c 为 nil 时只建 user 行（三方
// 免密建号，repo 同款 nil 分支）。
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
	if c != nil {
		c.UserID = m.ID
		if err := u.creds.Create(ctx, c); err != nil {
			return err
		}
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

// fakeThirdpartySignup ThirdpartySignup 的 fake（tp 分支）：SignupState
// 返回预置状态；CreateBind 留档并支持错误注入 / 恢复重试。
type fakeThirdpartySignup struct {
	state     ThirdpartySignupState
	stateErr  error
	created   []*model.UserThirdpartyBind
	unionArgs []string // 每次 CreateBind 的 (unionProviderKey, unionID)
	createErr error
}

func (f *fakeThirdpartySignup) SignupState(context.Context, string) (ThirdpartySignupState, error) {
	return f.state, f.stateErr
}

func (f *fakeThirdpartySignup) CreateBind(_ context.Context, b *model.UserThirdpartyBind, unionProviderKey, unionID string) error {
	if f.createErr != nil {
		return f.createErr
	}
	bb := *b
	f.created = append(f.created, &bb)
	f.unionArgs = append(f.unionArgs, unionProviderKey+"|"+unionID)
	return nil
}

// newSetPassDeps 汇总 set_password 步的全 fake 依赖。
type setPassFakes struct {
	users      *signupUsers
	creds      *signupCreds
	epoch      *fakeEpochSync
	audit      *fakeAudit
	thirdparty *fakeThirdpartySignup
}

func newSetPassFakes() *setPassFakes {
	f := &setPassFakes{
		users: &signupUsers{
			byID:       map[int64]*model.User{},
			byUsername: map[string]*model.User{},
			byEmail:    map[string]*model.User{},
			byPhone:    map[string]*model.User{},
		},
		creds:      &signupCreds{rows: map[int64]*model.UserCredential{}},
		epoch:      &fakeEpochSync{},
		audit:      &fakeAudit{},
		thirdparty: &fakeThirdpartySignup{state: ThirdpartySignupState{Enabled: true}},
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
		Thirdparty:  f.thirdparty,
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

// —— 三方免密建号（§12.5 行 1501-1505、§2.7.5 行 685）——

// tpLoginToken 签一枚 flow=login + tp 的 login_token（LoginOauth
// binding_required 重签形态，§12.5 行 1501）。
func tpLoginToken(t *testing.T, s *State) string {
	t.Helper()
	tok, err := s.Issue(&token.LoginTokenPayload{
		Tid:  "tid-tp",
		Flow: "login",
		Tp: &token.ThirdParty{
			ProviderKey: "qq", OpenId: "openid_1", UnionId: "union_1",
			Nickname: "QQ 用户", AvatarUrl: "https://q.cn/a.png",
		},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

// newTPSubmitDeps 组装 tp 分支用例的引擎依赖（password 因子注册表 +
// setpass fakes；tp 分支不经 captcha / verify）。返回 settings 供用例
// 运行期覆写注册开关。
func newTPSubmitDeps(t *testing.T, at time.Time) (*Engine, *setPassFakes, *State, *testSettings) {
	t.Helper()
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorPassword] = passwordOnlyFactor()
	fk := newSetPassFakes()
	st := testState(t, at)
	e := deps.engine(st)
	e.setpass = fk.deps(deps.settings)
	return e, fk, st, deps.settings
}

// TestThirdpartySignupIgnoresPassword tp 分支仅收 username、忽略 password
//（§2.7.5 行 685）：带 password 请求成功建号且无 password credential 行；
// flow=login 由 Register 端点接受（§12.5 行 1505）；不提交 captcha 亦成功
//（tp 分支不经 captcha，此处默认口径）。
func TestThirdpartySignupIgnoresPassword(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	e, fk, st, _ := newTPSubmitDeps(t, at)
	tok := tpLoginToken(t, st)

	got := e.Submit(context.Background(), "register", Request{
		LoginToken: tok, Method: "password", Step: "set_password",
		Payload: &factor.Payload{Username: "alice_tp", Password: testWeakPassword},
	})
	if got.Status != StatusSuccess {
		t.Fatalf("resp = %+v, want success（弱密码应被忽略）", got)
	}
	// 免密建号：user 行建立、无 password credential。
	if len(fk.users.created) != 1 || fk.users.created[0].Username != "alice_tp" {
		t.Fatalf("created users = %+v", fk.users.created)
	}
	if len(fk.creds.created) != 0 {
		t.Errorf("免密建号不应写 credential, got %v", fk.creds.created)
	}
	// 绑定行：pk/openid/nickname/avatar + Union 参数（§12.7 行 1548）。
	if len(fk.thirdparty.created) != 1 {
		t.Fatalf("绑定写入 %d 行", len(fk.thirdparty.created))
	}
	b := fk.thirdparty.created[0]
	if b.ProviderKey != "qq" || b.OpenID != "openid_1" || b.Nickname != "QQ 用户" || b.UserID == 0 {
		t.Errorf("绑定行 = %+v", b)
	}
	if got.UserId == 0 || got.SessionId == "" {
		t.Errorf("success 信封 = %+v", got)
	}
}

// TestThirdpartySignupNoPassword 不带 password 的请求同样成功（「仅收
// username」的正向形态）。
func TestThirdpartySignupNoPassword(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	e, _, st, _ := newTPSubmitDeps(t, at)
	got := e.Submit(context.Background(), "register", Request{
		LoginToken: tpLoginToken(t, st), Method: "password", Step: "set_password",
		Payload: &factor.Payload{Username: "bob_tp"},
	})
	if got.Status != StatusSuccess {
		t.Fatalf("resp = %+v, want success", got)
	}
}

// TestThirdpartySignupValidations tp 分支的 username 校验沿用 register
// 既有口径：缺失 / 规则违规 → invalid_request；占用 → username_taken。
func TestThirdpartySignupValidations(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	e, fk, st, _ := newTPSubmitDeps(t, at)
	fk.users.byUsername["carol_tp"] = &model.User{ID: 99, Username: "carol_tp"}
	tok := tpLoginToken(t, st)

	for _, tc := range []struct {
		name     string
		username string
		want     string
	}{
		{"缺失", "", StatusInvalidRequest},
		{"规则违规", "ab", StatusInvalidRequest},
		{"占用", "carol_tp", StatusUsernameTaken},
	} {
		got := e.Submit(context.Background(), "register", Request{
			LoginToken: tok, Method: "password", Step: "set_password",
			Payload: &factor.Payload{Username: tc.username},
		})
		if got.Status != tc.want {
			t.Errorf("%s: status = %q, want %q", tc.name, got.Status, tc.want)
		}
	}
	if len(fk.users.created) != 0 {
		t.Errorf("失败用例不应建号, got %d", len(fk.users.created))
	}
}

// TestThirdpartySignupDisabled provider enable_signup=0 → signup_disabled
//（§12.5 行 1504；provider 失效 stateErr 同走 failed）。
func TestThirdpartySignupDisabled(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	e, fk, st, _ := newTPSubmitDeps(t, at)
	fk.thirdparty.state = ThirdpartySignupState{Enabled: false, UnionKey: ""}

	got := e.Submit(context.Background(), "register", Request{
		LoginToken: tpLoginToken(t, st), Method: "password", Step: "set_password",
		Payload: &factor.Payload{Username: "dave_tp"},
	})
	if got.Status != StatusSignupDisabled {
		t.Fatalf("status = %q, want signup_disabled", got.Status)
	}
	if len(fk.users.created) != 0 {
		t.Errorf("不应建号, got %d", len(fk.users.created))
	}

	// provider 失效（查询错误）→ failed。
	fk.thirdparty.stateErr = errors.New("provider gone")
	got = e.Submit(context.Background(), "register", Request{
		LoginToken: tpLoginToken(t, st), Method: "password", Step: "set_password",
		Payload: &factor.Payload{Username: "dave_tp"},
	})
	if got.Status != StatusFailed {
		t.Errorf("stateErr: status = %q, want failed", got.Status)
	}
}

// TestThirdpartySignupBindRetry 绑定写入失败 → failed，tp 仍在 login_token
// 可重试（默认分步边界）；重试（bind 恢复）换用户名后成功。
func TestThirdpartySignupBindRetry(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	e, fk, st, _ := newTPSubmitDeps(t, at)
	tok := tpLoginToken(t, st)

	// 第一次：bind 失败 → failed（user 已建）。
	fk.thirdparty.createErr = errors.New("db down")
	got := e.Submit(context.Background(), "register", Request{
		LoginToken: tok, Method: "password", Step: "set_password",
		Payload: &factor.Payload{Username: "erin_tp"},
	})
	if got.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if len(fk.thirdparty.created) != 0 {
		t.Errorf("bind 失败不应留档, got %d", len(fk.thirdparty.created))
	}

	// 重试：bind 恢复，同一 login_token（tp 仍在）→ 换用户名建号成功。
	fk.thirdparty.createErr = nil
	got = e.Submit(context.Background(), "register", Request{
		LoginToken: tok, Method: "password", Step: "set_password",
		Payload: &factor.Payload{Username: "erin_tp2"},
	})
	if got.Status != StatusSuccess {
		t.Fatalf("重试 status = %q, want success", got.Status)
	}
	if len(fk.thirdparty.created) != 1 {
		t.Errorf("重试后绑定行 = %d, want 1", len(fk.thirdparty.created))
	}
}

// TestThirdpartySignupBindDuplicate bind 命中唯一键（三方身份已绑他号）
// → target_taken（§1.6 行 256）。
func TestThirdpartySignupBindDuplicate(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	e, fk, st, _ := newTPSubmitDeps(t, at)
	fk.thirdparty.createErr = fmt.Errorf("bind repo: create with union: %w: %w",
		repo.ErrBindDuplicate, errors.New("1062"))

	got := e.Submit(context.Background(), "register", Request{
		LoginToken: tpLoginToken(t, st), Method: "password", Step: "set_password",
		Payload: &factor.Payload{Username: "frank_tp"},
	})
	if got.Status != StatusTargetTaken {
		t.Fatalf("status = %q, want target_taken", got.Status)
	}
}

// TestThirdpartySignupUnionPassthrough SignupState 的 UnionKey / tp 载荷
// unionid 透传到 CreateBind（§12.7 行 1548：Union 行同事务）。
func TestThirdpartySignupUnionPassthrough(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	e, fk, st, _ := newTPSubmitDeps(t, at)
	fk.thirdparty.state = ThirdpartySignupState{Enabled: true, UnionKey: "qq_union"}

	got := e.Submit(context.Background(), "register", Request{
		LoginToken: tpLoginToken(t, st), Method: "password", Step: "set_password",
		Payload: &factor.Payload{Username: "grace_tp"},
	})
	if got.Status != StatusSuccess {
		t.Fatalf("status = %q, want success", got.Status)
	}
	if len(fk.thirdparty.unionArgs) != 1 || fk.thirdparty.unionArgs[0] != "qq_union|union_1" {
		t.Errorf("Union 透传 = %v, want [qq_union|union_1]", fk.thirdparty.unionArgs)
	}
}

// TestThirdpartySignupNilDeps 未注入 Thirdparty 依赖 → failed（半装配防御）。
func TestThirdpartySignupNilDeps(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	deps := newTestDeps(t, at)
	deps.registry.factors[factor.FactorPassword] = passwordOnlyFactor()
	fk := newSetPassFakes()
	e := deps.engine(testState(t, at))
	d := fk.deps(deps.settings)
	d.Thirdparty = nil
	e.setpass = d

	got := e.Submit(context.Background(), "register", Request{
		LoginToken: tpLoginToken(t, testState(t, at)), Method: "password", Step: "set_password",
		Payload: &factor.Payload{Username: "heidi_tp"},
	})
	if got.Status != StatusFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
}

// TestThirdpartySignupSignupPasswordSwitch tp 免密建号跳过
// allow_signup_password（三方建号开关唯一归 provider enable_signup，
// §2.7.5 行 673 / §12.5 行 1504）、保留 allow_registration（整体开关
// fail-closed）；普通注册（tp 空）仍受 allow_signup_password 管。
func TestThirdpartySignupSignupPasswordSwitch(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)

	t.Run("allow_signup_password=0 + tp 建号仍成功", func(t *testing.T) {
		e, fk, st, s := newTPSubmitDeps(t, at)
		s.bools[settings.KeyAllowSignupPassword] = false
		fk.thirdparty.state = ThirdpartySignupState{Enabled: true}

		got := e.Submit(context.Background(), "register", Request{
			LoginToken: tpLoginToken(t, st), Method: "password", Step: "set_password",
			Payload: &factor.Payload{Username: "ivy_tp"},
		})
		if got.Status != StatusSuccess {
			t.Fatalf("status = %q, want success（tp 分支不受 allow_signup_password 管）", got.Status)
		}
		if len(fk.users.created) != 1 {
			t.Errorf("建号 = %d, want 1", len(fk.users.created))
		}
	})

	t.Run("allow_registration=0 → tp 建号仍拒绝", func(t *testing.T) {
		e, _, st, s := newTPSubmitDeps(t, at)
		s.bools[settings.KeyAllowRegistration] = false

		got := e.Submit(context.Background(), "register", Request{
			LoginToken: tpLoginToken(t, st), Method: "password", Step: "set_password",
			Payload: &factor.Payload{Username: "jack_tp"},
		})
		if got.Status != StatusSignupDisabled {
			t.Fatalf("status = %q, want signup_disabled（allow_registration fail-closed）", got.Status)
		}
	})

	t.Run("普通注册仍受 allow_signup_password 管", func(t *testing.T) {
		e, _, _, s := newTPSubmitDeps(t, at)
		s.bools[settings.KeyAllowSignupPassword] = false

		got := e.Submit(context.Background(), "register", Request{
			LoginToken: "", Method: "password", Step: "set_password",
			Payload: &factor.Payload{Username: "kate_tp", Password: testStrongPassword},
		})
		if got.Status != StatusSignupDisabled {
			t.Fatalf("status = %q, want signup_disabled（普通直通注册受方式开关管）", got.Status)
		}
	})
}
