// bindcontact_test.go account 域手机 / 邮箱换绑族 service 层单测
//（不连 DB / Redis，全 fake 注入：真 *otp.Service + fake Store 精确回放
// SendResult / VerifyResult；真 *captcha.Gate + fake settings / catalog /
// verifier 照 captcha/gate_test.go 与 service/qrcode_test.go 惯例；审计
// 复用同包 fakeAudit）。覆盖：challenge 全链（成功、captcha 缺失 / 无效、
// 占用他人、命中自己幂等零动作、限流 deny 两形态、渠道未配置码保留）/
// verify 全链（成功列更新参数与审计逐字段、invalid_code 含剩余次数与
// owner=uid 传参、too_many_attempts、code_expired、格式非法不消耗尝试、
// TOCTOU 唯一键冲突、uid 用户不存在、step 非法）。
package account

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/internal/cache"
	"authloft/internal/captcha"
	"authloft/internal/eventlog"
	core "authloft/internal/otp"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// —— fake 全家（Bind 前缀命名避免与同包既有 fake 冲突）——

// bindTestUID 当前会话 uid 样例；bindTestUIDStr 为其字符串形态（码内
// owner 的期望值）。
const (
	bindTestUID    = int64(10086)
	bindTestUIDStr = "10086"
)

// fakeBindUsers BindContactStore 的 fake：存在性 / 占用回放 + 列更新
// 入参记录 + 错误注入（同 fakeProfileStore 风格）。
type fakeBindUsers struct {
	self     *model.User            // nil → FindByID 回放包装 ErrRecordNotFound
	occupied map[string]*model.User // target → 占用行（FindByPhone / FindByEmail 共用）

	updateCalls []bindContactUpdate
	updateErr   error
}

// bindContactUpdate UpdateContactColumns 入参记录。
type bindContactUpdate struct {
	id                        int64
	phone, email              *string
	phoneVerified, emailVerified *int8
}

func (f *fakeBindUsers) FindByID(context.Context, int64) (*model.User, error) {
	if f.self == nil {
		return nil, fmt.Errorf("user repo: find by id: %w", gorm.ErrRecordNotFound)
	}
	return f.self, nil
}

func (f *fakeBindUsers) FindByPhone(_ context.Context, phone string) (*model.User, error) {
	if u, ok := f.occupied[phone]; ok {
		return u, nil
	}
	return nil, fmt.Errorf("user repo: find by phone: %w", gorm.ErrRecordNotFound)
}

func (f *fakeBindUsers) FindByEmail(_ context.Context, email string) (*model.User, error) {
	if u, ok := f.occupied[email]; ok {
		return u, nil
	}
	return nil, fmt.Errorf("user repo: find by email: %w", gorm.ErrRecordNotFound)
}

func (f *fakeBindUsers) UpdateContactColumns(_ context.Context, id int64, phone, email *string, phoneVerified, emailVerified *int8) error {
	f.updateCalls = append(f.updateCalls, bindContactUpdate{
		id: id, phone: phone, email: email,
		phoneVerified: phoneVerified, emailVerified: emailVerified,
	})
	return f.updateErr
}

// fakeBindOTPStore core.Store 的 fake：真 *otp.Service 的存储底座，精确
// 回放 SendResult / VerifyResult，并记录 Issue / Check 全部入参。
type fakeBindOTPStore struct {
	sends       []bindIssueCall
	sendResult  cache.SendResult
	sendErr     error
	verifies    []bindCheckCall
	verifyRes   cache.VerifyResult
	attemptsLeft int64
	verifyErr   error
}

// bindIssueCall Issue 的入参记录（store.Send 的参数）。
type bindIssueCall struct {
	target, purpose, owner, ip, code string
}

// bindCheckCall Check 的入参记录（store.Verify 的参数）。
type bindCheckCall struct {
	target, purpose, owner, code string
}

func (f *fakeBindOTPStore) Send(_ context.Context, target, purpose, owner, ip, code string) (cache.SendResult, error) {
	f.sends = append(f.sends, bindIssueCall{target: target, purpose: purpose, owner: owner, ip: ip, code: code})
	if f.sendErr != nil {
		return cache.SendResult(-1), f.sendErr
	}
	return f.sendResult, nil
}

func (f *fakeBindOTPStore) Verify(_ context.Context, target, purpose, owner, code string) (cache.CodeVerifyResult, error) {
	f.verifies = append(f.verifies, bindCheckCall{target: target, purpose: purpose, owner: owner, code: code})
	if f.verifyErr != nil {
		return cache.CodeVerifyResult{Result: cache.VerifyMissing}, f.verifyErr
	}
	return cache.CodeVerifyResult{Result: f.verifyRes, AttemptsLeft: f.attemptsLeft}, nil
}

// fakeBindSender BindCodeSender 的 fake：记录投递 target + 错误注入。
type fakeBindSender struct {
	calls []string
	err   error
}

func (f *fakeBindSender) SendCode(_ context.Context, target, _ string) error {
	f.calls = append(f.calls, target)
	return f.err
}

// fakeBindSettings captcha.Settings 的 fake：无配置（阈值回落默认）。
type fakeBindSettings struct{}

func (fakeBindSettings) GetInt64(string) (int64, bool) { return 0, false }

// fakeBindCatalog captcha.ProviderCatalog 的 fake：p 为 nil 时返回 nil 降级
// 内置图形码（gate.go 降级路径，gate_test.go 同款）；非 nil 时回放指定
// Provider，用于核对 captcha 失败错误载荷携带的配置与 gate 判定同源。
type fakeBindCatalog struct{ p *captcha.Provider }

func (f fakeBindCatalog) Current(context.Context) (*captcha.Provider, error) { return f.p, nil }

// fakeBindCaptchaVerifier captcha.Verifier 的 fake：err 控制放行 / 无效 /
// 基础设施错误。
type fakeBindCaptchaVerifier struct{ err error }

func (f *fakeBindCaptchaVerifier) Verify(context.Context, string, captcha.Submission) error {
	return f.err
}

// —— 测试环境 ——

// bindTestEnv 单测装配（service/qrcode_test.go 环境惯例）。
type bindTestEnv struct {
	users    *fakeBindUsers
	store    *fakeBindOTPStore
	sender   *fakeBindSender
	verifier *fakeBindCaptchaVerifier
	audit    *fakeAudit
	svc      *BindContactService
	now      time.Time
}

// newBindTestEnv 全绿装配：uid 用户行存在、目标未被占用、验证码全默认
// 参数、captcha 放行（Submission 需配 builtin_image）。
func newBindTestEnv() *bindTestEnv {
	now := time.Unix(1730000000, 0).UTC()
	env := &bindTestEnv{
		users:    &fakeBindUsers{self: bindTestUser(), occupied: map[string]*model.User{}},
		store:    &fakeBindOTPStore{},
		sender:   &fakeBindSender{},
		verifier: &fakeBindCaptchaVerifier{},
		audit:    &fakeAudit{},
		now:      now,
	}
	env.svc = NewBindContactService(BindContactDeps{
		Users:  env.users,
		OTP:    core.NewService(env.store, core.DefaultConfig()),
		Sender: env.sender,
		Gate:   captcha.NewGate(fakeBindSettings{}, fakeBindCatalog{}, env.verifier),
		Config: core.DefaultConfig(),
		Audit:  env.audit,
		Now:    func() time.Time { return now },
	})
	return env
}

// bindTestUser uid=10086 的用户行样例。
func bindTestUser() *model.User { return &model.User{ID: bindTestUID, Username: "zhang_san"} }

// bindCaptchaOK 与内置图形码（降级配置）匹配的提交样例。
func bindCaptchaOK() *captcha.Submission {
	return &captcha.Submission{ProviderKey: captcha.BuiltinProviderKey, ID: "cap-1", Answer: "0422"}
}

// bindChallengePhone / bindChallengeEmail 便捷入参（默认全绿 challenge）。
func bindChallengePhone(target string) BindPhoneInput {
	return BindPhoneInput{Step: bindStepChallenge, Target: target, Captcha: bindCaptchaOK(), IP: "9.9.9.9"}
}

func bindChallengeEmail(target string) BindEmailInput {
	return BindEmailInput{Step: bindStepChallenge, Target: target, Captcha: bindCaptchaOK(), IP: "9.9.9.9"}
}

// bindNoSideEffects 断言零写码、零发信、零列更新、零审计。
func bindNoSideEffects(t *testing.T, env *bindTestEnv) {
	t.Helper()
	if len(env.store.sends) != 0 {
		t.Errorf("写码应不发生，实际 %d 次", len(env.store.sends))
	}
	if len(env.sender.calls) != 0 {
		t.Errorf("发信应不发生，实际 %d 次", len(env.sender.calls))
	}
	if len(env.users.updateCalls) != 0 {
		t.Errorf("列更新应不发生，实际 %d 次", len(env.users.updateCalls))
	}
	if len(env.audit.events) != 0 {
		t.Errorf("审计应不发生，实际 %d 条", len(env.audit.events))
	}
}

// TestBindChallengeSuccess challenge 成功：写码恰一次（purpose=bind、
// owner=uid 字符串、target、ip、6 位码）+ 发信恰一次 + 无审计无列更新；
// phone / email 两渠道表驱动。
func TestBindChallengeSuccess(t *testing.T) {
	cases := []struct {
		name   string
		phone  bool
		target string
	}{
		{"phone", true, "13800138000"},
		{"email", false, "user@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newBindTestEnv()
			ctx := context.Background()
			var err error
			if tc.phone {
				err = env.svc.BindPhone(ctx, bindTestUID, bindChallengePhone(tc.target))
			} else {
				err = env.svc.BindEmail(ctx, bindTestUID, bindChallengeEmail(tc.target))
			}
			if err != nil {
				t.Fatalf("challenge = %v, want nil", err)
			}
			if len(env.store.sends) != 1 {
				t.Fatalf("写码次数 = %d, want 1", len(env.store.sends))
			}
			c := env.store.sends[0]
			if c.purpose != purposeBind {
				t.Errorf("purpose = %q, want %q", c.purpose, purposeBind)
			}
			if c.owner != bindTestUIDStr {
				t.Errorf("owner = %q, want %q（§10.1 行 1158 账号域 owner=uid）", c.owner, bindTestUIDStr)
			}
			if c.target != tc.target {
				t.Errorf("写码 target = %q, want %q", c.target, tc.target)
			}
			if c.ip != "9.9.9.9" {
				t.Errorf("ip = %q, want 9.9.9.9", c.ip)
			}
			if !core.WellFormed(c.code) {
				t.Errorf("码值 %q 非 6 位纯数字", c.code)
			}
			if len(env.sender.calls) != 1 || env.sender.calls[0] != tc.target {
				t.Errorf("发信 = %v, want [%s]", env.sender.calls, tc.target)
			}
			if len(env.users.updateCalls) != 0 {
				t.Errorf("列更新应不发生，实际 %d 次", len(env.users.updateCalls))
			}
			if len(env.audit.events) != 0 {
				t.Errorf("challenge 不投审计，实际 %d 条", len(env.audit.events))
			}
		})
	}
}

// TestBindChallengeCaptcha captcha 缺失 → captcha_required；校验不通过 →
// captcha_invalid；两者均在占用查询之前拦截、零副作用（§3.4 行 896
// 「captcha 必过」）。
func TestBindChallengeCaptcha(t *testing.T) {
	t.Run("required", func(t *testing.T) {
		env := newBindTestEnv()
		err := env.svc.BindPhone(context.Background(), bindTestUID,
			BindPhoneInput{Step: bindStepChallenge, Target: "13800138000", Captcha: nil, IP: "9.9.9.9"})
		if !errors.Is(err, ErrBindCaptchaRequired) {
			t.Fatalf("err = %v, want ErrBindCaptchaRequired", err)
		}
		bindNoSideEffects(t, env)
	})
	t.Run("invalid", func(t *testing.T) {
		env := newBindTestEnv()
		env.verifier.err = captcha.ErrInvalid
		err := env.svc.BindEmail(context.Background(), bindTestUID,
			BindEmailInput{Step: bindStepChallenge, Target: "user@example.com", Captcha: bindCaptchaOK()})
		if !errors.Is(err, ErrBindCaptchaInvalid) {
			t.Fatalf("err = %v, want ErrBindCaptchaInvalid", err)
		}
		bindNoSideEffects(t, env)
	})
}

// TestBindChallengeCaptchaFailureCarriesGateConfig 可证伪：Gate.Evaluate
// 返回的当前生效配置必须随哨兵错误透出（§9.1 同源），errors.Is 仍可判别
// 原哨兵。断言取反（Config 不等于 gate 输出 / 错误不携带配置 / 三字段
// 为空）即失败。
func TestBindChallengeCaptchaFailureCarriesGateConfig(t *testing.T) {
	catalog := fakeBindCatalog{p: &captcha.Provider{ProviderKey: "cf_turnstile", Type: "turnstile", SiteKey: "0xSITE"}}
	gate := captcha.NewGate(fakeBindSettings{}, catalog, &fakeBindCaptchaVerifier{})
	want := gate.Config(context.Background())
	svc := NewBindContactService(BindContactDeps{
		Users:  &fakeBindUsers{self: bindTestUser(), occupied: map[string]*model.User{}},
		OTP:    core.NewService(&fakeBindOTPStore{}, core.DefaultConfig()),
		Sender: &fakeBindSender{},
		Gate:   gate,
		Config: core.DefaultConfig(),
	})
	cases := []struct {
		name         string
		in           BindPhoneInput
		wantSentinel error
	}{
		{"required", BindPhoneInput{Step: bindStepChallenge, Target: "13800138000"}, ErrBindCaptchaRequired},
		{"invalid", BindPhoneInput{Step: bindStepChallenge, Target: "13800138000", Captcha: &captcha.Submission{ProviderKey: "builtin_image"}}, ErrBindCaptchaInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.BindPhone(context.Background(), bindTestUID, tc.in)
			if !errors.Is(err, tc.wantSentinel) {
				t.Fatalf("err = %v, want %v", err, tc.wantSentinel)
			}
			var f *BindCaptchaFailure
			if !errors.As(err, &f) {
				t.Fatalf("err = %T, want *BindCaptchaFailure（配置未透出）", err)
			}
			if f.Config != want {
				t.Fatalf("carried Config = %+v, want gate 输出 %+v", f.Config, want)
			}
			if f.Config.ProviderKey == "" || f.Config.Type == "" || f.Config.SiteKey == "" {
				t.Fatalf("carried Config 三字段须非空: %+v", f.Config)
			}
		})
	}
}

// TestBindChallengeTargetTaken 目标已占用于他人 → target_taken（§3.4
// 行 892）；零写码零发信。
func TestBindChallengeTargetTaken(t *testing.T) {
	env := newBindTestEnv()
	env.users.occupied["13800138000"] = &model.User{ID: 10010, Username: "li_si"}
	err := env.svc.BindPhone(context.Background(), bindTestUID, bindChallengePhone("13800138000"))
	if !errors.Is(err, ErrBindTargetTaken) {
		t.Fatalf("err = %v, want ErrBindTargetTaken", err)
	}
	if len(env.store.sends) != 0 || len(env.sender.calls) != 0 {
		t.Fatalf("占用后应零写码零发信，实际写码 %d 发信 %d", len(env.store.sends), len(env.sender.calls))
	}
	if len(env.audit.events) != 0 {
		t.Fatalf("占用失败不投审计，实际 %d 条", len(env.audit.events))
	}
}

// TestBindChallengeIdempotentSelf 目标已绑自己 → 幂等成功直接返回 nil，
// 不写码、不发信、不投审计（幂等分支口径）。
func TestBindChallengeIdempotentSelf(t *testing.T) {
	env := newBindTestEnv()
	env.users.occupied["user@example.com"] = bindTestUser()
	err := env.svc.BindEmail(context.Background(), bindTestUID, bindChallengeEmail("user@example.com"))
	if err != nil {
		t.Fatalf("幂等 challenge = %v, want nil", err)
	}
	bindNoSideEffects(t, env)
}

// TestBindChallengeTooManyRequests 限流 deny 两形态：冷却（retry_after=
// 60s）与单目标日限额（retry_after=次日重置），均不发信（§1.6 行 243、
// §10.3）；Issue 已被调用（真实 Lua 在冷却时不覆盖旧码）。
func TestBindChallengeTooManyRequests(t *testing.T) {
	cases := []struct {
		name       string
		result     cache.SendResult
		wantSubstr string
	}{
		{"cooldown", cache.SendCooldown, "retry_after=60s"},
		{"target daily limit", cache.SendTargetDailyLimit, "retry_after="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newBindTestEnv()
			env.store.sendResult = tc.result
			err := env.svc.BindPhone(context.Background(), bindTestUID, bindChallengePhone("13800138000"))
			if !errors.Is(err, ErrBindTooManyRequests) {
				t.Fatalf("err = %v, want ErrBindTooManyRequests", err)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("err = %v, 应含 %q（§1.6 行 243 倒计时）", err, tc.wantSubstr)
			}
			if len(env.sender.calls) != 0 {
				t.Fatalf("限流 deny 不发信，实际 %d 次", len(env.sender.calls))
			}
			if len(env.audit.events) != 0 {
				t.Fatalf("限流不投审计，实际 %d 条", len(env.audit.events))
			}
		})
	}
}

// TestBindChallengeProviderDisabled 渠道未配置 → provider_disabled，且
// 已写码保留不回滚（§8.2 行 1051：允许 60s 后重发）。
func TestBindChallengeProviderDisabled(t *testing.T) {
	env := newBindTestEnv()
	env.sender.err = provider.ErrChannelNotConfigured
	err := env.svc.BindPhone(context.Background(), bindTestUID, bindChallengePhone("13800138000"))
	if !errors.Is(err, ErrBindProviderDisabled) {
		t.Fatalf("err = %v, want ErrBindProviderDisabled", err)
	}
	if len(env.store.sends) != 1 {
		t.Fatalf("码应保留（发送失败不回滚），写码 %d 次, want 1", len(env.store.sends))
	}
	if len(env.audit.events) != 0 {
		t.Fatalf("challenge 不投审计，实际 %d 条", len(env.audit.events))
	}
}

// TestBindVerifySuccess verify 成功：Check 收 purpose=bind / owner=uid
// 字符串；列更新参数逐字段（phone+phone_verified=1 或 email+
// email_verified=1，另一侧 nil）；审计事件逐字段（Event / ActorType /
// ActorID / UserID / Target=掩码 / Detail=DetailTargetMasked(掩码) /
// CreatedAt=注入时钟）。
func TestBindVerifySuccess(t *testing.T) {
	cases := []struct {
		name     string
		phone    bool
		target   string
		masked   string
		event    string
	}{
		{"phone", true, "13800138000", "138****8000", eventlog.EventBindPhone},
		{"email", false, "user@example.com", "u***@example.com", eventlog.EventBindEmail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newBindTestEnv()
			env.store.verifyRes = cache.VerifyOK
			ctx := context.Background()
			var err error
			if tc.phone {
				err = env.svc.BindPhone(ctx, bindTestUID, BindPhoneInput{Step: bindStepVerify, Target: tc.target, Code: "123456"})
			} else {
				err = env.svc.BindEmail(ctx, bindTestUID, BindEmailInput{Step: bindStepVerify, Target: tc.target, Code: "123456"})
			}
			if err != nil {
				t.Fatalf("verify = %v, want nil", err)
			}
			if len(env.store.verifies) != 1 {
				t.Fatalf("Check 次数 = %d, want 1", len(env.store.verifies))
			}
			chk := env.store.verifies[0]
			if chk.purpose != purposeBind || chk.owner != bindTestUIDStr || chk.target != tc.target || chk.code != "123456" {
				t.Errorf("Check 入参 = %+v, want {purpose:%s owner:%s target:%s code:123456}", chk, purposeBind, bindTestUIDStr, tc.target)
			}
			if len(env.users.updateCalls) != 1 {
				t.Fatalf("列更新次数 = %d, want 1", len(env.users.updateCalls))
			}
			upd := env.users.updateCalls[0]
			if upd.id != bindTestUID {
				t.Errorf("列更新 id = %d, want %d", upd.id, bindTestUID)
			}
			if tc.phone {
				if upd.phone == nil || *upd.phone != tc.target {
					t.Errorf("phone 列 = %v, want %q", upd.phone, tc.target)
				}
				if upd.phoneVerified == nil || *upd.phoneVerified != 1 {
					t.Errorf("phone_verified = %v, want 1", upd.phoneVerified)
				}
				if upd.email != nil || upd.emailVerified != nil {
					t.Errorf("email 侧应为 nil，实际 (%v, %v)", upd.email, upd.emailVerified)
				}
			} else {
				if upd.email == nil || *upd.email != tc.target {
					t.Errorf("email 列 = %v, want %q", upd.email, tc.target)
				}
				if upd.emailVerified == nil || *upd.emailVerified != 1 {
					t.Errorf("email_verified = %v, want 1", upd.emailVerified)
				}
				if upd.phone != nil || upd.phoneVerified != nil {
					t.Errorf("phone 侧应为 nil，实际 (%v, %v)", upd.phone, upd.phoneVerified)
				}
			}
			if len(env.audit.events) != 1 {
				t.Fatalf("审计条数 = %d, want 1（verify 成功写库后投递）", len(env.audit.events))
			}
			ev := env.audit.events[0]
			if ev.Event != tc.event {
				t.Errorf("Event = %q, want %q", ev.Event, tc.event)
			}
			if ev.ActorType != eventlog.ActorTypeUser {
				t.Errorf("ActorType = %q, want user", ev.ActorType)
			}
			if ev.ActorID != bindTestUID || ev.UserID != bindTestUID {
				t.Errorf("ActorID/UserID = (%d, %d), want (%d, %d)", ev.ActorID, ev.UserID, bindTestUID, bindTestUID)
			}
			if ev.Target != tc.masked {
				t.Errorf("Target = %q, want 掩码 %q", ev.Target, tc.masked)
			}
			if want := eventlog.DetailTargetMasked(tc.masked); string(ev.Detail) != string(want) {
				t.Errorf("Detail = %x, want %x（detail={target_masked}）", ev.Detail, want)
			}
			if !ev.CreatedAt.Equal(env.now) {
				t.Errorf("CreatedAt = %v, want %v", ev.CreatedAt, env.now)
			}
		})
	}
}

// TestBindVerifyInvalidCode 错码 → invalid_code 且携带剩余次数
//（§1.6 行 248）；码内 uid 与会话 uid 不一致同样落该形态——owner 比对在
// 存储层（cache/lua/verify_code.lua 行 23-33：code 与 owner 任一不符即走
// 错码分支），本用例断言 service 把当前 uid 作为 owner 传入 Check，即可
// 保证「码内 uid ≠ 当前 uid」时按错码处理；不写库不投审计。
func TestBindVerifyInvalidCode(t *testing.T) {
	env := newBindTestEnv()
	env.store.verifyRes = cache.VerifyMismatch
	env.store.attemptsLeft = 3
	err := env.svc.BindPhone(context.Background(), bindTestUID,
		BindPhoneInput{Step: bindStepVerify, Target: "13800138000", Code: "654321"})
	if err == nil {
		t.Fatal("verify 错码应失败")
	}
	if !errors.Is(err, ErrBindInvalidCode) {
		t.Fatalf("err = %v, want ErrBindInvalidCode（§3.4 行 897 不一致 → invalid_code）", err)
	}
	var icce *BindInvalidCodeError
	if !errors.As(err, &icce) || icce.AttemptsLeft != 3 {
		t.Errorf("剩余次数应可经 errors.As 取得 3，got %+v", icce)
	}
	if len(env.store.verifies) != 1 || env.store.verifies[0].owner != bindTestUIDStr {
		t.Errorf("owner 传参 = %v, want %q（当前会话 uid）", env.store.verifies, bindTestUIDStr)
	}
	if len(env.users.updateCalls) != 0 || len(env.audit.events) != 0 {
		t.Errorf("错码不应写库 / 投审计（列更新 %d 审计 %d）", len(env.users.updateCalls), len(env.audit.events))
	}
}

// TestBindVerifyExhausted 错码达尝试上限 → too_many_attempts（§1.6 行
// 244）。
func TestBindVerifyExhausted(t *testing.T) {
	env := newBindTestEnv()
	env.store.verifyRes = cache.VerifyExhausted
	err := env.svc.BindEmail(context.Background(), bindTestUID,
		BindEmailInput{Step: bindStepVerify, Target: "user@example.com", Code: "654321"})
	if !errors.Is(err, ErrBindTooManyAttempts) {
		t.Fatalf("err = %v, want ErrBindTooManyAttempts", err)
	}
	if len(env.users.updateCalls) != 0 || len(env.audit.events) != 0 {
		t.Errorf("超限不应写库 / 投审计（列更新 %d 审计 %d）", len(env.users.updateCalls), len(env.audit.events))
	}
}

// TestBindVerifyCodeExpired 无码（未发送 / 已消费 / 过期 / 值损坏）→
// code_expired（§1.6 行 249）。
func TestBindVerifyCodeExpired(t *testing.T) {
	env := newBindTestEnv()
	env.store.verifyRes = cache.VerifyMissing
	err := env.svc.BindPhone(context.Background(), bindTestUID,
		BindPhoneInput{Step: bindStepVerify, Target: "13800138000", Code: "123456"})
	if !errors.Is(err, ErrBindCodeExpired) {
		t.Fatalf("err = %v, want ErrBindCodeExpired", err)
	}
	if len(env.users.updateCalls) != 0 {
		t.Errorf("过期不应写库，实际 %d 次", len(env.users.updateCalls))
	}
}

// TestBindVerifyInvalidRequest 格式非法（target 空 / code 空 / 非 6 位 /
// 非纯数字）→ invalid_request，且不进入存储、不消耗尝试次数（factor/otp
// 同口径）。
func TestBindVerifyInvalidRequest(t *testing.T) {
	cases := []struct {
		name   string
		target string
		code   string
	}{
		{"empty target", "   ", "123456"},
		{"empty code", "13800138000", ""},
		{"short code", "13800138000", "12345"},
		{"non digits", "13800138000", "12ab45"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newBindTestEnv()
			err := env.svc.BindPhone(context.Background(), bindTestUID,
				BindPhoneInput{Step: bindStepVerify, Target: tc.target, Code: tc.code})
			if !errors.Is(err, ErrBindInvalidRequest) {
				t.Fatalf("err = %v, want ErrBindInvalidRequest", err)
			}
			if len(env.store.verifies) != 0 {
				t.Errorf("格式错不应触存储（消耗尝试次数），实际 %d 次", len(env.store.verifies))
			}
		})
	}
}

// TestBindVerifyTOCTOU verify 落库命中唯一键冲突（challenge 拦截后目标被
// 他人抢占）→ target_taken，不投审计；行被删 → user_not_found 防御分支。
func TestBindVerifyTOCTOU(t *testing.T) {
	t.Run("duplicate", func(t *testing.T) {
		env := newBindTestEnv()
		env.store.verifyRes = cache.VerifyOK
		// 同 repo 列级更新的冲突判别链（UserRepo.Create 的 1062 包装同源）。
		env.users.updateErr = fmt.Errorf("user repo: update contact columns: %w: %w", repo.ErrUserDuplicate, gorm.ErrDuplicatedKey)
		err := env.svc.BindPhone(context.Background(), bindTestUID,
			BindPhoneInput{Step: bindStepVerify, Target: "13800138000", Code: "123456"})
		if !errors.Is(err, ErrBindTargetTaken) {
			t.Fatalf("err = %v, want ErrBindTargetTaken（TOCTOU 唯一键冲突）", err)
		}
		if len(env.audit.events) != 0 {
			t.Fatalf("冲突不应投审计，实际 %d 条", len(env.audit.events))
		}
	})
	t.Run("user gone", func(t *testing.T) {
		env := newBindTestEnv()
		env.store.verifyRes = cache.VerifyOK
		env.users.updateErr = fmt.Errorf("user repo: update contact columns: %w", gorm.ErrRecordNotFound)
		err := env.svc.BindEmail(context.Background(), bindTestUID,
			BindEmailInput{Step: bindStepVerify, Target: "user@example.com", Code: "123456"})
		if !errors.Is(err, ErrBindUserNotFound) {
			t.Fatalf("err = %v, want ErrBindUserNotFound（落库前行被删防御分支）", err)
		}
		if len(env.audit.events) != 0 {
			t.Fatalf("防御分支不投审计，实际 %d 条", len(env.audit.events))
		}
	})
}

// TestBindUserNotFound uid 用户行不存在：challenge / verify 两步均
// user_not_found 且零副作用（存在性先判先于任何写操作，profile.go 口径）。
func TestBindUserNotFound(t *testing.T) {
	t.Run("challenge", func(t *testing.T) {
		env := newBindTestEnv()
		env.users.self = nil
		err := env.svc.BindPhone(context.Background(), bindTestUID, bindChallengePhone("13800138000"))
		if !errors.Is(err, ErrBindUserNotFound) {
			t.Fatalf("err = %v, want ErrBindUserNotFound", err)
		}
		bindNoSideEffects(t, env)
	})
	t.Run("verify", func(t *testing.T) {
		env := newBindTestEnv()
		env.users.self = nil
		env.store.verifyRes = cache.VerifyOK
		err := env.svc.BindEmail(context.Background(), bindTestUID,
			BindEmailInput{Step: bindStepVerify, Target: "user@example.com", Code: "123456"})
		if !errors.Is(err, ErrBindUserNotFound) {
			t.Fatalf("err = %v, want ErrBindUserNotFound", err)
		}
		// 先于码消费：Check 未被调用。
		if len(env.store.verifies) != 0 {
			t.Errorf("存在性先判应先于码消费，Check 已调 %d 次", len(env.store.verifies))
		}
		bindNoSideEffects(t, env)
	})
}

// TestBindStepInvalid step 非法（空 / 未知值）→ invalid_request，零副作用。
func TestBindStepInvalid(t *testing.T) {
	cases := []struct {
		name string
		step string
	}{
		{"empty", ""},
		{"unknown", "magic"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newBindTestEnv()
			err := env.svc.BindPhone(context.Background(), bindTestUID,
				BindPhoneInput{Step: tc.step, Target: "13800138000", Captcha: bindCaptchaOK(), Code: "123456"})
			if !errors.Is(err, ErrBindInvalidRequest) {
				t.Fatalf("err = %v, want ErrBindInvalidRequest", err)
			}
			bindNoSideEffects(t, env)
		})
	}
}

// TestBindSourceIPFallback IP 空值兜底 "unknown"（factor/otp clientIP 同款：
// 避免空键绕过单 IP 日限额，§10.3）。
func TestBindSourceIPFallback(t *testing.T) {
	env := newBindTestEnv()
	err := env.svc.BindPhone(context.Background(), bindTestUID,
		BindPhoneInput{Step: bindStepChallenge, Target: "13800138000", Captcha: bindCaptchaOK()})
	if err != nil {
		t.Fatalf("challenge = %v, want nil", err)
	}
	if len(env.store.sends) != 1 || env.store.sends[0].ip != "unknown" {
		t.Fatalf("ip = %v, want unknown", env.store.sends)
	}
}

// TestBindMask 电话 / 邮箱掩码边界（与 dto 版同构：前 3+****+后 4；本地
// 首字符+***+域名；短号码整体 ****；无 @ 仅 ***）。
func TestBindMask(t *testing.T) {
	if got := bindMaskPhone("13800138000"); got != "138****8000" {
		t.Errorf("maskPhone = %q", got)
	}
	if got := bindMaskPhone("1234567"); got != "****" {
		t.Errorf("maskPhone(7 位) = %q, want ****", got)
	}
	if got := bindMaskEmail("user@example.com"); got != "u***@example.com" {
		t.Errorf("maskEmail = %q", got)
	}
	if got := bindMaskEmail("noat"); got != "***" {
		t.Errorf("maskEmail(无 @) = %q, want ***", got)
	}
}

// TestBindInvalidCodeErrorUnwrap 哨兵判别与剩余次数携带的契约自检。
func TestBindInvalidCodeErrorUnwrap(t *testing.T) {
	err := error(&BindInvalidCodeError{AttemptsLeft: 4})
	if !errors.Is(err, ErrBindInvalidCode) {
		t.Fatal("errors.Is 应命中基哨兵")
	}
	if got := err.Error(); !strings.Contains(got, strconv.FormatInt(4, 10)) {
		t.Errorf("Error() = %q, 应含剩余次数 4", got)
	}
}
