// password_test.go account 域密码族 service 层单测（不连 DB/Redis，
// PasswordUserStore / PasswordCredentialStore / PasswordEpochSync /
// PasswordSettingsReader / AuditSink 全 fake 注入；策略内核逐规则判定由
// security 包 policy_test 覆盖，此处测 ChangePassword 编排：改密链
// 〔验证旧密码 → Update → IncEpoch+Sync → 审计〕、无密码账号补建 Create、
// password_weak / invalid_credentials / invalid_request / not_found 各错误
// 边界、settings 五键现读热更新、同步失败不投审计。旧密码校验失败不做
// pwd_fail_capture 锁定计数（文档未覆盖该联动，实现即不计数，fake 亦无
// 该依赖——本文件全量用例即其行为证明）。
package account

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/internal/eventlog"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/settings"
)

// 密码族测试数据（NewPassw0rd / OldPassw0rd 均满足默认策略且不在弱口令
// 字典；与用户名 zhang_san 无包含关系）。
const (
	testOldPassword = "OldPassw0rd"
	testNewPassword = "NewPassw0rd"
	testPasswordUID = int64(10086)
)

// testPasswordNow 固定时钟（updated_at / 审计 CreatedAt 断言用）。
var testPasswordNow = time.Unix(1764000000, 0).UTC()

// oldHashOnce 旧密码 argon2id 哈希（懒加载整包测试进程只算一次；真实
// HashPassword 而非硬编码串——VerifyPassword 按串内参数重算，fake 存量
// 哈希必须真实可校验）。
var oldHashOnce = sync.OnceValue(func() string {
	h, err := security.HashPassword(testOldPassword)
	if err != nil {
		panic(fmt.Sprintf("hash old password: %v", err))
	}
	return h
})

// fakePasswordUsers PasswordUserStore 的 fake：行回放 + 调用记录 + 错误注入。
type fakePasswordUsers struct {
	user      *model.User
	findErr   error
	findCalls []int64
	incEpoch  int16
	incCalls  []int64
	incErr    error
}

func (f *fakePasswordUsers) FindByID(_ context.Context, id int64) (*model.User, error) {
	f.findCalls = append(f.findCalls, id)
	return f.user, f.findErr
}

func (f *fakePasswordUsers) IncEpoch(_ context.Context, id int64) (int16, error) {
	f.incCalls = append(f.incCalls, id)
	if f.incErr != nil {
		return 0, f.incErr
	}
	return f.incEpoch, nil
}

// fakePasswordCreds PasswordCredentialStore 的 fake：行回放 + 建库记录 +
// 错误注入（row=nil 时 FindByUserAndKind 回放 repo 包装形态的
// ErrRecordNotFound——无密码账号分支入口）。
type fakePasswordCreds struct {
	row         *model.UserCredential
	findCalls   []passwordCredFind
	updateCalls []*model.UserCredential
	createCalls []*model.UserCredential
	updateErr   error
	createErr   error
}

type passwordCredFind struct {
	uid  int64
	kind string
}

func (f *fakePasswordCreds) FindByUserAndKind(_ context.Context, userID int64, kind string) (*model.UserCredential, error) {
	f.findCalls = append(f.findCalls, passwordCredFind{uid: userID, kind: kind})
	if f.row == nil {
		return nil, fmt.Errorf("credential repo: find by user kind: %w", gorm.ErrRecordNotFound)
	}
	return f.row, nil
}

func (f *fakePasswordCreds) Create(_ context.Context, c *model.UserCredential) error {
	f.createCalls = append(f.createCalls, c)
	return f.createErr
}

func (f *fakePasswordCreds) Update(_ context.Context, c *model.UserCredential) error {
	f.updateCalls = append(f.updateCalls, c)
	return f.updateErr
}

// fakePasswordEpoch PasswordEpochSync 的 fake：调用记录 + 错误注入。
type fakePasswordEpoch struct {
	syncCalls []passwordEpochSyncCall
	syncErr   error
}

type passwordEpochSyncCall struct {
	uid   int64
	epoch int16
}

func (f *fakePasswordEpoch) Sync(_ context.Context, uid int64, epoch int16) error {
	f.syncCalls = append(f.syncCalls, passwordEpochSyncCall{uid: uid, epoch: epoch})
	return f.syncErr
}

// fakePasswordSettings PasswordSettingsReader 的 fake：键值回放（map 可变，
// 热更新用例两次调用间改值即验证「每次校验现读」）。
type fakePasswordSettings struct {
	ints  map[string]int64
	bools map[string]bool
}

func (f *fakePasswordSettings) GetInt64(key string) (int64, bool) {
	v, ok := f.ints[key]
	return v, ok
}

func (f *fakePasswordSettings) GetBool(key string) (bool, bool) {
	v, ok := f.bools[key]
	return v, ok
}

// passwordTestUser 数据样例（含 email——equals-identity 固定规则用例需要）。
func passwordTestUser() *model.User {
	return &model.User{ID: testPasswordUID, Username: "zhang_san", Email: strPtr("zS9@example.com")}
}

// passwordTestRow 现存 password 凭证行（旧哈希真实可校验）。
func passwordTestRow() *model.UserCredential {
	return &model.UserCredential{ID: 55, UserID: testPasswordUID, Kind: kindPassword, Secret: []byte(oldHashOnce()), IsEnabled: 1}
}

// newPasswordService 构造被测 service（全依赖显式注入 + 固定时钟）。
func newPasswordService(users *fakePasswordUsers, creds *fakePasswordCreds, epoch *fakePasswordEpoch, st PasswordSettingsReader, audit AuditSink) *PasswordService {
	return NewPasswordService(PasswordDeps{
		Users:    users,
		Creds:    creds,
		Epoch:    epoch,
		Settings: st,
		Audit:    audit,
		Now:      func() time.Time { return testPasswordNow },
	})
}

// newPasswordEnv 默认环境三件套 + fakeAudit。
func newPasswordEnv() (*fakePasswordUsers, *fakePasswordCreds, *fakePasswordEpoch, *fakeAudit) {
	return &fakePasswordUsers{user: passwordTestUser(), incEpoch: 7},
		&fakePasswordCreds{row: passwordTestRow()},
		&fakePasswordEpoch{},
		&fakeAudit{}
}

// TestPasswordChangeHappyPath 改密链（§3.3 行 872）：旧密码验证通过 →
// 恰一次 Update（新哈希可验、旧哈希失效、is_enabled=1、updated_at 刷新）→
// IncEpoch 恰一次 + al:pwdep Sync 恰一次（epoch 透传）→ 恰一条
// change_password 审计（actor=user、ActorID=UserID=uid、detail={pwd_epoch}）。
func TestPasswordChangeHappyPath(t *testing.T) {
	users, creds, epoch, audit := newPasswordEnv()
	svc := newPasswordService(users, creds, epoch, nil, audit)

	if err := svc.ChangePassword(context.Background(), testPasswordUID, testOldPassword, testNewPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if n := len(creds.findCalls); n != 1 || creds.findCalls[0] != (passwordCredFind{uid: testPasswordUID, kind: kindPassword}) {
		t.Errorf("FindByUserAndKind = %v, want 恰一次 (uid=%d kind=password)", creds.findCalls, testPasswordUID)
	}
	if n := len(creds.updateCalls); n != 1 {
		t.Fatalf("Update calls = %d, want 1", n)
	}
	if n := len(creds.createCalls); n != 0 {
		t.Errorf("Create calls = %d, want 0（有行走 Update）", n)
	}
	row := creds.updateCalls[0]
	if row.ID != 55 || row.IsEnabled != 1 {
		t.Errorf("updated row = (id=%d is_enabled=%d), want (55, 1)", row.ID, row.IsEnabled)
	}
	if !row.UpdatedAt.Equal(testPasswordNow) {
		t.Errorf("updated_at = %v, want 固定时钟 %v", row.UpdatedAt, testPasswordNow)
	}
	if string(row.Secret) == oldHashOnce() {
		t.Error("secret 未更新（仍为旧哈希）")
	}
	if err := security.VerifyPassword(testNewPassword, string(row.Secret)); err != nil {
		t.Errorf("新密码校验新哈希: %v", err)
	}
	if err := security.VerifyPassword(testOldPassword, string(row.Secret)); err == nil {
		t.Error("旧密码仍可过新哈希, want 失效")
	}

	if len(users.incCalls) != 1 || users.incCalls[0] != testPasswordUID {
		t.Errorf("IncEpoch calls = %v, want 恰一次 uid=%d", users.incCalls, testPasswordUID)
	}
	if len(epoch.syncCalls) != 1 || epoch.syncCalls[0] != (passwordEpochSyncCall{uid: testPasswordUID, epoch: 7}) {
		t.Errorf("Sync calls = %v, want 恰一次 (uid=%d epoch=7)", epoch.syncCalls, testPasswordUID)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	ev := audit.events[0]
	if ev.Event != eventlog.EventChangePassword || ev.ActorType != eventlog.ActorTypeUser ||
		ev.ActorID != testPasswordUID || ev.UserID != testPasswordUID {
		t.Errorf("audit = (%s %s actor=%d user=%d), want (change_password user %d %d)",
			ev.Event, ev.ActorType, ev.ActorID, ev.UserID, testPasswordUID, testPasswordUID)
	}
	if string(ev.Detail) != string(eventlog.DetailPwdEpoch(7)) {
		t.Error("audit detail 与 DetailPwdEpoch(7) 不符")
	}
	if !ev.CreatedAt.Equal(testPasswordNow) {
		t.Errorf("audit created_at = %v, want 固定时钟", ev.CreatedAt)
	}
}

// TestPasswordChangeSetWithoutPassword 无密码账号直接设密（需求 §4.1.9
// 行 128、setPassReset 行 299-302 同口径）：password 行缺失 → 不验旧密码
// 补建 Create（UserID/Kind/IsEnabled/新哈希），currentPassword 空与传入
// 均可（文档仅约定「已设置密码时必填」，无行时传入值忽略——既定口径）。
func TestPasswordChangeSetWithoutPassword(t *testing.T) {
	for name, current := range map[string]string{
		"current 留空":   "",
		"current 传入忽略": "whatever",
	} {
		users := &fakePasswordUsers{user: passwordTestUser(), incEpoch: 3}
		creds := &fakePasswordCreds{row: nil} // FindByUserAndKind 回 ErrRecordNotFound
		epoch := &fakePasswordEpoch{}
		audit := &fakeAudit{}
		svc := newPasswordService(users, creds, epoch, nil, audit)

		if err := svc.ChangePassword(context.Background(), testPasswordUID, current, testNewPassword); err != nil {
			t.Fatalf("%s: ChangePassword: %v", name, err)
		}
		if n := len(creds.createCalls); n != 1 {
			t.Fatalf("%s: Create calls = %d, want 1（无行补建）", name, n)
		}
		if n := len(creds.updateCalls); n != 0 {
			t.Errorf("%s: Update calls = %d, want 0", name, n)
		}
		c := creds.createCalls[0]
		if c.UserID != testPasswordUID || c.Kind != kindPassword || c.IsEnabled != 1 {
			t.Errorf("%s: created = (uid=%d kind=%s is_enabled=%d), want (10086 password 1)", name, c.UserID, c.Kind, c.IsEnabled)
		}
		if err := security.VerifyPassword(testNewPassword, string(c.Secret)); err != nil {
			t.Errorf("%s: 新密码校验补建哈希: %v", name, err)
		}
		if !c.UpdatedAt.Equal(testPasswordNow) {
			t.Errorf("%s: created updated_at = %v, want 固定时钟", name, c.UpdatedAt)
		}
		if len(epoch.syncCalls) != 1 || epoch.syncCalls[0] != (passwordEpochSyncCall{uid: testPasswordUID, epoch: 3}) {
			t.Errorf("%s: Sync calls = %v, want 恰一次 epoch=3", name, epoch.syncCalls)
		}
		if len(audit.events) != 1 || audit.events[0].Event != eventlog.EventChangePassword {
			t.Errorf("%s: audit = %v, want change_password 恰一条", name, audit.events)
		}
	}
}

// TestPasswordChangeWeakPassword newPassword 不满足 §5.6 策略 →
// ErrPasswordWeak（五键可配规则 + 固定三规则逐类代表用例），零写库、
// 零 IncEpoch、零审计。
func TestPasswordChangeWeakPassword(t *testing.T) {
	for name, tc := range map[string]struct {
		password string
		email    *string
	}{
		"短于最小长度":        {password: "Ab1!"},
		"字符类不足":         {password: "abcdefghij"},
		"与邮箱完全相同(固定规则)": {password: "zS9@example.com", email: strPtr("zS9@example.com")},
		"包含用户名":         {password: "A1zhang_san"},
		"含空白(固定规则)":     {password: "Passw0rd 9x"},
		"命中弱口令字典":       {password: "Admin12345"},
	} {
		users, creds, epoch, audit := newPasswordEnv()
		users.user.Email = tc.email
		svc := newPasswordService(users, creds, epoch, nil, audit)

		err := svc.ChangePassword(context.Background(), testPasswordUID, testOldPassword, tc.password)
		if !errors.Is(err, ErrPasswordWeak) {
			t.Errorf("%s: err = %v, want ErrPasswordWeak", name, err)
		}
		if len(creds.updateCalls) != 0 || len(creds.createCalls) != 0 {
			t.Errorf("%s: 写库发生（update=%d create=%d）, want 零", name, len(creds.updateCalls), len(creds.createCalls))
		}
		if len(users.incCalls) != 0 || len(epoch.syncCalls) != 0 {
			t.Errorf("%s: IncEpoch/Sync 发生, want 零（password_weak 先于失效链）", name)
		}
		if len(audit.events) != 0 {
			t.Errorf("%s: audit = %d 条, want 0", name, len(audit.events))
		}
	}
}

// TestPasswordChangeWrongCurrentPassword 旧密码错误 →
// ErrPasswordInvalidCredentials（§1.6 行 247 invalid_credentials 口径），
// 零写库 / 零失效链 / 零审计；且不做 pwd_fail_capture 锁定计数
// （fake 无该依赖，文档未覆盖联动——本用例即「不计数」的行为证明）。
func TestPasswordChangeWrongCurrentPassword(t *testing.T) {
	users, creds, epoch, audit := newPasswordEnv()
	svc := newPasswordService(users, creds, epoch, nil, audit)

	err := svc.ChangePassword(context.Background(), testPasswordUID, "WrongPassw0rd", testNewPassword)
	if !errors.Is(err, ErrPasswordInvalidCredentials) {
		t.Fatalf("err = %v, want ErrPasswordInvalidCredentials", err)
	}
	if len(creds.updateCalls) != 0 || len(creds.createCalls) != 0 {
		t.Errorf("写库发生（update=%d create=%d）, want 零", len(creds.updateCalls), len(creds.createCalls))
	}
	if len(users.incCalls) != 0 || len(epoch.syncCalls) != 0 || len(audit.events) != 0 {
		t.Errorf("失效链 / 审计发生（inc=%d sync=%d audit=%d）, want 全零",
			len(users.incCalls), len(epoch.syncCalls), len(audit.events))
	}
}

// TestPasswordChangeMissingCurrentPassword 已设置密码而 currentPassword
// 未填（§3.3 行 876「已设置密码时必填」）→ ErrPasswordInvalidRequest，
// 零写库。
func TestPasswordChangeMissingCurrentPassword(t *testing.T) {
	users, creds, epoch, audit := newPasswordEnv()
	svc := newPasswordService(users, creds, epoch, nil, audit)

	err := svc.ChangePassword(context.Background(), testPasswordUID, "", testNewPassword)
	if !errors.Is(err, ErrPasswordInvalidRequest) {
		t.Fatalf("err = %v, want ErrPasswordInvalidRequest", err)
	}
	if len(creds.updateCalls) != 0 || len(creds.createCalls) != 0 || len(audit.events) != 0 {
		t.Errorf("写库 / 审计发生, want 零")
	}
}

// TestPasswordChangeInvalidInput uid 非法 / newPassword 缺失 →
// ErrPasswordInvalidRequest，先于一切仓库访问（含 FindByID）。
func TestPasswordChangeInvalidInput(t *testing.T) {
	for name, tc := range map[string]struct {
		uid          int64
		current, new string
	}{
		"uid=0":          {uid: 0, current: testOldPassword, new: testNewPassword},
		"uid<0":          {uid: -1, current: testOldPassword, new: testNewPassword},
		"new_password 空": {uid: testPasswordUID, current: testOldPassword, new: ""},
	} {
		users, creds, epoch, audit := newPasswordEnv()
		svc := newPasswordService(users, creds, epoch, nil, audit)

		if err := svc.ChangePassword(context.Background(), tc.uid, tc.current, tc.new); !errors.Is(err, ErrPasswordInvalidRequest) {
			t.Errorf("%s: err = %v, want ErrPasswordInvalidRequest", name, err)
		}
		if len(users.findCalls) != 0 {
			t.Errorf("%s: FindByID 发生 = %d 次, want 0（入参边界先于读库）", name, len(users.findCalls))
		}
	}
}

// TestPasswordChangeUserNotFound user 行不存在 → gorm.ErrRecordNotFound
// 包装透传（handler 转 not_found），零写库。
func TestPasswordChangeUserNotFound(t *testing.T) {
	users, creds, epoch, audit := newPasswordEnv()
	users.user = nil
	users.findErr = fmt.Errorf("user repo: find by id: %w", gorm.ErrRecordNotFound)
	svc := newPasswordService(users, creds, epoch, nil, audit)

	err := svc.ChangePassword(context.Background(), testPasswordUID, testOldPassword, testNewPassword)
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("err = %v, want gorm.ErrRecordNotFound 透传", err)
	}
	if len(creds.updateCalls) != 0 || len(creds.createCalls) != 0 || len(users.incCalls) != 0 {
		t.Error("写库发生, want 零")
	}
}

// TestPasswordChangePolicyHotRead settings 五键现读保证热更新
// （§5.6 行 1317「只对后续请求生效」）：同一 service 实例，min_length 从
// 12 调回 8 后同一密码由 password_weak 转为通过——策略每次校验现读。
func TestPasswordChangePolicyHotRead(t *testing.T) {
	users, creds, epoch, audit := newPasswordEnv()
	st := &fakePasswordSettings{ints: map[string]int64{settings.KeyPwdMinLength: 12}}
	svc := newPasswordService(users, creds, epoch, st, audit)

	// NewPassw0rd 长 10 < 12 → password_weak。
	if err := svc.ChangePassword(context.Background(), testPasswordUID, testOldPassword, testNewPassword); !errors.Is(err, ErrPasswordWeak) {
		t.Fatalf("min_length=12: err = %v, want ErrPasswordWeak", err)
	}
	// 调回 8（热更新，无重启）→ 同一密码通过。
	st.ints[settings.KeyPwdMinLength] = 8
	if err := svc.ChangePassword(context.Background(), testPasswordUID, testOldPassword, testNewPassword); err != nil {
		t.Fatalf("min_length=8: ChangePassword: %v", err)
	}
	if len(creds.updateCalls) != 1 {
		t.Errorf("Update calls = %d, want 1（第二轮成功写库）", len(creds.updateCalls))
	}
}

// TestPasswordChangeSyncFailure epoch 同步失败 → 错误上抛（DB 密码已改，
// 重试幂等），审计不投（审计在失效链成功之后）。
func TestPasswordChangeSyncFailure(t *testing.T) {
	users, creds, epoch, audit := newPasswordEnv()
	epoch.syncErr = errors.New("redis: connection refused")
	svc := newPasswordService(users, creds, epoch, nil, audit)

	err := svc.ChangePassword(context.Background(), testPasswordUID, testOldPassword, testNewPassword)
	if err == nil || !errors.Is(err, epoch.syncErr) {
		t.Fatalf("err = %v, want 同步错误上抛", err)
	}
	if len(audit.events) != 0 {
		t.Errorf("audit = %d 条, want 0（同步失败不投审计）", len(audit.events))
	}
	if len(creds.updateCalls) != 1 {
		t.Errorf("Update calls = %d, want 1（DB 密码已改，失败后重试幂等）", len(creds.updateCalls))
	}
}

// TestPasswordChangeIncEpochFailure epoch 递增失败 → 错误上抛，
// 零 Sync、零审计。
func TestPasswordChangeIncEpochFailure(t *testing.T) {
	users, creds, epoch, audit := newPasswordEnv()
	users.incErr = errors.New("user repo: inc epoch: db down")
	svc := newPasswordService(users, creds, epoch, nil, audit)

	if err := svc.ChangePassword(context.Background(), testPasswordUID, testOldPassword, testNewPassword); err == nil {
		t.Fatal("err = nil, want 递增错误上抛")
	}
	if len(epoch.syncCalls) != 0 || len(audit.events) != 0 {
		t.Errorf("Sync/audit 发生（sync=%d audit=%d）, want 全零", len(epoch.syncCalls), len(audit.events))
	}
}

// TestPasswordChangeAuditOptional Audit 未注入（nil）→ 主链路照常
// 成功不 panic（装配层可选依赖，webauthn / thirdparty 同口径）。
func TestPasswordChangeAuditOptional(t *testing.T) {
	users, creds, epoch, _ := newPasswordEnv()
	svc := newPasswordService(users, creds, epoch, nil, nil)

	if err := svc.ChangePassword(context.Background(), testPasswordUID, testOldPassword, testNewPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if len(epoch.syncCalls) != 1 {
		t.Errorf("Sync calls = %d, want 1", len(epoch.syncCalls))
	}
}
