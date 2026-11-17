// user_test.go：admin 用户管理族 service 层单测。fake 全进程内
// 隔离（不连 DB / Redis），覆盖清单：UpdateUserStatus 两态 +
// IncEpoch / Sync 断言 + 审计、ResetUserPassword password_weak / 成功失效链
// + 审计（无行同构补建）、Unbind Union 连带两分支 + 单事务回滚两注入、
// Union 单独解绑拒绝 / 审计、
// Unlock uid 维度 + ip 账号哈希维度重算、GetUserEvents login_success 过滤与
// 分页透传、ListUsers 过滤透传与 userStatus 枚举校验、GetUser 聚合
// （profile 行投影）、目标分级写门禁矩阵（authorizeUserWrite 三向 +
// 权限查询故障不放行）、UpdateUserProfile PATCH has 位 / 值域校验 / 审计、
// UpdateUserContact 写即置已验证 / 显式清空 / 唯一冲突不审计 / 强制下线、
// 救援族五方法（SetUserMfa 开关两态与强制下线集合、UnbindUserTOTP、
// ResetUserRecoveryCodes 重生成无明文回显、SetCredentialEnabled 密码凭证
// 停用拒绝与零失效链零审计、DeleteCredential 强制下线与审计 detail、
// 五方法门禁复用）。
// q 模糊 / 排序 / 分页边界的真库行为归 repo 用例（user_repo_test.go）。
package admin_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"gorm.io/gorm"

	accountv1 "authloft/gen/go/api/account/v1"
	adminv1 "authloft/gen/go/api/admin/v1"
	credentialpb "authloft/gen/go/credential"
	"authloft/internal/eventlog"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	adminsvc "authloft/internal/service/admin"
)

// —— fake 全家（窄接口逐一落档）——

type userFakeUsers struct {
	user    *model.User
	findErr error

	gotQuery  repo.UserListQuery
	listRows  []model.User
	listTotal int64

	statusUpdated []userFakeStatus
	statusErr     error

	incIDs  []int64
	incNext int16

	// —— MFA 开关（SetUserMfa 走 UpdateMfaRequired 列级更新）——
	mfaUpdated []userFakeMfaUpdate
	mfaErr     error

	// —— 资料 / 联系方式编辑族（UpdateUserProfile / UpdateUserContact / GetUser 投影）——
	profileRow     *model.UserProfile      // 现行 user_profile 行（nil = 行缺失）
	getProfileErr  error                   // GetProfile 注入故障（非 notfound）
	profileSaved   []*model.UserProfile    // SaveProfile 落盘留档
	profileCols    []userFakeProfileCols   // UpdateProfileColumns 调用留档
	contactUpdated []userFakeContactUpdate // UpdateContactColumns 调用留档
	contactErr     error                   // UpdateContactColumns 注入（含 ErrUserDuplicate 冲突）
	phoneHolders   map[string]*model.User  // phone → 占用行（FindByPhone）
	emailHolders   map[string]*model.User  // email → 占用行（FindByEmail）
}

type userFakeProfileCols struct {
	id               int64
	nickname, avatar *string
}

type userFakeContactUpdate struct {
	id             int64
	phone, email   *string
	phoneV, emailV *int8
}

type userFakeStatus struct {
	id     int64
	status int8
}

type userFakeMfaUpdate struct {
	id  int64
	mfa int8
}

func (f *userFakeUsers) FindByID(_ context.Context, id int64) (*model.User, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if f.user == nil || f.user.ID != id {
		return nil, fmt.Errorf("user repo: find by id: %w", gorm.ErrRecordNotFound)
	}
	return f.user, nil
}

func (f *userFakeUsers) ListUsers(_ context.Context, q repo.UserListQuery) ([]model.User, int64, error) {
	f.gotQuery = q
	return f.listRows, f.listTotal, nil
}

func (f *userFakeUsers) UpdateUserStatus(_ context.Context, id int64, status int8) error {
	if f.statusErr != nil {
		return f.statusErr
	}
	// 模拟 repo 的 rows=0 存在性判定（UpdateUserStatus 契约）。
	if f.user == nil || f.user.ID != id {
		return fmt.Errorf("user repo: update user status: %w", gorm.ErrRecordNotFound)
	}
	f.statusUpdated = append(f.statusUpdated, userFakeStatus{id: id, status: status})
	return nil
}

func (f *userFakeUsers) IncEpoch(_ context.Context, id int64) (int16, error) {
	f.incIDs = append(f.incIDs, id)
	return f.incNext, nil
}

func (f *userFakeUsers) UpdateMfaRequired(_ context.Context, id int64, mfaRequired int8) error {
	if f.mfaErr != nil {
		return f.mfaErr
	}
	// 模拟 repo 的 rows=0 存在性判定（UpdateMfaRequired 契约）。
	if f.user == nil || f.user.ID != id {
		return fmt.Errorf("user repo: update mfa required: %w", gorm.ErrRecordNotFound)
	}
	f.mfaUpdated = append(f.mfaUpdated, userFakeMfaUpdate{id: id, mfa: mfaRequired})
	return nil
}

func (f *userFakeUsers) FindByPhone(_ context.Context, phone string) (*model.User, error) {
	if row, ok := f.phoneHolders[phone]; ok {
		return row, nil
	}
	return nil, fmt.Errorf("user repo: find by phone: %w", gorm.ErrRecordNotFound)
}

func (f *userFakeUsers) FindByEmail(_ context.Context, email string) (*model.User, error) {
	if row, ok := f.emailHolders[email]; ok {
		return row, nil
	}
	return nil, fmt.Errorf("user repo: find by email: %w", gorm.ErrRecordNotFound)
}

func (f *userFakeUsers) UpdateProfileColumns(_ context.Context, id int64, nickname, avatarURL *string) error {
	// 模拟 repo 的 rows=0 存在性判定（UpdateProfileColumns 契约）。
	if f.user == nil || f.user.ID != id {
		return fmt.Errorf("user repo: update profile columns: %w", gorm.ErrRecordNotFound)
	}
	f.profileCols = append(f.profileCols, userFakeProfileCols{id: id, nickname: nickname, avatar: avatarURL})
	return nil
}

func (f *userFakeUsers) UpdateContactColumns(_ context.Context, id int64, phone, email *string, phoneVerified, emailVerified *int8) error {
	if f.contactErr != nil {
		return f.contactErr
	}
	// 模拟 repo 的 rows=0 存在性判定（UpdateContactColumns 契约）。
	if f.user == nil || f.user.ID != id {
		return fmt.Errorf("user repo: update contact columns: %w", gorm.ErrRecordNotFound)
	}
	f.contactUpdated = append(f.contactUpdated, userFakeContactUpdate{id: id, phone: phone, email: email, phoneV: phoneVerified, emailV: emailVerified})
	return nil
}

func (f *userFakeUsers) GetProfile(_ context.Context, userID int64) (*model.UserProfile, error) {
	if f.getProfileErr != nil {
		return nil, f.getProfileErr
	}
	if f.profileRow == nil || f.profileRow.UserID != userID {
		return nil, fmt.Errorf("user repo: get profile: %w", gorm.ErrRecordNotFound)
	}
	return f.profileRow, nil
}

func (f *userFakeUsers) SaveProfile(_ context.Context, p *model.UserProfile) error {
	f.profileSaved = append(f.profileSaved, p)
	return nil
}

type userFakeCreds struct {
	byKind  map[string]*model.UserCredential
	list    []model.UserCredential
	created []*model.UserCredential
	updated []*model.UserCredential

	// —— 救援族（按 credentialId 定位，§5.4）——
	byID            map[int64]*model.UserCredential // credentialId → 行（含他人行用于归属拒绝）
	findIDErr       error
	setEnabled      []userFakeCredEnable
	setEnabledErr   error
	deletedByKind   []userFakeCredDeleteKind // DeleteByUserAndKind 调用留档
	deleteByKindErr error
	deletedByID     []userFakeCredDeleteID // DeleteByID 调用留档（user 维度透传断言）
	deleteIDErr     error
}

type userFakeCredEnable struct {
	id      int64
	enabled bool
}

type userFakeCredDeleteKind struct {
	userID int64
	kind   string
}

type userFakeCredDeleteID struct {
	userID int64
	id     int64
}

func (f *userFakeCreds) FindByUserAndKind(_ context.Context, _ int64, kind string) (*model.UserCredential, error) {
	if c, ok := f.byKind[kind]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("credential repo: find by user kind: %w", gorm.ErrRecordNotFound)
}

func (f *userFakeCreds) FindByID(_ context.Context, id int64) (*model.UserCredential, error) {
	if f.findIDErr != nil {
		return nil, f.findIDErr
	}
	if c, ok := f.byID[id]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("credential repo: find by id: %w", gorm.ErrRecordNotFound)
}

func (f *userFakeCreds) ListByUser(_ context.Context, _ int64) ([]model.UserCredential, error) {
	return f.list, nil
}

func (f *userFakeCreds) Create(_ context.Context, c *model.UserCredential) error {
	f.created = append(f.created, c)
	return nil
}

func (f *userFakeCreds) Update(_ context.Context, c *model.UserCredential) error {
	f.updated = append(f.updated, c)
	return nil
}

func (f *userFakeCreds) SetEnabled(_ context.Context, id int64, enabled bool) error {
	if f.setEnabledErr != nil {
		return f.setEnabledErr
	}
	f.setEnabled = append(f.setEnabled, userFakeCredEnable{id: id, enabled: enabled})
	return nil
}

func (f *userFakeCreds) DeleteByUserAndKind(_ context.Context, userID int64, kind string) error {
	if f.deleteByKindErr != nil {
		return f.deleteByKindErr
	}
	// 模拟 repo 的行存在性语义（DeleteByUserAndKind 契约：未命中返回
	// 包装的 gorm.ErrRecordNotFound）。
	if _, ok := f.byKind[kind]; !ok {
		return fmt.Errorf("credential repo: delete by user kind: %w", gorm.ErrRecordNotFound)
	}
	f.deletedByKind = append(f.deletedByKind, userFakeCredDeleteKind{userID: userID, kind: kind})
	return nil
}

func (f *userFakeCreds) DeleteByID(_ context.Context, userID, id int64) error {
	if f.deleteIDErr != nil {
		return f.deleteIDErr
	}
	f.deletedByID = append(f.deletedByID, userFakeCredDeleteID{userID: userID, id: id})
	return nil
}

type userFakeBinds struct {
	rows    []model.UserThirdpartyBind
	unbound []int64

	unionKeys  map[string]bool // provider_key → category=union（级联判定数据源，模拟 tx 内查 provider 行）
	deleteErr  error           // 普通行删除失败注入：整体回滚（rows / unbound 零落盘）
	cascadeErr error           // Union 行连带删除失败注入：整体回滚
}

func (f *userFakeBinds) ListByUserID(_ context.Context, _ int64) ([]model.UserThirdpartyBind, error) {
	// 返回副本：repo 每次查询从 DB 读新行，删除不改动调用方持有的切片
	//（直接回 f.rows 会让删除的原地改写破坏 service 侧 rows 底层数组）。
	return append([]model.UserThirdpartyBind(nil), f.rows...), nil
}

// UnbindWithUnionCascade 模拟 repo 单事务语义（参照
// TestRegisterCredentialFailureRollsBackUser 的回滚断言形态）：全流程对
// 副本推进，任一步失败（deleteErr / cascadeErr 注入、行不存在、归属不符）
// 则整体不落盘（回滚），成功才写回 rows / unbound。级联判定按 unionKeys
// 模拟 tx 内查 provider.category（key 缺失读零值 false = 非 Union，与 repo
// 「provider 行缺失按非 Union 处理」同语义）；unionProviderKey 为空只删
// 普通行。
func (f *userFakeBinds) UnbindWithUnionCascade(_ context.Context, id, userID int64, unionProviderKey string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	var after []model.UserThirdpartyBind
	deleted := false
	for i := range f.rows {
		if f.rows[i].ID == id {
			if f.rows[i].UserID != userID {
				return repo.ErrBindNotOwned
			}
			deleted = true
			continue
		}
		after = append(after, f.rows[i])
	}
	if !deleted {
		return fmt.Errorf("bind repo: unbind with union cascade: %w", gorm.ErrRecordNotFound)
	}
	var cascaded []int64
	if unionProviderKey != "" {
		hasNonUnion := false
		for i := range after {
			if after[i].ProviderKey == unionProviderKey || f.unionKeys[after[i].ProviderKey] {
				continue
			}
			hasNonUnion = true
			break
		}
		if !hasNonUnion {
			if f.cascadeErr != nil {
				return f.cascadeErr
			}
			kept := make([]model.UserThirdpartyBind, 0, len(after))
			for i := range after {
				if after[i].ProviderKey == unionProviderKey {
					cascaded = append(cascaded, after[i].ID)
					continue
				}
				kept = append(kept, after[i])
			}
			after = kept
		}
	}
	f.rows = after
	f.unbound = append(f.unbound, id)
	f.unbound = append(f.unbound, cascaded...)
	return nil
}

type userFakeProviders struct{ rows map[string]*model.Provider }

func (f *userFakeProviders) FindByKey(_ context.Context, key string) (*model.Provider, error) {
	if p, ok := f.rows[key]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("provider repo: find by key: %w", gorm.ErrRecordNotFound)
}

type userFakeEvents struct {
	gotQuery repo.EventLogListQuery
	rows     []model.EventLog
	total    int64
}

func (f *userFakeEvents) ListByUser(_ context.Context, q repo.EventLogListQuery) ([]model.EventLog, int64, error) {
	f.gotQuery = q
	return f.rows, f.total, nil
}

type userFakeEpoch struct{ synced []userFakeSync }

type userFakeSync struct {
	uid   int64
	epoch int16
}

func (f *userFakeEpoch) Sync(_ context.Context, uid int64, epoch int16) error {
	f.synced = append(f.synced, userFakeSync{uid: uid, epoch: epoch})
	return nil
}

type userFakePwfail struct {
	resetRefs   []string
	deletedRefs []string
}

func (f *userFakePwfail) Reset(_ context.Context, userRef string) error {
	f.resetRefs = append(f.resetRefs, userRef)
	return nil
}

func (f *userFakePwfail) DeleteAccountRef(_ context.Context, accountHash string) error {
	f.deletedRefs = append(f.deletedRefs, accountHash)
	return nil
}

type userFakeAudit struct{ events []model.EventLog }

func (f *userFakeAudit) PushEvent(ev model.EventLog) { f.events = append(f.events, ev) }

type userFakeSettings struct {
	ints  map[string]int64
	bools map[string]bool
}

func (f userFakeSettings) GetInt64(key string) (int64, bool) {
	v, ok := f.ints[key]
	return v, ok
}

func (f userFakeSettings) GetBool(key string) (bool, bool) {
	v, ok := f.bools[key]
	return v, ok
}

// userFakePermissions 权限点查询 fake（SuperadminChecker）：按 uid 授予、
// 按 uid 注入故障，并记录查询调用序列（门禁优先级 / fail-closed 断言）。
// HasAnyPermission 按「授予表非空」判定——持有任意权限点（含 superadmin）
// 即 true，普通管理员目标用非 superadmin 权限点条目构造。map 零值读安全
// ——零值 fake 表示「无任何权限点」。
type userFakePermissions struct {
	granted     map[int64]map[string]bool
	errByUID    map[int64]error
	anyErrByUID map[int64]error // HasAnyPermission 专属故障注入（区分两查询的 fail-closed 断言）
	calls       []int64
}

func (f *userFakePermissions) HasPermission(_ context.Context, uid int64, point string) (bool, error) {
	f.calls = append(f.calls, uid)
	if err := f.errByUID[uid]; err != nil {
		return false, err
	}
	return f.granted[uid][point], nil
}

func (f *userFakePermissions) HasAnyPermission(_ context.Context, uid int64) (bool, error) {
	f.calls = append(f.calls, uid)
	if err := f.anyErrByUID[uid]; err != nil {
		return false, err
	}
	return len(f.granted[uid]) > 0, nil
}

// userGrantSuperadmins 构造「指定 uid 持有 superadmin」的授予表。
func userGrantSuperadmins(uids ...int64) map[int64]map[string]bool {
	m := make(map[int64]map[string]bool, len(uids))
	for _, uid := range uids {
		m[uid] = map[string]bool{adminsvc.PointSuperAdmin: true}
	}
	return m
}

// newUserSvc 组造 service 与全部 fake（零值 settings → security 默认策略档）。
// 可选注入权限 fake；不传则默认无权限点。
func newUserSvc(perms ...*userFakePermissions) (*adminsvc.UserService, *userFakeUsers, *userFakeCreds, *userFakeBinds,
	*userFakeProviders, *userFakeEvents, *userFakeEpoch, *userFakePwfail, *userFakeAudit) {
	users, creds, binds := &userFakeUsers{}, &userFakeCreds{}, &userFakeBinds{}
	providers, events := &userFakeProviders{rows: map[string]*model.Provider{}}, &userFakeEvents{}
	epoch, pwfail, audit := &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}
	var permission *userFakePermissions
	if len(perms) > 0 && perms[0] != nil {
		permission = perms[0]
	} else {
		permission = &userFakePermissions{}
	}
	svc := adminsvc.NewUserService(users, creds, binds, providers, events, epoch, pwfail, audit, userFakeSettings{}, permission)
	return svc, users, creds, binds, providers, events, epoch, pwfail, audit
}

func userTestRow() *model.User {
	phone, email := "13800138000", "alice@example.com"
	now := time.Unix(1761700000, 0).UTC()
	return &model.User{
		ID: 42, Username: "alice", Nickname: "Alice", AvatarURL: "https://cdn.example.com/a.png",
		Phone: &phone, Email: &email, UserStatus: 1, Epoch: 3,
		CreatedAt: now, UpdatedAt: now,
	}
}

// TestUserServiceGetMe uid 透传 FindByID；uid<=0 拒绝；行缺失 404。
func TestUserServiceGetMe(t *testing.T) {
	ctx := context.Background()
	svc, users, _, _, _, _, _, _, _ := newUserSvc()
	users.user = userTestRow()

	row, err := svc.GetMe(ctx, 42)
	if err != nil || row.Username != "alice" || row.Nickname != "Alice" || row.AvatarURL == "" {
		t.Fatalf("GetMe = (%+v, %v), want alice 行", row, err)
	}
	if _, err := svc.GetMe(ctx, 0); !errors.Is(err, adminsvc.ErrInvalidRequest) {
		t.Fatalf("uid=0 应 ErrInvalidRequest, got %v", err)
	}
	if _, err := svc.GetMe(ctx, 404); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("行缺失应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserServiceListUsers 过滤透传：q / userStatus / sort / order / 分页原样
// 进 repo 查询；userStatus 枚举外的值拒绝。
func TestUserServiceListUsers(t *testing.T) {
	ctx := context.Background()
	svc, users, _, _, _, _, _, _, _ := newUserSvc()
	users.listRows, users.listTotal = []model.User{*userTestRow()}, 1

	status := int64(1)
	if _, _, err := svc.ListUsers(ctx, adminsvc.ListUsersFilter{
		Q: "ali", UserStatus: &status, Page: 2, PageSize: 50, Sort: "created_at", Order: "asc",
	}); err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	got := users.gotQuery
	if got.Q != "ali" || got.UserStatus == nil || *got.UserStatus != 1 ||
		got.Page != 2 || got.PageSize != 50 || got.Sort != "created_at" || got.Order != "asc" {
		t.Fatalf("透传查询 = %+v", got)
	}
	bad := int64(2)
	if _, _, err := svc.ListUsers(ctx, adminsvc.ListUsersFilter{UserStatus: &bad}); !errors.Is(err, adminsvc.ErrInvalidRequest) {
		t.Fatalf("userStatus=2 应 ErrInvalidRequest, got %v", err)
	}
}

// TestUserServiceGetUser 聚合 user + 凭证概览 + 绑定列表；id<=0 拒绝。
func TestUserServiceGetUser(t *testing.T) {
	ctx := context.Background()
	svc, users, creds, binds, _, _, _, _, _ := newUserSvc()
	users.user = userTestRow()
	creds.list = []model.UserCredential{{ID: 7, UserID: 42, Kind: "password", IsEnabled: 1}}
	binds.rows = []model.UserThirdpartyBind{{ID: 9, UserID: 42, ProviderKey: "wechat_mp_1", OpenID: "oX-1"}}

	d, err := svc.GetUser(ctx, 42)
	if err != nil || d.User.ID != 42 || len(d.Credentials) != 1 || d.Credentials[0].Kind != "password" ||
		len(d.Bindings) != 1 || d.Bindings[0].ProviderKey != "wechat_mp_1" {
		t.Fatalf("GetUser = (%+v, %v)", d, err)
	}
	if _, err := svc.GetUser(ctx, 0); !errors.Is(err, adminsvc.ErrInvalidRequest) {
		t.Fatalf("id=0 应 ErrInvalidRequest, got %v", err)
	}
	if _, err := svc.GetUser(ctx, 404); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("行缺失应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserServiceUpdateUserStatus 覆盖清单：两态——禁用（0）走列级 UPDATE +
// IncEpoch + al:pwdep Sync + 审计 admin_disable_user；启用（1）只列级 UPDATE，
// 不递增 epoch、不审计。userStatus 枚举外拒绝；行缺失 404。
func TestUserServiceUpdateUserStatus(t *testing.T) {
	ctx := context.Background()

	svc, users, _, _, _, _, epoch, _, audit := newUserSvc()
	users.user = userTestRow()
	users.incNext = 4
	if err := svc.UpdateUserStatus(ctx, 1, 42, 0); err != nil {
		t.Fatalf("禁用: %v", err)
	}
	if len(users.statusUpdated) != 1 || users.statusUpdated[0].status != 0 {
		t.Fatalf("列级 UPDATE = %+v, want status=0", users.statusUpdated)
	}
	if len(users.incIDs) != 1 || users.incIDs[0] != 42 {
		t.Fatalf("禁用应 IncEpoch(42), got %v", users.incIDs)
	}
	if len(epoch.synced) != 1 || epoch.synced[0] != (userFakeSync{uid: 42, epoch: 4}) {
		t.Fatalf("禁用应 Sync(42, 4), got %+v", epoch.synced)
	}
	if len(audit.events) != 1 || audit.events[0].Event != eventlog.EventAdminDisableUser ||
		audit.events[0].ActorType != eventlog.ActorTypeAdmin || audit.events[0].ActorID != 1 ||
		audit.events[0].UserID != 42 {
		t.Fatalf("禁用审计 = %+v", audit.events)
	}

	svc, users, _, _, _, _, epoch, _, audit = newUserSvc()
	users.user = userTestRow()
	if err := svc.UpdateUserStatus(ctx, 1, 42, 1); err != nil {
		t.Fatalf("启用: %v", err)
	}
	if len(users.statusUpdated) != 1 || users.statusUpdated[0].status != 1 {
		t.Fatalf("列级 UPDATE = %+v, want status=1", users.statusUpdated)
	}
	if len(users.incIDs) != 0 || len(epoch.synced) != 0 || len(audit.events) != 0 {
		t.Fatalf("启用不应触碰失效链/审计: inc=%v sync=%v audit=%v", users.incIDs, epoch.synced, audit.events)
	}

	svc, _, _, _, _, _, _, _, _ = newUserSvc()
	if err := svc.UpdateUserStatus(ctx, 1, 42, 7); !errors.Is(err, adminsvc.ErrInvalidRequest) {
		t.Fatalf("userStatus=7 应 ErrInvalidRequest, got %v", err)
	}
	if err := svc.UpdateUserStatus(ctx, 1, 404, 0); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("行缺失应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserServiceResetUserPassword 覆盖清单：password_weak；成功失效链
// （credential 更新 + IncEpoch + al:pwdep Sync + 审计 admin_reset_password
// detail={pwd_epoch}）；无 password 行同构补建（Create 口径，setpass reset 同款）。
func TestUserServiceResetUserPassword(t *testing.T) {
	ctx := context.Background()

	// 弱密码（默认策略：min 8 + 3 字符类）→ ErrPasswordWeak，不触碰任何写。
	svc, users, creds, _, _, _, epoch, _, audit := newUserSvc()
	users.user = userTestRow()
	if err := svc.ResetUserPassword(ctx, 1, 42, "short"); !errors.Is(err, adminsvc.ErrPasswordWeak) {
		t.Fatalf("弱密码应 ErrPasswordWeak, got %v", err)
	}
	if len(creds.updated) != 0 || len(creds.created) != 0 || len(users.incIDs) != 0 ||
		len(epoch.synced) != 0 || len(audit.events) != 0 {
		t.Fatalf("弱密码不应触碰写路径: %+v %+v", creds.updated, creds.created)
	}

	// 成功：有行 Update + IncEpoch + Sync + 审计 detail={pwd_epoch}。
	svc, users, creds, _, _, _, epoch, _, audit = newUserSvc()
	users.user = userTestRow()
	users.incNext = 5
	creds.byKind = map[string]*model.UserCredential{
		"password": {ID: 7, UserID: 42, Kind: "password", Secret: []byte("old-hash"), IsEnabled: 0},
	}
	if err := svc.ResetUserPassword(ctx, 1, 42, "Str0ngPass!"); err != nil {
		t.Fatalf("重置: %v", err)
	}
	if len(creds.updated) != 1 || string(creds.updated[0].Secret) == "old-hash" ||
		creds.updated[0].IsEnabled != 1 {
		t.Fatalf("凭证更新 = %+v（secret 应换新、is_enabled 应回 1）", creds.updated)
	}
	if len(creds.created) != 0 {
		t.Fatalf("有行不应补建: %+v", creds.created)
	}
	if len(users.incIDs) != 1 || len(epoch.synced) != 1 || epoch.synced[0] != (userFakeSync{uid: 42, epoch: 5}) {
		t.Fatalf("失效链 = inc %v sync %+v", users.incIDs, epoch.synced)
	}
	if len(audit.events) != 1 || audit.events[0].Event != eventlog.EventAdminResetPassword ||
		audit.events[0].UserID != 42 || audit.events[0].ActorID != 1 {
		t.Fatalf("重置审计 = %+v", audit.events)
	}
	if string(audit.events[0].Detail) != string(eventlog.DetailPwdEpoch(5)) {
		t.Fatalf("审计 detail 应 {pwd_epoch:5}, got %q", audit.events[0].Detail)
	}

	// 无 password 行 → 同构补建 Create（setpass reset 口径）。
	creds = &userFakeCreds{}
	svc = adminsvc.NewUserService(&userFakeUsers{user: userTestRow()}, creds, &userFakeBinds{},
		&userFakeProviders{rows: map[string]*model.Provider{}}, &userFakeEvents{},
		&userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{}, &userFakePermissions{})
	if err := svc.ResetUserPassword(ctx, 1, 42, "Str0ngPass!"); err != nil {
		t.Fatalf("补建重置: %v", err)
	}
	if len(creds.created) != 1 || creds.created[0].Kind != "password" || creds.created[0].UserID != 42 ||
		creds.created[0].IsEnabled != 1 {
		t.Fatalf("补建行 = %+v", creds.created)
	}
	if err := svc.ResetUserPassword(ctx, 1, 404, "Str0ngPass!"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("行缺失应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserServiceSuperadminGuards superadmin 门禁判定（两接口 table-driven）：
// 禁用 superadmin 被拒 / 启用 superadmin 放行 / 禁用普通用户放行；非 superadmin
// 重置 superadmin 被拒 / superadmin 重置 superadmin 放行 / superadmin 重置自己放行 /
// 重置普通用户放行；权限查询故障原样上抛（fail-closed）；权限门禁按目标先、actor 后顺序查。
func TestUserServiceSuperadminGuards(t *testing.T) {
	ctx := context.Background()
	dbErr := errors.New("permission repo: db down")

	t.Run("UpdateUserStatus", func(t *testing.T) {
		tests := []struct {
			name        string
			perms       *userFakePermissions
			status      int64
			wantErr     error
			wantQueries []int64
			wantWrite   bool
		}{
			{
				name: "禁用 superadmin 被拒", perms: &userFakePermissions{granted: userGrantSuperadmins(42)},
				status: 0, wantErr: adminsvc.ErrPermissionDenied, wantQueries: []int64{42},
			},
			{
				name: "启用 superadmin 放行", perms: &userFakePermissions{granted: userGrantSuperadmins(42)},
				status: 1, wantQueries: nil, wantWrite: true,
			},
			{
				name: "禁用普通用户放行", perms: &userFakePermissions{},
				status: 0, wantQueries: []int64{42}, wantWrite: true,
			},
			{
				name: "权限查询故障原样上抛", perms: &userFakePermissions{errByUID: map[int64]error{42: dbErr}},
				status: 0, wantErr: dbErr, wantQueries: []int64{42},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc, users, _, _, _, _, epoch, _, audit := newUserSvc(tt.perms)
				users.user, users.incNext = userTestRow(), 4
				err := svc.UpdateUserStatus(ctx, 1, 42, tt.status)
				if tt.wantErr != nil {
					if !errors.Is(err, tt.wantErr) {
						t.Fatalf("err = %v, want %v", err, tt.wantErr)
					}
				} else if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				assertPermQueries(t, tt.perms.calls, tt.wantQueries)
				if !tt.wantWrite {
					if len(users.statusUpdated) != 0 || len(users.incIDs) != 0 || len(epoch.synced) != 0 || len(audit.events) != 0 {
						t.Fatalf("拒绝/故障不应触碰写路径: status=%v inc=%v sync=%v audit=%v",
							users.statusUpdated, users.incIDs, epoch.synced, audit.events)
					}
					return
				}
				if len(users.statusUpdated) != 1 || users.statusUpdated[0].status != int8(tt.status) {
					t.Fatalf("列级 UPDATE = %+v, want status=%d", users.statusUpdated, tt.status)
				}
				if tt.status == 0 && (len(users.incIDs) != 1 || len(audit.events) != 1) {
					t.Fatalf("禁用仍应走失效链 + 审计: inc=%v audit=%v", users.incIDs, audit.events)
				}
			})
		}
	})

	t.Run("ResetUserPassword", func(t *testing.T) {
		tests := []struct {
			name        string
			actor       int64
			perms       *userFakePermissions
			wantErr     error
			wantQueries []int64
			wantWrite   bool
		}{
			{
				name: "非 superadmin 重置 superadmin 被拒", actor: 1, perms: &userFakePermissions{granted: userGrantSuperadmins(42)},
				wantErr: adminsvc.ErrPermissionDenied, wantQueries: []int64{42, 1},
			},
			{
				name: "superadmin 重置 superadmin 放行", actor: 1, perms: &userFakePermissions{granted: userGrantSuperadmins(42, 1)},
				wantQueries: []int64{42, 1}, wantWrite: true,
			},
			{
				name: "superadmin 重置自己放行", actor: 42, perms: &userFakePermissions{granted: userGrantSuperadmins(42)},
				wantQueries: []int64{42, 42}, wantWrite: true,
			},
			{
				name: "重置普通用户放行（不查 actor）", actor: 1, perms: &userFakePermissions{},
				wantQueries: []int64{42}, wantWrite: true,
			},
			{
				name: "目标权限查询故障原样上抛", actor: 1, perms: &userFakePermissions{errByUID: map[int64]error{42: dbErr}},
				wantErr: dbErr, wantQueries: []int64{42},
			},
			{
				name: "actor 权限查询故障原样上抛", actor: 1, perms: &userFakePermissions{
					granted: userGrantSuperadmins(42), errByUID: map[int64]error{1: dbErr},
				},
				wantErr: dbErr, wantQueries: []int64{42, 1},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc, users, creds, _, _, _, epoch, _, audit := newUserSvc(tt.perms)
				users.user = userTestRow()
				err := svc.ResetUserPassword(ctx, tt.actor, 42, "Str0ngPass!")
				if tt.wantErr != nil {
					if !errors.Is(err, tt.wantErr) {
						t.Fatalf("err = %v, want %v", err, tt.wantErr)
					}
				} else if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				assertPermQueries(t, tt.perms.calls, tt.wantQueries)
				wrote := len(creds.created)+len(creds.updated) != 0 || len(users.incIDs) != 0 ||
					len(epoch.synced) != 0 || len(audit.events) != 0
				if wrote != tt.wantWrite {
					t.Fatalf("写路径触达 = %v, want %v（cred %v/%v inc %v sync %v audit %v）",
						wrote, tt.wantWrite, creds.created, creds.updated, users.incIDs, epoch.synced, audit.events)
				}
			})
		}

		// not_found 优先于权限判定：目标不存在时 FindByID 先返回 404，不查权限表。
		perms := &userFakePermissions{}
		svc, _, _, _, _, _, _, _, _ := newUserSvc(perms)
		if err := svc.ResetUserPassword(ctx, 1, 404, "Str0ngPass!"); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("行缺失应 ErrRecordNotFound, got %v", err)
		}
		if len(perms.calls) != 0 {
			t.Fatalf("目标不存在不应查权限, calls=%v", perms.calls)
		}
	})
}

// assertPermQueries 断言权限查询 uid 序列（顺序敏感：目标先、actor 后）。
func assertPermQueries(t *testing.T, got, want []int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("权限查询 = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("权限查询 = %v, want %v", got, want)
		}
	}
}

func userUnionProviders() *userFakeProviders {
	return &userFakeProviders{rows: map[string]*model.Provider{
		"wechat_union": {ProviderKey: "wechat_union", Category: "union"},
		"wechat_mp_1":  {ProviderKey: "wechat_mp_1", Category: "oauth", UnionProvider: "wechat_union"},
		"wechat_mp_2":  {ProviderKey: "wechat_mp_2", Category: "oauth", UnionProvider: "wechat_union"},
		"standalone":   {ProviderKey: "standalone", Category: "oauth"},
	}}
}

// userUnionKeys fake 级联判定的 provider_key → category=union 映射
// （与 userUnionProviders 的 wechat_union 对齐；map 读零值 false = 非
// Union，与 repo「provider 行缺失按非 Union 处理」同语义）。
func userUnionKeys() map[string]bool {
	return map[string]bool{"wechat_union": true}
}

// TestUserServiceUnbindUserThirdparty 覆盖清单：Union Provider 行单独解绑拒绝
// （invalid_request）；普通行删除 + 审计 thirdparty_unbind（target=provider_key、
// detail={provider_key, open_id}）；连带删 Union——无剩余非 Union 行时删对应
// Union 行、仍有非 Union 行时保留（§12.7 行 1548）；单事务回滚——普通行删除
// 失败 / Union 连带删除失败两注入点均整体不落盘、不投审计；
// 未绑该渠道 404。
func TestUserServiceUnbindUserThirdparty(t *testing.T) {
	ctx := context.Background()

	// Union 单独解绑拒绝。
	binds := &userFakeBinds{}
	svc := adminsvc.NewUserService(&userFakeUsers{user: userTestRow()}, &userFakeCreds{},
		binds, userUnionProviders(), &userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{},
		&userFakeAudit{}, userFakeSettings{}, &userFakePermissions{})
	if err := svc.UnbindUserThirdparty(ctx, 1, 42, "wechat_union"); !errors.Is(err, adminsvc.ErrInvalidRequest) {
		t.Fatalf("Union 单独解绑应 ErrInvalidRequest, got %v", err)
	}

	// 连带删：仅剩 Union 行 → 一并删除（单事务内）。
	audit := &userFakeAudit{}
	binds = &userFakeBinds{unionKeys: userUnionKeys(), rows: []model.UserThirdpartyBind{
		{ID: 11, UserID: 42, ProviderKey: "wechat_mp_1", OpenID: "oX-1"},
		{ID: 12, UserID: 42, ProviderKey: "wechat_union", OpenID: "union-1"},
	}}
	svc = adminsvc.NewUserService(&userFakeUsers{user: userTestRow()}, &userFakeCreds{},
		binds, userUnionProviders(), &userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{},
		audit, userFakeSettings{}, &userFakePermissions{})
	if err := svc.UnbindUserThirdparty(ctx, 1, 42, "wechat_mp_1"); err != nil {
		t.Fatalf("解绑: %v", err)
	}
	if len(binds.rows) != 0 || len(binds.unbound) != 2 {
		t.Fatalf("应连带删 Union 行: rows=%+v unbound=%v", binds.rows, binds.unbound)
	}
	if len(audit.events) != 1 || audit.events[0].Event != eventlog.EventThirdpartyUnbind ||
		audit.events[0].Target != "wechat_mp_1" || audit.events[0].ActorID != 1 || audit.events[0].UserID != 42 {
		t.Fatalf("解绑审计 = %+v", audit.events)
	}
	// detail = {provider_key, open_id}（msgpack map 键序不保证，按解码后字段断言）。
	var detail map[string]any
	if err := msgpack.Unmarshal(audit.events[0].Detail, &detail); err != nil ||
		detail["provider_key"] != "wechat_mp_1" || detail["open_id"] != "oX-1" {
		t.Fatalf("审计 detail = %q → %+v, want {provider_key:wechat_mp_1 open_id:oX-1}", audit.events[0].Detail, detail)
	}

	// 保留：仍有其他非 Union 绑定行（wechat_mp_2）→ Union 行保留。
	binds = &userFakeBinds{unionKeys: userUnionKeys(), rows: []model.UserThirdpartyBind{
		{ID: 21, UserID: 42, ProviderKey: "wechat_mp_1", OpenID: "oX-1"},
		{ID: 22, UserID: 42, ProviderKey: "wechat_mp_2", OpenID: "oX-2"},
		{ID: 23, UserID: 42, ProviderKey: "wechat_union", OpenID: "union-1"},
	}}
	svc = adminsvc.NewUserService(&userFakeUsers{user: userTestRow()}, &userFakeCreds{},
		binds, userUnionProviders(), &userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{},
		&userFakeAudit{}, userFakeSettings{}, &userFakePermissions{})
	if err := svc.UnbindUserThirdparty(ctx, 1, 42, "wechat_mp_1"); err != nil {
		t.Fatalf("解绑: %v", err)
	}
	if len(binds.rows) != 2 || len(binds.unbound) != 1 {
		t.Fatalf("应只删普通行保留 Union: rows=%+v unbound=%v", binds.rows, binds.unbound)
	}

	// 单事务回滚①：tx 内普通行删除失败 → 整体回滚，Union 行不删、
	// 不投审计。
	audit = &userFakeAudit{}
	binds = &userFakeBinds{unionKeys: userUnionKeys(), deleteErr: errors.New("delete boom"), rows: []model.UserThirdpartyBind{
		{ID: 51, UserID: 42, ProviderKey: "wechat_mp_1", OpenID: "oX-1"},
		{ID: 52, UserID: 42, ProviderKey: "wechat_union", OpenID: "union-1"},
	}}
	svc = adminsvc.NewUserService(&userFakeUsers{user: userTestRow()}, &userFakeCreds{},
		binds, userUnionProviders(), &userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{},
		audit, userFakeSettings{}, &userFakePermissions{})
	if err := svc.UnbindUserThirdparty(ctx, 1, 42, "wechat_mp_1"); err == nil {
		t.Fatal("删除失败应上抛错误")
	}
	if len(binds.rows) != 2 || len(binds.unbound) != 0 || len(audit.events) != 0 {
		t.Fatalf("普通行删除失败应整体回滚: rows=%+v unbound=%v audit=%v", binds.rows, binds.unbound, audit.events)
	}

	// 单事务回滚②：tx 内 Union 连带删除失败 → 普通行删除一并回滚（旧两跳
	// 非同事务时普通行已删、重试 404 无法自愈；级联收编 repo 单事务后可重试）。
	audit = &userFakeAudit{}
	binds = &userFakeBinds{unionKeys: userUnionKeys(), cascadeErr: errors.New("cascade boom"), rows: []model.UserThirdpartyBind{
		{ID: 61, UserID: 42, ProviderKey: "wechat_mp_1", OpenID: "oX-1"},
		{ID: 62, UserID: 42, ProviderKey: "wechat_union", OpenID: "union-1"},
	}}
	svc = adminsvc.NewUserService(&userFakeUsers{user: userTestRow()}, &userFakeCreds{},
		binds, userUnionProviders(), &userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{},
		audit, userFakeSettings{}, &userFakePermissions{})
	if err := svc.UnbindUserThirdparty(ctx, 1, 42, "wechat_mp_1"); err == nil {
		t.Fatal("连带删除失败应上抛错误")
	}
	if len(binds.rows) != 2 || len(binds.unbound) != 0 || len(audit.events) != 0 {
		t.Fatalf("连带删除失败应整体回滚（普通行不悬空）: rows=%+v unbound=%v audit=%v", binds.rows, binds.unbound, audit.events)
	}

	// 无 union_provider 的渠道：无连带逻辑，直接删。
	binds = &userFakeBinds{rows: []model.UserThirdpartyBind{
		{ID: 31, UserID: 42, ProviderKey: "standalone", OpenID: "oX-3"},
	}}
	svc = adminsvc.NewUserService(&userFakeUsers{user: userTestRow()}, &userFakeCreds{},
		binds, userUnionProviders(), &userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{},
		&userFakeAudit{}, userFakeSettings{}, &userFakePermissions{})
	if err := svc.UnbindUserThirdparty(ctx, 1, 42, "standalone"); err != nil || len(binds.rows) != 0 {
		t.Fatalf("standalone 解绑 = (%v), rows=%+v", err, binds.rows)
	}

	// 未绑该渠道 / provider 不存在 → 404；空 providerKey → invalid_request。
	svc = adminsvc.NewUserService(&userFakeUsers{user: userTestRow()}, &userFakeCreds{},
		&userFakeBinds{}, userUnionProviders(), &userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{},
		&userFakeAudit{}, userFakeSettings{}, &userFakePermissions{})
	if err := svc.UnbindUserThirdparty(ctx, 1, 42, "wechat_mp_2"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("未绑该渠道应 404, got %v", err)
	}
	if err := svc.UnbindUserThirdparty(ctx, 1, 42, "no_such_provider"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("provider 不存在应 404, got %v", err)
	}
	if err := svc.UnbindUserThirdparty(ctx, 1, 42, ""); !errors.Is(err, adminsvc.ErrInvalidRequest) {
		t.Fatalf("空 providerKey 应 ErrInvalidRequest, got %v", err)
	}
}

// TestUserServiceUnlockUser 覆盖清单：uid 维度键（Reset("42")）+ 按当前
// phone / email 重算 ip 账号哈希维度（sha256 hex，factor/password userRef
// 同款格式）；未绑定联系方式只清 uid 维度；行缺失 404。
func TestUserServiceUnlockUser(t *testing.T) {
	ctx := context.Background()
	svc, users, _, _, _, _, _, pwfail, _ := newUserSvc()
	users.user = userTestRow()

	if err := svc.UnlockUser(ctx, 42); err != nil {
		t.Fatalf("解锁: %v", err)
	}
	if len(pwfail.resetRefs) != 1 || pwfail.resetRefs[0] != "42" {
		t.Fatalf("uid 维度 Reset = %v, want [42]", pwfail.resetRefs)
	}
	wantRefs := map[string]bool{}
	for _, ident := range []string{"13800138000", "alice@example.com"} {
		sum := sha256.Sum256([]byte(ident))
		wantRefs[hex.EncodeToString(sum[:])] = true
	}
	if len(pwfail.deletedRefs) != 2 {
		t.Fatalf("ip 维度重算 = %v, want 2 个哈希", pwfail.deletedRefs)
	}
	for _, got := range pwfail.deletedRefs {
		if !wantRefs[got] {
			t.Fatalf("ip 维度哈希 %q 不在预期集", got)
		}
	}

	// 无联系方式：只清 uid 维度。
	svc, users, _, _, _, _, _, pwfail, _ = newUserSvc()
	users.user = &model.User{ID: 43, Username: "bob"}
	if err := svc.UnlockUser(ctx, 43); err != nil {
		t.Fatalf("解锁: %v", err)
	}
	if len(pwfail.resetRefs) != 1 || pwfail.resetRefs[0] != strconv.FormatInt(43, 10) || len(pwfail.deletedRefs) != 0 {
		t.Fatalf("无联系方式应只清 uid 维度: reset=%v deleted=%v", pwfail.resetRefs, pwfail.deletedRefs)
	}

	// 行缺失 404。
	svc, _, _, _, _, _, _, _, _ = newUserSvc()
	if err := svc.UnlockUser(ctx, 404); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("行缺失应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserServiceGetUserEvents login_success 过滤 + 分页透传；事件类型不在
// 查询参数中重复（user.proto 注释）。
func TestUserServiceGetUserEvents(t *testing.T) {
	ctx := context.Background()
	svc, _, _, _, _, events, _, _, _ := newUserSvc()
	events.rows = []model.EventLog{{ID: 3, Event: "login_success", UserID: 42}}
	events.total = 7

	rows, total, err := svc.GetUserEvents(ctx, 42, 3, 50)
	if err != nil || total != 7 || len(rows) != 1 || rows[0].Event != "login_success" {
		t.Fatalf("GetUserEvents = (%+v, %d, %v)", rows, total, err)
	}
	if events.gotQuery.UserID != 42 || events.gotQuery.Event != eventlog.EventLoginSuccess ||
		events.gotQuery.Page != 3 || events.gotQuery.PageSize != 50 {
		t.Fatalf("查询透传 = %+v, want user=42 event=login_success page=3 size=50", events.gotQuery)
	}
}

// TestNewUserServiceNilPanics fail-fast 构造（口径同 provider.NewService）。
func TestNewUserServiceNilPanics(t *testing.T) {
	users := &userFakeUsers{}
	providers := &userFakeProviders{rows: map[string]*model.Provider{}}
	mustPanicUser(t, "nil users", func() {
		adminsvc.NewUserService(nil, &userFakeCreds{}, &userFakeBinds{}, providers,
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{}, &userFakePermissions{})
	})
	mustPanicUser(t, "nil creds", func() {
		adminsvc.NewUserService(users, nil, &userFakeBinds{}, providers,
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{}, &userFakePermissions{})
	})
	mustPanicUser(t, "nil binds", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, nil, providers,
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{}, &userFakePermissions{})
	})
	mustPanicUser(t, "nil providers", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, nil,
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{}, &userFakePermissions{})
	})
	mustPanicUser(t, "nil events", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, providers,
			nil, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{}, &userFakePermissions{})
	})
	mustPanicUser(t, "nil epoch", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, providers,
			&userFakeEvents{}, nil, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{}, &userFakePermissions{})
	})
	mustPanicUser(t, "nil pwfail", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, providers,
			&userFakeEvents{}, &userFakeEpoch{}, nil, &userFakeAudit{}, userFakeSettings{}, &userFakePermissions{})
	})
	mustPanicUser(t, "nil audit", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, providers,
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, nil, userFakeSettings{}, &userFakePermissions{})
	})
	mustPanicUser(t, "nil settings", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, providers,
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, nil, &userFakePermissions{})
	})
	mustPanicUser(t, "nil permissions", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, providers,
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{}, nil)
	})
}

func mustPanicUser(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: 未 panic", name)
		}
	}()
	fn()
}

// —— UpdateUserProfile / UpdateUserContact / 目标分级写门禁 ——

// userGrantNormalAdmin 构造「指定 uid 持有任意权限点但不含 superadmin」的
// 授予表（普通管理员目标，门禁矩阵中档）。
func userGrantNormalAdmin(uids ...int64) map[int64]map[string]bool {
	m := make(map[int64]map[string]bool, len(uids))
	for _, uid := range uids {
		m[uid] = map[string]bool{"editor": true}
	}
	return m
}

// TestUserServiceUserWriteGate 目标账户分级门禁矩阵（§5.4 /《后端架构》§4.8，
// 经 UpdateUserProfile / UpdateUserContact 两写入口 table-driven）：
// superadmin 目标一律拒绝（任何操作者，含其自身）；普通管理员目标仅
// superadmin 操作者可写；普通目标放行（UpdateUserContact 另要求 superadmin
// 操作者——无凭据接管例外）；目标 HasPermission / HasAnyPermission 查询
// 故障与操作者查询故障原样上抛不放行（fail-closed，非 permission_denied）；
// 被拒时不触任何写路径。
func TestUserServiceUserWriteGate(t *testing.T) {
	ctx := context.Background()
	dbErr := errors.New("permission repo: db down")
	actorSA := int64(1)
	actorPlain := int64(2)

	tests := []struct {
		name string
		// targetPerms 目标 42 的授予表；actorSuperadmin 操作者是否持
		// superadmin；actorErr / targetPermErr / targetAnyErr 故障注入。
		targetPerms     map[string]bool
		actorSuperadmin bool
		actorErr        error
		targetPermErr   error
		targetAnyErr    error
		// wantContactDenied UpdateUserContact 对该组合的期望（普通目标 +
		// 普通操作者时仅 contact 拒、profile 放行）。
		wantContactDenied bool
		wantErr           error
	}{
		{name: "superadmin 目标 superadmin 操作者拒", targetPerms: map[string]bool{adminsvc.PointSuperAdmin: true}, actorSuperadmin: true, wantErr: adminsvc.ErrPermissionDenied},
		{name: "superadmin 目标普通操作者拒", targetPerms: map[string]bool{adminsvc.PointSuperAdmin: true}, actorSuperadmin: false, wantErr: adminsvc.ErrPermissionDenied},
		{name: "普通管理员目标 superadmin 操作者放行", targetPerms: map[string]bool{"editor": true}, actorSuperadmin: true},
		{name: "普通管理员目标普通操作者拒", targetPerms: map[string]bool{"editor": true}, actorSuperadmin: false, wantErr: adminsvc.ErrPermissionDenied},
		{name: "普通目标 superadmin 操作者放行", targetPerms: map[string]bool{}, actorSuperadmin: true},
		{name: "普通目标普通操作者 profile 放行 contact 拒", targetPerms: map[string]bool{}, actorSuperadmin: false, wantContactDenied: true},
		{name: "目标 HasPermission 故障不放行", targetPerms: map[string]bool{}, actorSuperadmin: true, targetPermErr: dbErr, wantErr: dbErr},
		{name: "目标 HasAnyPermission 故障不放行", targetPerms: map[string]bool{}, actorSuperadmin: true, targetAnyErr: dbErr, wantErr: dbErr},
		{name: "操作者查询故障不放行", targetPerms: map[string]bool{"editor": true}, actorSuperadmin: true, actorErr: dbErr, wantErr: dbErr},
	}

	for _, tt := range tests {
		perms := &userFakePermissions{
			granted: map[int64]map[string]bool{
				42: tt.targetPerms,
			},
			errByUID:    map[int64]error{},
			anyErrByUID: map[int64]error{},
		}
		if tt.actorSuperadmin {
			perms.granted[actorSA] = map[string]bool{adminsvc.PointSuperAdmin: true}
		}
		if tt.actorErr != nil {
			perms.errByUID[actorSA] = tt.actorErr
		}
		if tt.targetPermErr != nil {
			perms.errByUID[42] = tt.targetPermErr
		}
		if tt.targetAnyErr != nil {
			perms.anyErrByUID[42] = tt.targetAnyErr
		}

		t.Run(tt.name+"/UpdateUserProfile", func(t *testing.T) {
			svc, users, _, _, _, _, _, _, audit := newUserSvc(perms)
			users.user = userTestRow()
			err := svc.UpdateUserProfile(ctx, actorSA, 42, &adminv1.UpdateUserProfileRequest{Id: 42})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				if len(users.profileCols) != 0 || len(users.profileSaved) != 0 || len(audit.events) != 0 {
					t.Fatalf("拒绝不应写库或审计: cols=%v saved=%v audit=%d", users.profileCols, users.profileSaved, len(audit.events))
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if len(users.incIDs) != 0 {
				t.Fatalf("资料编辑不触发会话失效: inc=%v", users.incIDs)
			}
		})

		t.Run(tt.name+"/UpdateUserContact", func(t *testing.T) {
			svc, users, _, _, _, _, epoch, _, audit := newUserSvc(perms)
			users.user = userTestRow()
			users.incNext = 5
			err := svc.UpdateUserContact(ctx, actorSA, 42, &adminv1.UpdateUserContactRequest{Id: 42})
			if tt.wantErr != nil || tt.wantContactDenied {
				want := tt.wantErr
				if want == nil {
					want = adminsvc.ErrPermissionDenied
				}
				if !errors.Is(err, want) {
					t.Fatalf("err = %v, want %v", err, want)
				}
				if len(users.contactUpdated) != 0 || len(users.incIDs) != 0 || len(epoch.synced) != 0 || len(audit.events) != 0 {
					t.Fatalf("拒绝不应写库/下线/审计: %+v inc=%v sync=%v audit=%d",
						users.contactUpdated, users.incIDs, epoch.synced, len(audit.events))
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			// 放行分支（含空 PATCH）：写库后走强制下线链（contact 专属用例
			// 断言明细，这里只断言链路被触发）。
			if len(users.incIDs) != 1 || len(epoch.synced) != 1 {
				t.Fatalf("放行应触发强制下线链: inc=%v sync=%v", users.incIDs, epoch.synced)
			}
		})

		// actorPlain 组合只补跑「普通目标 + 普通操作者」的差异档（其余档与
		// actorSA 结果同构，不重复展开）。
		if tt.name == "普通目标普通操作者 profile 放行 contact 拒" {
			perms := &userFakePermissions{granted: map[int64]map[string]bool{42: tt.targetPerms}}
			t.Run(tt.name+"/actorPlain profile 放行", func(t *testing.T) {
				svc, users, _, _, _, _, _, _, audit := newUserSvc(perms)
				users.user = userTestRow()
				if err := svc.UpdateUserProfile(ctx, actorPlain, 42, &adminv1.UpdateUserProfileRequest{Id: 42}); err != nil {
					t.Fatalf("普通操作者改普通账户资料应放行, got %v", err)
				}
				if len(audit.events) != 1 {
					t.Fatalf("放行应审计: %d", len(audit.events))
				}
			})
			t.Run(tt.name+"/actorPlain contact 拒", func(t *testing.T) {
				svc, users, _, _, _, _, epoch, _, audit := newUserSvc(perms)
				users.user = userTestRow()
				if err := svc.UpdateUserContact(ctx, actorPlain, 42, &adminv1.UpdateUserContactRequest{Id: 42}); !errors.Is(err, adminsvc.ErrPermissionDenied) {
					t.Fatalf("普通操作者改联系方式应拒, got %v", err)
				}
				if len(users.contactUpdated) != 0 || len(users.incIDs) != 0 || len(epoch.synced) != 0 || len(audit.events) != 0 {
					t.Fatalf("拒绝不应有副作用")
				}
			})
		}
	}
}

// TestUserServiceUpdateUserProfile PATCH has 位与校验（§5.4）：未设置不改
// （零写库）、显式空串 = 清空、profile 子字段 has 位合并（现行行保留未传
// 子字段）、gender / birthday 值域校验违规 invalid_request 且零写库、
// 审计 admin_update_user detail={changed_fields} 仅字段名、不触发会话失效。
func TestUserServiceUpdateUserProfile(t *testing.T) {
	ctx := context.Background()
	perms := &userFakePermissions{granted: userGrantSuperadmins(1)}

	// 全未设置 = 合法空操作：零写库，审计 changed_fields 空表。
	svc, users, _, _, _, _, epoch, _, audit := newUserSvc(perms)
	users.user = userTestRow()
	if err := svc.UpdateUserProfile(ctx, 1, 42, &adminv1.UpdateUserProfileRequest{Id: 42}); err != nil {
		t.Fatalf("空 PATCH: %v", err)
	}
	if len(users.profileCols) != 0 || len(users.profileSaved) != 0 {
		t.Fatalf("空 PATCH 零写库: cols=%+v saved=%+v", users.profileCols, users.profileSaved)
	}
	if len(users.incIDs) != 0 || len(epoch.synced) != 0 {
		t.Fatalf("资料编辑不触发会话失效: inc=%v sync=%v", users.incIDs, epoch.synced)
	}
	if len(audit.events) != 1 || audit.events[0].Event != eventlog.EventAdminUpdateUser ||
		audit.events[0].ActorType != eventlog.ActorTypeAdmin || audit.events[0].ActorID != 1 ||
		audit.events[0].UserID != 42 {
		t.Fatalf("空 PATCH 审计 = %+v", audit.events)
	}
	if !strings.Contains(string(audit.events[0].Detail), "changed_fields") {
		t.Fatalf("审计 detail 应含 changed_fields 键, got %q", audit.events[0].Detail)
	}

	// 显式空串 = 清空（nickname 指针非 nil 且为空串 → 列级 UPDATE 透传）；
	// profile 行缺失 → 从零值行起合并建行。
	svc, users, _, _, _, _, _, _, audit = newUserSvc(perms)
	users.user = userTestRow()
	empty := ""
	if err := svc.UpdateUserProfile(ctx, 1, 42, &adminv1.UpdateUserProfileRequest{
		Id: 42, Nickname: &empty,
		Profile: &accountv1.UserProfile{Locale: ptrStr("zh-CN")},
	}); err != nil {
		t.Fatalf("清空 + profile: %v", err)
	}
	if len(users.profileCols) != 1 || users.profileCols[0].nickname == nil || *users.profileCols[0].nickname != "" {
		t.Fatalf("显式清空应透传空串指针: %+v", users.profileCols)
	}
	if len(users.profileSaved) != 1 || users.profileSaved[0].UserID != 42 || users.profileSaved[0].Locale != "zh-CN" {
		t.Fatalf("profile 建行 = %+v", users.profileSaved)
	}
	if len(audit.events) != 1 {
		t.Fatalf("审计条数 = %d", len(audit.events))
	}
	var detail map[string]any
	if err := msgpack.Unmarshal(audit.events[0].Detail, &detail); err != nil {
		t.Fatalf("detail 解码: %v", err)
	}
	fields, _ := detail["changed_fields"].([]any)
	if len(fields) != 2 || fields[0] != "nickname" || fields[1] != "locale" {
		t.Fatalf("changed_fields = %v, want [nickname locale]", fields)
	}

	// 未设置子字段保留现行值（合并语义）：现行 locale=fr-FR，只传 gender。
	svc, users, _, _, _, _, _, _, _ = newUserSvc(perms)
	users.user = userTestRow()
	users.profileRow = &model.UserProfile{UserID: 42, Locale: "fr-FR"}
	gender := int64(1)
	if err := svc.UpdateUserProfile(ctx, 1, 42, &adminv1.UpdateUserProfileRequest{
		Id:      42,
		Profile: &accountv1.UserProfile{Gender: &gender},
	}); err != nil {
		t.Fatalf("合并: %v", err)
	}
	if len(users.profileSaved) != 1 || users.profileSaved[0].Gender != 1 || users.profileSaved[0].Locale != "fr-FR" {
		t.Fatalf("合并结果 = %+v（gender 覆盖、locale 保留）", users.profileSaved)
	}

	// 值域校验违规 → invalid_request 且零写库零审计（先于任何写操作）。
	for name, req := range map[string]*adminv1.UpdateUserProfileRequest{
		"gender 越界":   {Id: 42, Profile: &accountv1.UserProfile{Gender: ptrI64(3)}},
		"birthday 非法": {Id: 42, Profile: &accountv1.UserProfile{Birthday: ptrStr("2000-13-40")}},
	} {
		svc, users, _, _, _, _, _, _, audit = newUserSvc(perms)
		users.user = userTestRow()
		if err := svc.UpdateUserProfile(ctx, 1, 42, req); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("%s 应 ErrInvalidRequest, got %v", name, err)
		}
		if len(users.profileCols) != 0 || len(users.profileSaved) != 0 || len(audit.events) != 0 {
			t.Fatalf("%s 零写库零审计: cols=%v saved=%v audit=%v", name, users.profileCols, users.profileSaved, audit.events)
		}
	}

	// 行缺失 → 404。
	svc, users, _, _, _, _, _, _, _ = newUserSvc(perms)
	if err := svc.UpdateUserProfile(ctx, 1, 404, &adminv1.UpdateUserProfileRequest{Id: 404}); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("行缺失应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserServiceUpdateUserContact 联系方式编辑（§5.4）：写即置已验证 /
// 显式清空置 0、格式校验、唯一冲突（预检与落库 TOCTOU）返回字段级错误且
// 不投审计、命中自己 = 原值重放、成功后强制下线（IncEpoch + Sync）+ 审计
// detail 仅字段名不含联系方式明文。
func TestUserServiceUpdateUserContact(t *testing.T) {
	ctx := context.Background()
	perms := &userFakePermissions{granted: userGrantSuperadmins(1)}

	// 写非空 phone → verified=1 + IncEpoch + Sync + 审计（detail 无明文）。
	svc, users, _, _, _, _, epoch, _, audit := newUserSvc(perms)
	users.user = userTestRow()
	users.incNext = 9
	if err := svc.UpdateUserContact(ctx, 1, 42, &adminv1.UpdateUserContactRequest{Id: 42, Phone: ptrStr("13900001111")}); err != nil {
		t.Fatalf("改手机号: %v", err)
	}
	if len(users.contactUpdated) != 1 {
		t.Fatalf("列更新次数 = %d", len(users.contactUpdated))
	}
	up := users.contactUpdated[0]
	if up.phone == nil || *up.phone != "13900001111" || up.email != nil || up.phoneV == nil || *up.phoneV != 1 || up.emailV != nil {
		t.Fatalf("列更新入参 = %+v（phone 写值 + phone_verified=1）", up)
	}
	if len(users.incIDs) != 1 || users.incIDs[0] != 42 || len(epoch.synced) != 1 || epoch.synced[0] != (userFakeSync{uid: 42, epoch: 9}) {
		t.Fatalf("强制下线链 = inc %v sync %+v", users.incIDs, epoch.synced)
	}
	if len(audit.events) != 1 || audit.events[0].Event != eventlog.EventAdminUpdateContact ||
		audit.events[0].UserID != 42 || audit.events[0].ActorID != 1 {
		t.Fatalf("审计 = %+v", audit.events)
	}
	if strings.Contains(string(audit.events[0].Detail), "13900001111") {
		t.Fatalf("审计 detail 不得含联系方式明文: %q", audit.events[0].Detail)
	}
	var detail map[string]any
	if err := msgpack.Unmarshal(audit.events[0].Detail, &detail); err != nil {
		t.Fatalf("detail 解码: %v", err)
	}
	fields, _ := detail["changed_fields"].([]any)
	if len(fields) != 1 || fields[0] != "phone" {
		t.Fatalf("changed_fields = %v, want [phone]", fields)
	}

	// 显式清空 email → email_verified=0（清空值透传空串，repo 归一写 NULL）。
	svc, users, _, _, _, _, epoch, _, audit = newUserSvc(perms)
	users.user = userTestRow()
	if err := svc.UpdateUserContact(ctx, 1, 42, &adminv1.UpdateUserContactRequest{Id: 42, Email: ptrStr("  ")}); err != nil {
		t.Fatalf("清空邮箱: %v", err)
	}
	up = users.contactUpdated[0]
	if up.email == nil || *up.email != "" || up.emailV == nil || *up.emailV != 0 || up.phone != nil {
		t.Fatalf("清空入参 = %+v（email 空串 + email_verified=0）", up)
	}
	if len(users.incIDs) != 1 || len(audit.events) != 1 {
		t.Fatalf("清空同样触发下线与审计: inc=%v audit=%d", users.incIDs, len(audit.events))
	}

	// 格式违规 → invalid_request 零写库零审计。
	svc, users, _, _, _, _, epoch, _, audit = newUserSvc(perms)
	users.user = userTestRow()
	if err := svc.UpdateUserContact(ctx, 1, 42, &adminv1.UpdateUserContactRequest{Id: 42, Phone: ptrStr("12345")}); !errors.Is(err, adminsvc.ErrInvalidRequest) {
		t.Fatalf("非法手机号应 ErrInvalidRequest, got %v", err)
	}
	if len(users.contactUpdated) != 0 || len(users.incIDs) != 0 || len(audit.events) != 0 {
		t.Fatalf("格式违规零副作用: %+v inc=%v audit=%d", users.contactUpdated, users.incIDs, len(audit.events))
	}

	// 唯一冲突（预检命中他人）→ ErrTargetTaken，不写库、不下线、不审计。
	svc, users, _, _, _, _, epoch, _, audit = newUserSvc(perms)
	users.user = userTestRow()
	users.phoneHolders = map[string]*model.User{"13900001111": {ID: 7, Username: "bob"}}
	if err := svc.UpdateUserContact(ctx, 1, 42, &adminv1.UpdateUserContactRequest{Id: 42, Phone: ptrStr("13900001111")}); !errors.Is(err, adminsvc.ErrTargetTaken) {
		t.Fatalf("冲突应 ErrTargetTaken, got %v", err)
	}
	if len(users.contactUpdated) != 0 || len(users.incIDs) != 0 || len(epoch.synced) != 0 || len(audit.events) != 0 {
		t.Fatalf("冲突零副作用: %+v inc=%v sync=%v audit=%d", users.contactUpdated, users.incIDs, epoch.synced, len(audit.events))
	}

	// 唯一冲突（TOCTOU：预检后落库前被抢）→ repo ErrUserDuplicate 归一同字段级错误。
	svc, users, _, _, _, _, _, _, _ = newUserSvc(perms)
	users.user = userTestRow()
	users.contactErr = fmt.Errorf("user repo: update contact columns: %w: %w", repo.ErrUserDuplicate, errors.New("1062"))
	if err := svc.UpdateUserContact(ctx, 1, 42, &adminv1.UpdateUserContactRequest{Id: 42, Phone: ptrStr("13900001111")}); !errors.Is(err, adminsvc.ErrTargetTaken) {
		t.Fatalf("TOCTOU 冲突应 ErrTargetTaken, got %v", err)
	}

	// 命中自己 = 原值重放，放行（幂等重写 + verified 置 1）。
	svc, users, _, _, _, _, _, _, audit = newUserSvc(perms)
	users.user = userTestRow()
	users.phoneHolders = map[string]*model.User{"13800138000": userTestRow()}
	if err := svc.UpdateUserContact(ctx, 1, 42, &adminv1.UpdateUserContactRequest{Id: 42, Phone: ptrStr("13800138000")}); err != nil {
		t.Fatalf("原值重放: %v", err)
	}
	if len(users.contactUpdated) != 1 || len(audit.events) != 1 {
		t.Fatalf("原值重放照常写库与审计: %+v audit=%d", users.contactUpdated, len(audit.events))
	}

	// 行缺失 → 404。
	svc, users, _, _, _, _, _, _, _ = newUserSvc(perms)
	if err := svc.UpdateUserContact(ctx, 1, 404, &adminv1.UpdateUserContactRequest{Id: 404}); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("行缺失应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserServiceGetUserProfileProjection GetUser 详情的 profile 投影：
// 行存在如实返回，行缺失容忍为 nil（读口径同 §3.1 GetProfile，不视为错误）。
func TestUserServiceGetUserProfileProjection(t *testing.T) {
	ctx := context.Background()
	svc, users, _, _, _, _, _, _, _ := newUserSvc()
	users.user = userTestRow()
	birthday := time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)
	users.profileRow = &model.UserProfile{UserID: 42, Gender: 2, Birthday: &birthday, Locale: "zh-CN"}

	d, err := svc.GetUser(ctx, 42)
	if err != nil || d.Profile == nil || d.Profile.Gender != 2 || d.Profile.Locale != "zh-CN" ||
		d.Profile.Birthday == nil || !d.Profile.Birthday.Equal(birthday) {
		t.Fatalf("GetUser 投影 = (%+v, %v)", d.Profile, err)
	}

	svc, users, _, _, _, _, _, _, _ = newUserSvc()
	users.user = userTestRow()
	if d, err := svc.GetUser(ctx, 42); err != nil || d.Profile != nil {
		t.Fatalf("profile 行缺失应容忍为 nil, got (%+v, %v)", d.Profile, err)
	}
}

// ptrStr / ptrI64 测试用指针构造助手。
func ptrStr(v string) *string { return &v }
func ptrI64(v int64) *int64   { return &v }

// —— 救援族 5 方法（§5.4）：值域 / 门禁复用 / 强制下线集合 / 审计 ——

// TestUserServiceSetUserMfa 管理端开关两步验证：开启只写开关列（不触发
// 失效链、不审计）；关闭写列后走 IncEpoch + Sync + 审计 admin_disable_mfa
// （detail={enabled:false}）；值域 0|1 之外 invalid_request 且零副作用；
// 目标行缺失 404。
func TestUserServiceSetUserMfa(t *testing.T) {
	ctx := context.Background()

	t.Run("开启不触发失效链与审计", func(t *testing.T) {
		svc, users, _, _, _, _, epoch, _, audit := newUserSvc()
		users.user = userTestRow()
		if err := svc.SetUserMfa(ctx, 1, 42, 1); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(users.mfaUpdated) != 1 || users.mfaUpdated[0] != (userFakeMfaUpdate{id: 42, mfa: 1}) {
			t.Fatalf("mfaUpdated = %+v, want [{42 1}]", users.mfaUpdated)
		}
		if len(users.incIDs) != 0 || len(epoch.synced) != 0 {
			t.Fatalf("开启不应触发会话失效: inc=%v sync=%v", users.incIDs, epoch.synced)
		}
		if len(audit.events) != 0 {
			t.Fatalf("开启不应投审计: %+v", audit.events)
		}
	})

	t.Run("关闭触发强制下线与审计", func(t *testing.T) {
		svc, users, _, _, _, _, epoch, _, audit := newUserSvc()
		users.user = userTestRow()
		users.incNext = 7
		if err := svc.SetUserMfa(ctx, 1, 42, 0); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(users.mfaUpdated) != 1 || users.mfaUpdated[0].mfa != 0 {
			t.Fatalf("mfaUpdated = %+v, want mfa=0", users.mfaUpdated)
		}
		if len(users.incIDs) != 1 || users.incIDs[0] != 42 ||
			len(epoch.synced) != 1 || epoch.synced[0] != (userFakeSync{uid: 42, epoch: 7}) {
			t.Fatalf("关闭应走失效链: inc=%v sync=%v", users.incIDs, epoch.synced)
		}
		if len(audit.events) != 1 {
			t.Fatalf("关闭应投审计: %d", len(audit.events))
		}
		ev := audit.events[0]
		if ev.Event != eventlog.EventAdminDisableMFA || ev.ActorType != eventlog.ActorTypeAdmin ||
			ev.ActorID != 1 || ev.UserID != 42 {
			t.Fatalf("审计事件 = %+v", ev)
		}
		var d map[string]any
		if err := msgpack.Unmarshal(ev.Detail, &d); err != nil {
			t.Fatalf("detail 解码: %v", err)
		}
		if v, ok := d["enabled"].(bool); !ok || v != false {
			t.Fatalf("detail = %+v, want enabled:false", d)
		}
	})

	t.Run("值域 0|1 之外拒绝且零副作用", func(t *testing.T) {
		svc, users, _, _, _, _, epoch, _, audit := newUserSvc()
		users.user = userTestRow()
		if err := svc.SetUserMfa(ctx, 1, 42, 2); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
		if len(users.mfaUpdated) != 0 || len(users.incIDs) != 0 || len(epoch.synced) != 0 || len(audit.events) != 0 {
			t.Fatalf("值域拒绝不应有副作用")
		}
	})

	t.Run("目标行缺失 404", func(t *testing.T) {
		svc, users, _, _, _, _, _, _, _ := newUserSvc()
		users.user = userTestRow()
		if err := svc.SetUserMfa(ctx, 1, 99, 1); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("err = %v, want ErrRecordNotFound", err)
		}
	})
}

// TestUserServiceUnbindUserTOTP 管理员救援解绑 TOTP：删 kind=totp 凭证行
// （recovery_code 行不在契约范围）→ 强制下线 → 审计 admin_unbind_totp
// （detail={}）；totp 行缺失 404 且零副作用。
func TestUserServiceUnbindUserTOTP(t *testing.T) {
	ctx := context.Background()

	t.Run("成功删 totp 行并强制下线", func(t *testing.T) {
		svc, users, creds, _, _, _, epoch, _, audit := newUserSvc()
		users.user = userTestRow()
		creds.byKind = map[string]*model.UserCredential{
			"totp": {ID: 3, UserID: 42, Kind: "totp"},
		}
		users.incNext = 4
		if err := svc.UnbindUserTOTP(ctx, 1, 42); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(creds.deletedByKind) != 1 || creds.deletedByKind[0] != (userFakeCredDeleteKind{userID: 42, kind: "totp"}) {
			t.Fatalf("deletedByKind = %+v", creds.deletedByKind)
		}
		if len(users.incIDs) != 1 || len(epoch.synced) != 1 || epoch.synced[0].uid != 42 {
			t.Fatalf("解绑应走失效链: inc=%v sync=%v", users.incIDs, epoch.synced)
		}
		if len(audit.events) != 1 || audit.events[0].Event != eventlog.EventAdminUnbindTotp ||
			audit.events[0].UserID != 42 || audit.events[0].ActorID != 1 {
			t.Fatalf("审计事件 = %+v", audit.events)
		}
		var d map[string]any
		if err := msgpack.Unmarshal(audit.events[0].Detail, &d); err != nil {
			t.Fatalf("detail 解码: %v", err)
		}
		if len(d) != 0 {
			t.Fatalf("detail = %+v, want 空对象（不记 TOTP 密钥）", d)
		}
	})

	t.Run("totp 行缺失 404 且零副作用", func(t *testing.T) {
		svc, users, creds, _, _, _, epoch, _, audit := newUserSvc()
		users.user = userTestRow()
		if err := svc.UnbindUserTOTP(ctx, 1, 42); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("err = %v, want ErrRecordNotFound", err)
		}
		if len(creds.deletedByKind) != 0 || len(users.incIDs) != 0 || len(epoch.synced) != 0 || len(audit.events) != 0 {
			t.Fatalf("删除失败不应有失效与审计")
		}
	})
}

// TestUserServiceResetUserRecoveryCodes 重生成恢复码：meta 整行覆盖为 10 条
// 互异 8 位存储形新码（与旧码全异）、is_enabled 不动；方法只返回 error、
// 审计 detail 为空对象（响应与审计均无明文回显）；不触发失效链；行缺失 404。
func TestUserServiceResetUserRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	oldCodes := []string{"aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd", "eeeeeeee",
		"ffffffff", "gggggggg", "hhhhhhhh", "jjjjjjjj", "kkkkkkkk"}

	t.Run("重生成写回 meta 且无明文出口", func(t *testing.T) {
		svc, users, creds, _, _, _, epoch, _, audit := newUserSvc()
		users.user = userTestRow()
		oldMeta, err := repo.MarshalCredentialMeta(&credentialpb.CredentialMeta{RecoveryCodes: oldCodes})
		if err != nil {
			t.Fatalf("marshal 旧 meta: %v", err)
		}
		creds.byKind = map[string]*model.UserCredential{
			"recovery_code": {ID: 9, UserID: 42, Kind: "recovery_code", Meta: oldMeta, IsEnabled: 1},
		}
		if err := svc.ResetUserRecoveryCodes(ctx, 1, 42); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(creds.updated) != 1 {
			t.Fatalf("updated = %d 次, want 1", len(creds.updated))
		}
		row := creds.updated[0]
		if row.ID != 9 || row.Kind != "recovery_code" || row.IsEnabled != 1 {
			t.Fatalf("更新行 = %+v, is_enabled 应不动", row)
		}
		meta, err := repo.UnmarshalCredentialMeta(row.Meta)
		if err != nil {
			t.Fatalf("unmarshal 新 meta: %v", err)
		}
		if len(meta.GetRecoveryCodes()) != 10 {
			t.Fatalf("新码 = %d 条, want 10", len(meta.GetRecoveryCodes()))
		}
		seen := map[string]bool{}
		old := map[string]bool{}
		for _, c := range oldCodes {
			old[c] = true
		}
		for _, c := range meta.GetRecoveryCodes() {
			if len(c) != 8 {
				t.Fatalf("码长 = %d, want 8", len(c))
			}
			for _, r := range c {
				if !strings.ContainsRune("0123456789abcdefghjkmnpqrstvwxyz", r) {
					t.Fatalf("码 %q 含非法字符 %q", c, r)
				}
			}
			if seen[c] {
				t.Fatalf("批内重复码 %q", c)
			}
			if old[c] {
				t.Fatalf("新码与旧码重合 %q", c)
			}
			seen[c] = true
		}
		// 无明文出口：方法只返回 error（签名即契约），审计 detail 为空对象、
		// 不含任何码值。
		if len(users.incIDs) != 0 || len(epoch.synced) != 0 {
			t.Fatalf("恢复码重置不应触发会话失效")
		}
		if len(audit.events) != 1 || audit.events[0].Event != eventlog.EventAdminRecoveryCodesReset {
			t.Fatalf("审计事件 = %+v", audit.events)
		}
		var d map[string]any
		if err := msgpack.Unmarshal(audit.events[0].Detail, &d); err != nil {
			t.Fatalf("detail 解码: %v", err)
		}
		if len(d) != 0 {
			t.Fatalf("detail = %+v, want 空对象（不记任何码值）", d)
		}
	})

	t.Run("recovery_code 行缺失 404", func(t *testing.T) {
		svc, users, _, _, _, _, _, _, audit := newUserSvc()
		users.user = userTestRow()
		if err := svc.ResetUserRecoveryCodes(ctx, 1, 42); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("err = %v, want ErrRecordNotFound", err)
		}
		if len(audit.events) != 0 {
			t.Fatalf("失败不应审计")
		}
	})
}

// TestUserServiceSetCredentialEnabled 停用 / 启用单条凭证：密码凭证停用拒绝
// （invalid_request，避免无密码可用态）且不触碰启用态；凭证缺失 / 属他人统一
// 404；全程不触发失效链、不投审计（契约口径）。
func TestUserServiceSetCredentialEnabled(t *testing.T) {
	ctx := context.Background()

	newCredSvc := func(kind string) (*adminsvc.UserService, *userFakeUsers, *userFakeCreds, *userFakeEpoch, *userFakeAudit) {
		svc, users, creds, _, _, _, epoch, _, audit := newUserSvc()
		users.user = userTestRow()
		creds.byID = map[int64]*model.UserCredential{
			7: {ID: 7, UserID: 42, Kind: kind},
		}
		return svc, users, creds, epoch, audit
	}

	t.Run("非密码凭证停用成功且零失效链零审计", func(t *testing.T) {
		svc, users, creds, epoch, audit := newCredSvc("totp")
		if err := svc.SetCredentialEnabled(ctx, 1, 42, 7, false); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(creds.setEnabled) != 1 || creds.setEnabled[0] != (userFakeCredEnable{id: 7, enabled: false}) {
			t.Fatalf("setEnabled = %+v", creds.setEnabled)
		}
		if len(users.incIDs) != 0 || len(epoch.synced) != 0 || len(audit.events) != 0 {
			t.Fatalf("凭证启停不应触发失效链或审计")
		}
	})

	t.Run("密码凭证停用拒绝", func(t *testing.T) {
		svc, _, creds, epoch, audit := newCredSvc("password")
		if err := svc.SetCredentialEnabled(ctx, 1, 42, 7, false); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
		if len(creds.setEnabled) != 0 || len(epoch.synced) != 0 || len(audit.events) != 0 {
			t.Fatalf("拒绝不应有副作用")
		}
	})

	t.Run("密码凭证启用成功", func(t *testing.T) {
		svc, _, creds, epoch, audit := newCredSvc("password")
		if err := svc.SetCredentialEnabled(ctx, 1, 42, 7, true); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(creds.setEnabled) != 1 || creds.setEnabled[0] != (userFakeCredEnable{id: 7, enabled: true}) {
			t.Fatalf("setEnabled = %+v", creds.setEnabled)
		}
		if len(epoch.synced) != 0 || len(audit.events) != 0 {
			t.Fatalf("启用不应触发失效链或审计")
		}
	})

	t.Run("凭证缺失与属他人统一 404", func(t *testing.T) {
		svc, _, creds, _, _ := newCredSvc("totp")
		if err := svc.SetCredentialEnabled(ctx, 1, 42, 8, false); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("缺失 err = %v, want ErrRecordNotFound", err)
		}
		// 他人凭证（UserID≠42）与缺失同形态返回，不泄露归属。
		creds.byID[8] = &model.UserCredential{ID: 8, UserID: 43, Kind: "totp"}
		if err := svc.SetCredentialEnabled(ctx, 1, 42, 8, false); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("属他人 err = %v, want ErrRecordNotFound", err)
		}
		if len(creds.setEnabled) != 0 {
			t.Fatalf("拒绝不应触碰启用态")
		}
	})

	t.Run("参数缺失 invalid_request", func(t *testing.T) {
		svc, _, _, _, _ := newCredSvc("totp")
		if err := svc.SetCredentialEnabled(ctx, 1, 42, 0, false); !errors.Is(err, adminsvc.ErrInvalidRequest) {
			t.Fatalf("err = %v, want ErrInvalidRequest", err)
		}
	})
}

// TestUserServiceDeleteCredential 删除单条凭证：按 credentialId 删（user 维度
// 透传 repo 双重定位）→ 强制下线 → 审计 admin_credential_delete
// （detail={credential_id, kind}，不记 secret）；缺失 / 属他人 404。
func TestUserServiceDeleteCredential(t *testing.T) {
	ctx := context.Background()

	t.Run("成功删除并强制下线与审计", func(t *testing.T) {
		svc, users, creds, _, _, _, epoch, _, audit := newUserSvc()
		users.user = userTestRow()
		creds.byID = map[int64]*model.UserCredential{
			7: {ID: 7, UserID: 42, Kind: "webauthn"},
		}
		users.incNext = 6
		if err := svc.DeleteCredential(ctx, 1, 42, 7); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if len(creds.deletedByID) != 1 || creds.deletedByID[0] != (userFakeCredDeleteID{userID: 42, id: 7}) {
			t.Fatalf("deletedByID = %+v", creds.deletedByID)
		}
		if len(users.incIDs) != 1 || len(epoch.synced) != 1 || epoch.synced[0].uid != 42 {
			t.Fatalf("删凭证应走失效链: inc=%v sync=%v", users.incIDs, epoch.synced)
		}
		if len(audit.events) != 1 || audit.events[0].Event != eventlog.EventAdminCredentialDelete {
			t.Fatalf("审计事件 = %+v", audit.events)
		}
		var d map[string]any
		if err := msgpack.Unmarshal(audit.events[0].Detail, &d); err != nil {
			t.Fatalf("detail 解码: %v", err)
		}
		if id, ok := d["credential_id"].(int64); !ok || id != 7 {
			t.Fatalf("detail credential_id = %+v, want 7", d["credential_id"])
		}
		if d["kind"] != "webauthn" {
			t.Fatalf("detail kind = %+v, want webauthn", d["kind"])
		}
		if _, ok := d["secret"]; ok {
			t.Fatalf("detail 不应含 secret")
		}
	})

	t.Run("凭证缺失与属他人统一 404", func(t *testing.T) {
		svc, users, creds, _, _, _, epoch, _, audit := newUserSvc()
		users.user = userTestRow()
		if err := svc.DeleteCredential(ctx, 1, 42, 8); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("缺失 err = %v, want ErrRecordNotFound", err)
		}
		creds.byID = map[int64]*model.UserCredential{
			8: {ID: 8, UserID: 43, Kind: "totp"},
		}
		if err := svc.DeleteCredential(ctx, 1, 42, 8); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("属他人 err = %v, want ErrRecordNotFound", err)
		}
		if len(creds.deletedByID) != 0 || len(users.incIDs) != 0 || len(epoch.synced) != 0 || len(audit.events) != 0 {
			t.Fatalf("拒绝不应有副作用")
		}
	})
}

// TestUserServiceRescueWriteGate 救援族五方法门禁复用（authorizeUserWrite
// 矩阵细节由既有目标分级门禁用例承担，此处验证接线）：superadmin 目标一律
// 拒（含 superadmin 操作者）；普通管理员目标遇非 superadmin 操作者拒；
// 权限查询故障原样上抛（fail-closed，不映射 permission_denied）——拒绝与
// 故障均零副作用。
func TestUserServiceRescueWriteGate(t *testing.T) {
	ctx := context.Background()
	dbErr := errors.New("permission repo: db down")

	ops := []struct {
		name string
		call func(svc *adminsvc.UserService) error
	}{
		{"SetUserMfa", func(svc *adminsvc.UserService) error { return svc.SetUserMfa(ctx, 1, 42, 0) }},
		{"UnbindUserTOTP", func(svc *adminsvc.UserService) error { return svc.UnbindUserTOTP(ctx, 1, 42) }},
		{"ResetUserRecoveryCodes", func(svc *adminsvc.UserService) error { return svc.ResetUserRecoveryCodes(ctx, 1, 42) }},
		{"SetCredentialEnabled", func(svc *adminsvc.UserService) error { return svc.SetCredentialEnabled(ctx, 1, 42, 7, false) }},
		{"DeleteCredential", func(svc *adminsvc.UserService) error { return svc.DeleteCredential(ctx, 1, 42, 7) }},
	}
	scenarios := []struct {
		name     string
		granted  map[int64]map[string]bool
		errByUID map[int64]error
		want     error
	}{
		{
			name:    "superadmin 目标一律拒",
			granted: map[int64]map[string]bool{42: {adminsvc.PointSuperAdmin: true}, 1: {adminsvc.PointSuperAdmin: true}},
			want:    adminsvc.ErrPermissionDenied,
		},
		{
			name:    "普通管理员目标非 superadmin 操作者拒",
			granted: map[int64]map[string]bool{42: {"editor": true}},
			want:    adminsvc.ErrPermissionDenied,
		},
		{
			name:     "目标权限查询故障不放行",
			granted:  map[int64]map[string]bool{},
			errByUID: map[int64]error{42: dbErr},
			want:     dbErr,
		},
	}
	for _, op := range ops {
		for _, sc := range scenarios {
			t.Run(op.name+"/"+sc.name, func(t *testing.T) {
				perms := &userFakePermissions{
					granted:     sc.granted,
					errByUID:    sc.errByUID,
					anyErrByUID: map[int64]error{},
				}
				svc, users, creds, _, _, _, epoch, _, audit := newUserSvc(perms)
				users.user = userTestRow()
				err := op.call(svc)
				if !errors.Is(err, sc.want) {
					t.Fatalf("err = %v, want %v", err, sc.want)
				}
				if len(users.mfaUpdated) != 0 || len(creds.updated) != 0 || len(creds.setEnabled) != 0 ||
					len(creds.deletedByKind) != 0 || len(creds.deletedByID) != 0 ||
					len(users.incIDs) != 0 || len(epoch.synced) != 0 || len(audit.events) != 0 {
					t.Fatalf("拒绝 / 故障不应有副作用")
				}
			})
		}
	}
}
