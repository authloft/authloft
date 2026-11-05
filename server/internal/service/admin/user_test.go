// user_test.go：admin 用户管理族 service 层单测。fake 全进程内
// 隔离（不连 DB / Redis），覆盖清单：UpdateUserStatus 两态 +
// IncEpoch / Sync 断言 + 审计、ResetUserPassword password_weak / 成功失效链
// + 审计（无行同构补建）、Unbind Union 连带两分支 + 单事务回滚两注入、
// Union 单独解绑拒绝 / 审计、
// Unlock uid 维度 + ip 账号哈希维度重算、GetUserEvents login_success 过滤与
// 分页透传、ListUsers 过滤透传与 userStatus 枚举校验、GetUser 聚合。
// q 模糊 / 排序 / 分页边界的真库行为归 repo 用例（user_repo_test.go）。
package admin_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"gorm.io/gorm"

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
	statusErr    error

	incIDs  []int64
	incNext int16
}

type userFakeStatus struct {
	id     int64
	status int8
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

type userFakeCreds struct {
	byKind  map[string]*model.UserCredential
	list    []model.UserCredential
	created []*model.UserCredential
	updated []*model.UserCredential
}

func (f *userFakeCreds) FindByUserAndKind(_ context.Context, _ int64, kind string) (*model.UserCredential, error) {
	if c, ok := f.byKind[kind]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("credential repo: find by user kind: %w", gorm.ErrRecordNotFound)
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
//「provider 行缺失按非 Union 处理」同语义）；unionProviderKey 为空只删
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

// newUserSvc 组造 service 与全部 fake（零值 settings → security 默认策略档）。
func newUserSvc() (*adminsvc.UserService, *userFakeUsers, *userFakeCreds, *userFakeBinds,
	*userFakeProviders, *userFakeEvents, *userFakeEpoch, *userFakePwfail, *userFakeAudit) {
	users, creds, binds := &userFakeUsers{}, &userFakeCreds{}, &userFakeBinds{}
	providers, events := &userFakeProviders{rows: map[string]*model.Provider{}}, &userFakeEvents{}
	epoch, pwfail, audit := &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}
	svc := adminsvc.NewUserService(users, creds, binds, providers, events, epoch, pwfail, audit, userFakeSettings{})
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
		&userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{})
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

func userUnionProviders() *userFakeProviders {
	return &userFakeProviders{rows: map[string]*model.Provider{
		"wechat_union": {ProviderKey: "wechat_union", Category: "union"},
		"wechat_mp_1":  {ProviderKey: "wechat_mp_1", Category: "oauth", UnionProvider: "wechat_union"},
		"wechat_mp_2":  {ProviderKey: "wechat_mp_2", Category: "oauth", UnionProvider: "wechat_union"},
		"standalone":   {ProviderKey: "standalone", Category: "oauth"},
	}}
}

// userUnionKeys fake 级联判定的 provider_key → category=union 映射
//（与 userUnionProviders 的 wechat_union 对齐；map 读零值 false = 非
// Union，与 repo「provider 行缺失按非 Union 处理」同语义）。
func userUnionKeys() map[string]bool {
	return map[string]bool{"wechat_union": true}
}

// TestUserServiceUnbindUserThirdparty 覆盖清单：Union Provider 行单独解绑拒绝
//（invalid_request）；普通行删除 + 审计 thirdparty_unbind（target=provider_key、
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
		&userFakeAudit{}, userFakeSettings{})
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
		audit, userFakeSettings{})
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
		&userFakeAudit{}, userFakeSettings{})
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
		audit, userFakeSettings{})
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
		audit, userFakeSettings{})
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
		&userFakeAudit{}, userFakeSettings{})
	if err := svc.UnbindUserThirdparty(ctx, 1, 42, "standalone"); err != nil || len(binds.rows) != 0 {
		t.Fatalf("standalone 解绑 = (%v), rows=%+v", err, binds.rows)
	}

	// 未绑该渠道 / provider 不存在 → 404；空 providerKey → invalid_request。
	svc = adminsvc.NewUserService(&userFakeUsers{user: userTestRow()}, &userFakeCreds{},
		&userFakeBinds{}, userUnionProviders(), &userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{},
		&userFakeAudit{}, userFakeSettings{})
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
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{})
	})
	mustPanicUser(t, "nil creds", func() {
		adminsvc.NewUserService(users, nil, &userFakeBinds{}, providers,
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{})
	})
	mustPanicUser(t, "nil binds", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, nil, providers,
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{})
	})
	mustPanicUser(t, "nil providers", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, nil,
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{})
	})
	mustPanicUser(t, "nil events", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, providers,
			nil, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{})
	})
	mustPanicUser(t, "nil epoch", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, providers,
			&userFakeEvents{}, nil, &userFakePwfail{}, &userFakeAudit{}, userFakeSettings{})
	})
	mustPanicUser(t, "nil pwfail", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, providers,
			&userFakeEvents{}, &userFakeEpoch{}, nil, &userFakeAudit{}, userFakeSettings{})
	})
	mustPanicUser(t, "nil audit", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, providers,
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, nil, userFakeSettings{})
	})
	mustPanicUser(t, "nil settings", func() {
		adminsvc.NewUserService(users, &userFakeCreds{}, &userFakeBinds{}, providers,
			&userFakeEvents{}, &userFakeEpoch{}, &userFakePwfail{}, &userFakeAudit{}, nil)
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
