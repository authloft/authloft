// user / user_profile 表 repo 层测试：真实测试实例经 UC_TEST_DB_DRIVER +
// UC_TEST_DB_DSN env 注入（兼容读 UC_TEST_MYSQL_DSN），无 env 时 skip。
// 表结构由迁移建（§3.16 DDL 唯一来源）；用例开始清空全表、结束清空并
// 自证零残留（口径与既有 DB 测试一致）。方言与清理 / 互斥细节见
// testsupport_test.go。连接串只经环境变量注入，代码不含主机 / 凭证信息。
package repo

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"authloft/internal/repo/model"
)

// bunFilterSQLDB 构造不触库的 bun 连接（sql.Open 惰性建连 + String() 纯
// SQL 构造），供无需 DSN 的 SQL 断言用例。DSN 形态与生产同构，连接串不含
// 真实凭证。
func bunFilterSQLDB(t *testing.T) *bun.DB {
	t.Helper()
	sqldb, err := sql.Open("mysql", "u:p@tcp(127.0.0.1:3306)/x?parseTime=true")
	if err != nil {
		t.Fatalf("sql.Open 失败: %v", err)
	}
	db := bun.NewDB(sqldb, newMySQLDialect())
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestUserRepoListUsersFilterSQL（无需 DSN 的 SQL 构造断言）：§5.4 四维度
// 筛选、默认过滤 deleted_ 前缀与凭证类型子查询均进入 WHERE 集；不设筛选时
// 不追加任何条件（无 WHERE 子句）。
func TestUserRepoListUsersFilterSQL(t *testing.T) {
	rp := NewUserRepo(bunFilterSQLDB(t))
	from, to := int64(1000), int64(2000)
	loginFrom, loginTo := int64(3000), int64(4000)
	mfa := int8(1)
	q := UserListQuery{
		ExcludeDeleted: true,
		CreatedFrom:    &from, CreatedTo: &to,
		LastLoginFrom: &loginFrom, LastLoginTo: &loginTo,
		MfaRequired: &mfa, CredentialKind: "webauthn",
	}
	filtered := rp.listUsersFilter(context.Background(), q).String()
	for _, want := range []string{
		"POSITION('deleted_' IN LOWER(username)) <> 1", "created_at >=", "created_at <=",
		"last_login_at >=", "last_login_at <=", "mfa_required =",
		"user_credential", "kind =",
	} {
		if !strings.Contains(filtered, want) {
			t.Errorf("SQL 缺 %q: %s", want, filtered)
		}
	}

	plain := rp.listUsersFilter(context.Background(), UserListQuery{}).String()
	if strings.Contains(plain, " WHERE ") || strings.Contains(plain, "POSITION(") ||
		strings.Contains(plain, "mfa_required =") || strings.Contains(plain, "user_credential") {
		t.Errorf("无筛选时不应追加条件: %s", plain)
	}
}

// TestUserRepoExcludeDeletedCaseInsensitive ExcludeDeleted 过滤不分大小写
// （§5.4 默认过滤与 §2.3 前缀禁用同口径）：真库实证 LOWER(username) 使
// deleted_ / DELETED_ / Deleted_ 变体行均不出现在列表——口径固定为大小写
// 无关，不依赖列 collation（生产实例 collation 无法从仓库判定）。
func TestUserRepoExcludeDeletedCaseInsensitive(t *testing.T) {
	rp, _ := userTestSetup(t)
	ctx := context.Background()

	now := time.Unix(1761700000, 0).UTC()
	rows := []model.User{
		{Username: "alice", CreatedAt: now, UpdatedAt: now},
		{Username: "deleted_1", CreatedAt: now, UpdatedAt: now},
		{Username: "DELETED_2", CreatedAt: now, UpdatedAt: now},
		{Username: "Deleted_3", CreatedAt: now, UpdatedAt: now},
	}
	for i := range rows {
		if err := rp.Create(ctx, &rows[i]); err != nil {
			t.Fatalf("Create %q 失败: %v", rows[i].Username, err)
		}
	}

	got, total, err := rp.ListUsers(ctx, UserListQuery{ExcludeDeleted: true, Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if total != 1 || len(got) != 1 || got[0].Username != "alice" {
		t.Fatalf("过滤结果 = (%d 行, total=%d), want 仅 alice", len(got), total)
	}
}

// userTestSetup 准备方言就绪的空库 + bun 连接（清空 → 建表 → 测后零残留
// 清理，口径见 testsupport_test.go），返回就绪的 UserRepo 与底层 *bun.DB
// （供用例直接构造特定列状态，如置 epoch 边界值）。
func userTestSetup(t *testing.T) (*UserRepo, *bun.DB) {
	t.Helper()
	db := repoTestDB(t)
	return NewUserRepo(db), db
}

// TestUserRepoFindByKeys（env-skip）：Create 默认值与自增回填 → 四个
// 唯一键 / 主键查询命中同一行、字段一致；可空列 NULL 语义；未命中
// ErrRecordNotFound。
func TestUserRepoFindByKeys(t *testing.T) {
	rp, _ := userTestSetup(t)
	ctx := context.Background()

	phone, email := "13800138000", "zhang@example.com"
	u := &model.User{
		Username:      "zhang_san",
		Phone:         &phone,
		Email:         &email,
		PhoneVerified: 1,
		EmailVerified: 1,
		Nickname:      "张三",
		AvatarURL:     "https://cdn.example.com/a.jpg",
	}
	if err := rp.Create(ctx, u); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	if u.ID == 0 {
		t.Fatal("Create 后 ID 应非零（自增回填）")
	}
	if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
		t.Error("Create 应自动填充 created_at / updated_at")
	}

	// 无 phone / email 的用户：可空列 NULL（唯一键允许多个 NULL）。
	if err := rp.Create(ctx, &model.User{Username: "li_si", Nickname: "李四"}); err != nil {
		t.Fatalf("Create 无联系方式的用户失败: %v", err)
	}

	for name, fn := range map[string]func() (*model.User, error){
		"id":       func() (*model.User, error) { return rp.FindByID(ctx, u.ID) },
		"username": func() (*model.User, error) { return rp.FindByUsername(ctx, "zhang_san") },
		"phone":    func() (*model.User, error) { return rp.FindByPhone(ctx, phone) },
		"email":    func() (*model.User, error) { return rp.FindByEmail(ctx, email) },
	} {
		got, err := fn()
		if err != nil {
			t.Fatalf("FindBy%s 失败: %v", name, err)
		}
		if got.ID != u.ID {
			t.Errorf("FindBy%s 命中 id=%d, want %d", name, got.ID, u.ID)
		}
		if got.Username != "zhang_san" || got.Nickname != "张三" ||
			got.AvatarURL != "https://cdn.example.com/a.jpg" ||
			got.PhoneVerified != 1 || got.EmailVerified != 1 {
			t.Errorf("FindBy%s 字段不一致: %+v", name, got)
		}
		if got.UserStatus != 1 || got.MfaRequired != 0 || got.Epoch != 0 {
			t.Errorf("默认值应 user_status=1 mfa_required=0 epoch=0: %+v", got)
		}
		if got.LastLoginAt != nil {
			t.Errorf("last_login_at 初始应为 NULL: %v", got.LastLoginAt)
		}
	}

	// 未命中路径。
	for name, fn := range map[string]func() (*model.User, error){
		"id":       func() (*model.User, error) { return rp.FindByID(ctx, 404) },
		"username": func() (*model.User, error) { return rp.FindByUsername(ctx, "nope") },
		"phone":    func() (*model.User, error) { return rp.FindByPhone(ctx, "13999999999") },
		"email":    func() (*model.User, error) { return rp.FindByEmail(ctx, "nobody@example.com") },
	} {
		if _, err := fn(); !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("FindBy%s 未命中应 ErrRecordNotFound, got %v", name, err)
		}
	}
}

// TestUserRepoCreateDuplicate（env-skip）：三个唯一键各自冲突可判别
// （errors.Is ErrUserDuplicate）、冲突不入库；不冲突的创建成功。
func TestUserRepoCreateDuplicate(t *testing.T) {
	rp, _ := userTestSetup(t)
	ctx := context.Background()

	phone, email := "13800138000", "zhang@example.com"
	if err := rp.Create(ctx, &model.User{
		Username: "zhang_san", Phone: &phone, Email: &email, Nickname: "张三",
	}); err != nil {
		t.Fatalf("首个用户 Create 失败: %v", err)
	}

	dupPhone, otherEmail := "13800138000", "other@example.com"
	if err := rp.Create(ctx, &model.User{
		Username: "clone_phone", Phone: &dupPhone, Email: &otherEmail,
	}); !errors.Is(err, ErrUserDuplicate) {
		t.Errorf("同 phone 冲突应 ErrUserDuplicate, got %v", err)
	}

	dupEmail, newPhone := "zhang@example.com", "13900139000"
	if err := rp.Create(ctx, &model.User{
		Username: "clone_email", Phone: &newPhone, Email: &dupEmail,
	}); !errors.Is(err, ErrUserDuplicate) {
		t.Errorf("同 email 冲突应 ErrUserDuplicate, got %v", err)
	}

	if err := rp.Create(ctx, &model.User{
		Username: "zhang_san", Nickname: "重名",
	}); !errors.Is(err, ErrUserDuplicate) {
		t.Errorf("同 username 冲突应 ErrUserDuplicate, got %v", err)
	}

	// 全新组合创建成功。
	p3, e3 := "13700137000", "fresh@example.com"
	if err := rp.Create(ctx, &model.User{
		Username: "wang_wu", Phone: &p3, Email: &e3,
	}); err != nil {
		t.Errorf("不冲突的 Create 应成功: %v", err)
	}

	// 冲突的行均未入库：库内只有 2 个成功创建的用户。
	rows, total, err := rp.ListUsers(ctx, UserListQuery{})
	if err != nil || total != 2 || len(rows) != 2 {
		t.Errorf("冲突不应入库: total=%d len=%d err=%v; want 2/2/nil", total, len(rows), err)
	}
}

// TestUserRepoEpochWraparound（env-skip）：IncEpoch 常规递增、两边界
// 回绕（29999→30000 递增不触发回绕；30000→1 回绕跳 0，§4.2 行 685）、
// GetEpoch 回源一致、不存在用户 ErrRecordNotFound。
func TestUserRepoEpochWraparound(t *testing.T) {
	rp, db := userTestSetup(t)
	ctx := context.Background()

	u := &model.User{Username: "epoch_user"}
	if err := rp.Create(ctx, u); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}

	// 初始 epoch=0（DDL 默认）。
	if e, err := rp.GetEpoch(ctx, u.ID); err != nil || e != 0 {
		t.Fatalf("初始 epoch = %d, err %v; want 0, nil", e, err)
	}

	// 常规递增：0 → 1 → 2。
	for want := int16(1); want <= 2; want++ {
		got, err := rp.IncEpoch(ctx, u.ID)
		if err != nil || got != want {
			t.Fatalf("IncEpoch = %d, err %v; want %d", got, err, want)
		}
	}
	if e, err := rp.GetEpoch(ctx, u.ID); err != nil || e != 2 {
		t.Fatalf("GetEpoch = %d, err %v; want 2", e, err)
	}

	// 边界一：29999 + 1 = 30000，不 > 30000，不触发回绕。
	userTestSetEpoch(t, db, u.ID, 29999)
	if got, err := rp.IncEpoch(ctx, u.ID); err != nil || got != 30000 {
		t.Fatalf("29999 → IncEpoch = %d, err %v; want 30000", got, err)
	}
	// 边界二：30000 + 1 = 30001 > 30000 → 回绕为 1（跳过 0）。
	if got, err := rp.IncEpoch(ctx, u.ID); err != nil || got != 1 {
		t.Fatalf("30000 → IncEpoch = %d, err %v; want 1（回绕跳 0）", got, err)
	}
	if e, err := rp.GetEpoch(ctx, u.ID); err != nil || e != 1 {
		t.Fatalf("回绕后 GetEpoch = %d, err %v; want 1", e, err)
	}

	// 不存在的用户。
	if _, err := rp.IncEpoch(ctx, 404); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("IncEpoch 不存在用户应 ErrRecordNotFound, got %v", err)
	}
	if _, err := rp.GetEpoch(ctx, 404); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("GetEpoch 不存在用户应 ErrRecordNotFound, got %v", err)
	}
}

// userTestSetStatus 直接置 user_status 列构造禁用态：Create 路径下零值 0
// 经 DEFAULT 占位由 DB 默认值 1 填充（CODE_GUIDE §3.5 零值口径），struct
// 插入落不了 0，故用列级 UPDATE（与 admin 禁用路径 §5.4 UpdateUserStatus
// 同构）。
func userTestSetStatus(t *testing.T, db *bun.DB, id int64, v int8) {
	t.Helper()
	if _, err := db.NewUpdate().Model((*model.User)(nil)).
		Where("id = ?", id).
		Set("user_status = ?", v).
		Exec(context.Background()); err != nil {
		t.Fatalf("置 user_status=%d 失败: %v", v, err)
	}
}

// userTestSetEpoch 直接置 epoch 列构造边界前提（列级 UPDATE，不走被测方法）。
func userTestSetEpoch(t *testing.T, db *bun.DB, id int64, v int16) {
	t.Helper()
	if _, err := db.NewUpdate().Model((*model.User)(nil)).
		Where("id = ?", id).
		Set("epoch = ?", v).
		Exec(context.Background()); err != nil {
		t.Fatalf("置 epoch=%d 失败: %v", v, err)
	}
}

// TestUserRepoUpdateLastLogin（env-skip）：last_login_at 写入与读回
// （DATETIME 秒级精度，输入截断到秒）；最新值覆盖；同值二次更新幂等
// 不误报（changed-rows 语义下 RowsAffected=0 但行存在）；不存在用户
// 可判别。
func TestUserRepoUpdateLastLogin(t *testing.T) {
	rp, _ := userTestSetup(t)
	ctx := context.Background()

	u := &model.User{Username: "login_user"}
	if err := rp.Create(ctx, u); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	if got, err := rp.FindByID(ctx, u.ID); err != nil || got.LastLoginAt != nil {
		t.Fatalf("初始 last_login_at 应 nil: %v, err %v", got.LastLoginAt, err)
	}

	t1 := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := rp.UpdateLastLogin(ctx, u.ID, t1); err != nil {
		t.Fatalf("UpdateLastLogin 失败: %v", err)
	}
	got, err := rp.FindByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindByID 失败: %v", err)
	}
	if got.LastLoginAt == nil || !got.LastLoginAt.Equal(t1) {
		t.Errorf("last_login_at = %v, want %v", got.LastLoginAt, t1)
	}

	// 更晚的时间覆盖旧值（§5.2 合并语义「只保留最新时间」的落库侧）。
	t2 := time.Now().Truncate(time.Second)
	if err := rp.UpdateLastLogin(ctx, u.ID, t2); err != nil {
		t.Fatalf("UpdateLastLogin 二次失败: %v", err)
	}
	if got, err = rp.FindByID(ctx, u.ID); err != nil ||
		got.LastLoginAt == nil || !got.LastLoginAt.Equal(t2) {
		t.Errorf("last_login_at = %v, want %v（最新值）", got.LastLoginAt, t2)
	}

	// 同值二次更新（§5.2 队列幂等重放）：MySQL changed-rows 语义下
	// RowsAffected=0，但行存在，不应误报 ErrRecordNotFound。
	if err := rp.UpdateLastLogin(ctx, u.ID, t2); err != nil {
		t.Fatalf("同值二次更新应幂等成功，不误报 ErrRecordNotFound: %v", err)
	}

	if err := rp.UpdateLastLogin(ctx, 404, t2); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("不存在用户应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserRepoUpdateProfileColumns（env-skip）：§3.2 UpdateProfile 可选字段
// 部分更新的 user 表侧——两列齐写、nil 列不写（未传不覆盖）、同值幂等
// 不误报、不存在用户可判别。
func TestUserRepoUpdateProfileColumns(t *testing.T) {
	rp, _ := userTestSetup(t)
	ctx := context.Background()

	u := &model.User{Username: "profile_user", Nickname: "旧昵称", AvatarURL: "https://cdn.example.com/old.jpg"}
	if err := rp.Create(ctx, u); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}

	// 两列齐写。
	nick, avatar := "新昵称", "https://cdn.example.com/new.jpg"
	if err := rp.UpdateProfileColumns(ctx, u.ID, &nick, &avatar); err != nil {
		t.Fatalf("UpdateProfileColumns 失败: %v", err)
	}
	got, err := rp.FindByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindByID 失败: %v", err)
	}
	if got.Nickname != nick || got.AvatarURL != avatar {
		t.Errorf("资料列 = (%q, %q), want (%q, %q)", got.Nickname, got.AvatarURL, nick, avatar)
	}

	// 只传 nickname（avatarURL = nil = 未传不覆盖）。
	nick2 := "又新昵称"
	if err := rp.UpdateProfileColumns(ctx, u.ID, &nick2, nil); err != nil {
		t.Fatalf("UpdateProfileColumns 单列失败: %v", err)
	}
	if got, err = rp.FindByID(ctx, u.ID); err != nil || got.Nickname != nick2 || got.AvatarURL != avatar {
		t.Errorf("单列更新 = (%q, %q), want (%q, %q)（nil 列不覆盖）", got.Nickname, got.AvatarURL, nick2, avatar)
	}

	// 同值二次更新：changed-rows 语义下 RowsAffected=0，但行存在，
	// 不应误报 ErrRecordNotFound。
	if err := rp.UpdateProfileColumns(ctx, u.ID, &nick2, nil); err != nil {
		t.Fatalf("同值二次更新应幂等成功: %v", err)
	}

	if err := rp.UpdateProfileColumns(ctx, 404, &nick2, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("不存在用户应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserRepoUpdateContactColumns（env-skip；BindContactStore 窄接口
// 的生产实现）：phone / email + 对应 verified 位列级更新（nil = 不写入）、
// uk_phone / uk_email 唯一键冲突 → ErrUserDuplicate（TOCTOU 占用回补口径，
// §10.2）、行不存在 → ErrRecordNotFound、同值幂等。
func TestUserRepoUpdateContactColumns(t *testing.T) {
	rp, _ := userTestSetup(t)
	ctx := context.Background()

	u := &model.User{Username: "bind_user"}
	if err := rp.Create(ctx, u); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	other := &model.User{Username: "other_user"}
	if err := rp.Create(ctx, other); err != nil {
		t.Fatalf("Create other 失败: %v", err)
	}

	// 绑定手机：phone + phone_verified=1，email 列不动（nil 不写入）。
	phone := "13800138000"
	one := int8(1)
	if err := rp.UpdateContactColumns(ctx, u.ID, &phone, nil, &one, nil); err != nil {
		t.Fatalf("UpdateContactColumns phone 失败: %v", err)
	}
	got, err := rp.FindByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("FindByID 失败: %v", err)
	}
	if got.Phone == nil || *got.Phone != phone || got.PhoneVerified != 1 {
		t.Errorf("phone 列 = (%v, %d), want (%q, 1)", got.Phone, got.PhoneVerified, phone)
	}
	if got.Email != nil || got.EmailVerified != 0 {
		t.Errorf("email 列 = (%v, %d), want (nil, 0)（nil 不写入）", got.Email, got.EmailVerified)
	}

	// 换绑邮箱：email + email_verified=1，phone 列保留。
	email := "bound@example.com"
	if err := rp.UpdateContactColumns(ctx, u.ID, nil, &email, nil, &one); err != nil {
		t.Fatalf("UpdateContactColumns email 失败: %v", err)
	}
	if got, err = rp.FindByID(ctx, u.ID); err != nil || *got.Phone != phone || *got.Email != email ||
		got.PhoneVerified != 1 || got.EmailVerified != 1 {
		t.Errorf("两联系方式 = (%v %d, %v %d)", got.Phone, got.PhoneVerified, got.Email, got.EmailVerified)
	}

	// 唯一键冲突：目标 phone 已被他人占用 → ErrUserDuplicate（errors.Is 判别，
	// service 层 TOCTOU 分支依赖）。
	if err := rp.UpdateContactColumns(ctx, u.ID, &phone, nil, &one, nil); err != nil {
		t.Fatalf("占位预置失败: %v", err)
	}
	taken := "13900139000"
	if err := rp.UpdateContactColumns(ctx, other.ID, &taken, nil, &one, nil); err != nil {
		t.Fatalf("占位预置 other 失败: %v", err)
	}
	if err := rp.UpdateContactColumns(ctx, u.ID, &taken, nil, &one, nil); !errors.Is(err, ErrUserDuplicate) {
		t.Errorf("占用目标应 ErrUserDuplicate, got %v", err)
	}
	takenEmail := "taken@example.com"
	if err := rp.UpdateContactColumns(ctx, other.ID, nil, &takenEmail, nil, &one); err != nil {
		t.Fatalf("占位预置 other email 失败: %v", err)
	}
	if err := rp.UpdateContactColumns(ctx, u.ID, nil, &takenEmail, nil, &one); !errors.Is(err, ErrUserDuplicate) {
		t.Errorf("占用邮箱应 ErrUserDuplicate, got %v", err)
	}

	// 占用冲突后原值未被动：u 仍是 phone + bound@example.com。
	if got, err = rp.FindByID(ctx, u.ID); err != nil || *got.Phone != phone || *got.Email != email {
		t.Errorf("冲突后原值 = (%v, %v), want (%q, %q)", got.Phone, got.Email, phone, email)
	}

	// 全指针 nil：仅刷新 updated_at（幂等成功，changed-rows 语义不误报）。
	if err := rp.UpdateContactColumns(ctx, u.ID, nil, nil, nil, nil); err != nil {
		t.Fatalf("全 nil 应幂等成功: %v", err)
	}

	// 同值二次更新：changed-rows 语义 RowsAffected=0，行存在 → 幂等成功。
	if err := rp.UpdateContactColumns(ctx, u.ID, &phone, nil, &one, nil); err != nil {
		t.Fatalf("同值二次更新应幂等成功: %v", err)
	}

	// 显式清空：空串指针 → 列写 NULL 而非空串（uk_phone / uk_email 对空串
	// 仍唯一，多行清空互撞；NULL 不参与唯一约束，§4.2 删除匿名化同口径），
	// verified 位随调用方置 0。
	clear, zero := "", int8(0)
	if err := rp.UpdateContactColumns(ctx, u.ID, &clear, nil, &zero, nil); err != nil {
		t.Fatalf("显式清空 phone 失败: %v", err)
	}
	if got, err = rp.FindByID(ctx, u.ID); err != nil || got.Phone != nil || got.PhoneVerified != 0 {
		t.Errorf("清空后 phone 列 = (%v, %d), want (NULL, 0)", got.Phone, got.PhoneVerified)
	}
	// 多行同时清空不撞唯一键（NULL 不参与唯一约束）。
	if err := rp.UpdateContactColumns(ctx, other.ID, &clear, nil, &zero, nil); err != nil {
		t.Fatalf("他人清空 phone 应成功（NULL 不唯一冲突）: %v", err)
	}

	// 行不存在 → ErrRecordNotFound。
	if err := rp.UpdateContactColumns(ctx, 404, &phone, nil, &one, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("不存在用户应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserRepoListUsers（env-skip）：user_status 过滤 + §1.7 分页参数
// （page 1 起、pageSize 默认 20 上限 100）、id 降序全序稳定。
func TestUserRepoListUsers(t *testing.T) {
	rp, db := userTestSetup(t)
	ctx := context.Background()

	// 5 个用户：3 个正常（1）、2 个禁用（0），id 递增。
	for i := 1; i <= 5; i++ {
		u := &model.User{Username: fmt.Sprintf("user_%02d", i)}
		if err := rp.Create(ctx, u); err != nil {
			t.Fatalf("Create user_%02d 失败: %v", i, err)
		}
		if i == 2 || i == 4 {
			// Create 零值被 default:1 tag 值显式写入 INSERT（落 1），禁用
			// 态走列级 UPDATE 构造（与 admin 禁用路径同构，见 model.User 注释）。
			userTestSetStatus(t, db, u.ID, 0)
		}
	}

	// 无过滤 + 分页：id DESC（user_05, user_04）。
	rows, total, err := rp.ListUsers(ctx, UserListQuery{Page: 1, PageSize: 2})
	if err != nil || total != 5 || len(rows) != 2 {
		t.Fatalf("page1 = %d 行 total=%d err=%v; want 2/5/nil", len(rows), total, err)
	}
	if rows[0].Username != "user_05" || rows[1].Username != "user_04" {
		t.Errorf("page1 顺序 = %s,%s; want user_05,user_04（id DESC）",
			rows[0].Username, rows[1].Username)
	}

	if rows, _, err = rp.ListUsers(ctx, UserListQuery{Page: 2, PageSize: 2}); err != nil ||
		len(rows) != 2 || rows[0].Username != "user_03" || rows[1].Username != "user_02" {
		t.Fatalf("page2 = %+v err=%v; want user_03,user_02", rows, err)
	}
	if rows, _, err = rp.ListUsers(ctx, UserListQuery{Page: 3, PageSize: 2}); err != nil ||
		len(rows) != 1 || rows[0].Username != "user_01" {
		t.Fatalf("page3 = %+v err=%v; want user_01", rows, err)
	}
	if rows, _, err = rp.ListUsers(ctx, UserListQuery{Page: 4, PageSize: 2}); err != nil || len(rows) != 0 {
		t.Fatalf("page4 越界应空: %d 行 err=%v", len(rows), err)
	}

	// user_status 过滤。
	one := int8(1)
	if rows, total, err = rp.ListUsers(ctx, UserListQuery{UserStatus: &one}); err != nil ||
		total != 3 || len(rows) != 3 {
		t.Fatalf("status=1: %d 行 total=%d err=%v; want 3/3", len(rows), total, err)
	}
	for _, r := range rows {
		if r.UserStatus != 1 {
			t.Errorf("status=1 过滤泄漏: %+v", r)
		}
	}
	zero := int8(0)
	if _, total, err = rp.ListUsers(ctx, UserListQuery{UserStatus: &zero}); err != nil || total != 2 {
		t.Fatalf("status=0: total=%d err=%v; want 2", total, err)
	}

	// 分页参数归一：Page<1 归 1；PageSize<1 默认 20（5 行全量）；
	// PageSize>100 clamp 100 不报错。
	if rows, total, err = rp.ListUsers(ctx, UserListQuery{Page: 0, PageSize: 2}); err != nil ||
		total != 5 || len(rows) != 2 {
		t.Errorf("Page=0 应归 1: %d/%d %v", len(rows), total, err)
	}
	if rows, total, err = rp.ListUsers(ctx, UserListQuery{}); err != nil ||
		total != 5 || len(rows) != 5 {
		t.Errorf("零值应默认 pageSize=20: %d/%d %v", len(rows), total, err)
	}
	if _, _, err = rp.ListUsers(ctx, UserListQuery{Page: 1, PageSize: 150}); err != nil {
		t.Errorf("PageSize=150 应 clamp 100 不报错: %v", err)
	}
}

// TestUserProfileReadWrite（env-skip）：SaveProfile 插入 / 整行覆盖、
// GetProfile 读回（DATE 列、VARBINARY extra、NULL extra 与 NULL
// birthday）；未命中 ErrRecordNotFound。
func TestUserProfileReadWrite(t *testing.T) {
	rp, _ := userTestSetup(t)
	ctx := context.Background()

	u := &model.User{Username: "profile_user"}
	if err := rp.Create(ctx, u); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}

	birthday := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	p := &model.UserProfile{
		UserID:    u.ID,
		Gender:    1,
		Birthday:  &birthday,
		Locale:    "zh-CN",
		Timezone:  "Asia/Shanghai",
		Extra:     []byte{0x82, 0xa7, 'c', 'o', 'm', 'p', 'a', 'n', 'y'},
		UpdatedAt: time.Now().Truncate(time.Second),
	}
	if err := rp.SaveProfile(ctx, p); err != nil {
		t.Fatalf("SaveProfile 插入失败: %v", err)
	}

	got, err := rp.GetProfile(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetProfile 失败: %v", err)
	}
	if got.Gender != 1 || got.Birthday == nil || !got.Birthday.Equal(birthday) ||
		got.Locale != "zh-CN" || got.Timezone != "Asia/Shanghai" {
		t.Errorf("读回字段不一致: %+v", got)
	}
	if !bytes.Equal(got.Extra, p.Extra) {
		t.Errorf("extra = %v, want %v", got.Extra, p.Extra)
	}

	// 覆盖：整行 UPSERT（birthday 置 NULL、extra 置空）。
	p2 := &model.UserProfile{
		UserID:    u.ID,
		Gender:    2,
		Birthday:  nil,
		Locale:    "en",
		Timezone:  "UTC",
		Extra:     nil,
		UpdatedAt: time.Now().Truncate(time.Second),
	}
	if err := rp.SaveProfile(ctx, p2); err != nil {
		t.Fatalf("SaveProfile 覆盖失败: %v", err)
	}
	if got, err = rp.GetProfile(ctx, u.ID); err != nil {
		t.Fatalf("GetProfile 二次失败: %v", err)
	}
	if got.Gender != 2 || got.Birthday != nil || got.Locale != "en" ||
		got.Timezone != "UTC" || len(got.Extra) != 0 {
		t.Errorf("覆盖后字段不一致: %+v", got)
	}

	// 未命中。
	if _, err := rp.GetProfile(ctx, 404); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("GetProfile 未命中应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserRepoListByIDs（env-skip）：GetUserProfiles 批量读的 repo 支撑
// （接口文档 §7.2 行 1436）——user / user_profile 两表各一条 IN 语句：
// 命中行全量返回、缺失 id 自然缺席（跳过语义归 handler）；user_profile 行
// 缺失的用户（u3）在 profiles 中无行；空 ids 双空零触库；全缺失 ids 返回
// 空集不报错（空批量空集语义，§7.2 行 1467）。
func TestUserRepoListByIDs(t *testing.T) {
	rp, _ := userTestSetup(t)
	ctx := context.Background()

	u1 := &model.User{Username: "batch_u1", Nickname: "甲"}
	u2 := &model.User{Username: "batch_u2", Nickname: "乙"}
	u3 := &model.User{Username: "batch_u3", Nickname: "丙"} // 无 user_profile 行
	for _, u := range []*model.User{u1, u2, u3} {
		if err := rp.Create(ctx, u); err != nil {
			t.Fatalf("Create 失败: %v", err)
		}
	}
	p1 := &model.UserProfile{UserID: u1.ID, Locale: "zh-CN", Timezone: "Asia/Shanghai", UpdatedAt: time.Now().Truncate(time.Second)}
	p2 := &model.UserProfile{UserID: u2.ID, Locale: "en", Timezone: "UTC", UpdatedAt: time.Now().Truncate(time.Second)}
	for _, p := range []*model.UserProfile{p1, p2} {
		if err := rp.SaveProfile(ctx, p); err != nil {
			t.Fatalf("SaveProfile 失败: %v", err)
		}
	}

	// 含缺失 id（999999）的批量：user 行 3、profile 行 2。
	ids := []int64{u1.ID, 999999, u2.ID, u3.ID, u1.ID}
	users, profiles, err := rp.ListByIDs(ctx, ids)
	if err != nil {
		t.Fatalf("ListByIDs 失败: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("user 行数 = %d, want 3（缺失 id 不产生行）", len(users))
	}
	gotUsers := map[int64]model.User{}
	for _, u := range users {
		gotUsers[u.ID] = u
	}
	for _, id := range []int64{u1.ID, u2.ID, u3.ID} {
		u, ok := gotUsers[id]
		if !ok {
			t.Fatalf("user id=%d 缺席", id)
		}
		if u.Username == "" || u.CreatedAt.IsZero() {
			t.Errorf("user id=%d 字段不全: %+v", id, u)
		}
	}
	if len(profiles) != 2 {
		t.Fatalf("profile 行数 = %d, want 2（u3 无行）", len(profiles))
	}
	gotProfiles := map[int64]model.UserProfile{}
	for _, p := range profiles {
		gotProfiles[p.UserID] = p
	}
	for uid, want := range map[int64]*model.UserProfile{u1.ID: p1, u2.ID: p2} {
		p, ok := gotProfiles[uid]
		if !ok {
			t.Fatalf("profile uid=%d 缺席", uid)
		}
		if p.Locale != want.Locale || p.Timezone != want.Timezone {
			t.Errorf("profile uid=%d = (locale=%q tz=%q), want (%q, %q)", uid, p.Locale, p.Timezone, want.Locale, want.Timezone)
		}
	}

	// 空 ids：双空零触库、无错误。
	if users, profiles, err = rp.ListByIDs(ctx, nil); err != nil || users != nil || profiles != nil {
		t.Errorf("空 ids: (users=%v profiles=%v err=%v), want 双 nil 无错", users, profiles, err)
	}

	// 全缺失 ids：空集不报错（对应 handler 缺失跳过语义）。
	if users, profiles, err = rp.ListByIDs(ctx, []int64{404101, 404102}); err != nil || len(users) != 0 || len(profiles) != 0 {
		t.Errorf("全缺失 ids: (users=%d profiles=%d err=%v), want 空集无错", len(users), len(profiles), err)
	}
}

// TestUserRepoListUsersSearchSort（env-skip）：q 对 username / nickname /
// email / phone 四列做字面子串匹配（POSITION 口径，%/_/\ 一律按字面量参与
// 匹配）；sort / order 消费（合法列名排序、缺省与字符集外回落 id、order 仅
// asc 改向）。
func TestUserRepoListUsersSearchSort(t *testing.T) {
	rp, _ := userTestSetup(t)
	ctx := context.Background()

	rows := []struct {
		username, nickname, phone, email string
	}{
		{"alice_01", "爱丽丝", "13800000001", "alice@example.com"},
		{"bob_02", "Alice Chen", "13900000002", "bob@example.com"},
		{"carol_03", "卡罗尔", "13700000003", "carol@example.com"},
		{"dave_04", "戴夫", "13600000004", "alice@corp.example.com"},
	}
	for _, r := range rows {
		u := &model.User{Username: r.username, Nickname: r.nickname}
		if r.phone != "" {
			u.Phone = &r.phone
		}
		if r.email != "" {
			u.Email = &r.email
		}
		if err := rp.Create(ctx, u); err != nil {
			t.Fatalf("Create %s 失败: %v", r.username, err)
		}
	}

	// q 命中 username（alice_01）/ nickname（Alice Chen，大小写不敏感列排序规则
	// 下命中）/ email 域名（alice@、alice@corp）——含列：username + email 两个
	// alice 条目 + nickname 的 Alice Chen。
	got, total, err := rp.ListUsers(ctx, UserListQuery{Q: "alice"})
	if err != nil {
		t.Fatalf("Q=alice: %v", err)
	}
	if total != 3 || len(got) != 3 {
		t.Fatalf("Q=alice = (%d 行, total=%d), want 3/3（username/nickname/email 三列命中）", len(got), total)
	}

	// q 命中 phone 前缀。
	if _, total, err = rp.ListUsers(ctx, UserListQuery{Q: "138"}); err != nil || total != 1 {
		t.Fatalf("Q=138 = total %d err=%v, want 1（phone 列命中）", total, err)
	}

	// 通配符按字面量匹配（POSITION 口径，无转义语义）：q="100%" 只含字面
	// 百分号，无行命中。
	if _, total, err = rp.ListUsers(ctx, UserListQuery{Q: "100%"}); err != nil || total != 0 {
		t.Fatalf("Q=100%% = total %d err=%v, want 0（%% 按字面量匹配）", total, err)
	}
	// _ 按字面量：q="i_e" 若 _ 是通配符会命中 alice_01（i_通配_e 命中 ice）
	// 与 alice@example.com；字面匹配下无行包含 i_e。
	if _, total, err = rp.ListUsers(ctx, UserListQuery{Q: "i_e"}); err != nil || total != 0 {
		t.Fatalf("Q=i_e = total %d err=%v, want 0（_ 按字面量匹配）", total, err)
	}

	// sort=username + order=asc：主序生效。
	if got, _, err = rp.ListUsers(ctx, UserListQuery{Sort: "username", Order: "asc", PageSize: 10}); err != nil ||
		len(got) != 4 || got[0].Username != "alice_01" || got[3].Username != "dave_04" {
		t.Fatalf("sort=username asc = %v err=%v", usernames(got), err)
	}
	// 同主序（nickname 唯一）+ order 缺省 desc。
	if got, _, err = rp.ListUsers(ctx, UserListQuery{Sort: "username", PageSize: 10}); err != nil ||
		got[0].Username != "dave_04" {
		t.Fatalf("sort=username 缺省 order = %v err=%v, want dave_04 在首（desc）", usernames(got), err)
	}
	// 字符集外 sort（注入防御）→ 回落 id，不报错。
	if _, _, err = rp.ListUsers(ctx, UserListQuery{Sort: "id; DROP TABLE user", Order: "desc"}); err != nil {
		t.Fatalf("非法 sort 应回落不报错: %v", err)
	}
	// 排序 + 分页叠加：sort=username asc，page2 size 2 取后两行。
	if got, _, err = rp.ListUsers(ctx, UserListQuery{Sort: "username", Order: "asc", Page: 2, PageSize: 2}); err != nil ||
		len(got) != 2 || got[0].Username != "carol_03" || got[1].Username != "dave_04" {
		t.Fatalf("sort+page2 = %v err=%v", usernames(got), err)
	}

	// \ 按字面量参与匹配：反斜杠用户名可被 q 原文命中（不经转义、不破坏
	// 匹配），置于计数类断言之后不影响前序行数口径。
	if err := rp.Create(ctx, &model.User{Username: `win\dows`}); err != nil {
		t.Fatalf("Create 反斜杠用户名失败: %v", err)
	}
	if _, total, err = rp.ListUsers(ctx, UserListQuery{Q: `win\dows`}); err != nil || total != 1 {
		t.Fatalf(`Q=win\dows = total %d err=%v, want 1（\ 按字面量匹配）`, total, err)
	}
}

func usernames(rows []model.User) []string {
	out := make([]string, len(rows))
	for i := range rows {
		out[i] = rows[i].Username
	}
	return out
}

// TestUserRepoUpdateUserStatus（env-skip）：列级 UPDATE 禁用 / 启用
// （零值 0 落库——列级更新不受 default:1 tag 影响）；updated_at 刷新；同值
// 重放幂等成功；不存在 → ErrRecordNotFound。
func TestUserRepoUpdateUserStatus(t *testing.T) {
	rp, db := userTestSetup(t)
	ctx := context.Background()

	u := &model.User{Username: "alice"}
	if err := rp.Create(ctx, u); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	// updated_at 回拨 1 分钟（DATETIME 秒级精度下，避免与 Create 同秒导致
	// 刷新断言误判——口径同 userTestSetEpoch 的直接置列前提构造）。
	before := time.Now().Add(-time.Minute).Truncate(time.Second)
	if _, err := db.NewUpdate().Model((*model.User)(nil)).
		Where("id = ?", u.ID).
		Set("updated_at = ?", before).
		Exec(ctx); err != nil {
		t.Fatalf("回拨 updated_at 失败: %v", err)
	}

	// 禁用：user_status 0 必须真实落库（Create 的 default:1 tag 契约对照）。
	if err := rp.UpdateUserStatus(ctx, u.ID, 0); err != nil {
		t.Fatalf("禁用失败: %v", err)
	}
	row, err := rp.FindByID(ctx, u.ID)
	if err != nil || row.UserStatus != 0 {
		t.Fatalf("禁用后 user_status = (%d, %v), want 0", row.UserStatus, err)
	}
	if !row.UpdatedAt.After(before) {
		t.Fatalf("updated_at 应刷新: before=%v after=%v", before, row.UpdatedAt)
	}

	// 同值重放幂等成功（changed-rows=0 + 行在）。
	if err := rp.UpdateUserStatus(ctx, u.ID, 0); err != nil {
		t.Fatalf("同值重放应幂等: %v", err)
	}

	// 启用回 1。
	if err := rp.UpdateUserStatus(ctx, u.ID, 1); err != nil {
		t.Fatalf("启用失败: %v", err)
	}
	if row, err = rp.FindByID(ctx, u.ID); err != nil || row.UserStatus != 1 {
		t.Fatalf("启用后 user_status = (%d, %v), want 1", row.UserStatus, err)
	}

	// 不存在 → ErrRecordNotFound。
	if err := rp.UpdateUserStatus(ctx, 404, 0); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("不存在应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserRepoUpdateMfaRequired（env-skip）：列级 UPDATE 两步验证开关
// （§3.5 SetMfa 唯一写入端）；updated_at 刷新、epoch 不受影响（开关切换
// 不改变登录凭据）；同值重放幂等成功；不存在 → ErrRecordNotFound。
func TestUserRepoUpdateMfaRequired(t *testing.T) {
	rp, db := userTestSetup(t)
	ctx := context.Background()

	u := &model.User{Username: "alice"}
	if err := rp.Create(ctx, u); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	before := time.Now().Add(-time.Minute).Truncate(time.Second)
	if _, err := db.NewUpdate().Model((*model.User)(nil)).
		Where("id = ?", u.ID).
		Set("updated_at = ?", before).
		Exec(ctx); err != nil {
		t.Fatalf("回拨 updated_at 失败: %v", err)
	}
	epochBefore := u.Epoch

	// 开启：mfa_required 1 落库。
	if err := rp.UpdateMfaRequired(ctx, u.ID, 1); err != nil {
		t.Fatalf("开启失败: %v", err)
	}
	row, err := rp.FindByID(ctx, u.ID)
	if err != nil || row.MfaRequired != 1 {
		t.Fatalf("开启后 mfa_required = (%d, %v), want 1", row.MfaRequired, err)
	}
	if !row.UpdatedAt.After(before) {
		t.Fatalf("updated_at 应刷新: before=%v after=%v", before, row.UpdatedAt)
	}
	if row.Epoch != epochBefore {
		t.Fatalf("epoch 不应变化: before=%d after=%d", epochBefore, row.Epoch)
	}

	// 同值重放幂等成功（changed-rows=0 + 行在）。
	if err := rp.UpdateMfaRequired(ctx, u.ID, 1); err != nil {
		t.Fatalf("同值重放应幂等: %v", err)
	}

	// 关闭回 0。
	if err := rp.UpdateMfaRequired(ctx, u.ID, 0); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}
	if row, err = rp.FindByID(ctx, u.ID); err != nil || row.MfaRequired != 0 {
		t.Fatalf("关闭后 mfa_required = (%d, %v), want 0", row.MfaRequired, err)
	}

	// 不存在 → ErrRecordNotFound。
	if err := rp.UpdateMfaRequired(ctx, 404, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("不存在应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserRepoAnonymizeUser（env-skip）：删除用户的单事务匿名化改写
// （§4.2）——user 行改写清单（username="deleted_<id>" / user_status=0 /
// 联系方式置 NULL 与 verified 清零 / 资料列清空 / mfa_required=0 / epoch
// 递增，last_login_at 与 created_at 保留）、user_profile 五列清空、凭证
// 与 WebAuthn 附加表全清、第三方绑定全清（Union 连带行随之清零）、返回
// 新 epoch、回绕 30000→1、不存在用户 ErrRecordNotFound。
func TestUserRepoAnonymizeUser(t *testing.T) {
	rp, db := userTestSetup(t)
	ctx := context.Background()

	phone, email := "13800138000", "alice@example.com"
	lastLogin := time.Unix(1761700000, 0).UTC().Truncate(time.Second)
	u := &model.User{
		Username: "alice", Phone: &phone, Email: &email, Nickname: "Alice",
		AvatarURL: "https://cdn.example.com/a.png", LastLoginAt: &lastLogin,
	}
	if err := rp.Create(ctx, u); err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	if _, err := db.NewUpdate().Model((*model.User)(nil)).
		Where("id = ?", u.ID).
		Set("mfa_required = ?", 1).
		Set("epoch = ?", 3).
		Exec(ctx); err != nil {
		t.Fatalf("构造 mfa_required/epoch 前提失败: %v", err)
	}

	birthday := time.Unix(631152000, 0).UTC()
	if err := rp.SaveProfile(ctx, &model.UserProfile{
		UserID: u.ID, Gender: 2, Birthday: &birthday,
		Locale: "zh-CN", Timezone: "Asia/Shanghai", Extra: []byte(`{"k":"v"}`),
		UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("SaveProfile 失败: %v", err)
	}

	// 凭证四行（password / totp / webauthn / recovery_code）+ WebAuthn 附加行。
	now := time.Now()
	credRows := []model.UserCredential{
		{UserID: u.ID, Kind: "password", Secret: []byte("hash"), CreatedAt: now, UpdatedAt: now},
		{UserID: u.ID, Kind: "totp", Secret: []byte("key"), CreatedAt: now, UpdatedAt: now},
		{UserID: u.ID, Kind: "webauthn", Secret: []byte("pk"), CreatedAt: now, UpdatedAt: now},
		{UserID: u.ID, Kind: "recovery_code", Secret: []byte("meta"), CreatedAt: now, UpdatedAt: now},
	}
	for i := range credRows {
		if _, err := db.NewInsert().Model(&credRows[i]).Exec(ctx); err != nil {
			t.Fatalf("凭证 Create 失败: %v", err)
		}
	}
	if _, err := db.NewInsert().Model(&model.UserCredentialWebauthn{
		ID: credRows[2].ID, UserID: u.ID, Kind: "webauthn",
		PublicKey: []byte("cose"), CredentialID: "cred-1", SignCount: 5,
	}).Exec(ctx); err != nil {
		t.Fatalf("WebAuthn 附加行 Create 失败: %v", err)
	}

	// 绑定两行：普通渠道 + Union 归并行（§12.7）。
	bindRows := []model.UserThirdpartyBind{
		{UserID: u.ID, ProviderKey: "wechat_mp_1", OpenID: "oX-1", CreatedAt: now},
		{UserID: u.ID, ProviderKey: "wechat_union", OpenID: "union-1", CreatedAt: now},
	}
	for i := range bindRows {
		if _, err := db.NewInsert().Model(&bindRows[i]).Exec(ctx); err != nil {
			t.Fatalf("绑定 Create 失败: %v", err)
		}
	}

	at := time.Unix(1761800000, 0).UTC()
	epoch, err := rp.AnonymizeUser(ctx, u.ID, at)
	if err != nil || epoch != 4 {
		t.Fatalf("AnonymizeUser = (epoch %d, err %v); want (4, nil)", epoch, err)
	}

	row, err := rp.FindByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("匿名化后行不应物理删除: %v", err)
	}
	if row.Username != fmt.Sprintf("deleted_%d", u.ID) {
		t.Errorf("username = %q, want deleted_<id>", row.Username)
	}
	if row.UserStatus != 0 || row.MfaRequired != 0 || row.Epoch != 4 {
		t.Errorf("status/mfa/epoch = (%d, %d, %d), want (0, 0, 4)", row.UserStatus, row.MfaRequired, row.Epoch)
	}
	if row.Phone != nil || row.Email != nil || row.PhoneVerified != 0 || row.EmailVerified != 0 {
		t.Errorf("联系方式应置 NULL 清零: phone=%v email=%v pv=%d ev=%d", row.Phone, row.Email, row.PhoneVerified, row.EmailVerified)
	}
	if row.Nickname != "" || row.AvatarURL != "" {
		t.Errorf("资料列应清空: nickname=%q avatar=%q", row.Nickname, row.AvatarURL)
	}
	if row.LastLoginAt == nil || !row.LastLoginAt.Equal(lastLogin) {
		t.Errorf("last_login_at 应保留: %v, want %v", row.LastLoginAt, lastLogin)
	}
	if !row.CreatedAt.Truncate(time.Second).Equal(u.CreatedAt.Truncate(time.Second)) {
		t.Errorf("created_at 应保留: %v, want %v", row.CreatedAt, u.CreatedAt)
	}
	if !row.UpdatedAt.Truncate(time.Second).Equal(at.Truncate(time.Second)) {
		t.Errorf("updated_at 应为改写时刻: %v, want %v", row.UpdatedAt, at)
	}

	// user_profile 五列清空（行仍在）。
	p, err := rp.GetProfile(ctx, u.ID)
	if err != nil {
		t.Fatalf("profile 行应仍在（清空非删行）: %v", err)
	}
	if p.Gender != 0 || p.Birthday != nil || p.Locale != "" || p.Timezone != "" || p.Extra != nil {
		t.Errorf("profile 应清空: %+v", p)
	}

	// 凭证 / WebAuthn 附加表 / 绑定全清（含 Union 连带行）。
	if n, err := db.NewSelect().Model((*model.UserCredential)(nil)).Where("user_id = ?", u.ID).Count(ctx); err != nil || n != 0 {
		t.Errorf("凭证应全清: n=%d err=%v", n, err)
	}
	if n, err := db.NewSelect().Model((*model.UserCredentialWebauthn)(nil)).Where("user_id = ?", u.ID).Count(ctx); err != nil || n != 0 {
		t.Errorf("WebAuthn 附加表应全清: n=%d err=%v", n, err)
	}
	if n, err := db.NewSelect().Model((*model.UserThirdpartyBind)(nil)).Where("user_id = ?", u.ID).Count(ctx); err != nil || n != 0 {
		t.Errorf("绑定（含 Union 连带行）应全清: n=%d err=%v", n, err)
	}

	// 回绕边界：epoch=30000 时匿名化 → 1（跳过 0，语义同 IncEpoch）。
	w := &model.User{Username: "wrap_user"}
	if err := rp.Create(ctx, w); err != nil {
		t.Fatalf("回绕用户 Create 失败: %v", err)
	}
	userTestSetEpoch(t, db, w.ID, 30000)
	if epoch, err := rp.AnonymizeUser(ctx, w.ID, at); err != nil || epoch != 1 {
		t.Fatalf("回绕匿名化 = (epoch %d, err %v); want (1, nil)", epoch, err)
	}

	// 不存在用户 → ErrRecordNotFound。
	if _, err := rp.AnonymizeUser(ctx, 404, at); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("不存在应 ErrRecordNotFound, got %v", err)
	}
}
