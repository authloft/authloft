// user / user_profile 表 repo 层测试：真实 MariaDB 测试实例经
// UC_TEST_MYSQL_DSN env 注入，无 env 时 skip。表结构由 migrate.Up 建
// （§3.16 DDL 唯一来源）；用例开始 drop 全表、结束 drop 全表 +
// assertNoTables 自证零残留（口径与既有 DB 测试一致）。跨二进制
// 互斥由 settings_repo_test.go 的 TestMain（GET_LOCK uc_test_db_slot）保
// 证；共享辅助 dropAllTables / assertNoTables / dbTestConfig 在彼处与
// db_test.go。连接串只经环境变量注入，代码不含主机 / 凭证信息。
package repo

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/internal/migrate"
	"authloft/internal/repo/model"
)

// userTestSetup 清库 + 建表 + 注册测后零残留清理，返回就绪的 UserRepo
// 与底层 *gorm.DB（供用例直接构造特定列状态，如置 epoch 边界值）。
func userTestSetup(t *testing.T) (*UserRepo, *gorm.DB) {
	t.Helper()
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过 user repo 集成用例")
	}
	ctx := context.Background()
	raw, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("打开连接失败: %v", err)
	}
	if err := raw.Ping(); err != nil {
		t.Fatalf("连接 MariaDB 测试实例失败: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := dropAllTables(raw); err != nil {
		t.Fatalf("用例开始清空测试库失败: %v", err)
	}
	if err := migrate.Up(ctx, dsn); err != nil {
		t.Fatalf("migrate up 失败: %v", err)
	}
	t.Cleanup(func() {
		if err := dropAllTables(raw); err != nil {
			t.Errorf("测后清空测试库失败: %v", err)
		}
		if err := assertNoTables(raw); err != nil {
			t.Errorf("零残留自证失败: %v", err)
		}
	})
	db, err := Open(dbTestConfig(dsn, 10, 5, time.Minute))
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
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
		if _, err := fn(); !errors.Is(err, gorm.ErrRecordNotFound) {
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
	if _, err := rp.IncEpoch(ctx, 404); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("IncEpoch 不存在用户应 ErrRecordNotFound, got %v", err)
	}
	if _, err := rp.GetEpoch(ctx, 404); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("GetEpoch 不存在用户应 ErrRecordNotFound, got %v", err)
	}
}

// userTestSetStatus 直接置 user_status 列构造禁用态：GORM Create 的
// default:1 语义下零值 0 被 tag 值 1 显式写入 INSERT 并回填 struct
//（gorm@v1.31.2 callbacks/create.go:340-343），struct 插入落不了 0，
// 故用列级 UPDATE（与 admin 禁用路径 §5.4 UpdateUserStatus 同构）。
func userTestSetStatus(t *testing.T, db *gorm.DB, id int64, v int8) {
	t.Helper()
	if err := db.Model(&model.User{}).Where("id = ?", id).Update("user_status", v).Error; err != nil {
		t.Fatalf("置 user_status=%d 失败: %v", v, err)
	}
}

// userTestSetEpoch 直接置 epoch 列构造边界前提（GORM 更新，不走被测方法）。
func userTestSetEpoch(t *testing.T, db *gorm.DB, id int64, v int16) {
	t.Helper()
	if err := db.Model(&model.User{}).Where("id = ?", id).Update("epoch", v).Error; err != nil {
		t.Fatalf("置 epoch=%d 失败: %v", v, err)
	}
}

// TestUserRepoUpdateLastLogin（env-skip）：last_login_at 写入与读回
//（DATETIME 秒级精度，输入截断到秒）；最新值覆盖；同值二次更新幂等
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

	if err := rp.UpdateLastLogin(ctx, 404, t2); !errors.Is(err, gorm.ErrRecordNotFound) {
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

	if err := rp.UpdateProfileColumns(ctx, 404, &nick2, nil); !errors.Is(err, gorm.ErrRecordNotFound) {
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

	// 行不存在 → ErrRecordNotFound。
	if err := rp.UpdateContactColumns(ctx, 404, &phone, nil, &one, nil); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("不存在用户应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserRepoListUsers（env-skip）：user_status 过滤 + §1.7 分页参数
//（page 1 起、pageSize 默认 20 上限 100）、id 降序全序稳定。
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
	if _, err := rp.GetProfile(ctx, 404); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("GetProfile 未命中应 ErrRecordNotFound, got %v", err)
	}
}

// TestUserRepoListByIDs（env-skip）：GetUserProfiles 批量读的 repo 支撑
//（接口文档 §7.2 行 1436）——user / user_profile 两表各一条 IN 语句：
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
// email / phone 四列模糊匹配（%q%，通配符转义为字面量）；sort / order 消费
//（合法列名排序、缺省与字符集外回落 id、order 仅 asc 改向）。
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

	// LIKE 通配符按字面量匹配：q="100%" 只含字面百分号，无行命中（不报错）。
	if _, total, err = rp.ListUsers(ctx, UserListQuery{Q: "100%"}); err != nil || total != 0 {
		t.Fatalf("Q=100%% = total %d err=%v, want 0（通配符转义为字面量）", total, err)
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
}

func usernames(rows []model.User) []string {
	out := make([]string, len(rows))
	for i := range rows {
		out[i] = rows[i].Username
	}
	return out
}

// TestUserRepoUpdateUserStatus（env-skip）：列级 UPDATE 禁用 / 启用
//（零值 0 落库——列级更新不受 default:1 tag 影响）；updated_at 刷新；同值
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
	if err := db.Model(&model.User{}).Where("id = ?", u.ID).Update("updated_at", before).Error; err != nil {
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
	if err := rp.UpdateUserStatus(ctx, 404, 0); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("不存在应 ErrRecordNotFound, got %v", err)
	}
}
