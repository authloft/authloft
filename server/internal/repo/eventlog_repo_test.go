// event_log 表 repo 层测试：真实 MariaDB 测试实例经
// UC_TEST_MYSQL_DSN env 注入，无 env 时全部用例 skip。表结构由 migrate.Up
// 建（§3.16 DDL 唯一来源）；用例开始 drop 全表、结束 drop 全表 +
// assertNoTables 自证零残留（同既有 repo 测试口径）。跨二进制互斥由
// settings_repo_test.go 的 TestMain（GET_LOCK
// uc_test_db_slot）保证；共享辅助 dropAllTables / assertNoTables /
// dbTestConfig 在彼处与 db_test.go，本文件不自带 TestMain。连接串只经
// 环境变量注入，代码不含主机 / 凭证信息。
package repo

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/internal/migrate"
	"authloft/internal/repo/model"
)

// eventLogTestSetup 清库 + 建表 + 注册测后零残留清理，返回就绪的
// EventLogRepo 与 GORM 连接（后者供用例回读断言）。
func eventLogTestSetup(t *testing.T) (*EventLogRepo, *gorm.DB) {
	t.Helper()
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过 event log repo 集成用例")
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
	return NewEventLogRepo(db), db
}

// TestEventLogRepoBatchInsert（env-skip）：批量写入后字段原样回读；
// 零值 default 列取 DDL 默认；detail nil → NULL、非 nil（含空字节）→ 原样
// 落库；created_at 显式值保留、零值由 repo 填当前时刻。
func TestEventLogRepoBatchInsert(t *testing.T) {
	rp, db := eventLogTestSetup(t)
	ctx := context.Background()

	fixed := time.Now().Truncate(time.Second).Add(-time.Hour)
	detail := []byte{0x00, 0x01, 0x7f, 0xff}
	before := time.Now()
	rows := []model.EventLog{
		{
			Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42,
			ClientID: "oidc_app", AMR: "pwd,otp", IP: "10.0.0.1", UA: "ua/1.0",
			Detail: detail, CreatedAt: fixed,
		},
		// 全零：actor_id/user_id 取 DEFAULT 0，字符串列取 DEFAULT ''，
		// detail nil，created_at 零值交给 repo 填。
		{Event: "provider_update", ActorType: "system", Target: "qq"},
		// 空但非 nil 的 detail 应按原样字节落成零长 BLOB，而非 NULL。
		{Event: "change_password", ActorType: "admin", ActorID: 1, UserID: 7, Detail: []byte{}},
	}
	if err := rp.BatchInsert(ctx, rows); err != nil {
		t.Fatalf("BatchInsert 失败: %v", err)
	}

	var got []model.EventLog
	if err := db.WithContext(ctx).Order("id ASC").Find(&got).Error; err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("回读 = %d 行, want 3", len(got))
	}

	// 行 0：全字段原样、detail 二进制保留、created_at 显式值保留。
	r0 := got[0]
	if r0.ID == 0 {
		t.Error("自增 id 应回填")
	}
	if r0.Event != "login_success" || r0.ActorType != "user" || r0.ActorID != 42 ||
		r0.UserID != 42 || r0.ClientID != "oidc_app" || r0.AMR != "pwd,otp" ||
		r0.IP != "10.0.0.1" || r0.UA != "ua/1.0" || r0.Target != "" {
		t.Errorf("行 0 字段不一致: %+v", r0)
	}
	if !bytes.Equal(r0.Detail, detail) {
		t.Errorf("行 0 detail = %v, want %v", r0.Detail, detail)
	}
	if !r0.CreatedAt.Equal(fixed) {
		t.Errorf("行 0 created_at = %v, want %v", r0.CreatedAt, fixed)
	}

	// 行 1：默认值列、nil detail、created_at 由 repo 填充。
	r1 := got[1]
	if r1.ActorID != 0 || r1.UserID != 0 || r1.ClientID != "" ||
		r1.AMR != "" || r1.IP != "" || r1.UA != "" {
		t.Errorf("行 1 默认值列不正确: %+v", r1)
	}
	if r1.Target != "qq" {
		t.Errorf("行 1 target = %q, want \"qq\"", r1.Target)
	}
	if r1.Detail != nil {
		t.Errorf("行 1 detail 应为 NULL, got %v", r1.Detail)
	}
	if r1.CreatedAt.IsZero() {
		t.Error("行 1 created_at 零值应由 repo 填充")
	}
	if d := r1.CreatedAt.Sub(before); d < -time.Second || d > 2*time.Second {
		t.Errorf("行 1 created_at = %v 偏离写入时刻 %v", r1.CreatedAt, before)
	}

	// 行 2：空非 nil detail 落成零长 BLOB，created_at 同样被填充。
	r2 := got[2]
	if len(r2.Detail) != 0 {
		t.Errorf("行 2 detail 长度 = %d, want 0", len(r2.Detail))
	}
	if r2.CreatedAt.IsZero() {
		t.Error("行 2 created_at 零值应由 repo 填充")
	}

	// detail NULL 语义按 SQL 直查确认：仅行 1 为 NULL。
	var nullCount, emptyCount int64
	if err := db.WithContext(ctx).
		Raw("SELECT COUNT(*) FROM event_log WHERE detail IS NULL").
		Scan(&nullCount).Error; err != nil {
		t.Fatalf("查 detail NULL 计数失败: %v", err)
	}
	if nullCount != 1 {
		t.Errorf("detail IS NULL = %d 行, want 1", nullCount)
	}
	if err := db.WithContext(ctx).
		Raw("SELECT COUNT(*) FROM event_log WHERE detail IS NOT NULL AND OCTET_LENGTH(detail) = 0").
		Scan(&emptyCount).Error; err != nil {
		t.Fatalf("查 detail 空 BLOB 计数失败: %v", err)
	}
	if emptyCount != 1 {
		t.Errorf("detail 零长 BLOB = %d 行, want 1", emptyCount)
	}
}

// TestEventLogRepoBatchInsertChunks（env-skip）：超过批上限的行数按
// EventLogBatchSize 分批插入且全部落库、id 自增连续；所有零值 created_at
// 均被填充。
func TestEventLogRepoBatchInsertChunks(t *testing.T) {
	rp, db := eventLogTestSetup(t)
	ctx := context.Background()

	if EventLogBatchSize != 200 {
		t.Errorf("EventLogBatchSize = %d, want 200（§5.2 攒批口径）", EventLogBatchSize)
	}
	n := EventLogBatchSize + 5
	rows := make([]model.EventLog, n)
	for i := range rows {
		rows[i] = model.EventLog{Event: "login_success", ActorType: "user", UserID: int64(i + 1)}
	}
	if err := rp.BatchInsert(ctx, rows); err != nil {
		t.Fatalf("BatchInsert %d 行失败: %v", n, err)
	}

	var count int64
	if err := db.WithContext(ctx).Model(&model.EventLog{}).Count(&count).Error; err != nil {
		t.Fatalf("计数失败: %v", err)
	}
	if count != int64(n) {
		t.Fatalf("落库 = %d 行, want %d", count, n)
	}

	var got []model.EventLog
	if err := db.WithContext(ctx).Order("id ASC").Find(&got).Error; err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if len(got) != n {
		t.Fatalf("回读 = %d 行, want %d", len(got), n)
	}
	for i := 1; i < len(got); i++ {
		if got[i].ID <= got[i-1].ID {
			t.Fatalf("id 应随插入顺序递增: [%d]=%d [%d]=%d", i-1, got[i-1].ID, i, got[i].ID)
		}
	}
	for i, r := range got {
		if r.CreatedAt.IsZero() {
			t.Fatalf("第 %d 行 created_at 应被填充", i)
		}
		if r.UserID != int64(i+1) {
			t.Fatalf("第 %d 行 user_id = %d, want %d", i, r.UserID, i+1)
		}
	}
}

// TestEventLogRepoBatchInsertEmpty（env-skip）：nil / 空切片 no-op，不写
// 任何行、不报错。
func TestEventLogRepoBatchInsertEmpty(t *testing.T) {
	rp, db := eventLogTestSetup(t)
	ctx := context.Background()

	if err := rp.BatchInsert(ctx, nil); err != nil {
		t.Errorf("BatchInsert(nil) 应 nil, got %v", err)
	}
	if err := rp.BatchInsert(ctx, []model.EventLog{}); err != nil {
		t.Errorf("BatchInsert(空切片) 应 nil, got %v", err)
	}
	var count int64
	if err := db.WithContext(ctx).Model(&model.EventLog{}).Count(&count).Error; err != nil {
		t.Fatalf("计数失败: %v", err)
	}
	if count != 0 {
		t.Errorf("空批量应不写行, got %d 行", count)
	}
}

// TestEventLogRepoListByUser（env-skip）：user 维度 + event 过滤分页
//（GetUserEvents「该用户登录记录」的数据源）——只出目标用户的行、event
// 非空时再过滤、id DESC 全序稳定、分页归一（page 1 起、pageSize 默认 20 /
// clamp 100）、total 为过滤后总数。
func TestEventLogRepoListByUser(t *testing.T) {
	rp, _ := eventLogTestSetup(t)
	ctx := context.Background()

	// 用户 42：3 条 login_success + 1 条 change_password（乱序插入，id 递增）；
	// 用户 43：2 条 login_success（不串页）。
	rows := []model.EventLog{
		{Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42, IP: "1.1.1.1"},
		{Event: "change_password", ActorType: "user", ActorID: 42, UserID: 42},
		{Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42, IP: "2.2.2.2"},
		{Event: "login_success", ActorType: "user", ActorID: 43, UserID: 43},
		{Event: "login_success", ActorType: "user", ActorID: 42, UserID: 42, IP: "3.3.3.3"},
		{Event: "login_success", ActorType: "user", ActorID: 43, UserID: 43},
	}
	if err := rp.BatchInsert(ctx, rows); err != nil {
		t.Fatalf("BatchInsert 失败: %v", err)
	}

	// event=login_success + user=42：3 行，id DESC。
	got, total, err := rp.ListByUser(ctx, EventLogListQuery{UserID: 42, Event: "login_success"})
	if err != nil || total != 3 || len(got) != 3 {
		t.Fatalf("login_success@42 = (%d 行, total=%d, %v), want 3/3", len(got), total, err)
	}
	for i := 1; i < len(got); i++ {
		if got[i].ID >= got[i-1].ID || got[i].UserID != 42 || got[i].Event != "login_success" {
			t.Fatalf("顺序 / 过滤泄漏: %+v", got)
		}
	}

	// event 过滤关闭（空）：42 的全部 4 行。
	if _, total, err = rp.ListByUser(ctx, EventLogListQuery{UserID: 42}); err != nil || total != 4 {
		t.Fatalf("全事件@42 total = %d err=%v, want 4", total, err)
	}

	// 分页：page 2 size 2（login_success@42 的第 2 页恰 1 行）+ 归一（page 0
	// → 1、pageSize 0 → 20、>100 clamp 不报错）。
	if got, total, err = rp.ListByUser(ctx, EventLogListQuery{UserID: 42, Event: "login_success", Page: 2, PageSize: 2}); err != nil ||
		total != 3 || len(got) != 1 {
		t.Fatalf("page2 = (%d 行, total=%d, %v), want 1/3", len(got), total, err)
	}
	if _, _, err = rp.ListByUser(ctx, EventLogListQuery{UserID: 42, Page: 0, PageSize: 0}); err != nil {
		t.Fatalf("分页归一不应报错: %v", err)
	}
	if _, _, err = rp.ListByUser(ctx, EventLogListQuery{UserID: 42, Page: 1, PageSize: 150}); err != nil {
		t.Fatalf("pageSize=150 应 clamp 不报错: %v", err)
	}

	// 不存在的用户：空页 + total 0。
	if got, total, err = rp.ListByUser(ctx, EventLogListQuery{UserID: 404, Event: "login_success"}); err != nil ||
		total != 0 || len(got) != 0 {
		t.Fatalf("空集 = (%d 行, total=%d, %v), want 0/0", len(got), total, err)
	}
}
