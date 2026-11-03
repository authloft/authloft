// settings 表 repo 层测试：真实 MariaDB 测试实例经
// UC_TEST_MYSQL_DSN env 注入，无 env 时 skip。表结构由 migrate.Up 建
// （§3.16 DDL 唯一来源）；用例开始 drop 全表、结束 drop 全表 +
// assertNoTables 自证零残留（清理口径与既有 DB 测试一致）；跨二进制
// 错峰改用 MySQL GET_LOCK 命名锁（与 settings 包 store_test 同名互斥，
// 原因见彼处 TestMain 注释：轮询式等安静在双二进制同点起跑时互卡）。
// 连接串只经环境变量注入，代码不含主机 / 凭证信息。
package repo

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"authloft/internal/migrate"
	"authloft/internal/repo/model"
)

// testDBLockName 测试库互斥锁名（与 settings 包 store_test 同名，两个
// DB 测试二进制靠它严格串行）。机制全解见 settings 包 store_test.go 的
// TestMain 注释。
const testDBLockName = "uc_test_db_slot"

// TestMain 共享测试库串行化（GET_LOCK 持锁贯穿 m.Run()，机制说明见
// settings 包 store_test.go 的 TestMain 注释）。
func TestMain(m *testing.M) {
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		os.Exit(m.Run())
	}
	db := acquireTestDB(dsn)
	code := m.Run()
	if db != nil {
		_ = db.Close() // 关连接即释放 GET_LOCK
	}
	os.Exit(code)
}

// acquireTestDB 获取测试库互斥槽：单连接 *sql.DB——GET_LOCK 与安静探测
// 共用同一物理连接。
func acquireTestDB(dsn string) *sql.DB {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var got int
	if err := db.QueryRow("SELECT GET_LOCK(?, ?)", testDBLockName, 300).Scan(&got); err != nil || got != 1 {
		_ = db.Close()
		return nil
	}
	waitQuietOnConn(db)
	return db
}

// waitQuietOnConn 在持锁连接上等库安静：库内无表，连续
// quietConfirmations 次、间隔 quietInterval 才放行；总上限 quietTimeout
// 防御性兜底（超时放行）。不看连接数：兄弟二进制阻塞在 GET_LOCK 的
// 等待连接无表、无害，若计入会互相卡到超时（实测）。
func waitQuietOnConn(db *sql.DB) {
	const (
		quietConfirmations = 3
		quietInterval      = 500 * time.Millisecond
		quietTimeout       = 90 * time.Second
	)
	deadline := time.Now().Add(quietTimeout)
	streak := 0
	for time.Now().Before(deadline) {
		if connQuiet(db) {
			streak++
			if streak >= quietConfirmations {
				return
			}
		} else {
			streak = 0
		}
		time.Sleep(quietInterval)
	}
}

// connQuiet 单次探测：库内无表。
func connQuiet(db *sql.DB) bool {
	var tables int
	if err := db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()").Scan(&tables); err != nil {
		return false
	}
	return tables == 0
}

// dropAllTables 删除测试库中全部表（含 goose_db_version），实现用例间
// 隔离与零残留。SET FOREIGN_KEY_CHECKS=0 保证任意删除顺序可行。
func dropAllTables(db *sql.DB) error {
	rows, err := db.Query("SHOW TABLES")
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(tables) == 0 {
		return nil
	}
	if _, err := db.Exec("SET FOREIGN_KEY_CHECKS = 0"); err != nil {
		return err
	}
	quoted := make([]string, len(tables))
	for i, tbl := range tables {
		quoted[i] = "`" + strings.ReplaceAll(tbl, "`", "``") + "`"
	}
	if _, err := db.Exec("DROP TABLE " + strings.Join(quoted, ", ")); err != nil {
		return err
	}
	_, err = db.Exec("SET FOREIGN_KEY_CHECKS = 1")
	return err
}

// assertNoTables 清理自证：SHOW TABLES 必须为空（零残留）。
func assertNoTables(db *sql.DB) error {
	rows, err := db.Query("SHOW TABLES")
	if err != nil {
		return err
	}
	defer rows.Close()
	var left []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		left = append(left, name)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(left) > 0 {
		return fmt.Errorf("残留表: %v", left)
	}
	return nil
}

// TestSettingsRepoRoundTrip（env-skip）：LoadAll 空表 → UpsertAll 插入 →
// UpsertAll 更新（v / updated_by 变更，未涉及行不动）→ InsertIgnoreAll
// 不覆写已有行、只补缺失行；空集短路。
func TestSettingsRepoRoundTrip(t *testing.T) {
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过 settings repo 集成用例")
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
	rp := NewSettingsRepo(db)

	// 空表 LoadAll：空集、无错误。
	rows, err := rp.LoadAll(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("空表 LoadAll = %d 行, err %v；want 0, nil", len(rows), err)
	}

	// UpsertAll 插入两行（v 为 §4.7 JSON 编码口径）。
	now := time.Now()
	if err := rp.UpsertAll(ctx, []model.Setting{
		{K: "pwd_min_length", V: "8", UpdatedAt: now, UpdatedBy: 0},
		{K: "cookie_name", V: `"al_session"`, UpdatedAt: now, UpdatedBy: 0},
	}); err != nil {
		t.Fatalf("UpsertAll 插入失败: %v", err)
	}
	rows, err = rp.LoadAll(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("插入后 LoadAll = %d 行, err %v；want 2", len(rows), err)
	}
	byKey := map[string]model.Setting{}
	for _, r := range rows {
		byKey[r.K] = r
	}
	if r := byKey["pwd_min_length"]; r.V != "8" || r.UpdatedBy != 0 {
		t.Errorf("pwd_min_length 行 = %+v", r)
	}
	if r := byKey["cookie_name"]; r.V != `"al_session"` {
		t.Errorf("cookie_name 行 v = %q", r.V)
	}

	// UpsertAll 更新：v 与 updated_by 变更，未涉及行不动。
	later := now.Add(time.Hour)
	if err := rp.UpsertAll(ctx, []model.Setting{
		{K: "pwd_min_length", V: "10", UpdatedAt: later, UpdatedBy: 42},
	}); err != nil {
		t.Fatalf("UpsertAll 更新失败: %v", err)
	}
	rows, err = rp.LoadAll(ctx)
	if err != nil {
		t.Fatalf("更新后 LoadAll: %v", err)
	}
	byKey = map[string]model.Setting{}
	for _, r := range rows {
		byKey[r.K] = r
	}
	if r := byKey["pwd_min_length"]; r.V != "10" || r.UpdatedBy != 42 {
		t.Errorf("更新后 pwd_min_length = %+v；want v=10 by=42", r)
	}
	if r := byKey["cookie_name"]; r.V != `"al_session"` || r.UpdatedBy != 0 {
		t.Errorf("未涉及行不应变动: %+v", r)
	}

	// InsertIgnoreAll：已有行不覆写（保持 v=10），缺失行补入。
	if err := rp.InsertIgnoreAll(ctx, []model.Setting{
		{K: "pwd_min_length", V: "8", UpdatedAt: later.Add(time.Hour), UpdatedBy: 0},
		{K: "otp_ttl", V: "300", UpdatedAt: later.Add(time.Hour), UpdatedBy: 0},
	}); err != nil {
		t.Fatalf("InsertIgnoreAll 失败: %v", err)
	}
	rows, err = rp.LoadAll(ctx)
	if err != nil || len(rows) != 3 {
		t.Fatalf("InsertIgnore 后 LoadAll = %d 行, err %v；want 3", len(rows), err)
	}
	byKey = map[string]model.Setting{}
	for _, r := range rows {
		byKey[r.K] = r
	}
	if r := byKey["pwd_min_length"]; r.V != "10" || r.UpdatedBy != 42 {
		t.Errorf("InsertIgnore 不得覆写已有行: %+v", r)
	}
	if r := byKey["otp_ttl"]; r.V != "300" {
		t.Errorf("缺失行应补入 otp_ttl=300: %+v", r)
	}

	// 空集短路：无错误、无副作用。
	if err := rp.UpsertAll(ctx, nil); err != nil {
		t.Errorf("UpsertAll 空集应 nil: %v", err)
	}
	if err := rp.InsertIgnoreAll(ctx, nil); err != nil {
		t.Errorf("InsertIgnoreAll 空集应 nil: %v", err)
	}
}
