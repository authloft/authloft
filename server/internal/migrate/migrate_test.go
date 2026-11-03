package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
)

// wantTables §4 全部 11 张表（§3.16 首版迁移范围），顺序与迁移文件一致。
var wantTables = []string{
	"provider",
	"user",
	"user_profile",
	"user_credential",
	"user_credential_webauthn",
	"user_thirdparty_bind",
	"sso_client",
	"oidc_client",
	"oidc_refresh_token",
	"event_log",
	"settings",
}

// envDSN 返回测试用 DSN；UC_TEST_MYSQL_DSN 未设置时跳过本组集成用例
// （skip-on-no-env：本地无 DB / CI 未配 service 时自动跳过）。
// 修订口径（2026-11-03）：DSN 直接指向专用测试库，不再
// 另建 schema；连接串只经环境变量注入，代码不含任何主机 / 凭证信息。
func envDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过迁移集成用例")
	}
	return dsn
}

// newTestDB 为单个用例准备独立环境：连接 DSN 所指测试库，开始前清空
// 全部表（用例间隔离），结束后 t.Cleanup 彻底清空并自证零残留。
func newTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dsn := envDSN(t)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("打开连接失败: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("连接 MariaDB 测试实例失败: %v", err)
	}
	if err := dropAllTables(db); err != nil {
		t.Fatalf("用例开始清空测试库失败: %v", err)
	}
	t.Cleanup(func() {
		if err := dropAllTables(db); err != nil {
			t.Errorf("用例结束清理测试库失败: %v", err)
		}
		if err := assertNoTables(db); err != nil {
			t.Errorf("清理自证失败: %v", err)
		}
		db.Close()
	})
	return db, dsn
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

// requireAllTables 断言测试库中 §4 全部 11 张表存在。
func requireAllTables(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, tbl := range wantTables {
		var n int
		err := db.QueryRow(
			"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?",
			tbl,
		).Scan(&n)
		if err != nil {
			t.Fatalf("查询表 %s 失败: %v", tbl, err)
		}
		if n == 0 {
			t.Errorf("迁移后表 %s 不存在", tbl)
		}
	}
}

// appliedVersion 返回 goose 版本表已应用的最大版本（无记录时 0）。
// goose 建版本表时会插入零版本行（version_id=0，is_applied=1）。
func appliedVersion(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	var v int64
	err := db.QueryRow(
		"SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied = 1",
	).Scan(&v)
	if err != nil {
		t.Fatalf("查询 goose_db_version 失败: %v", err)
	}
	return v
}

// appliedRows 返回 goose 版本表 is_applied=1 的行数。
func appliedRows(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM goose_db_version WHERE is_applied = 1",
	).Scan(&n)
	if err != nil {
		t.Fatalf("统计 goose_db_version 行数失败: %v", err)
	}
	return n
}

// TestG1EmptyUpToLatest §21.2 G 组①：空库一步 migrate up 到最新，
// §4 全部 11 张表建立、版本表记录最新版本。
func TestG1EmptyUpToLatest(t *testing.T) {
	db, dsn := newTestDB(t)
	if err := Up(context.Background(), dsn); err != nil {
		t.Fatalf("空库 migrate up 失败: %v", err)
	}
	requireAllTables(t, db)
	if v := appliedVersion(t, db); v != 1 {
		t.Errorf("迁移后版本表最新版本 = %d, want 1", v)
	}
}

// TestG2UpIdempotent §21.2 G 组②：版本已最新时重复执行 migrate up
// 零变更（幂等秒过），版本表不新增写入。
func TestG2UpIdempotent(t *testing.T) {
	db, dsn := newTestDB(t)
	ctx := context.Background()
	if err := Up(ctx, dsn); err != nil {
		t.Fatalf("首次 migrate up 失败: %v", err)
	}
	rows := appliedRows(t, db)
	if err := Up(ctx, dsn); err != nil {
		t.Fatalf("版本已最新时重复 migrate up 失败: %v", err)
	}
	if got := appliedRows(t, db); got != rows {
		t.Errorf("重复 up 后版本表新增写入: %d -> %d", rows, got)
	}
	if v := appliedVersion(t, db); v != 1 {
		t.Errorf("重复 up 后版本 = %d, want 1", v)
	}
}

// TestG3HalfBuiltRecovery §21.2 G 组③：半建库恢复——模拟迁移失败的
// 残留状态（§3.16：失败版本不记行，goose 零版本行仍在；半成品表残缺），
// 重跑 migrate up 即重试同版本，一步续装到位。
// 只删 version_id=1 的行：goose 语义要求零版本行存在，删光全部行会让
// up 直接报 missing zero version，而真实失败残留恰恰是零行仍在。
func TestG3HalfBuiltRecovery(t *testing.T) {
	db, dsn := newTestDB(t)
	ctx := context.Background()
	if err := Up(ctx, dsn); err != nil {
		t.Fatalf("准备阶段首次 migrate up 失败: %v", err)
	}
	// 模拟失败残留：版本 1 未记入版本表 + 半成品表残缺。
	if _, err := db.Exec("DELETE FROM goose_db_version WHERE version_id = 1"); err != nil {
		t.Fatalf("删除版本行失败: %v", err)
	}
	for _, tbl := range []string{"settings", "event_log"} {
		if _, err := db.Exec("DROP TABLE " + tbl); err != nil {
			t.Fatalf("删除表 %s 失败: %v", tbl, err)
		}
	}
	// 半建状态下安装判据应为未完成（迁移未到最新）。
	if ok, err := Installed(ctx, dsn); err != nil || ok {
		t.Fatalf("半建库 Installed = (%v, %v), want (false, nil)", ok, err)
	}
	// 重跑 migrate up 重试同版本，续装到位（IF NOT EXISTS 补齐残缺表）。
	if err := Up(ctx, dsn); err != nil {
		t.Fatalf("半建库重跑 migrate up 失败: %v", err)
	}
	requireAllTables(t, db)
	if v := appliedVersion(t, db); v != 1 {
		t.Errorf("恢复后版本表最新版本 = %d, want 1", v)
	}
}

// TestInstalledCriteria 安装判据（§3.16）：迁移版本表最新 + 管理员
// user.id=1 存在，两个未完成分支与正向分支逐个验证。
func TestInstalledCriteria(t *testing.T) {
	db, dsn := newTestDB(t)
	ctx := context.Background()

	// 分支①：空库（迁移未应用）→ 未初始化。
	if ok, err := Installed(ctx, dsn); err != nil || ok {
		t.Fatalf("空库 Installed = (%v, %v), want (false, nil)", ok, err)
	}

	// 分支②：迁移最新但管理员不存在 → 未初始化。
	if err := Up(ctx, dsn); err != nil {
		t.Fatalf("migrate up 失败: %v", err)
	}
	if ok, err := Installed(ctx, dsn); err != nil || ok {
		t.Fatalf("无管理员 Installed = (%v, %v), want (false, nil)", ok, err)
	}

	// 正向：插入管理员（固定 ID=1，§4.2）→ 已初始化。
	if _, err := db.Exec(
		"INSERT INTO user (id, username, created_at, updated_at) VALUES (1, 'admin', NOW(), NOW())",
	); err != nil {
		t.Fatalf("插入管理员失败: %v", err)
	}
	if ok, err := Installed(ctx, dsn); err != nil || !ok {
		t.Fatalf("有管理员 Installed = (%v, %v), want (true, nil)", ok, err)
	}
}
