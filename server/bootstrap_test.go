// bootstrap 正常模式装配链测试（§3.1 行 253）：装配顺序断言
//（config → DB → migrate → Redis，用错误传播逐段证明）+ env-skip 真连
// 用例（DB 连通、migrate up 幂等、Redis PING）。清理与错峰口径沿用
// migrate_test / setup_db_test：用例开始清空全部表、结束后
// 清空并自证零残留；连接串只经环境变量注入（UC_TEST_MYSQL_DSN /
// UC_TEST_REDIS_ADDR），代码不含主机 / 凭证信息。
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authloft/internal/config"
)

// wantTables §4 全部 11 张表（§3.16 首版迁移范围），与 migrate_test 一致。
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

// TestMain 共享测试库错峰（与 setup_db_test 同模式）：DSN 存在时先等
// 库「安静」（表空且无其他连接，连续多次确认）再进 m.Run()——避免与同时在
// 跑的 migrate / setup 测试二进制互删对方的表（本包真连用例会 migrate up +
// dropAllTables）。
func TestMain(m *testing.M) {
	if dsn := os.Getenv("UC_TEST_MYSQL_DSN"); dsn != "" {
		waitQuietDB(dsn)
	}
	os.Exit(m.Run())
}

// waitQuietDB / dbQuiet / dropAllTables / assertNoTables 与 migrate_test /
// setup_db_test 同实现（跨包私有不共享，保持同口径副本）。

// waitQuietDB 等待共享测试库空闲：SHOW TABLES 为空 且 processlist 中无
// 其他 test 库连接（排除自身），连续 quietConfirmations 次、间隔
// quietInterval 满足才放行；总上限 quietTimeout 防御性兜底。
func waitQuietDB(dsn string) {
	const (
		quietConfirmations = 3
		quietInterval      = 500 * time.Millisecond
		quietTimeout       = 90 * time.Second
	)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return // 连接失败留给具体用例报告
	}
	defer db.Close()
	deadline := time.Now().Add(quietTimeout)
	streak := 0
	for time.Now().Before(deadline) {
		if dbQuiet(db) {
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

// dbQuiet 单次探测：库内无表且无其他会话连接。
func dbQuiet(db *sql.DB) bool {
	var tables int
	if err := db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()").Scan(&tables); err != nil {
		return false
	}
	if tables > 0 {
		return false
	}
	var others int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM information_schema.processlist WHERE db = DATABASE() AND id <> CONNECTION_ID()",
	).Scan(&others); err != nil {
		return false
	}
	return others == 0
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

// requireAllTables 断言测试库中 §4 全部 11 张表存在（migrate up 真实执行
// 的证据，§3.16 行 572）。
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

// assembleConfig 构造真连用例的自造 *config.Config（§3.2 约定 1 / §20）：
// assemble 只读 DB / Redis 两段，其余字段零值即可。
func assembleConfig(dsn, redisAddr string) *config.Config {
	return &config.Config{
		DB: config.DBConfig{
			DSN:             dsn,
			MaxOpenConns:    10,
			MaxIdleConns:    5,
			ConnMaxLifetime: config.Duration{Duration: time.Minute},
		},
		Redis: config.RedisConfig{Addr: redisAddr, DB: 0, PoolSize: 10},
	}
}

// TestRunFailsFastOnInvalidConfig：装配顺序第一步是 config——config 非法
//（listen 缺失）时 run 返回 "config:" 前缀错误，未落到 DB / migrate /
// Redis 任何后续步骤。
func TestRunFailsFastOnInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(path)
	if err == nil || !strings.Contains(err.Error(), "config:") {
		t.Fatalf("run err = %v, want \"config:\" prefixed load/validate error", err)
	}
}

// TestAssembleOrderDBBeforeMigrateRedis：装配顺序 DB → migrate → Redis——
// DB 不可达（保留端口 + 短超时）时 assemble 停在 DB 步骤（"db:" 前缀错误），
// 绝不产生 migrate（migration_failed）或 Redis（redis:）的错误。
func TestAssembleOrderDBBeforeMigrateRedis(t *testing.T) {
	cfg := assembleConfig("test:123456@tcp(127.0.0.1:1)/test?timeout=500ms", "127.0.0.1:1")
	_, err := assemble(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "db:") {
		t.Fatalf("assemble err = %v, want \"db:\" prefixed error", err)
	}
	if strings.Contains(err.Error(), "migration_failed") || strings.Contains(err.Error(), "redis:") {
		t.Fatalf("assemble err = %v, want fail at DB step before migrate/redis", err)
	}
}

// TestAssembleRealChain（env-skip）：真连装配链 config→DB→migrate up→Redis
//——assemble 成功后 DB ping 通、§4 全部 11 张表存在（migrate 步骤真实
// 执行）、Redis PING 通；复跑 assemble 幂等（版本已最新时 migrate up 秒过
// 不报错，§3.16）。测后清空全表并自证零残留。
func TestAssembleRealChain(t *testing.T) {
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	addr := os.Getenv("UC_TEST_REDIS_ADDR")
	if dsn == "" || addr == "" {
		t.Skip("UC_TEST_MYSQL_DSN / UC_TEST_REDIS_ADDR 未设置，跳过装配真连用例")
	}
	ctx := context.Background()

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

	cfg := assembleConfig(dsn, addr)
	deps, err := assemble(ctx, cfg)
	if err != nil {
		t.Fatalf("装配链失败: %v", err)
	}
	closeDeps := func(d *assembled) {
		if sqlDB, err := d.db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		_ = d.rdb.Close()
	}
	// t.Cleanup LIFO：连接先于清表释放，避免 dropAllTables 时残留占用。
	t.Cleanup(func() { closeDeps(deps) })

	// 步骤 2 DB：装配产物连通。
	sqlDB, err := deps.db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		t.Fatalf("db ping: %v", err)
	}
	// 步骤 3 migrate up：§4 全部 11 张表落库。
	requireAllTables(t, db)
	// 步骤 4 Redis：装配产物 PING 通。
	if err := deps.rdb.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis ping: %v", err)
	}

	// 幂等：复跑整条 assemble（migrate up 版本已最新时秒过，§3.16）。
	deps2, err := assemble(ctx, cfg)
	if err != nil {
		t.Fatalf("复跑 assemble 不幂等: %v", err)
	}
	t.Cleanup(func() { closeDeps(deps2) })
}
