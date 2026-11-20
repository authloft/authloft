package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"

	"authloft/internal/config"
	"authloft/migrations"
)

// wantTables §4 全部 14 张表（§3.16 首版迁移范围），顺序与迁移文件一致。
var wantTables = []string{
	"provider",
	"user",
	"user_profile",
	"user_credential",
	"user_credential_webauthn",
	"user_thirdparty_bind",
	"sso_client",
	"oidc_client",
	"template",
	"oidc_refresh_token",
	"event_log",
	"settings",
	"user_permission",
	"oidc_consent",
}

// 测试库 env 与互斥锁常量：口径为 UC_TEST_DB_DRIVER + UC_TEST_DB_DSN 双
// 变量显式指定方言与连接串，仅设 UC_TEST_MYSQL_DSN 时兼容读为 mysql +
// 其值。本段与 repo 包 testsupport_test.go 同口径副本（测试文件不可跨包
// import，机制改动须两处同步）；pg 键为锁名 FNV-1a 64 位散列按 int64
// 补码截断，与 GET_LOCK 名锁保持同一互斥身份。
const (
	envTestDBDriver    = "UC_TEST_DB_DRIVER"
	envTestDBDSN       = "UC_TEST_DB_DSN"
	envMySQLDSNLegacy  = "UC_TEST_MYSQL_DSN"
	testDBLockName     = "uc_test_db_slot"
	pgTestLockWaitTime = 300 * time.Second
	testDBLockKeyPG    = -2607616838611919394
)

// testDBTarget 一次测试运行的测试库目标：方言 + 连接串。
type testDBTarget struct {
	driver config.Driver
	dsn    string
}

// resolveTestDBEnv 解析测试库 env：三变量全空 = 未请求测试库（集成用例
// skip，不视为错误）；双变量只配一半 = 配置错误（fail-fast，防注入链
// 断裂时用例静默 skip 假绿）；driver 取值越界同报错。
func resolveTestDBEnv() (*testDBTarget, error) {
	driverName := os.Getenv(envTestDBDriver)
	dsn := os.Getenv(envTestDBDSN)
	if driverName == "" && dsn == "" {
		if legacy := os.Getenv(envMySQLDSNLegacy); legacy != "" {
			return &testDBTarget{driver: config.DriverMySQL, dsn: legacy}, nil
		}
		return nil, nil
	}
	if driverName == "" || dsn == "" {
		return nil, fmt.Errorf("%s 与 %s 必须成对设置（现 driver=%q dsn=%q）", envTestDBDriver, envTestDBDSN, driverName, dsn)
	}
	switch config.Driver(driverName) {
	case config.DriverMySQL, config.DriverPostgres:
		return &testDBTarget{driver: config.Driver(driverName), dsn: dsn}, nil
	default:
		return nil, fmt.Errorf("%s=%q 非法（want mysql|postgres）", envTestDBDriver, driverName)
	}
}

// TestMain 共享测试库串行化（锁名 uc_test_db_slot 持锁贯穿 m.Run()；五包
// 统一接锁，机制背景见 repo 包 testsupport_test.go 的 TestMain 注释）。
// 本包 mysql 与 postgres 两侧用例齐备，激活哪个方言就锁哪个方言的库：
// mysql → GET_LOCK（与 settings / repo / setup / main 的 DB 测试二进制
// 串行）；postgres → pg_advisory_lock（与 repo 二进制串行）。拿不到锁 /
// 出错时放行兜底，与既有 GET_LOCK 口径一致（宁可试跑不挂死）。
func TestMain(m *testing.M) {
	target, err := resolveTestDBEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "authloft 测试环境变量错误: "+err.Error())
		os.Exit(1)
	}
	var db *sql.DB
	if target != nil {
		db = acquireTestSlot(target)
	}
	code := m.Run()
	if db != nil {
		releaseTestSlot(target, db)
	}
	os.Exit(code)
}

// acquireTestSlot 获取测试库互斥槽（testlock）：单连接 *sql.DB——锁与安静
// 探测共用同一物理连接（连接一多探测口径就乱）。
func acquireTestSlot(target *testDBTarget) *sql.DB {
	db, err := NewDB(target.driver, target.dsn)
	if err != nil {
		return nil
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var ok bool
	switch target.driver {
	case config.DriverPostgres:
		ok = pgAcquireAdvisoryLock(db)
	default:
		// GET_LOCK 等待上限 300s：拿不到返回 0，按放行兜底处理。
		if err := db.QueryRow("SELECT GET_LOCK(?, ?)", testDBLockName, int(pgTestLockWaitTime.Seconds())).Scan(&ok); err != nil {
			ok = false
		}
	}
	if !ok {
		_ = db.Close()
		return nil
	}
	waitQuietOnConn(db, target.driver)
	logTestSlot(target, db)
	return db
}

// pgAcquireAdvisoryLock 持 PG advisory 锁：pg_advisory_lock 本身无超时
// 参数、阻塞等待可能无限挂死，等待侧以 statement_timeout 兜底（阻塞中的
// 锁语句到点被取消，对齐 MySQL GET_LOCK 的 300s 等待上限）；SET LOCAL 在
// 事务内生效、提交后随事务回退。锁本身 session 级，COMMIT 不释放。
func pgAcquireAdvisoryLock(db *sql.DB) bool {
	if _, err := db.Exec("BEGIN"); err != nil {
		return false
	}
	if _, err := db.Exec(fmt.Sprintf("SET LOCAL statement_timeout = '%ds'", int(pgTestLockWaitTime.Seconds()))); err != nil {
		_, _ = db.Exec("ROLLBACK")
		return false
	}
	if _, err := db.Exec("SELECT pg_advisory_lock($1)", testDBLockKeyPG); err != nil {
		_, _ = db.Exec("ROLLBACK")
		return false
	}
	_, err := db.Exec("COMMIT")
	return err == nil
}

// releaseTestSlot 释放互斥槽：PG 侧先显式 pg_advisory_unlock 再关连接
// （连接关闭本身也会释放 session 级锁，进程异常退出同理由连接断开兜底，
// unlock 只是让显式路径可观测）；mysql 侧关连接即释放 GET_LOCK。
func releaseTestSlot(target *testDBTarget, db *sql.DB) {
	if target.driver == config.DriverPostgres {
		_, _ = db.Exec("SELECT pg_advisory_unlock($1)", testDBLockKeyPG)
	}
	_ = db.Close()
	fmt.Fprintf(os.Stderr, "authloft test: test db slot released (lock=%s driver=%s)\n", testDBLockName, target.driver)
}

// logTestSlot 落库自证：持锁连接上查当前库名打到 stderr（方言对应位：
// mysql DATABASE() / pg current_database()）。
func logTestSlot(target *testDBTarget, db *sql.DB) {
	query := "SELECT DATABASE()"
	if target.driver == config.DriverPostgres {
		query = "SELECT current_database()"
	}
	var dbname string
	if err := db.QueryRow(query).Scan(&dbname); err != nil {
		dbname = "<unknown>"
	}
	fmt.Fprintf(os.Stderr, "authloft test: test db slot acquired (lock=%s driver=%s database=%s)\n", testDBLockName, target.driver, dbname)
}

// waitQuietOnConn 在持锁连接上等库安静：库内无表（有表 = 有未按预期
// 清理的残留），连续 quietConfirmations 次、间隔 quietInterval 才放行；
// 总上限 quietTimeout 防御性兜底（超时放行，宁可试跑不挂死）。不看
// 连接数：兄弟二进制阻塞在互斥锁上的等待连接无表、无害，若计入会
// 互相卡到超时（实测）。
func waitQuietOnConn(db *sql.DB, driver config.Driver) {
	const (
		quietConfirmations = 3
		quietInterval      = 500 * time.Millisecond
		quietTimeout       = 90 * time.Second
	)
	deadline := time.Now().Add(quietTimeout)
	streak := 0
	for time.Now().Before(deadline) {
		if connQuiet(db, driver) {
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

// connQuiet 单次探测：库内无表。残留探测按方言分派——mysql 用
// information_schema.tables + DATABASE() 限定当前库；pg 用 pg_tables +
// current_schema() 限定当前库当前 schema（pg_tables 为每库视图，跨库表
// 天然不可见）。
func connQuiet(db *sql.DB, driver config.Driver) bool {
	var tables int
	var err error
	if driver == config.DriverPostgres {
		err = db.QueryRow("SELECT COUNT(*) FROM pg_tables WHERE schemaname = current_schema()").Scan(&tables)
	} else {
		err = db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()").Scan(&tables)
	}
	if err != nil {
		return false
	}
	return tables == 0
}

// envDSN 返回测试用 DSN；测试库 env 未设置或激活方言非 mysql 时跳过本组
// 集成用例（skip-on-no-env：本地无 DB / CI 未配 service 时自动跳过）。
// DSN 直接指向专用测试库，不再另建 schema；连接串只经环境变量注入，
// 代码不含任何主机 / 凭证信息。
func envDSN(t *testing.T) string {
	t.Helper()
	target, err := resolveTestDBEnv()
	if err != nil {
		t.Fatalf("测试环境变量错误: %v", err)
	}
	if target == nil || target.driver != config.DriverMySQL {
		t.Skipf("测试库 env 未设置或激活方言非 mysql（%s+%s，或兼容 %s），跳过迁移 mysql 集成用例", envTestDBDriver, envTestDBDSN, envMySQLDSNLegacy)
	}
	return target.dsn
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

// requireAllTables 断言测试库中 §4 全部 14 张表存在。
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

// TestGooseDialect goose Provider 方言按 driver 选择：postgres →
// DialectPostgres；mysql 与空值（存量配置缺 driver 字段的回落口径）→
// DialectMySQL。
func TestGooseDialect(t *testing.T) {
	if got := gooseDialect(config.DriverMySQL); got != goose.DialectMySQL {
		t.Errorf("mysql dialect = %v, want %v", got, goose.DialectMySQL)
	}
	if got := gooseDialect(config.DriverPostgres); got != goose.DialectPostgres {
		t.Errorf("postgres dialect = %v, want %v", got, goose.DialectPostgres)
	}
	if got := gooseDialect(""); got != goose.DialectMySQL {
		t.Errorf("empty driver dialect = %v, want %v", got, goose.DialectMySQL)
	}
}

// dialectVersions 收集方言目录根下的迁移版本号（文件名形如
// 000001_init.sql，取前导数字），顺带断言文件可读且非空。
func dialectVersions(t *testing.T, fsys fs.FS) []int64 {
	t.Helper()
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatalf("读取方言目录失败: %v", err)
	}
	versions := make([]int64, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			t.Errorf("方言目录不应出现子目录: %s", e.Name())
			continue
		}
		v, err := strconv.ParseInt(strings.SplitN(e.Name(), "_", 2)[0], 10, 64)
		if err != nil {
			t.Errorf("迁移文件名解析版本失败: %s: %v", e.Name(), err)
			continue
		}
		if data, err := fs.ReadFile(fsys, e.Name()); err != nil || len(data) == 0 {
			t.Errorf("迁移文件读取失败或为空: %s: %v", e.Name(), err)
		}
		versions = append(versions, v)
	}
	slices.Sort(versions)
	return versions
}

// TestDialectFS 迁移目录按方言收集（fs.Sub 剥层）：两个方言目录均可读、
// 版本号集合一一对应；未知方言报错。纯 FS 断言，不依赖数据库环境。
func TestDialectFS(t *testing.T) {
	mysqlFS, err := migrations.DialectFS(migrations.DialectMySQL)
	if err != nil {
		t.Fatalf("mysql 方言 FS 获取失败: %v", err)
	}
	pgFS, err := migrations.DialectFS(migrations.DialectPostgres)
	if err != nil {
		t.Fatalf("postgres 方言 FS 获取失败: %v", err)
	}
	want := []int64{1}
	if mysqlV := dialectVersions(t, mysqlFS); !slices.Equal(mysqlV, want) {
		t.Errorf("mysql 方言版本集合 = %v, want %v", mysqlV, want)
	}
	if pgV := dialectVersions(t, pgFS); !slices.Equal(pgV, want) {
		t.Errorf("postgres 方言版本集合 = %v, want %v", pgV, want)
	}
	if _, err := migrations.DialectFS("sqlite3"); err == nil {
		t.Error("未知方言应报错")
	}
}

// TestNewDBFactory 统一连接工厂（repo.Open / 本包 / setup 三处建连共享）
// 的反向与构造用例：mysql 非法 DSN 建连期报错；postgres URL 形态返回可用
// 连接对象（pgdriver 惰性连接，构造不拨号）；未知 driver 报错。
func TestNewDBFactory(t *testing.T) {
	if db, err := NewDB(config.DriverMySQL, "not a dsn"); err == nil {
		_ = db.Close()
		t.Fatal("mysql 非法 DSN 应报错")
	}
	pgDB, err := NewDB(config.DriverPostgres, "postgres://authloft:pass@127.0.0.1:5432/authloft?sslmode=disable")
	if err != nil {
		t.Fatalf("postgres 连接对象构造失败: %v", err)
	}
	_ = pgDB.Close()
	if db, err := NewDB(config.Driver("sqlite"), "whatever"); err == nil {
		_ = db.Close()
		t.Fatal("未知 driver 应报错")
	}
}

// TestNewDBMySQLReal（env-skip，激活方言为 mysql 时实跑）：工厂 mysql
// 分支真连测试库并 ping。
func TestNewDBMySQLReal(t *testing.T) {
	target, err := resolveTestDBEnv()
	if err != nil {
		t.Fatalf("测试环境变量错误: %v", err)
	}
	if target == nil || target.driver != config.DriverMySQL {
		t.Skipf("测试库 env 未设置或激活方言非 mysql（%s+%s，或兼容 %s），跳过工厂 mysql 真连用例", envTestDBDriver, envTestDBDSN, envMySQLDSNLegacy)
	}
	db, err := NewDB(config.DriverMySQL, target.dsn)
	if err != nil {
		t.Fatalf("NewDB mysql 真连失败: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

// pgTestTarget 返回激活方言为 postgres 时的测试库目标（envDSN 的 PG 侧
// 对应位）：未设置或方言不符即 skip——本地无 PG 实例属常态，实跑在 CI
// postgres 矩阵；连接串只经环境变量注入。
func pgTestTarget(t *testing.T) *testDBTarget {
	t.Helper()
	target, err := resolveTestDBEnv()
	if err != nil {
		t.Fatalf("测试环境变量错误: %v", err)
	}
	if target == nil || target.driver != config.DriverPostgres {
		t.Skipf("测试库 env 未设置或激活方言非 postgres（%s+%s），跳过迁移 postgres 用例（实跑在 CI postgres 矩阵）", envTestDBDriver, envTestDBDSN)
	}
	return target
}

// TestNewDBPostgresReal（env-skip）：工厂 postgres 分支真连。本地无
// PostgreSQL，实跑在 CI postgres 矩阵；连接串只经环境变量注入。
func TestNewDBPostgresReal(t *testing.T) {
	target := pgTestTarget(t)
	db, err := NewDB(config.DriverPostgres, target.dsn)
	if err != nil {
		t.Fatalf("NewDB postgres 真连失败: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

// TestG1EmptyUpToLatest §21.2 G 组①：空库一步 migrate up 到最新，
// §4 全部 12 张表建立、版本表记录最新版本。
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
// 重跑 migrate up 即重试未记版本，一步续装到位。
// 只删正版本行（version_id > 0，保留零版本行）：goose 语义要求零版本行
// 存在，删光全部行会让 up 直接报 missing zero version，而真实失败残留
// 恰恰是零行仍在。
func TestG3HalfBuiltRecovery(t *testing.T) {
	db, dsn := newTestDB(t)
	ctx := context.Background()
	if err := Up(ctx, dsn); err != nil {
		t.Fatalf("准备阶段首次 migrate up 失败: %v", err)
	}
	// 模拟失败残留：已应用版本（1、2）未记入版本表 + 半成品表残缺。
	if _, err := db.Exec("DELETE FROM goose_db_version WHERE version_id > 0"); err != nil {
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
	// 重跑 migrate up 重试未记版本，续装到位（IF NOT EXISTS 补齐残缺表）。
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

// ---- PostgreSQL 侧（env-skip：激活方言非 postgres 即跳过，实跑在 CI
// postgres 矩阵；本地无 PG 实例）。清理与探测用 PG 方言：pg_tables +
// current_schema() 残留口径、DROP TABLE ... CASCADE；跨二进制互斥走
// TestMain 的 pg_advisory_lock（与 repo 二进制的 PG 用例串行）。

// pgDropAllTables 删除当前 schema 全部表（含 goose_db_version），实现
// 用例间隔离与零残留；CASCADE 兜底任意删除顺序。
func pgDropAllTables(db *sql.DB) error {
	rows, err := db.Query("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
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
	quoted := make([]string, len(tables))
	for i, tbl := range tables {
		quoted[i] = `"` + strings.ReplaceAll(tbl, `"`, `""`) + `"`
	}
	_, err = db.Exec("DROP TABLE " + strings.Join(quoted, ", ") + " CASCADE")
	return err
}

// pgAssertNoTables 清理自证：当前 schema 必须无表（零残留）。
func pgAssertNoTables(db *sql.DB) error {
	rows, err := db.Query("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
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

// pgRequireAllTables 断言 §4 全部 14 张表存在（pg_tables 口径，
// current_schema() 限定）。
func pgRequireAllTables(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, tbl := range wantTables {
		var n int
		err := db.QueryRow(
			"SELECT COUNT(*) FROM pg_tables WHERE schemaname = current_schema() AND tablename = $1",
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

// pgAppliedVersion 返回 goose 版本表已应用的最大版本（PG 版本表
// is_applied 为 boolean；goose 建表时同样插入零版本行）。
func pgAppliedVersion(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	var v int64
	err := db.QueryRow(
		"SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version WHERE is_applied",
	).Scan(&v)
	if err != nil {
		t.Fatalf("查询 goose_db_version 失败: %v", err)
	}
	return v
}

// TestG1PostgresEmptyUpToLatest（env-skip）与 mysql 侧 G 组①同语义：
// PG 空库一步 migrate up 到最新，§4 全部 14 张表建立、版本表记录最新
// 版本。本地无 PG 实例，实跑在 CI postgres 矩阵；连接串只经环境变量注入，
// 代码不含任何主机 / 凭证信息。
func TestG1PostgresEmptyUpToLatest(t *testing.T) {
	target := pgTestTarget(t)
	db, err := NewDB(config.DriverPostgres, target.dsn)
	if err != nil {
		t.Fatalf("打开连接失败: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("连接 PostgreSQL 测试实例失败: %v", err)
	}
	if err := pgDropAllTables(db); err != nil {
		t.Fatalf("用例开始清空测试库失败: %v", err)
	}
	t.Cleanup(func() {
		if err := pgDropAllTables(db); err != nil {
			t.Errorf("用例结束清理测试库失败: %v", err)
		}
		if err := pgAssertNoTables(db); err != nil {
			t.Errorf("清理自证失败: %v", err)
		}
		db.Close()
	})
	ctx := context.Background()
	if err := gooseUp(ctx, db, config.DriverPostgres); err != nil {
		t.Fatalf("PG 空库 migrate up 失败: %v", err)
	}
	pgRequireAllTables(t, db)
	if v := pgAppliedVersion(t, db); v != 1 {
		t.Errorf("迁移后版本表最新版本 = %d, want 1", v)
	}
}
