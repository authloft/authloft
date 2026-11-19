// repo 包集成测试公共辅助（测试期私有，不参与构建产物）：
//   - 测试库 env 解析：UC_TEST_DB_DRIVER + UC_TEST_DB_DSN 双变量显式指定
//     方言与连接串；仅设 UC_TEST_MYSQL_DSN 时兼容读为 mysql + 其值（存量
//     本地脚本不变）。测试矩阵下同一套用例对两库各跑一遍，方言由 env 选定。
//   - testlock 跨二进制互斥：mysql GET_LOCK / postgres pg_advisory_lock
//     （session 级，pg_advisory_unlock 显式释放；进程异常退出由连接断开
//     释放，等待侧以 statement_timeout 兜底防挂死）。
//   - 方言分支的表清理与残留自证、按方言建正式 schema、bun 连接装配。
//
// 其他包（migrate / settings / setup / main）的 DB 测试辅助是本文件的
// 同口径副本（测试文件不可跨包 import），机制改动须同步。
package repo

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"

	"authloft/internal/config"
	"authloft/internal/migrate"
	"authloft/migrations"
)

// 测试库 env 变量名：新口径 UC_TEST_DB_DRIVER / UC_TEST_DB_DSN 成对生效；
// UC_TEST_MYSQL_DSN 为兼容读（等价 mysql + 其值），便于存量脚本平滑迁移。
const (
	envTestDBDriver    = "UC_TEST_DB_DRIVER"
	envTestDBDSN       = "UC_TEST_DB_DSN"
	envMySQLDSNLegacy  = "UC_TEST_MYSQL_DSN"
	testDBLockName     = "uc_test_db_slot"
	pgTestLockWaitTime = 300 * time.Second
)

// testDBLockKeyPG PG advisory 键：testDBLockName 的 FNV-1a 64 位散列按
// int64 补码截断——与 MySQL GET_LOCK 同名锁保持同一互斥身份，两方言各自
// 锁各自的库但语义（名 → 互斥槽）一致；advisory 键为库内命名空间，散列
// 碰撞概率可忽略。
const testDBLockKeyPG = -2607616838611919394

// testDBTarget 一次测试运行的测试库目标：方言 + 连接串（CI 矩阵 job 按
// dialect 各注入一套独立凭据）。
type testDBTarget struct {
	driver config.Driver
	dsn    string
}

// resolveTestDBEnv 解析测试库 env（口径全文见文件头注释）：
// 三变量全空 = 未请求测试库（集成用例 skip，不视为错误）；双变量只配
// 一半 = 配置错误（fail-fast，防注入链断裂时用例静默 skip 假绿——CI 上
// 宁可红也不绿）；driver 取值越界同报错。
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

// requireTestDB 返回解析出的测试库目标：env 未设置时 skip（本地无 DB /
// CI 未配 service 的常态）；want 与激活方言不符时同样 skip（另一方言的
// 矩阵 job 实跑本用例）。成对性 / 取值错误由 TestMain 拦截，此处防御性
// 再查。
func requireTestDB(t *testing.T, want config.Driver) *testDBTarget {
	t.Helper()
	target, err := resolveTestDBEnv()
	if err != nil {
		t.Fatalf("测试环境变量错误: %v", err)
	}
	if target == nil {
		t.Skipf("测试库 env 未设置（%s+%s，或兼容 %s），跳过集成用例", envTestDBDriver, envTestDBDSN, envMySQLDSNLegacy)
	}
	if target.driver != want {
		t.Skipf("激活方言 %s 与本用例方言 %s 不符，跳过（另一方言矩阵 job 实跑）", target.driver, want)
	}
	return target
}

// TestMain 共享测试库串行化：锁名 uc_test_db_slot 持锁贯穿 m.Run()。背景
// （为何不用轮询式等安静）：go test 默认并行启动多个包二进制，双二进制
// 同点起跑时探测连接常驻 processlist，轮询口径互相卡到超时后同时涌入
// 互删表（settings 包实测）；命名锁严格串行后错峰不再必要，等表空仅作
// 防御性兜底。方言按 resolveTestDBEnv 结果选择：mysql → GET_LOCK（与
// migrate / settings / setup / main 的 DB 测试二进制串行）；postgres →
// pg_advisory_lock（与 migrate 二进制串行，其余包无 PG 用例）。拿不到
// 锁 / 出错时放行兜底，与既有 GET_LOCK 口径一致（宁可试跑不挂死）。
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

// acquireTestSlot 获取测试库互斥槽（testlock）：单连接 *sql.DB——锁与
// 安静探测共用同一物理连接（连接一多探测口径就乱）。
func acquireTestSlot(target *testDBTarget) *sql.DB {
	db, err := migrate.NewDB(target.driver, target.dsn)
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
// 事务内生效、提交后随事务回退，不影响后续探测查询。锁本身 session 级，
// COMMIT 不释放。
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
// （契约口径；连接关闭本身也会释放 session 级锁，进程异常退出同理由
// 连接断开兜底，unlock 只是让显式路径可观测）；mysql 侧关连接即释放
// GET_LOCK。释放随日志输出，供并发时序排查。
func releaseTestSlot(target *testDBTarget, db *sql.DB) {
	if target.driver == config.DriverPostgres {
		_, _ = db.Exec("SELECT pg_advisory_unlock($1)", testDBLockKeyPG)
	}
	_ = db.Close()
	fmt.Fprintf(os.Stderr, "authloft test: test db slot released (lock=%s driver=%s)\n", testDBLockName, target.driver)
}

// logTestSlot 落库自证：持锁连接上查当前库名打到 stderr（方言对应位：
// mysql DATABASE() / pg current_database()）——跨二进制并发时序排查 +
// 互斥槽获取证据。
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
// 天然不可见，无 information_schema 的实例级混淆）。
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

// listTables 测试库当前库（当前 schema）的表清单，方言各自目录表口径
// （同 connQuiet）。
func listTables(db *sql.DB, driver config.Driver) ([]string, error) {
	if driver == config.DriverPostgres {
		rows, err := db.Query("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
		if err != nil {
			return nil, err
		}
		return scanTableNames(rows)
	}
	rows, err := db.Query("SHOW TABLES")
	if err != nil {
		return nil, err
	}
	return scanTableNames(rows)
}

func scanTableNames(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return names, nil
}

// dropAllTables 删除测试库中全部表（含 goose_db_version），实现用例间
// 隔离与零残留。按方言分派：mysql 先 SET FOREIGN_KEY_CHECKS=0 保证任意
// 删除顺序可行；pg 无此开关，DROP TABLE ... CASCADE 兜底外键依赖。
func dropAllTables(db *sql.DB, driver config.Driver) error {
	tables, err := listTables(db, driver)
	if err != nil {
		return err
	}
	if len(tables) == 0 {
		return nil
	}
	if driver == config.DriverPostgres {
		quoted := make([]string, len(tables))
		for i, tbl := range tables {
			quoted[i] = `"` + strings.ReplaceAll(tbl, `"`, `""`) + `"`
		}
		_, err = db.Exec("DROP TABLE " + strings.Join(quoted, ", ") + " CASCADE")
		return err
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

// assertNoTables 清理自证：库内必须无表（零残留）。
func assertNoTables(db *sql.DB, driver config.Driver) error {
	left, err := listTables(db, driver)
	if err != nil {
		return err
	}
	if len(left) > 0 {
		return fmt.Errorf("残留表: %v", left)
	}
	return nil
}

// dbTestConfig 构造只填 DB 段的自造 *config.Config（§3.2 约定 1 / §20：
// 测试传自造实例；Open 只读 DB 段）。driver 由测试库 env 解析结果注入，
// 同一用例集在两种方言下复用。
func dbTestConfig(driver config.Driver, dsn string, maxOpen, maxIdle int, lifetime time.Duration) *config.Config {
	return &config.Config{
		DB: config.DBConfig{
			Driver:          driver,
			DSN:             dsn,
			MaxOpenConns:    maxOpen,
			MaxIdleConns:    maxIdle,
			ConnMaxLifetime: config.Duration{Duration: lifetime},
		},
	}
}

// repoTestDB 为单个用例准备方言就绪的测试库并返回 bun 连接：测试库 env
// 未设置时 skip（本地无 DB / CI 未配 service 的常态），开始前清空全部表
// （用例间隔离）并按方言建正式表结构，结束后清空并自证零残留（清理
// 注册先于本函数返回，bun 连接经 repoTestBun 关闭后再执行）。方言与
// DSN 由测试库 env 解析，两种方言下同一用例集复用。
func repoTestDB(t *testing.T) *bun.DB {
	t.Helper()
	target, err := resolveTestDBEnv()
	if err != nil {
		t.Fatalf("测试环境变量错误: %v", err)
	}
	if target == nil {
		t.Skipf("测试库 env 未设置（%s+%s，或兼容 %s），跳过 repo 集成用例", envTestDBDriver, envTestDBDSN, envMySQLDSNLegacy)
	}
	raw, err := migrate.NewDB(target.driver, target.dsn)
	if err != nil {
		t.Fatalf("打开连接失败: %v", err)
	}
	if err := raw.Ping(); err != nil {
		t.Fatalf("连接测试实例失败（driver=%s）: %v", target.driver, err)
	}
	if err := dropAllTables(raw, target.driver); err != nil {
		t.Fatalf("用例开始清空测试库失败: %v", err)
	}
	if err := migrateTestSchema(context.Background(), target.driver, target.dsn); err != nil {
		t.Fatalf("migrate up 失败: %v", err)
	}
	t.Cleanup(func() {
		if err := dropAllTables(raw, target.driver); err != nil {
			t.Errorf("用例结束清理测试库失败: %v", err)
		}
		if err := assertNoTables(raw, target.driver); err != nil {
			t.Errorf("清理自证失败: %v", err)
		}
		_ = raw.Close()
	})
	return repoTestBun(t, target.driver, target.dsn)
}

// migrateTestSchema 建正式表结构（§3.16 DDL 唯一来源，绝不用 AutoMigrate）：
// mysql 走生产入口 migrate.Up（内部为工厂建连 + ping + goose up）；pg 的
// 生产 driver 贯通归后续工作，测试侧经同一统一连接工厂 + goose Provider
// 直连执行（方言目录由 migrations.DialectFS 按 driver 配对选择）。
func migrateTestSchema(ctx context.Context, driver config.Driver, dsn string) error {
	if driver == config.DriverMySQL {
		return migrate.Up(ctx, dsn)
	}
	db, err := migrate.NewDB(driver, dsn)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	fsys, err := migrations.DialectFS(string(driver))
	if err != nil {
		return fmt.Errorf("select migrations: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, fsys)
	if err != nil {
		return fmt.Errorf("new provider: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// repoTestBun 经 repo.Open 建方言就绪的 bun 连接（连接池参数为 repo 集成
// 用例统一口径 10/5/1m），随 t.Cleanup 关闭。
func repoTestBun(t *testing.T, driver config.Driver, dsn string) *bun.DB {
	t.Helper()
	db, err := Open(dbTestConfig(driver, dsn, 10, 5, time.Minute))
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
