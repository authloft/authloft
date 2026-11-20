package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/mysqldialect"

	"authloft/internal/config"
	"authloft/internal/migrate"
	"authloft/internal/partition"
)

// 测试库 env 解析 + testlock 互斥槽：repo 包 testsupport_test.go 的同口径副本
// （测试文件不可跨包 import，机制改动须与 repo / migrate / settings / setup /
// main 的副本同步）。UC_TEST_DB_DRIVER + UC_TEST_DB_DSN 成对显式指定方言与
// 连接串；仅设 UC_TEST_MYSQL_DSN 兼容读为 mysql + 其值。
const (
	envTestDBDriver   = "UC_TEST_DB_DRIVER"
	envTestDBDSN      = "UC_TEST_DB_DSN"
	envMySQLDSNLegacy = "UC_TEST_MYSQL_DSN"
	testDBLockName    = "uc_test_db_slot"
	testLockWait      = 300 * time.Second
)

// testDBLockKeyPG PG advisory 键：testDBLockName 的 FNV-1a 64 位散列按 int64
// 补码截断（与 repo / migrate 等副本同一常量，勿单独改值）。
const testDBLockKeyPG = -2607616838611919394

type testDBTarget struct {
	driver config.Driver
	dsn    string
}

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

// TestMain 跨二进制互斥：拿不到锁放行兜底（宁可试跑不挂死），与 repo 等包
// 副本同口径。本包用例自建自清专属命名表，不做全库等待与清理。
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
		if err := db.QueryRow("SELECT GET_LOCK(?, ?)", testDBLockName, int(testLockWait.Seconds())).Scan(&ok); err != nil {
			ok = false
		}
	}
	if !ok {
		_ = db.Close()
		return nil
	}
	return db
}

func pgAcquireAdvisoryLock(db *sql.DB) bool {
	if _, err := db.Exec("BEGIN"); err != nil {
		return false
	}
	if _, err := db.Exec(fmt.Sprintf("SET LOCAL statement_timeout = '%ds'", int(testLockWait.Seconds()))); err != nil {
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

func releaseTestSlot(target *testDBTarget, db *sql.DB) {
	if target.driver == config.DriverPostgres {
		_, _ = db.Exec("SELECT pg_advisory_unlock($1)", testDBLockKeyPG)
	}
	_ = db.Close()
	fmt.Fprintf(os.Stderr, "authloft test: test db slot released (lock=%s driver=%s)\n", testDBLockName, target.driver)
}

// testTableName 自建分区测试表：event_log 的分区化 DDL 属迁移范围，这里不碰
// 正式表、不走全量迁移，只建本包用例需要的最小分区结构，跑前跑后自清理。
const testTableName = "al_partition_event_log_test"

// mustDate ISO 日期字面量转零点时刻，写错直接 panic 暴露。
func mustDate(s string) time.Time {
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return d
}

// newTestManager 建方言就绪的 bun 连接 + 自建分区表，返回指向测试表的
// Manager；连接与表随 t.Cleanup 关闭 / 删除。
func newTestManager(t *testing.T, upperBounds ...string) *Manager {
	t.Helper()
	target := requireTestDB(t, config.DriverMySQL)
	raw, err := migrate.NewDB(config.DriverMySQL, target.dsn)
	if err != nil {
		t.Fatalf("打开测试连接失败: %v", err)
	}
	bunDB := bun.NewDB(raw, mysqldialect.New())
	t.Cleanup(func() { _ = bunDB.Close() })
	dropTestTable(t, bunDB)
	createTestTable(t, bunDB, upperBounds)
	return &Manager{db: bunDB, table: testTableName}
}

// dropTestTable 跑前清残留，并注册跑后清理（互斥槽保证跨二进制不互相误删）。
func dropTestTable(t *testing.T, db *bun.DB) {
	t.Helper()
	if _, err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", testTableName)); err != nil {
		t.Fatalf("清理测试表失败: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", testTableName)); err != nil {
			t.Errorf("测试表清理失败: %v", err)
		}
	})
}

// createTestTable 建最小分区结构：复合主键含分区键列（分区键必须进主键）、
// 自增首列 + pmax 兜底；upperBounds 非空时先建对应实体分区（升序），extraDefs
// 追加任意分区定义（须仍保持 RANGE 升序，用于非规范命名等场景）。表带
// MAXVALUE 分区后无法 ADD PARTITION，需多分区结构一律走重建。
func createTestTable(t *testing.T, db *bun.DB, upperBounds []string, extraDefs ...string) {
	t.Helper()
	defs := make([]string, 0, len(upperBounds)+1+len(extraDefs))
	for _, bound := range upperBounds {
		defs = append(defs, fmt.Sprintf("PARTITION p%s VALUES LESS THAN (TO_DAYS('%s'))",
			bound[:4]+bound[5:7]+bound[8:10], bound))
	}
	defs = append(defs, extraDefs...)
	defs = append(defs, "PARTITION pmax VALUES LESS THAN MAXVALUE")
	ddl := fmt.Sprintf(`CREATE TABLE %s (
  id BIGINT NOT NULL AUTO_INCREMENT,
  event VARCHAR(48) NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
PARTITION BY RANGE (TO_DAYS(created_at))
(%s)`, testTableName, joinComma(defs))
	if _, err := db.Exec(ddl); err != nil {
		t.Fatalf("建分区测试表失败: %v\nDDL: %s", err, ddl)
	}
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// insertRows 按字面量写行（DATETIME 用字符串字面量，无时区换算歧义），
// created_at 形如 "2026-11-20 10:00:00"。
func insertRows(t *testing.T, db *bun.DB, createdAts ...string) {
	t.Helper()
	for _, at := range createdAts {
		if _, err := db.Exec(
			fmt.Sprintf("INSERT INTO %s (event, created_at) VALUES ('e', ?)", testTableName), at,
		); err != nil {
			t.Fatalf("写测试行失败 (%s): %v", at, err)
		}
	}
}

// countInPartition 指定分区内的行数（PARTITION 选择器直查，绕开优化器裁剪）。
func countInPartition(t *testing.T, db *bun.DB, partName string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s PARTITION (%s)", testTableName, partName)).Scan(&n); err != nil {
		t.Fatalf("查分区 %s 行数失败: %v", partName, err)
	}
	return n
}

// fallbackPresent 兜底分区 pmax 是否仍在。
func fallbackPresent(t *testing.T, db *bun.DB) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`
SELECT COUNT(*)
FROM information_schema.partitions
WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND PARTITION_NAME = 'pmax'`,
		testTableName).Scan(&n); err != nil {
		t.Fatalf("查兜底分区失败: %v", err)
	}
	return n > 0
}

func listNames(t *testing.T, mgr *Manager) []string {
	t.Helper()
	parts, err := mgr.ListPartitions(context.Background())
	if err != nil {
		t.Fatalf("ListPartitions: %v", err)
	}
	names := make([]string, 0, len(parts))
	for _, p := range parts {
		names = append(names, p.Name)
	}
	return names
}

func assertNames(t *testing.T, mgr *Manager, want ...string) {
	t.Helper()
	got := listNames(t, mgr)
	if len(got) != len(want) {
		t.Fatalf("实体分区 = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("实体分区 = %v, want %v", got, want)
		}
	}
}

func TestListPartitions(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t)
	parts, err := mgr.ListPartitions(ctx)
	if err != nil {
		t.Fatalf("ListPartitions: %v", err)
	}
	if len(parts) != 0 {
		t.Fatalf("仅兜底时实体分区应为空, got %v", parts)
	}

	// 重建为多分区结构：pmax 与非 pYYYYMMDD 命名（pextra）都不进枚举，
	// 实体分区按上界日期升序。
	raw := mgr.db
	dropTestTable(t, raw)
	createTestTable(t, raw, []string{"2026-11-01", "2026-11-08", "2026-11-15"},
		"PARTITION pextra VALUES LESS THAN (TO_DAYS('2026-11-16'))")
	assertNames(t, mgr, "p20261101", "p20261108", "p20261115")
}

func TestEnsurePartitionCutsAndDiverts(t *testing.T) {
	// REORGANIZE 分流（《后端架构》§4.6）：切分前落在 pmax
	// 的当前范围行由数据库自动搬进新分区，超出范围的行留在兜底不丢。
	mgr := newTestManager(t)
	insertRows(t, mgr.db, "2026-11-20 10:00:00", "2030-01-01 00:00:00")

	ctx := context.Background()
	if err := mgr.EnsurePartition(ctx, mustDate("2026-11-20"), 7); err != nil {
		t.Fatalf("EnsurePartition: %v", err)
	}
	assertNames(t, mgr, "p20261127")
	if got := countInPartition(t, mgr.db, "p20261127"); got != 1 {
		t.Errorf("新分区行数 = %d, want 1（兜底积压行应被分流）", got)
	}
	if got := countInPartition(t, mgr.db, "pmax"); got != 1 {
		t.Errorf("兜底行数 = %d, want 1（范围外行应留在兜底）", got)
	}
	if !fallbackPresent(t, mgr.db) {
		t.Fatal("REORGANIZE 后兜底分区 pmax 必须仍然存在")
	}
}

func TestEnsurePartitionNoCutWhenCovered(t *testing.T) {
	// 最后一个分区上界还覆盖得住 today：不切、不循环补建。
	mgr := newTestManager(t, "2026-11-01", "2026-11-08", "2026-11-15", "2026-11-22", "2026-11-27")
	ctx := context.Background()
	if err := mgr.EnsurePartition(ctx, mustDate("2026-11-20"), 7); err != nil {
		t.Fatalf("EnsurePartition: %v", err)
	}
	assertNames(t, mgr, "p20261101", "p20261108", "p20261115", "p20261122", "p20261127")
}

func TestEnsurePartitionOnlyCutsOnce(t *testing.T) {
	// today == 上界（数据正落兜底）：切一次，重复调用不再补建。
	mgr := newTestManager(t, "2026-11-01", "2026-11-08", "2026-11-15", "2026-11-22", "2026-11-27")
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := mgr.EnsurePartition(ctx, mustDate("2026-11-27"), 7); err != nil {
			t.Fatalf("EnsurePartition 第 %d 次: %v", i+1, err)
		}
	}
	assertNames(t, mgr, "p20261101", "p20261108", "p20261115", "p20261122", "p20261127", "p20261204")
	if !fallbackPresent(t, mgr.db) {
		t.Fatal("兜底分区 pmax 必须仍然存在")
	}
}

func TestDropExcess(t *testing.T) {
	t.Run("drops oldest keeps quota", func(t *testing.T) {
		mgr := newTestManager(t, "2026-11-01", "2026-11-08", "2026-11-15", "2026-11-22", "2026-11-29")
		insertRows(t, mgr.db, "2026-11-05 00:00:00", "2026-11-10 00:00:00",
			"2026-11-17 00:00:00", "2026-11-25 00:00:00", "2030-01-01 00:00:00")
		ctx := context.Background()
		if err := mgr.DropExcess(ctx, 3); err != nil {
			t.Fatalf("DropExcess: %v", err)
		}
		assertNames(t, mgr, "p20261115", "p20261122", "p20261129")
		// 被淘汰分区（p20261101/p20261108）的行随之删除；存留分区 3 行 +
		// 兜底 1 行原样保留。
		var total int
		if err := mgr.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", testTableName)).Scan(&total); err != nil {
			t.Fatalf("查总行数失败: %v", err)
		}
		if total != 4 {
			t.Errorf("淘汰后总行数 = %d, want 4", total)
		}
		if got := countInPartition(t, mgr.db, "pmax"); got != 1 {
			t.Errorf("兜底行数 = %d, want 1", got)
		}
		if !fallbackPresent(t, mgr.db) {
			t.Fatal("淘汰后兜底分区 pmax 必须仍然存在（永不 DROP）")
		}
	})
	t.Run("quota clamped keeps newest", func(t *testing.T) {
		// X 越界被钳到 1：只保留最新分区，兜底不受影响。
		mgr := newTestManager(t, "2026-11-01", "2026-11-08", "2026-11-15")
		if err := mgr.DropExcess(context.Background(), 0); err != nil {
			t.Fatalf("DropExcess: %v", err)
		}
		assertNames(t, mgr, "p20261115")
		if !fallbackPresent(t, mgr.db) {
			t.Fatal("兜底分区 pmax 必须仍然存在")
		}
	})
}

// 编译期确认 Manager 实现接口。
var _ partition.PartitionManager = (*Manager)(nil)
