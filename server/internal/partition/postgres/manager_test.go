package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	"authloft/internal/config"
	"authloft/internal/migrate"
	"authloft/internal/partition"
)

// 测试库 env 解析 + testlock 互斥槽：repo 包 testsupport_test.go 的同口径副本
// （测试文件不可跨包 import，机制改动须与 repo / migrate / settings / setup /
// main 的副本同步）。UC_TEST_DB_DRIVER + UC_TEST_DB_DSN 成对显式指定方言与
// 连接串；仅设 UC_TEST_MYSQL_DSN 兼容读为 mysql + 其值（此时本包用例按矩阵
// 口径 skip，PG 唯一实跑场是 CI）。
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
// id 用裸 BIGINT 由用例显式赋值：PG 14 及以前分区父表不支持 IDENTITY 列，
// 与 CI 矩阵的 postgres:14 对齐。
const testTableName = "al_partition_event_log_test"

func mustDate(s string) time.Time {
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return d
}

// newTestManager 建方言就绪的 bun 连接 + 自建分区表（default 兜底 +
// upperBounds 对应的实体分区），返回指向测试表的 Manager。
func newTestManager(t *testing.T, upperBounds ...string) *Manager {
	t.Helper()
	target := requireTestDB(t, config.DriverPostgres)
	raw, err := migrate.NewDB(config.DriverPostgres, target.dsn)
	if err != nil {
		t.Fatalf("打开测试连接失败: %v", err)
	}
	bunDB := bun.NewDB(raw, pgdialect.New())
	t.Cleanup(func() { _ = bunDB.Close() })
	dropTestTable(t, bunDB)
	createTestTable(t, bunDB, upperBounds)
	return &Manager{db: bunDB, table: testTableName}
}

// dropTestTable 跑前清残留（父表级联挂载的子分区），并注册跑后清理；额外
// 防御性删本包用例会用到的独立分区表名（ATTACH 半途失败可能残留）。
func dropTestTable(t *testing.T, db *bun.DB) {
	t.Helper()
	drop := func() {
		if _, err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE", testTableName)); err != nil {
			t.Errorf("清理测试表失败: %v", err)
		}
		for _, name := range []string{"p20261101", "p20261108", "p20261115", "p20261122", "p20261127", "p20261129", "p20261204"} {
			if _, err := db.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s CASCADE", bun.Ident(name))); err != nil {
				t.Errorf("清理残留分区表 %s 失败: %v", name, err)
			}
		}
	}
	drop()
	t.Cleanup(drop)
}

// createTestTable 建最小分区结构：父表 RANGE(created_at) + default 兜底 +
// 实体分区（首个自 MINVALUE 起，其余首尾相接）。实体分区表名与生产 Manager
// 产出一致（顶层 pYYYYMMDD）。
func createTestTable(t *testing.T, db *bun.DB, upperBounds []string) {
	t.Helper()
	ddl := fmt.Sprintf(`CREATE TABLE %s (
  id BIGINT NOT NULL,
  event VARCHAR(48) NOT NULL,
  created_at TIMESTAMP NOT NULL,
  PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at)`, testTableName)
	if _, err := db.Exec(ddl); err != nil {
		t.Fatalf("建分区父表失败: %v", err)
	}
	if _, err := db.Exec(fmt.Sprintf(
		"CREATE TABLE %s PARTITION OF %s DEFAULT", testTableName+"_default", testTableName)); err != nil {
		t.Fatalf("建 default 兜底分区失败: %v", err)
	}
	prev := "MINVALUE"
	for _, bound := range upperBounds {
		name := "p" + bound[:4] + bound[5:7] + bound[8:10]
		if _, err := db.Exec(fmt.Sprintf(
			"CREATE TABLE %s PARTITION OF %s FOR VALUES FROM (%s) TO ('%s')",
			bun.Ident(name), bun.Ident(testTableName), prev, bound)); err != nil {
			t.Fatalf("建实体分区 %s 失败: %v", name, err)
		}
		prev = "'" + bound + "'"
	}
}

// insertRows 按字面量写行（TIMESTAMP 用字符串字面量，无时区换算歧义），
// created_at 形如 "2026-11-20 10:00:00"，id 由本函数顺序分配。
func insertRows(t *testing.T, db *bun.DB, createdAts ...string) {
	t.Helper()
	for i, at := range createdAts {
		if _, err := db.Exec(
			fmt.Sprintf("INSERT INTO %s (id, event, created_at) VALUES (?, 'e', ?)", testTableName),
			i+1, at,
		); err != nil {
			t.Fatalf("写测试行失败 (%s): %v", at, err)
		}
	}
}

// childCount 挂载后分区（顶层同名表）内的行数。
func childCount(t *testing.T, db *bun.DB, partName string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", bun.Ident(partName))).Scan(&n); err != nil {
		t.Fatalf("查分区 %s 行数失败: %v", partName, err)
	}
	return n
}

// fallbackPresent default 兜底分区是否仍在。
func fallbackPresent(t *testing.T, db *bun.DB) bool {
	t.Helper()
	var present bool
	if err := db.QueryRow(
		"SELECT to_regclass(?) IS NOT NULL", testTableName+"_default",
	).Scan(&present); err != nil {
		t.Fatalf("查兜底分区失败: %v", err)
	}
	return present
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
	mgr := newTestManager(t)
	if got := listNames(t, mgr); len(got) != 0 {
		t.Fatalf("仅兜底时实体分区应为空, got %v", got)
	}

	// 重建为多分区结构：default 与非 pYYYYMMDD 命名（pevents）都不进枚举，
	// 实体分区按上界日期升序。
	raw := mgr.db
	dropTestTable(t, raw)
	createTestTable(t, raw, []string{"2026-11-01", "2026-11-08", "2026-11-15"})
	if _, err := raw.Exec(fmt.Sprintf(
		"CREATE TABLE pevents PARTITION OF %s FOR VALUES FROM ('2026-11-15') TO ('2026-11-16')", testTableName)); err != nil {
		t.Fatalf("建非规范命名分区失败: %v", err)
	}
	assertNames(t, mgr, "p20261101", "p20261108", "p20261115")
}

func TestEnsurePartitionMovesDefaultRowsAndAttaches(t *testing.T) {
	// 三步搬移 + ATTACH（《后端架构》§4.6）：尚无实体分区时
	// 新分区自 MINVALUE 起，兜底里归属新范围的行搬进分区且数据不丢（id 保
	// 留），范围外的行留在兜底。
	mgr := newTestManager(t)
	insertRows(t, mgr.db, "2026-11-20 10:00:00", "2030-01-01 00:00:00")

	ctx := context.Background()
	if err := mgr.EnsurePartition(ctx, mustDate("2026-11-20"), 7); err != nil {
		t.Fatalf("EnsurePartition: %v", err)
	}
	assertNames(t, mgr, "p20261127")
	if got := childCount(t, mgr.db, "p20261127"); got != 1 {
		t.Errorf("新分区行数 = %d, want 1（兜底积压行应被搬移）", got)
	}
	if got := childCount(t, mgr.db, mgr.fallbackName()); got != 1 {
		t.Errorf("兜底行数 = %d, want 1（范围外行应留在兜底）", got)
	}
	var id int64
	if err := mgr.db.QueryRow(fmt.Sprintf("SELECT id FROM %s", bun.Ident("p20261127"))).Scan(&id); err != nil {
		t.Fatalf("读搬移行失败: %v", err)
	}
	if id != 1 {
		t.Errorf("搬移行 id = %d, want 1（数据不丢）", id)
	}
	if !fallbackPresent(t, mgr.db) {
		t.Fatal("挂载后兜底分区必须仍然存在")
	}
}

func TestEnsurePartitionStartsAtLastUpper(t *testing.T) {
	// 有既有实体分区时新分区自最大上界起、跨度大于间隔天数，兜底积压一次
	// 性分流（§2 的 today >= U 场景）。
	mgr := newTestManager(t, "2026-11-01", "2026-11-08", "2026-11-15")
	insertRows(t, mgr.db, "2026-11-21 12:00:00")

	ctx := context.Background()
	if err := mgr.EnsurePartition(ctx, mustDate("2026-11-20"), 7); err != nil {
		t.Fatalf("EnsurePartition: %v", err)
	}
	assertNames(t, mgr, "p20261101", "p20261108", "p20261115", "p20261127")
	if got := childCount(t, mgr.db, "p20261127"); got != 1 {
		t.Errorf("新分区行数 = %d, want 1", got)
	}
	if got := childCount(t, mgr.db, mgr.fallbackName()); got != 0 {
		t.Errorf("兜底行数 = %d, want 0（归属新范围的行应搬空）", got)
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
		t.Fatal("兜底分区必须仍然存在")
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
		if got := childCount(t, mgr.db, mgr.fallbackName()); got != 1 {
			t.Errorf("兜底行数 = %d, want 1", got)
		}
		if !fallbackPresent(t, mgr.db) {
			t.Fatal("淘汰后兜底分区必须仍然存在（永不 DROP）")
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
			t.Fatal("兜底分区必须仍然存在")
		}
	})
}

// 编译期确认 Manager 实现接口。
var _ partition.PartitionManager = (*Manager)(nil)
