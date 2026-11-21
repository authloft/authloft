// 分区维护任务测试：单元用例（fake 注入，锁 / 参数 / 生命周期语义）与
// 集成用例（env 门控实跑：真实 MySQL 自建分区表 + 真实 Redis 固定键，跑通
// 一轮真实维护与锁竞争路径）。外部测试包：需引用 settings 键常量构造
// TaskOptions（settings 依赖 repo，本包不可反向 import，测试包无此约束）。
package partition_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/mysqldialect"

	"authloft/internal/cache"
	"authloft/internal/config"
	"authloft/internal/migrate"
	"authloft/internal/partition"
	"authloft/internal/settings"
)

// ---------- 单元测试 fake ----------

// fakeManager PartitionManager fake：记录调用与实参，可注入错误。
type fakeManager struct {
	mu          sync.Mutex
	ensureCalls int
	dropCalls   int
	ensureDays  int
	dropMax     int
	ensureErr   error
	dropErr     error
}

func (f *fakeManager) EnsurePartition(_ context.Context, _ time.Time, intervalDays int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensureCalls++
	f.ensureDays = intervalDays
	return f.ensureErr
}

func (f *fakeManager) DropExcess(_ context.Context, maxPartitions int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropCalls++
	f.dropMax = maxPartitions
	return f.dropErr
}

func (f *fakeManager) ListPartitions(context.Context) ([]partition.Partition, error) {
	return nil, nil
}

// state 返回并发安全的调用计数副本。
func (f *fakeManager) state() (ensureCalls, dropCalls, ensureDays, dropMax int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ensureCalls, f.dropCalls, f.ensureDays, f.dropMax
}

// fakeParams map 兜底的参数读取 fake（键缺失 = GetInt64 ok=false）。
type fakeParams map[string]int64

func (f fakeParams) GetInt64(key string) (int64, bool) {
	v, ok := f[key]
	return v, ok
}

// fakeLocker 抢锁 fake：固定应答并记录实参。
type fakeLocker struct {
	mu    sync.Mutex
	ok    bool
	err   error
	calls int
	key   string
	ttl   time.Duration
}

func (f *fakeLocker) SetNX(_ context.Context, key string, _ any, ttl time.Duration) cache.BoolResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.key, f.ttl = key, ttl
	return cache.NewBoolResult(f.ok, f.err)
}

func (f *fakeLocker) state() (calls int, key string, ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.key, f.ttl
}

// waitFor 轮询等待条件成立（异步轮次的确定性观测窗口）。
func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal(msg)
}

const pDaysKey = "eventlog_partition_days"
const pMaxKey = "eventlog_max_partitions"

// TestTaskStartRunsImmediateRound Start 即跑首轮：锁成功 → 一轮维护（两键
// 实参透传）→ 默认锁键与 TTL。
func TestTaskStartRunsImmediateRound(t *testing.T) {
	mgr := &fakeManager{}
	locker := &fakeLocker{ok: true}
	task := partition.NewTask(mgr, fakeParams{pDaysKey: 7, pMaxKey: 26}, locker,
		partition.TaskOptions{DaysKey: pDaysKey, MaxKey: pMaxKey, Interval: time.Hour})
	defer task.Close()

	if err := task.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		ensureCalls, dropCalls, _, _ := mgr.state()
		return ensureCalls == 1 && dropCalls == 1
	}, "Start 后首轮未立即执行")

	ensureCalls, dropCalls, ensureDays, dropMax := mgr.state()
	if ensureCalls != 1 || dropCalls != 1 {
		t.Fatalf("首轮调用次数 = (ensure %d, drop %d), want (1, 1)", ensureCalls, dropCalls)
	}
	if ensureDays != 7 || dropMax != 26 {
		t.Fatalf("首轮实参 = (%d, %d), want (7, 26)", ensureDays, dropMax)
	}
	calls, key, ttl := locker.state()
	if calls != 1 {
		t.Fatalf("抢锁次数 = %d, want 1", calls)
	}
	if key != cache.PartitionLockKey() {
		t.Fatalf("锁键 = %q, want %q", key, cache.PartitionLockKey())
	}
	if ttl != 10*time.Minute {
		t.Fatalf("锁 TTL = %v, want 10m", ttl)
	}
}

// TestTaskLockBusyOrErrorSkipsRound 未抢到锁 / 抢锁报错：跳过本轮不动
// Manager，不向任务生命周期外抛错。
func TestTaskLockBusyOrErrorSkipsRound(t *testing.T) {
	t.Run("锁被占用", func(t *testing.T) {
		mgr := &fakeManager{}
		locker := &fakeLocker{ok: false}
		task := partition.NewTask(mgr, fakeParams{}, locker,
			partition.TaskOptions{DaysKey: pDaysKey, MaxKey: pMaxKey, Interval: time.Hour})
		defer task.Close()

		if err := task.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		waitFor(t, 2*time.Second, func() bool {
			calls, _, _ := locker.state()
			return calls == 1
		}, "抢锁未发生")
		task.Close() // 等 loop 退出后再断言：此后不可能再有轮次
		ensureCalls, dropCalls, _, _ := mgr.state()
		if ensureCalls != 0 || dropCalls != 0 {
			t.Fatalf("锁被占用仍执行了维护: ensure=%d drop=%d", ensureCalls, dropCalls)
		}
	})

	t.Run("抢锁报错", func(t *testing.T) {
		mgr := &fakeManager{}
		locker := &fakeLocker{err: errors.New("redis down")}
		task := partition.NewTask(mgr, fakeParams{}, locker,
			partition.TaskOptions{DaysKey: pDaysKey, MaxKey: pMaxKey, Interval: time.Hour})
		defer task.Close()

		if err := task.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		waitFor(t, 2*time.Second, func() bool {
			calls, _, _ := locker.state()
			return calls == 1
		}, "抢锁未发生")
		task.Close()
		ensureCalls, dropCalls, _, _ := mgr.state()
		if ensureCalls != 0 || dropCalls != 0 {
			t.Fatalf("抢锁报错仍执行了维护: ensure=%d drop=%d", ensureCalls, dropCalls)
		}
	})
}

// TestTaskClampParams 参数读取侧钳制兜底：越界（含非正数）/ 缺键回落默认
// 7/26，范围内值原样透传。
func TestTaskClampParams(t *testing.T) {
	cases := []struct {
		name     string
		params   fakeParams
		wantDays int
		wantMax  int
	}{
		{"非正数与超上限回落默认", fakeParams{pDaysKey: 0, pMaxKey: 400}, 7, 26},
		{"负数与超上限回落默认", fakeParams{pDaysKey: -5, pMaxKey: 366}, 7, 26},
		{"缺键回落默认", fakeParams{}, 7, 26},
		{"范围内原样透传", fakeParams{pDaysKey: 30, pMaxKey: 10}, 30, 10},
		{"边界值透传", fakeParams{pDaysKey: 1, pMaxKey: 365}, 1, 365},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mgr := &fakeManager{}
			task := partition.NewTask(mgr, c.params, &fakeLocker{ok: true},
				partition.TaskOptions{DaysKey: pDaysKey, MaxKey: pMaxKey, Interval: time.Hour})
			defer task.Close()

			if err := task.Start(context.Background()); err != nil {
				t.Fatalf("Start: %v", err)
			}
			waitFor(t, 2*time.Second, func() bool {
				ensureCalls, dropCalls, _, _ := mgr.state()
				return ensureCalls == 1 && dropCalls == 1
			}, "首轮未执行")
			_, _, ensureDays, dropMax := mgr.state()
			if ensureDays != c.wantDays || dropMax != c.wantMax {
				t.Fatalf("钳制结果 = (%d, %d), want (%d, %d)", ensureDays, dropMax, c.wantDays, c.wantMax)
			}
		})
	}
}

// TestTaskTickerPeriodicRounds Ticker 周期触发：首轮后按间隔持续轮转，
// Close 后不再新增轮次。
func TestTaskTickerPeriodicRounds(t *testing.T) {
	mgr := &fakeManager{}
	task := partition.NewTask(mgr, fakeParams{}, &fakeLocker{ok: true},
		partition.TaskOptions{DaysKey: pDaysKey, MaxKey: pMaxKey, Interval: 25 * time.Millisecond})
	defer task.Close()

	if err := task.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		ensureCalls, _, _, _ := mgr.state()
		return ensureCalls >= 3
	}, "Ticker 未周期触发")
	task.Close()

	ensureCalls, _, _, _ := mgr.state()
	time.Sleep(120 * time.Millisecond)
	ensureCalls2, _, _, _ := mgr.state()
	if ensureCalls2 != ensureCalls {
		t.Fatalf("Close 后轮次继续增长: %d -> %d", ensureCalls, ensureCalls2)
	}
}

// TestTaskRoundErrorsKeepRunning 轮内错误只记日志：Ensure / Drop 报错不中断
// 任务生命周期，后续轮次照常触发。
func TestTaskRoundErrorsKeepRunning(t *testing.T) {
	mgr := &fakeManager{ensureErr: errors.New("ddl failed"), dropErr: errors.New("ddl failed")}
	task := partition.NewTask(mgr, fakeParams{}, &fakeLocker{ok: true},
		partition.TaskOptions{DaysKey: pDaysKey, MaxKey: pMaxKey, Interval: 25 * time.Millisecond})
	defer task.Close()

	if err := task.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool {
		ensureCalls, _, _, _ := mgr.state()
		return ensureCalls >= 3
	}, "错误后任务未继续轮转")
}

// TestTaskCloseLifecycle Close 幂等且 Start 前调用安全。
func TestTaskCloseLifecycle(t *testing.T) {
	mgr := &fakeManager{}
	task := partition.NewTask(mgr, fakeParams{}, &fakeLocker{ok: true},
		partition.TaskOptions{DaysKey: pDaysKey, MaxKey: pMaxKey, Interval: time.Hour})

	task.Close() // Start 前：no-op，不得挂死
	if err := task.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	task.Close()
	task.Close() // 重复调用安全
}

// ---------- 集成测试（env 门控实跑） ----------

// 测试库 env 解析 + testlock 互斥槽：mysql/manager_test.go 同口径的 mysql 侧
// 副本（测试文件不可跨包 import）。仅 mysql 参与——PG 侧由 partitionpostgres
// 自身集成用例承接，激活方言非 mysql 时本包用例 skip。
const (
	envTestDBDriver   = "UC_TEST_DB_DRIVER"
	envTestDBDSN      = "UC_TEST_DB_DSN"
	envMySQLDSNLegacy = "UC_TEST_MYSQL_DSN"
	envTestRedisAddr  = "UC_TEST_REDIS_ADDR"
	testDBLockName    = "uc_test_db_slot"
	testLockWait      = 300 * time.Second
)

// testTableName 自建分区测试表（与 mysql / postgres 包的测试表名互异，跑前
// 跑后自清理，不碰正式表）。
const testTableName = "al_partition_task_test"

// resolveTestDBEnv 返回 mysql 测试连接串；未设置 / 激活方言非 mysql 返回空
// 串（用例 skip），env 配置非法返回错误。
func resolveTestDBEnv() (string, error) {
	driverName := os.Getenv(envTestDBDriver)
	dsn := os.Getenv(envTestDBDSN)
	if driverName == "" && dsn == "" {
		return os.Getenv(envMySQLDSNLegacy), nil
	}
	if driverName == "" || dsn == "" {
		return "", fmt.Errorf("%s 与 %s 必须成对设置（现 driver=%q dsn=%q）",
			envTestDBDriver, envTestDBDSN, driverName, dsn)
	}
	if config.Driver(driverName) != config.DriverMySQL {
		return "", nil
	}
	return dsn, nil
}

// TestMain 跨二进制互斥（拿不到锁放行兜底，宁可试跑不挂死）：本包用例
// 自建自清专属命名表，不做全库等待与清理。
func TestMain(m *testing.M) {
	dsn, err := resolveTestDBEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "authloft 测试环境变量错误: "+err.Error())
		os.Exit(1)
	}
	var db *sql.DB
	if dsn != "" {
		db = acquireTestSlot(dsn)
	}
	code := m.Run()
	if db != nil {
		releaseTestSlot(db)
	}
	os.Exit(code)
}

func acquireTestSlot(dsn string) *sql.DB {
	db, err := migrate.NewDB(config.DriverMySQL, dsn)
	if err != nil {
		return nil
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var ok bool
	if err := db.QueryRow("SELECT GET_LOCK(?, ?)", testDBLockName, int(testLockWait.Seconds())).Scan(&ok); err != nil {
		ok = false
	}
	if !ok {
		_ = db.Close()
		return nil
	}
	return db
}

func releaseTestSlot(db *sql.DB) {
	_ = db.Close()
	fmt.Fprintf(os.Stderr, "authloft test: test db slot released (lock=%s driver=mysql)\n", testDBLockName)
}

func requireTestDB(t *testing.T) string {
	t.Helper()
	dsn, err := resolveTestDBEnv()
	if err != nil {
		t.Fatalf("测试环境变量错误: %v", err)
	}
	if dsn == "" {
		t.Skipf("测试库 env 未设置或激活方言非 mysql（%s/%s），跳过集成用例", envTestDBDriver, envTestDBDSN)
	}
	return dsn
}

// requireTestRedis 真连测试实例（cache 包 redis_test.go 同口径副本）。
func requireTestRedis(t *testing.T) *cache.RedisClient {
	t.Helper()
	addr := os.Getenv(envTestRedisAddr)
	if addr == "" {
		t.Skipf("环境变量 %s 未设置，跳过 Redis 连接用例", envTestRedisAddr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rdb, err := cache.NewClient(ctx, &config.Config{
		Redis: config.RedisConfig{Addr: addr, DB: 0, PoolSize: 10},
	})
	if err != nil {
		t.Fatalf("Redis 真连失败: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// ddlManager 集成夹具：真实 MySQL 上的 PartitionManager——枚举走
// information_schema、决策复用本包 PlanCreate / PlanDrop 纯算法、DDL 直译
// （REORGANIZE 切分 pmax 兜底 / DROP 淘汰）。指向自建测试表，与生产
// event_log 表无关。
type ddlManager struct {
	db    *bun.DB
	table string
}

func (m *ddlManager) ListPartitions(ctx context.Context) ([]partition.Partition, error) {
	rows, err := m.db.QueryContext(ctx, `
SELECT PARTITION_NAME
FROM information_schema.partitions
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = ?
  AND PARTITION_NAME IS NOT NULL
ORDER BY PARTITION_ORDINAL_POSITION`, m.table)
	if err != nil {
		return nil, fmt.Errorf("partition task test: list: %w", err)
	}
	defer rows.Close()
	var out []partition.Partition
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("partition task test: scan: %w", err)
		}
		upper, ok := partition.ParseName(name)
		if !ok {
			continue // 兜底 pmax / 非实体命名不进决策
		}
		out = append(out, partition.Partition{Name: name, Upper: upper})
	}
	return out, rows.Err()
}

func (m *ddlManager) EnsurePartition(ctx context.Context, today time.Time, intervalDays int) error {
	parts, err := m.ListPartitions(ctx)
	if err != nil {
		return err
	}
	plan, _, cut := partition.PlanCreate(parts, today, intervalDays)
	if !cut {
		return nil
	}
	_, err = m.db.ExecContext(ctx, fmt.Sprintf(
		"ALTER TABLE %s REORGANIZE PARTITION pmax INTO (PARTITION %s VALUES LESS THAN (TO_DAYS('%s')), PARTITION pmax VALUES LESS THAN MAXVALUE)",
		m.table, plan.Name, plan.Upper.Format("2006-01-02")))
	return err
}

func (m *ddlManager) DropExcess(ctx context.Context, maxPartitions int) error {
	parts, err := m.ListPartitions(ctx)
	if err != nil {
		return err
	}
	for _, name := range partition.PlanDrop(parts, maxPartitions) {
		if _, err := m.db.ExecContext(ctx,
			fmt.Sprintf("ALTER TABLE %s DROP PARTITION %s", m.table, name)); err != nil {
			return err
		}
	}
	return nil
}

// newTestTable 建仅含 pmax 兜底的最小分区表，跑前清残留、跑后删除。
func newTestTable(t *testing.T, dsn string) *bun.DB {
	t.Helper()
	raw, err := migrate.NewDB(config.DriverMySQL, dsn)
	if err != nil {
		t.Fatalf("打开测试连接失败: %v", err)
	}
	bunDB := bun.NewDB(raw, mysqldialect.New())
	t.Cleanup(func() { _ = bunDB.Close() })

	if _, err := bunDB.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", testTableName)); err != nil {
		t.Fatalf("清理测试表失败: %v", err)
	}
	t.Cleanup(func() {
		if _, err := bunDB.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", testTableName)); err != nil {
			t.Errorf("测试表清理失败: %v", err)
		}
	})
	ddl := fmt.Sprintf(`CREATE TABLE %s (
  id BIGINT NOT NULL AUTO_INCREMENT,
  event VARCHAR(48) NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
PARTITION BY RANGE (TO_DAYS(created_at))
(PARTITION pmax VALUES LESS THAN MAXVALUE)`, testTableName)
	if _, err := bunDB.Exec(ddl); err != nil {
		t.Fatalf("建分区测试表失败: %v", err)
	}
	return bunDB
}

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

func mustListNames(t *testing.T, mgr *ddlManager) []string {
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

// TestTaskRealRound env 门控实跑：锁被占用时轮次全部跳过（不动表结构、任务
// 生命周期不受影响）；释放后一轮真实维护切出 today+7 上界的实体分区、兜底
// 保留；后续轮次幂等——已建范围覆盖得住今天则不再切区、余量未超不淘汰。
func TestTaskRealRound(t *testing.T) {
	dsn := requireTestDB(t)
	rdb := requireTestRedis(t)
	ctx := context.Background()

	mgr := &ddlManager{db: newTestTable(t, dsn), table: testTableName}

	lockKey := cache.PartitionLockKey()
	clearLock := func() {
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := rdb.Del(cctx, lockKey).Result(); err != nil {
			t.Fatalf("清理锁键失败: %v", err)
		}
	}
	clearLock()
	t.Cleanup(clearLock)

	// 默认快照（未 Preload 即种子默认值 7/26）：验证生产装配的 Store 直接
	// 满足参数读取通道、默认值流经真实轮次。
	store := settings.NewStore(nil, nil)
	opts := partition.TaskOptions{
		DaysKey:  settings.KeyEventlogPartitionDays,
		MaxKey:   settings.KeyEventlogMaxPartitions,
		Interval: 50 * time.Millisecond,
	}

	// 1) 锁被占用：多轮尝试全部跳过，实体分区保持为空（防并发 DDL 生效）。
	if ok, err := rdb.SetNX(ctx, lockKey, "test-holder", time.Minute).Result(); err != nil || !ok {
		t.Fatalf("预占锁失败: ok=%v err=%v", ok, err)
	}
	held := partition.NewTask(mgr, store, rdb, opts)
	if err := held.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(300 * time.Millisecond) // 50ms 间隔下约 6 轮尝试
	held.Close()
	if names := mustListNames(t, mgr); len(names) != 0 {
		t.Fatalf("锁被占用期间实体分区 = %v, want 空（未抢到锁不得动表）", names)
	}
	if !fallbackPresent(t, mgr.db) {
		t.Fatal("兜底分区 pmax 必须仍然存在")
	}
	clearLock()

	// 2) 释放锁：一轮真实维护切出预期分区（默认 7 天间隔 → today+7 上界）。
	wantPart := partition.NameForDate(time.Now().AddDate(0, 0, 7))
	free := partition.NewTask(mgr, store, rdb, opts)
	defer free.Close()
	if err := free.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool {
		return len(mustListNames(t, mgr)) == 1
	}, "一轮真实维护未切出实体分区")
	names := mustListNames(t, mgr)
	if names[0] != wantPart {
		t.Fatalf("实体分区 = %v, want [%s]", names, wantPart)
	}
	if !fallbackPresent(t, mgr.db) {
		t.Fatal("兜底分区 pmax 必须仍然存在")
	}

	// 3) 后续周期轮次：首轮抢到的锁 TTL 内未过期、轮询间隔又远小于 TTL，
	// 后续轮全部锁跳过、表结构保持首轮结果；决策幂等（已建范围覆盖得住
	// 今天不再切区、余量未超不淘汰）由 policy_test 与 mysql 包 EnsurePartition
	// 用例承接。
	time.Sleep(250 * time.Millisecond)
	if names := mustListNames(t, mgr); len(names) != 1 || names[0] != wantPart {
		t.Fatalf("后续轮次实体分区 = %v, want [%s]（幂等不再切区）", names, wantPart)
	}
}
