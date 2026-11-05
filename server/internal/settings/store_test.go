// settings 包 DB 集成测试：真实 MariaDB 测试实例经
// UC_TEST_MYSQL_DSN env 注入，无 env 时整组 skip（本地只跑 settings_test.go
// 纯逻辑用例）。清理口径沿用既有 DB 测试（migrate_test / setup_db_test /
// bootstrap_test）：用例开始 dropAllTables、migrate.Up 建正式表结构
// （§3.16：DDL 唯一来源，绝不用 AutoMigrate）、结束 drop 全表 +
// assertNoTables 自证零残留（写入的 settings 行随表清除）；但跨二进制
// 错峰不沿用其 waitQuietDB 轮询（双二进制同点起跑会互卡见 TestMain 注释），
// 改用 MySQL GET_LOCK 命名锁串行。连接串只经环境变量注入，代码不含
// 主机 / 凭证信息。
package settings

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"authloft/internal/config"
	"authloft/internal/migrate"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// testDBLockName 测试库互斥锁名（settings 与 repo 两个 DB 测试二进制用
// 同名串行；后续统一 migrate / setup / main 的 DB 测试时应沿用此名）。
const testDBLockName = "uc_test_db_slot"

// TestMain 共享测试库串行化：go test 默认并行启动多个包二进制，多个
// DB 测试二进制同点起跑时，纯轮询式「等库安静」会互相卡死——各自的
// 轮询连接常驻 processlist，而探测 SQL 的 id <> CONNECTION_ID() 只排除
// 自己（既有 waitQuietDB 模式在单二进制/错峰启动下成立，双
// 二进制同点起跑实测双双 90s 超时兜底、同时涌入互删表）。改为 MySQL
// 命名锁：GET_LOCK 持锁贯穿 m.Run()（连接关闭自动释放），同锁名二进制
// 严格串行；持锁连接常驻 processlist，未接入锁的存量二进制
// （migrate / setup / main 的 waitQuietDB 查「无其他连接」）看到即等待。
// 拿不到锁 / 出错时放行兜底，与旧模式语义一致。存量三包彼此间的锁步
// 竞争系既有问题（修复需统一接入本锁，超出本次改动范围）。
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

// acquireTestDB 获取测试库互斥槽：单连接 *sql.DB——GET_LOCK 与安静
// 探测共用同一物理连接（连接一多探测口径就乱）。
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

// waitQuietOnConn 在持锁连接上等库安静：库内无表（有表 = 有未接入锁
// 的存量二进制正在跑用例，等它跑完），连续 quietConfirmations 次、间隔
// quietInterval 才放行；总上限 quietTimeout 防御性兜底（超时放行，宁可
// 试跑不挂死）。不看连接数：兄弟二进制阻塞在 GET_LOCK 的等待连接无表、
// 无害，若计入会互相卡到超时（实测）。
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

// setupTestDB env-skip + 库准备 + 清理：返回 gorm 连接（经 repo.Open，
// 连接池随 t.Cleanup 关闭）。用例开始 drop 全表 → migrate.Up 建正式
// 表结构；结束后 drop 全表 + assertNoTables（零残留自证）。
func setupTestDB(t *testing.T) (*repo.SettingsRepo, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过 settings DB 集成用例")
	}
	raw, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("打开连接失败: %v", err)
	}
	if err := raw.Ping(); err != nil {
		t.Fatalf("连接 MariaDB 测试实例失败: %v", err)
	}
	t.Cleanup(func() {
		_ = raw.Close()
	})
	if err := dropAllTables(raw); err != nil {
		t.Fatalf("用例开始清空测试库失败: %v", err)
	}
	if err := migrate.Up(context.Background(), dsn); err != nil {
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
	db, err := repo.Open(&config.Config{
		DB: config.DBConfig{
			DSN:             dsn,
			MaxOpenConns:    10,
			MaxIdleConns:    5,
			ConnMaxLifetime: config.Duration{Duration: time.Minute},
		},
	})
	if err != nil {
		t.Fatalf("repo.Open 失败: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return repo.NewSettingsRepo(db), raw
}

// settingsRowCount 数 settings 表行数（零残留与补齐断言用）。
func settingsRowCount(t *testing.T, raw *sql.DB) int {
	t.Helper()
	var n int
	if err := raw.QueryRow("SELECT COUNT(*) FROM settings").Scan(&n); err != nil {
		t.Fatalf("count settings: %v", err)
	}
	return n
}

// TestNewStoreSeedsDefaults（纯逻辑）：未预热的 Store 即有全量默认快照，
// 类型化读与副本语义成立（Setup 模式无表即此档，§5.6 行 1275）。
func TestNewStoreSeedsDefaults(t *testing.T) {
	st := NewStore(nil, nil)
	if snap := st.Snapshot(); len(snap) != 35 {
		t.Fatalf("种子快照应 35 键，得 %d", len(snap))
	}
	if v, ok := st.GetInt64(KeyPwdMinLength); !ok || v != 8 {
		t.Errorf("GetInt64(pwd_min_length) = %d, %v；want 8, true", v, ok)
	}
	if v, ok := st.GetString(KeyCookieName); !ok || v != "al_session" {
		t.Errorf("GetString(cookie_name) = %q, %v", v, ok)
	}
	if v, ok := st.GetBool(KeyMfaEnabled); !ok || !v {
		t.Errorf("GetBool(mfa_enabled) = %v, %v", v, ok)
	}
	if v, ok := st.GetStringSlice(KeyLoginMethods); !ok || len(v) != 5 {
		t.Errorf("GetStringSlice(login_methods) = %v, %v", v, ok)
	}
	if _, ok := st.Get("no_such_key"); ok {
		t.Error("未知键 Get 应 false")
	}
	snap := st.Snapshot()
	snap[KeyCookieName] = "hacked"
	if v, _ := st.GetString(KeyCookieName); v != "al_session" {
		t.Error("Snapshot() 应返回副本，外部修改不得影响快照")
	}
	sl, _ := st.GetStringSlice(KeyLoginMethods)
	sl[0] = "mutated"
	if v, _ := st.GetStringSlice(KeyLoginMethods); v[0] != "password" {
		t.Error("GetStringSlice 应返回副本")
	}
}

// TestSetRejectsBeforeDB（纯逻辑）：校验失败在触碰 DB / Redis 之前返回
// （NewStore(nil, nil) 不 panic 即证明）；SetMany 任一键不过整批拒绝，
// 快照保持原值（不产生半截写入，§4.7 行 837）。
func TestSetRejectsBeforeDB(t *testing.T) {
	st := NewStore(nil, nil)
	ctx := context.Background()
	if err := st.Set(ctx, "no_such_key", 1, 0); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("白名单外键应拒绝，err = %v", err)
	}
	if err := st.Set(ctx, KeyPwdMinLength, "8", 0); err == nil {
		t.Fatal("string 值写 int64 键应拒绝")
	}
	err := st.SetMany(ctx, map[string]any{KeyPwdMinLength: int64(10), "no_such_key": 1}, 0)
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("SetMany 含非法键应整批拒绝，err = %v", err)
	}
	if v, _ := st.GetInt64(KeyPwdMinLength); v != 8 {
		t.Errorf("整批拒绝后快照应保持默认 8，得 %d", v)
	}
	if err := st.SetMany(ctx, nil, 0); err != nil {
		t.Errorf("空集应短路 nil，得 %v", err)
	}
}

// TestPreloadBackfillIdempotent（env-skip）：空表预热补齐 35 行默认值
// （updated_by=0）→ 快照与 Defaults 一致；复跑幂等（行数不变、已有自定义
// 值不被默认值冲掉——InsertIgnore 语义）；库中 JSON 损坏行 fail-fast。
func TestPreloadBackfillIdempotent(t *testing.T) {
	rp, raw := setupTestDB(t)
	ctx := context.Background()
	st := NewStore(rp, nil)

	// 空表 → 首次预热补齐全部 35 行。
	if err := st.Preload(ctx); err != nil {
		t.Fatalf("首次 Preload 失败: %v", err)
	}
	if n := settingsRowCount(t, raw); n != 35 {
		t.Fatalf("空表预热后应 35 行，得 %d", n)
	}
	def := Defaults()
	snap := st.Snapshot()
	if len(snap) != 35 {
		t.Fatalf("预热后快照应 35 键，得 %d", len(snap))
	}
	for k, want := range def {
		if got := snap[k]; !equalValue(got, want) {
			t.Errorf("键 %q 预热值 = %#v，默认应 %#v", k, got, want)
		}
	}
	var by int
	if err := raw.QueryRow("SELECT updated_by FROM settings WHERE k = ?", KeyPwdMinLength).Scan(&by); err != nil || by != 0 {
		t.Errorf("补齐行 updated_by 应 0（启动预热），得 %d, err %v", by, err)
	}

	// 已有自定义值的行不被复跑预热冲掉（幂等 + InsertIgnore）。
	if err := rp.UpsertAll(ctx, []model.Setting{settingRow(t, KeyPwdMinLength, "10", 42)}); err != nil {
		t.Fatalf("写入自定义值失败: %v", err)
	}
	if err := st.Preload(ctx); err != nil {
		t.Fatalf("二次 Preload 失败: %v", err)
	}
	if n := settingsRowCount(t, raw); n != 35 {
		t.Errorf("复跑后行数应仍 35，得 %d", n)
	}
	var v string
	if err := raw.QueryRow("SELECT v FROM settings WHERE k = ?", KeyPwdMinLength).Scan(&v); err != nil || v != "10" {
		t.Errorf("自定义值应存活（不被默认值 8 冲掉）：v = %q, err %v", v, err)
	}
	if got, _ := st.GetInt64(KeyPwdMinLength); got != 10 {
		t.Errorf("复跑预热快照应读回自定义值 10，得 %d", got)
	}

	// 删一行 → 预热只补该行，其余不动。
	if _, err := raw.Exec("DELETE FROM settings WHERE k = ?", KeyOtpTtl); err != nil {
		t.Fatalf("删除一行失败: %v", err)
	}
	if err := st.Preload(ctx); err != nil {
		t.Fatalf("三次 Preload 失败: %v", err)
	}
	if n := settingsRowCount(t, raw); n != 35 {
		t.Errorf("补齐缺失行后应回 35，得 %d", n)
	}
	if got, _ := st.GetInt64(KeyOtpTtl); got != 300 {
		t.Errorf("otp_ttl 应补回默认 300，得 %d", got)
	}

	// JSON 损坏行 → fail-fast 报错，不静默回落。
	if _, err := raw.Exec("UPDATE settings SET v = 'oops' WHERE k = ?", KeyPwdMaxLength); err != nil {
		t.Fatalf("写入损坏值失败: %v", err)
	}
	if err := st.Preload(ctx); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("损坏行应 fail-fast 报错，err = %v", err)
	}
	if _, err := raw.Exec("UPDATE settings SET v = '64' WHERE k = ?", KeyPwdMaxLength); err != nil {
		t.Fatalf("恢复损坏行失败: %v", err)
	}

	// 白名单外存量行：不进快照、不报错、不删除（读侧非破坏性）。
	if _, err := raw.Exec(
		"INSERT INTO settings (k, v, updated_at, updated_by) VALUES ('legacy_key', '1', NOW(), 0)",
	); err != nil {
		t.Fatalf("插入表外行失败: %v", err)
	}
	if err := st.Preload(ctx); err != nil {
		t.Fatalf("含表外行 Preload 应通过: %v", err)
	}
	if _, ok := st.Get("legacy_key"); ok {
		t.Error("表外键不应进快照")
	}
}

// TestSetManyEmptySliceReloadLoop（env-skip DB+Redis）：
// SetSettings 全量替换下任一 []string 键清空的落库闭环——SetMany 写
// 空/nil 切片 → 落库值必须是 "[]" 而非 "null"（修复前 Validate 对空切片
// 返回 nil → EncodeValue 落 JSON "null"）→ 新实例 Preload（重启口径）
// 与同实例 reload（watcher 热更口径，共用 loadSnapshot）均不因
// DecodeValue fail-fast 炸掉 → 快照读回非 nil 空切片。
func TestSetManyEmptySliceReloadLoop(t *testing.T) {
	rp, raw := setupTestDB(t)
	rdb := setupTestRedis(t)
	ctx := context.Background()

	storeA := NewStore(rp, rdb)
	if err := storeA.Preload(ctx); err != nil {
		t.Fatalf("写方 Preload 失败: %v", err)
	}

	// 全量替换清空场景：sso_domains 空列表、gateway_tokens nil
	//（proto 空 repeated 的真实形态，SetSettings 直达）。
	if err := storeA.SetMany(ctx, map[string]any{
		KeySsoDomains:    []string{},
		KeyGatewayTokens: []string(nil),
	}, 1); err != nil {
		t.Fatalf("SetMany 空列表失败: %v", err)
	}

	// 核心断言：落库值 "[]"（修复前为 "null"）。
	for _, k := range []string{KeySsoDomains, KeyGatewayTokens} {
		var v string
		if err := raw.QueryRow("SELECT v FROM settings WHERE k = ?", k).Scan(&v); err != nil {
			t.Fatalf("读取 %s 落库值失败: %v", k, err)
		}
		if v != "[]" {
			t.Fatalf("键 %s 落库值 = %q，want \"[]\"（\"null\" 会令 DecodeValue fail-fast）", k, v)
		}
	}

	// 写方本实例立即生效：apply 写入归一值，读回空列表（cloneValue 副本
	// 语义对空切片返回 nil——既有验收口径，消费方 len/迭代语义等价；
	// 存储层 DecodeValue("[]") 已归一非 nil，见上）。
	if got, _ := storeA.GetStringSlice(KeySsoDomains); len(got) != 0 {
		t.Errorf("写方快照 sso_domains = %#v，want 空列表", got)
	}

	// 重启口径：新实例 Preload 不炸 + 读回空列表（修复前 DecodeValue("null")
	// fail-fast，进程起不来）。
	storeB := NewStore(rp, rdb)
	if err := storeB.Preload(ctx); err != nil {
		t.Fatalf("空列表落库后新实例 Preload 应通过，err = %v", err)
	}
	if got, _ := storeB.GetStringSlice(KeyGatewayTokens); len(got) != 0 {
		t.Errorf("新实例快照 gateway_tokens = %#v，want 空列表", got)
	}

	// 热更口径：watcher reload 同一条 loadSnapshot 路径（包内直调私有
	// reload，与 Preload 的差异仅缺省键不写回）。
	if err := storeB.reload(ctx); err != nil {
		t.Fatalf("空列表落库后 reload 应通过，err = %v", err)
	}
	if got, _ := storeB.GetStringSlice(KeySsoDomains); len(got) != 0 {
		t.Errorf("reload 后快照 sso_domains = %#v，want 空列表", got)
	}
}

// settingRow 构造单行 Upsert 输入（测试便捷函数）。
func settingRow(t *testing.T, k, v string, by int64) model.Setting {
	t.Helper()
	return model.Setting{K: k, V: v, UpdatedAt: time.Now(), UpdatedBy: by}
}

// equalValue 深比较两个快照值（int64/string/bool/[]string 四类）。
func equalValue(a, b any) bool {
	as, aok := a.([]string)
	bs, bok := b.([]string)
	if aok || bok {
		if !aok || !bok || len(as) != len(bs) {
			return false
		}
		for i := range as {
			if as[i] != bs[i] {
				return false
			}
		}
		return true
	}
	return a == b
}
