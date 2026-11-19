// setup 包 DB 集成测试（env-skip，双库测试矩阵）：UC_TEST_DB_DRIVER +
// UC_TEST_DB_DSN 指向专用测试库时（兼容读 UC_TEST_MYSQL_DSN）真实跑两条
// 安装路径的端到端用例（迁移触发、管理员 ID=1 幂等创建、判据组合、失败
// 重试），同一套用例对 mysql / postgres 各跑一遍，方言由 env 选定；Redis
// 侧用本地假 RESP 服务（§13 语义只要求连通性）。与 migrate_test 相同模式：
// 用例开始前清空全部表、结束后清理并自证零残留；连接串只经环境变量注入，
// 代码不含主机 / 凭证信息。
package setup

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"authloft/internal/config"
	"authloft/internal/migrate"
)

// 测试库 env 变量名：UC_TEST_DB_DRIVER + UC_TEST_DB_DSN 双变量显式指定
// 方言与连接串，UC_TEST_MYSQL_DSN 为兼容读。解析逻辑与 repo 包
// testsupport_test.go 同口径（测试文件不可跨包 import，机制改动须同步）。
const (
	envTestDBDriver   = "UC_TEST_DB_DRIVER"
	envTestDBDSN      = "UC_TEST_DB_DSN"
	envMySQLDSNLegacy = "UC_TEST_MYSQL_DSN"
)

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

// testDBTarget 一次测试运行的测试库目标：方言 + 连接串。
type testDBTarget struct {
	driver config.Driver
	dsn    string
}

// testDBLockName 测试库互斥锁名（与 settings / repo / migrate / main 的
// DB 测试二进制同名串行）。机制全解见 repo 包 testsupport_test.go 的
// TestMain 注释。
const testDBLockName = "uc_test_db_slot"

// pgTestLockWaitTime PG advisory 锁等待上限（对齐 GET_LOCK 的 300s）。
const pgTestLockWaitTime = 300 * time.Second

// testDBLockKeyPG PG advisory 键：testDBLockName 的 FNV-1a 64 位散列按
// int64 补码截断——与 MySQL GET_LOCK 同名锁保持同一互斥身份；advisory 键
// 为库内命名空间，散列碰撞概率可忽略。与 repo 包同值（跨二进制互斥）。
const testDBLockKeyPG = -2607616838611919394

// TestMain 共享测试库串行化（锁持锁贯穿 m.Run()，机制说明见 repo 包
// testsupport_test.go 的 TestMain 注释）：mysql → GET_LOCK；postgres →
// pg_advisory_lock（session 级，等待侧以 statement_timeout 兜底防挂死）。
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

// acquireTestSlot 获取测试库互斥槽：单连接 *sql.DB——锁与安静探测共用
// 同一物理连接（连接一多探测口径就乱）。拿不到锁 / 出错时放行兜底，
// 与既有 GET_LOCK 口径一致（宁可试跑不挂死）。
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
	return db
}

// pgAcquireAdvisoryLock 持 PG advisory 锁：pg_advisory_lock 本身无超时
// 参数、阻塞等待可能无限挂死，等待侧以 statement_timeout 兜底；SET LOCAL
// 在事务内生效、提交后随事务回退，不影响后续探测查询。锁本身 session 级，
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
// （连接关闭本身也会释放 session 级锁，进程异常退出同理由连接断开兜底）；
// mysql 侧关连接即释放 GET_LOCK。
func releaseTestSlot(target *testDBTarget, db *sql.DB) {
	if target.driver == config.DriverPostgres {
		_, _ = db.Exec("SELECT pg_advisory_unlock($1)", testDBLockKeyPG)
	}
	_ = db.Close()
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

// envTarget 返回测试用方言与连接串；测试库 env 未设置时跳过本组集成用例
// （skip-on-no-env，本地无 DB / CI 未配 service 的常态）。方言由 env 决定，
// 同一套用例在测试矩阵下对两库各跑一遍。
func envTarget(t *testing.T) *testDBTarget {
	t.Helper()
	target, err := resolveTestDBEnv()
	if err != nil {
		t.Fatalf("测试环境变量错误: %v", err)
	}
	if target == nil {
		t.Skipf("测试库 env 未设置（%s+%s，或兼容 %s），跳过 setup 集成用例", envTestDBDriver, envTestDBDSN, envMySQLDSNLegacy)
	}
	return target
}

// newSetupTestDB 为单个用例准备独立环境（按 env 方言连接测试库，开始前
// 清空全部表），结束后 t.Cleanup 清空并自证零残留；同时返回临时
// configPath。
func newSetupTestDB(t *testing.T) (*testDBTarget, string) {
	t.Helper()
	target := envTarget(t)
	db, err := migrate.NewDB(target.driver, target.dsn)
	if err != nil {
		t.Fatalf("打开连接失败: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("连接测试实例失败（driver=%s）: %v", target.driver, err)
	}
	if err := dropAllTablesForSetup(db, target.driver); err != nil {
		t.Fatalf("用例开始清空测试库失败: %v", err)
	}
	t.Cleanup(func() {
		if err := dropAllTablesForSetup(db, target.driver); err != nil {
			t.Errorf("用例结束清理测试库失败: %v", err)
		}
		if err := assertNoTablesForSetup(db, target.driver); err != nil {
			t.Errorf("清理自证失败: %v", err)
		}
		db.Close()
	})
	return target, filepath.Join(t.TempDir(), "config.yaml")
}

// dropAllTablesForSetup / assertNoTablesForSetup 与 migrate_test 同实现
// （跨包私有不共享，此处保持同口径副本）：pg 无 FOREIGN_KEY_CHECKS 开关，
// DROP TABLE ... CASCADE 兜底任意删除顺序。
func dropAllTablesForSetup(db *sql.DB, driver config.Driver) error {
	tables, err := listTablesForSetup(db, driver)
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

// listTablesForSetup 测试库当前库（当前 schema）的表清单，方言各自目录表
// 口径（同 connQuiet）。
func listTablesForSetup(db *sql.DB, driver config.Driver) ([]string, error) {
	if driver == config.DriverPostgres {
		rows, err := db.Query("SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var names []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return nil, err
			}
			names = append(names, name)
		}
		return names, rows.Err()
	}
	rows, err := db.Query("SHOW TABLES")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func assertNoTablesForSetup(db *sql.DB, driver config.Driver) error {
	left, err := listTablesForSetup(db, driver)
	if err != nil {
		return err
	}
	if len(left) > 0 {
		return fmt.Errorf("残留表: %v", left)
	}
	return nil
}

// openSetupTestDB 直连测试库（断言用）。
func openSetupTestDB(t *testing.T, target *testDBTarget) *sql.DB {
	t.Helper()
	db, err := migrate.NewDB(target.driver, target.dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// postInstallJSON 向 setup server 发 SetupService/Install 的 Connect unary
// JSON 请求（§13.3；root 必填由调用方在 body 提供——不再读请求 Host）。
func postInstallJSON(s *Server, body map[string]any) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api.setup.v1.SetupService/Install", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	return rec
}

// postConfigJSON 向 setup server 发 SetupService/UploadConfig 的 Connect
// unary JSON 请求（§13.2）。
func postConfigJSON(s *Server, configText string) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(map[string]string{"config": configText})
	req := httptest.NewRequest(http.MethodPost, "/api.setup.v1.SetupService/UploadConfig", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	return rec
}

// waitExit 等待退出信号（带超时），返回是否已触发。
func waitExit(s *Server) bool {
	select {
	case <-s.Exposed():
		return true
	case <-time.After(3 * time.Second):
		return false
	}
}

// adminRow 查询管理员行（user 表 id=1 的 username；不存在返回 false）。
func adminRow(t *testing.T, db *sql.DB, driver config.Driver) (username string, exists bool) {
	t.Helper()
	err := db.QueryRow(fmt.Sprintf(
		"SELECT username FROM %s WHERE id = 1", migrate.UserTable(driver),
	)).Scan(&username)
	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil {
		t.Fatalf("query admin: %v", err)
	}
	return username, true
}

// adminCredentialSecret 查询管理员 password 凭证（不存在返回空）：secret
// 列在 PG 侧为 BYTEA，按 []byte 承载两方言通用。
func adminCredentialSecret(t *testing.T, db *sql.DB) string {
	t.Helper()
	var secret []byte
	err := db.QueryRow(
		"SELECT secret FROM user_credential WHERE user_id = 1 AND kind = 'password'",
	).Scan(&secret)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		t.Fatalf("query admin credential: %v", err)
	}
	return string(secret)
}

// installBody 构造路径 B 安装请求体（方言随测试目标，DSN 形态随方言不同
// 由调用方传 env 解析结果）。
func installBody(target *testDBTarget, redisAddr string) map[string]any {
	return map[string]any{
		"dbDriver":      string(target.driver),
		"dbDsn":         target.dsn,
		"redisAddr":     redisAddr,
		"adminUsername": "admin",
		"adminPassword": "Str0ngPassw0rd",
		"root":          "https://install.example.com",
	}
}

// probeDefaultUserID 按默认值（不带 id）插入一行 user 并返回生成主键：
// 安装显式写入 id=1 之后，后续默认值插入必须取到 id=2——钉住「显式 id
// 不产生序列 / 自增空洞」语义（PG IDENTITY 复位与 MySQL AUTO_INCREMENT
// 推进）。RETURNING 是 PG 侧语法，mysql 侧走 LastInsertId。
func probeDefaultUserID(t *testing.T, db *sql.DB, driver config.Driver) int64 {
	t.Helper()
	table := migrate.UserTable(driver)
	var id int64
	if driver == config.DriverPostgres {
		err := db.QueryRow(fmt.Sprintf(
			"INSERT INTO %s (username, user_status, created_at, updated_at) VALUES ('seqprobe', 1, NOW(), NOW()) RETURNING id", table,
		)).Scan(&id)
		if err != nil {
			t.Fatalf("default-id insert (postgres): %v", err)
		}
		return id
	}
	res, err := db.Exec(fmt.Sprintf(
		"INSERT INTO %s (username, user_status, created_at, updated_at) VALUES ('seqprobe', 1, NOW(), NOW())", table,
	))
	if err != nil {
		t.Fatalf("default-id insert (mysql): %v", err)
	}
	if id, err = res.LastInsertId(); err != nil {
		t.Fatalf("last insert id: %v", err)
	}
	return id
}

// TestInstallFreshEndToEnd 路径 B 端到端（§13.3）：空库 + 假 Redis →
// 200 {"restarting":true}（成功响应即消息本身，§1.0）+ 退出触发 + config
// 原子写入（可被 config.Load 加载，driver 与请求一致）+ 管理员 ID=1 创建 +
// argon2id 凭证行 + root 按所填写入、rp_id 缺省取 root 的 host（去 scheme
// 与端口，不再读请求 Host）+ 默认值插入取 id=2（序列 / 自增推进语义）。
func TestInstallFreshEndToEnd(t *testing.T) {
	target, configPath := newSetupTestDB(t)
	redisAddr := fakeRedis(t, "")
	s := NewServer(configPath)

	body := installBody(target, redisAddr)
	body["root"] = "https://install.example.com:8080"
	rec := postInstallJSON(s, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"restarting":true}` {
		t.Errorf("body = %q, want {\"restarting\":true}", got)
	}
	if !waitExit(s) {
		t.Error("successful install must trigger exit (restart)")
	}

	// config 已写入且可加载（下次进程按正常模式启动），方言随请求落盘。
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("written config must load: %v", err)
	}
	if cfg.DB.DSN != target.dsn || cfg.Redis.Addr != redisAddr {
		t.Errorf("config db/redis = %q / %q, want install inputs", cfg.DB.DSN, cfg.Redis.Addr)
	}
	if cfg.DB.EffectiveDriver() != target.driver {
		t.Errorf("config db.driver = %q, want %q", cfg.DB.EffectiveDriver(), target.driver)
	}
	if cfg.Authloft.Root != "https://install.example.com:8080" {
		t.Errorf("root = %q, want input root verbatim", cfg.Authloft.Root)
	}
	if cfg.Authloft.RpID != "install.example.com" {
		t.Errorf("rp_id = %q, want root host without port", cfg.Authloft.RpID)
	}

	// 管理员与凭证。
	db := openSetupTestDB(t, target)
	if username, ok := adminRow(t, db, target.driver); !ok || username != "admin" {
		t.Errorf("admin row = (%q, %v), want (\"admin\", true)", username, ok)
	}
	secret := adminCredentialSecret(t, db)
	if !strings.HasPrefix(secret, "$argon2id$") {
		t.Errorf("credential secret not argon2id PHC: %q", secret)
	}
	// 权限行是安装事务的一部分，须与管理员行同时落库（§3.15、§4.8）。
	var point string
	if err := db.QueryRow("SELECT point FROM user_permission WHERE user_id = 1").Scan(&point); err != nil {
		t.Fatalf("query admin permission: %v", err)
	}
	if point != "superadmin" {
		t.Errorf("admin permission point = %q, want superadmin", point)
	}
	// 显式 id=1 之后默认值插入必须取 id=2：PG 侧钉 IDENTITY 序列复位
	// （BY DEFAULT 显式插入不推进序列），MySQL 侧钉 AUTO_INCREMENT 推进。
	if got := probeDefaultUserID(t, db, target.driver); got != 2 {
		t.Errorf("default-id insert = %d, want 2 (sequence/auto_increment must advance past explicit id=1)", got)
	}
}

// TestInstallIdempotentRetry 幂等与失败重试（§3.15：setup 状态不落盘，
// 进程中断后重跑安装按同一路径继续）：第一次成功后再跑一次（模拟重启后
// 又进 setup）→ 管理员已存在则跳过（不重复建、不覆盖）；失败（Redis 不通）
// 不退出，修正后可重试成功。
func TestInstallIdempotentRetry(t *testing.T) {
	target, configPath := newSetupTestDB(t)
	redisAddr := fakeRedis(t, "")
	s := NewServer(configPath)

	first := postInstallJSON(s, installBody(target, redisAddr))
	if first.Code != http.StatusOK {
		t.Fatalf("first install: HTTP %d (body %s)", first.Code, first.Body.String())
	}

	// 管理员已存在但权限行缺失时仍须补写，两个存在性判定互不替代（§3.15）。
	preDB := openSetupTestDB(t, target)
	if _, err := preDB.Exec("DELETE FROM user_permission WHERE user_id = 1"); err != nil {
		t.Fatalf("delete permission row: %v", err)
	}

	// 第二次（换用户名）：管理员已存在 → 跳过插入，既有行不变。
	//（密码不含新用户名子串，避免 pwd_disallow_username 拦截——那不是本用例目标。）
	retry := installBody(target, redisAddr)
	retry["adminUsername"] = "other"
	retry["adminPassword"] = "SecondStr0ng9"
	second := postInstallJSON(s, retry)
	if second.Code != http.StatusOK {
		t.Fatalf("second install: HTTP %d (body %s)", second.Code, second.Body.String())
	}
	db := openSetupTestDB(t, target)
	if username, ok := adminRow(t, db, target.driver); !ok || username != "admin" {
		t.Errorf("admin must stay (\"admin\", true) after idempotent retry, got (%q, %v)", username, ok)
	}
	var users int
	if err := db.QueryRow(fmt.Sprintf(
		"SELECT COUNT(*) FROM %s WHERE id = 1", migrate.UserTable(target.driver),
	)).Scan(&users); err != nil || users != 1 {
		t.Errorf("admin rows = %d (err %v), want exactly 1", users, err)
	}
	// 重复安装不得产生第二行权限记录。
	var permRows int
	if err := db.QueryRow("SELECT COUNT(*) FROM user_permission WHERE user_id = 1 AND point = 'superadmin'").Scan(&permRows); err != nil {
		t.Fatalf("query permission rows: %v", err)
	}
	if permRows != 1 {
		t.Errorf("superadmin permission rows = %d, want 1", permRows)
	}

	// 失败重试：坏 Redis → redis_unreachable（Connect 错误体，unavailable +
	// ErrorInfo）且不触发退出。
	s2 := NewServer(configPath)
	bad := installBody(target, "127.0.0.1:1")
	rec := postInstallJSON(s2, bad)
	code, info := decodeConnectError(t, rec)
	if code != "unavailable" || info == nil || info.Code != CodeRedisUnreachable {
		t.Errorf("bad redis retry: connect=(%q, %+v), want unavailable + %s", code, info, CodeRedisUnreachable)
	}
	if waitExit(s2) {
		t.Error("failed retry must not trigger exit")
	}
}

// TestUploadConfigEndToEnd 路径 A 端到端（§13.2）：已安装库（迁移最新 +
// 管理员存在）上传合法 config → 迁移幂等秒过 + 管理员检查通过 → 200
// {"restarting":true} + 上传原文原子写入。config 方言与测试库一致（PG
// 侧 DSN 为 URL 形态，经 validatePGDSN 校验）。
func TestUploadConfigEndToEnd(t *testing.T) {
	target, configPath := newSetupTestDB(t)
	redisAddr := fakeRedis(t, "")
	s := NewServer(configPath)

	// 准备：路径 B 先完成安装（复用其建库 + 建管理员）。
	prep := postInstallJSON(s, installBody(target, redisAddr))
	if prep.Code != http.StatusOK {
		t.Fatalf("prepare install: HTTP %d (body %s)", prep.Code, prep.Body.String())
	}

	// 路径 A：上传合法 config（指向同一测试库 + 假 Redis）。
	s2 := NewServer(configPath)
	uploaded := uploadConfigYAML(target.driver, target.dsn, redisAddr)
	rec := postConfigJSON(s2, uploaded)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"restarting":true}` {
		t.Errorf("body = %q, want {\"restarting\":true}", got)
	}
	if !waitExit(s2) {
		t.Error("successful upload must trigger exit (restart)")
	}
	// 原文写入（保真——上传什么写什么）。
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	if string(data) != uploaded {
		t.Error("uploaded config must be written verbatim")
	}
}

// TestUploadConfigAdminMissing 路径 A 步骤 ④：版本已最新但管理员缺失 →
// admin_missing（Connect 错误体：failed_precondition + ErrorInfo，
// HTTP 400——提示改走全新安装）。
func TestUploadConfigAdminMissing(t *testing.T) {
	target, configPath := newSetupTestDB(t)
	redisAddr := fakeRedis(t, "")

	// 先完整安装再删掉管理员行，模拟「迁移最新 + 管理员缺失」。
	s := NewServer(configPath)
	prep := postInstallJSON(s, installBody(target, redisAddr))
	if prep.Code != http.StatusOK {
		t.Fatalf("prepare install: HTTP %d", prep.Code)
	}
	db := openSetupTestDB(t, target)
	if _, err := db.Exec(fmt.Sprintf(
		"DELETE FROM %s WHERE id = 1", migrate.UserTable(target.driver),
	)); err != nil {
		t.Fatalf("delete admin: %v", err)
	}

	s2 := NewServer(configPath)
	rec := postConfigJSON(s2, uploadConfigYAML(target.driver, target.dsn, redisAddr))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HTTP status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	code, info := decodeConnectError(t, rec)
	if code != "failed_precondition" || info == nil || info.Domain != setupDomain || info.Code != CodeAdminMissing {
		t.Fatalf("connect=(%q, %+v), want failed_precondition + setup/%s", code, info, CodeAdminMissing)
	}
	if waitExit(s2) {
		t.Error("admin_missing must not trigger exit")
	}
}

// TestInstallDomainErrorsWithRealDB 路径 B 域错误（真实 DB 下校验步骤）：
// 用户名不合规 → username_invalid；密码弱 → password_weak（校验在 ③，
// 连通与迁移之后）。失败均走 Connect 错误体（invalid_argument 400 +
// ErrorInfo），不写 config、不退出。
func TestInstallDomainErrorsWithRealDB(t *testing.T) {
	target, configPath := newSetupTestDB(t)
	redisAddr := fakeRedis(t, "")
	s := NewServer(configPath)

	badName := installBody(target, redisAddr)
	badName["adminUsername"] = "bad!"
	rec := postInstallJSON(s, badName)
	if code, info := decodeConnectError(t, rec); code != "invalid_argument" || info == nil || info.Code != CodeUsernameInvalid {
		t.Errorf("username invalid: connect=(%q, %+v), want invalid_argument + %s (rec %s)", code, info, CodeUsernameInvalid, rec.Body.String())
	}

	weak := installBody(target, redisAddr)
	weak["adminPassword"] = "weakpass"
	rec = postInstallJSON(s, weak)
	if code, info := decodeConnectError(t, rec); code != "invalid_argument" || info == nil || info.Code != CodePasswordWeak {
		t.Errorf("weak password: connect=(%q, %+v), want invalid_argument + %s (rec %s)", code, info, CodePasswordWeak, rec.Body.String())
	}

	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Errorf("failed installs must not write config, stat err = %v", err)
	}
	if waitExit(s) {
		t.Error("domain failures must not trigger exit")
	}
}

// TestInstallAdminUserStatusColumn 列名回归：管理员创建路径真实
// 落库（端到端、非 mock，FreshInstall → installAdmin → INSERT INTO user），
// 断言 user 行存在且 user_status=1。DDL 列名为 user_status
// （000001_init.sql：避开 API 信封保留字 status，接口文档 §1.0）；
// installAdmin 曾遗留旧列名 status 触发 Error 1054（Unknown column），
// 本用例钉住列名契约。
func TestInstallAdminUserStatusColumn(t *testing.T) {
	target, configPath := newSetupTestDB(t)
	redisAddr := fakeRedis(t, "")
	s := NewServer(configPath)

	rec := postInstallJSON(s, installBody(target, redisAddr))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	db := openSetupTestDB(t, target)
	var userStatus int
	if err := db.QueryRow(fmt.Sprintf(
		"SELECT user_status FROM %s WHERE id = 1", migrate.UserTable(target.driver),
	)).Scan(&userStatus); err != nil {
		t.Fatalf("query admin user_status: %v", err)
	}
	if userStatus != 1 {
		t.Errorf("admin user_status = %d, want 1 (正常)", userStatus)
	}
}
