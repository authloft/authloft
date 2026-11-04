// setup 包 DB 集成测试（env-skip）：UC_TEST_MYSQL_DSN 指向专用测试库时
// 真实跑两条安装路径的端到端用例（迁移触发、管理员 ID=1 幂等创建、判据
// 组合、失败重试），Redis 侧用本地假 RESP 服务（§13 语义只要求连通性）。
// 与 migrate_test 相同模式：用例开始前清空全部表、结束后清理并自证
// 零残留；连接串只经环境变量注入，代码不含主机 / 凭证信息。
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
)

// testDBLockName 测试库互斥锁名（与 settings / repo / migrate / main 的
// DB 测试二进制同名串行）。机制全解见 settings 包 store_test.go 的
// TestMain 注释。
const testDBLockName = "uc_test_db_slot"

// TestMain 共享测试库串行化（GET_LOCK 持锁贯穿 m.Run()，机制说明见
// settings 包 store_test.go 的 TestMain 注释）。取代旧的 waitQuietDB
// 错峰轮询（五包统一接锁）：旧口径查 processlist「无其他连接」，
// 而兄弟二进制阻塞在 GET_LOCK 的等待连接常驻 processlist，计入会互相
// 卡到超时（settings 包实测）；持锁串行后错峰不再必要，等表空仅作
// 防御性兜底。
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
// 共用同一物理连接（连接一多探测口径就乱）。
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

// waitQuietOnConn 在持锁连接上等库安静：库内无表（有表 = 有未按预期
// 清理的残留），连续 quietConfirmations 次、间隔 quietInterval 才放行；
// 总上限 quietTimeout 防御性兜底（超时放行，宁可试跑不挂死）。不看
// 连接数：兄弟二进制阻塞在 GET_LOCK 的等待连接无表、无害，若计入会
// 互相卡到超时（实测）。
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

// envDSN 返回测试用 DSN；UC_TEST_MYSQL_DSN 未设置时跳过本组集成用例
//（skip-on-no-env，与 migrate_test 同口径）。
func envDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过 setup 集成用例")
	}
	return dsn
}

// newSetupTestDB 为单个用例准备独立环境（连接 DSN 所指测试库，开始前清空
// 全部表），结束后 t.Cleanup 清空并自证零残留；同时返回临时 configPath。
func newSetupTestDB(t *testing.T) (dsn string, configPath string) {
	t.Helper()
	dsn = envDSN(t)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("打开连接失败: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("连接 MariaDB 测试实例失败: %v", err)
	}
	if err := dropAllTablesForSetup(db); err != nil {
		t.Fatalf("用例开始清空测试库失败: %v", err)
	}
	t.Cleanup(func() {
		if err := dropAllTablesForSetup(db); err != nil {
			t.Errorf("用例结束清理测试库失败: %v", err)
		}
		if err := assertNoTablesForSetup(db); err != nil {
			t.Errorf("清理自证失败: %v", err)
		}
		db.Close()
	})
	return dsn, filepath.Join(t.TempDir(), "config.yaml")
}

// dropAllTablesForSetup / assertNoTablesForSetup 与 migrate_test 同实现
//（跨包私有不共享，此处保持同口径副本）。
func dropAllTablesForSetup(db *sql.DB) error {
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

func assertNoTablesForSetup(db *sql.DB) error {
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

// openSetupTestDB 直连测试库（断言用）。
func openSetupTestDB(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("mysql", dsn)
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
// JSON 请求（带安装页 Host，供 root / rp_id 推导；§13.3）。
func postInstallJSON(s *Server, body map[string]any) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api.setup.v1.SetupService/Install", strings.NewReader(string(payload)))
	req.Host = "install.example.com:8080"
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
	req.Host = "install.example.com:8080"
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
func adminRow(t *testing.T, db *sql.DB) (username string, exists bool) {
	t.Helper()
	err := db.QueryRow("SELECT username FROM user WHERE id = 1").Scan(&username)
	if err == sql.ErrNoRows {
		return "", false
	}
	if err != nil {
		t.Fatalf("query admin: %v", err)
	}
	return username, true
}

// adminCredentialSecret 查询管理员 password 凭证（不存在返回空）。
func adminCredentialSecret(t *testing.T, db *sql.DB) string {
	t.Helper()
	var secret string
	err := db.QueryRow(
		"SELECT secret FROM user_credential WHERE user_id = 1 AND kind = 'password'",
	).Scan(&secret)
	if err == sql.ErrNoRows {
		return ""
	}
	if err != nil {
		t.Fatalf("query admin credential: %v", err)
	}
	return secret
}

// TestInstallFreshEndToEnd 路径 B 端到端（§13.3）：空库 + 假 Redis →
// 200 {"restarting":true}（成功响应即消息本身，§1.0）+ 退出触发 + config
// 原子写入（可被 config.Load 加载）+ 管理员 ID=1 创建 + argon2id 凭证行 +
// root/rp_id 按请求 Host 推导。
func TestInstallFreshEndToEnd(t *testing.T) {
	dsn, configPath := newSetupTestDB(t)
	redisAddr := fakeRedis(t, "")
	s := NewServer(configPath)

	rec := postInstallJSON(s, map[string]any{
		"dbDsn":         dsn,
		"redisAddr":     redisAddr,
		"adminUsername": "admin",
		"adminPassword": "Str0ngPassw0rd",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"restarting":true}` {
		t.Errorf("body = %q, want {\"restarting\":true}", got)
	}
	if !waitExit(s) {
		t.Error("successful install must trigger exit (restart)")
	}

	// config 已写入且可加载（下次进程按正常模式启动）。
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("written config must load: %v", err)
	}
	if cfg.DB.DSN != dsn || cfg.Redis.Addr != redisAddr {
		t.Errorf("config db/redis = %q / %q, want install inputs", cfg.DB.DSN, cfg.Redis.Addr)
	}
	if cfg.Authloft.Root != "https://install.example.com:8080" {
		t.Errorf("root = %q, want https://+request Host", cfg.Authloft.Root)
	}
	if cfg.Authloft.RpID != "install.example.com" {
		t.Errorf("rp_id = %q, want Host without port", cfg.Authloft.RpID)
	}

	// 管理员与凭证。
	db := openSetupTestDB(t, dsn)
	if username, ok := adminRow(t, db); !ok || username != "admin" {
		t.Errorf("admin row = (%q, %v), want (\"admin\", true)", username, ok)
	}
	secret := adminCredentialSecret(t, db)
	if !strings.HasPrefix(secret, "$argon2id$") {
		t.Errorf("credential secret not argon2id PHC: %q", secret)
	}
}

// TestInstallIdempotentRetry 幂等与失败重试（§3.15：setup 状态不落盘，
// 进程中断后重跑安装按同一路径继续）：第一次成功后再跑一次（模拟重启后
// 又进 setup）→ 管理员已存在则跳过（不重复建、不覆盖）；失败（Redis 不通）
// 不退出，修正后可重试成功。
func TestInstallIdempotentRetry(t *testing.T) {
	dsn, configPath := newSetupTestDB(t)
	redisAddr := fakeRedis(t, "")
	s := NewServer(configPath)

	first := postInstallJSON(s, map[string]any{
		"dbDsn":         dsn,
		"redisAddr":     redisAddr,
		"adminUsername": "admin",
		"adminPassword": "Str0ngPassw0rd",
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first install: HTTP %d (body %s)", first.Code, first.Body.String())
	}

	// 第二次（换用户名）：管理员已存在 → 跳过插入，既有行不变。
	//（密码不含新用户名子串，避免 pwd_disallow_username 拦截——那不是本用例目标。）
	second := postInstallJSON(s, map[string]any{
		"dbDsn":         dsn,
		"redisAddr":     redisAddr,
		"adminUsername": "other",
		"adminPassword": "SecondStr0ng9",
	})
	if second.Code != http.StatusOK {
		t.Fatalf("second install: HTTP %d (body %s)", second.Code, second.Body.String())
	}
	db := openSetupTestDB(t, dsn)
	if username, ok := adminRow(t, db); !ok || username != "admin" {
		t.Errorf("admin must stay (\"admin\", true) after idempotent retry, got (%q, %v)", username, ok)
	}
	var users int
	if err := db.QueryRow("SELECT COUNT(*) FROM user WHERE id = 1").Scan(&users); err != nil || users != 1 {
		t.Errorf("admin rows = %d (err %v), want exactly 1", users, err)
	}

	// 失败重试：坏 Redis → redis_unreachable（Connect 错误体，unavailable +
	// ErrorInfo）且不触发退出。
	s2 := NewServer(configPath)
	rec := postInstallJSON(s2, map[string]any{
		"dbDsn":         dsn,
		"redisAddr":     "127.0.0.1:1",
		"adminUsername": "admin",
		"adminPassword": "Str0ngPassw0rd",
	})
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
// {"restarting":true} + 上传原文原子写入。
func TestUploadConfigEndToEnd(t *testing.T) {
	dsn, configPath := newSetupTestDB(t)
	redisAddr := fakeRedis(t, "")
	s := NewServer(configPath)

	// 准备：路径 B 先完成安装（复用其建库 + 建管理员）。
	prep := postInstallJSON(s, map[string]any{
		"dbDsn":         dsn,
		"redisAddr":     redisAddr,
		"adminUsername": "admin",
		"adminPassword": "Str0ngPassw0rd",
	})
	if prep.Code != http.StatusOK {
		t.Fatalf("prepare install: HTTP %d (body %s)", prep.Code, prep.Body.String())
	}

	// 路径 A：上传合法 config（指向同一测试库 + 假 Redis）。
	s2 := NewServer(configPath)
	uploaded := uploadConfigYAML(dsn, redisAddr)
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
// HTTP 400，§13.2 行 1773——提示改走全新安装）。
func TestUploadConfigAdminMissing(t *testing.T) {
	dsn, configPath := newSetupTestDB(t)
	redisAddr := fakeRedis(t, "")

	// 先完整安装再删掉管理员行，模拟「迁移最新 + 管理员缺失」。
	s := NewServer(configPath)
	prep := postInstallJSON(s, map[string]any{
		"dbDsn":         dsn,
		"redisAddr":     redisAddr,
		"adminUsername": "admin",
		"adminPassword": "Str0ngPassw0rd",
	})
	if prep.Code != http.StatusOK {
		t.Fatalf("prepare install: HTTP %d", prep.Code)
	}
	db := openSetupTestDB(t, dsn)
	if _, err := db.Exec("DELETE FROM user WHERE id = 1"); err != nil {
		t.Fatalf("delete admin: %v", err)
	}

	s2 := NewServer(configPath)
	rec := postConfigJSON(s2, uploadConfigYAML(dsn, redisAddr))
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
	dsn, configPath := newSetupTestDB(t)
	redisAddr := fakeRedis(t, "")
	s := NewServer(configPath)

	rec := postInstallJSON(s, map[string]any{
		"dbDsn":         dsn,
		"redisAddr":     redisAddr,
		"adminUsername": "bad!",
		"adminPassword": "Str0ngPassw0rd",
	})
	if code, info := decodeConnectError(t, rec); code != "invalid_argument" || info == nil || info.Code != CodeUsernameInvalid {
		t.Errorf("username invalid: connect=(%q, %+v), want invalid_argument + %s (rec %s)", code, info, CodeUsernameInvalid, rec.Body.String())
	}

	rec = postInstallJSON(s, map[string]any{
		"dbDsn":         dsn,
		"redisAddr":     redisAddr,
		"adminUsername": "admin",
		"adminPassword": "weakpass",
	})
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
// （000001_init.sql 行 50：避开 API 信封保留字 status，接口文档 §1.0）；
// installAdmin 曾遗留旧列名 status 触发 Error 1054（Unknown column），
// 本用例钉住列名契约。
func TestInstallAdminUserStatusColumn(t *testing.T) {
	dsn, configPath := newSetupTestDB(t)
	redisAddr := fakeRedis(t, "")
	s := NewServer(configPath)

	rec := postInstallJSON(s, map[string]any{
		"dbDsn":         dsn,
		"redisAddr":     redisAddr,
		"adminUsername": "admin",
		"adminPassword": "Str0ngPassw0rd",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	db := openSetupTestDB(t, dsn)
	var userStatus int
	if err := db.QueryRow("SELECT user_status FROM user WHERE id = 1").Scan(&userStatus); err != nil {
		t.Fatalf("query admin user_status: %v", err)
	}
	if userStatus != 1 {
		t.Errorf("admin user_status = %d, want 1 (正常)", userStatus)
	}
}
