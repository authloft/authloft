// bootstrap 正常模式装配链测试（§3.1 行 253）：装配顺序断言
//（config → DB → migrate → Redis，用错误传播逐段证明）+ env-skip 真连
// 用例（DB 连通、migrate up 幂等、Redis PING）。清理口径沿用
// 既有 DB 测试（migrate_test / setup_db_test）：用例开始清空全部表、结束后
// 清空并自证零残留；跨二进制串行用 GET_LOCK 命名锁；
// 连接串只经环境变量注入（UC_TEST_MYSQL_DSN / UC_TEST_REDIS_ADDR），
// 代码不含主机 / 凭证信息。
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"authloft/internal/asyncqueue"
	"authloft/internal/config"
	"authloft/internal/connect"
	"authloft/internal/eventlog"
	"authloft/internal/factor"
	"authloft/internal/repo"
	"authloft/internal/service"
	"authloft/internal/settings"
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

// testDBLockName 测试库互斥锁名（与 settings / repo / migrate / setup 的
// DB 测试二进制同名串行）。机制全解见 settings 包 store_test.go 的
// TestMain 注释。
const testDBLockName = "uc_test_db_slot"

// TestMain 共享测试库串行化（GET_LOCK 持锁贯穿 m.Run()，机制说明见
// settings 包 store_test.go 的 TestMain 注释）。取代旧的 waitQuietDB
// 错峰轮询（五包统一接锁）：旧口径查 processlist「无其他连接」，
// 而兄弟二进制阻塞在 GET_LOCK 的等待连接常驻 processlist，计入会互相
// 卡到超时（settings 包实测）；持锁串行后错峰不再必要，等表空仅作
// 防御性兜底（本包真连用例会 migrate up + dropAllTables）。
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

// acquireTestDB / waitQuietOnConn / connQuiet / dropAllTables /
// assertNoTables 与 settings / repo 测试同实现（跨包私有不共享，
// 保持同口径副本）。

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
// （listen 缺失）时 run 返回 "config:" 前缀错误，未落到 DB / migrate /
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

// testSignKeyConfig 生成五把互不相同的随机 AES-256 密钥（std base64，kid=1），
// 仅供不连外部服务的装配单测（§1.4：五场景密钥必须独立）。
func testSignKeyConfig(t *testing.T) config.SignKeyConfig {
	t.Helper()
	next := func() config.KeyMaterial {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("generate key: %v", err)
		}
		return config.KeyMaterial{Key: base64.StdEncoding.EncodeToString(buf), Kid: 1}
	}
	return config.SignKeyConfig{
		Session:     next(),
		Login:       next(),
		Ticket:      next(),
		Cookie:      next(),
		SyncPayload: next(),
	}
}

// TestCodecsBuildFiveIndependent：五把 sign_key 逐把构造 codec，五个字段均
// 非 nil 且各自独立（不共用 KeyStore / Codec，§1.4 / §11.6.1）。
func TestCodecsBuildFiveIndependent(t *testing.T) {
	c, err := buildCodecs(&config.Config{SignKey: testSignKeyConfig(t)})
	if err != nil {
		t.Fatalf("buildCodecs: %v", err)
	}
	if c == nil {
		t.Fatal("buildCodecs returned nil codecs")
	}
	if c.Session == nil || c.Login == nil || c.Ticket == nil || c.Cookie == nil || c.SyncPayload == nil {
		t.Fatalf("codecs has nil fields: %+v", c)
	}
	if c.Session == c.Login || c.Session == c.Ticket || c.Session == c.Cookie || c.Session == c.SyncPayload ||
		c.Login == c.Ticket || c.Login == c.Cookie || c.Login == c.SyncPayload ||
		c.Ticket == c.Cookie || c.Ticket == c.SyncPayload || c.Cookie == c.SyncPayload {
		t.Error("five scenarios must use independent Codec instances, got duplicates")
	}
}

// TestCodecsBuildRejectsInvalidMaterial：base64 非法 / kid 越界 / 解码后长度
// 非 32 字节一律 fail-fast（装配层保留错误上抛，§3.2 约定 4）；并逐把验证
// 五场景密钥独立校验——任一场景非法都失败且错误定位到该字段名（§1.4 /
// §11.6.1）。
func TestCodecsBuildRejectsInvalidMaterial(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString(make([]byte, 16))
	cases := []struct {
		name string
		mut  func(*config.SignKeyConfig)
	}{
		{"invalid base64", func(s *config.SignKeyConfig) { s.Session.Key = "not-base64!!!" }},
		{"kid zero", func(s *config.SignKeyConfig) { s.Session.Kid = 0 }},
		{"kid overflow", func(s *config.SignKeyConfig) { s.Session.Kid = 256 }},
		{"key too short", func(s *config.SignKeyConfig) { s.Session.Key = shortKey }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sk := testSignKeyConfig(t)
			tc.mut(&sk)
			if _, err := buildCodecs(&config.Config{SignKey: sk}); err == nil {
				t.Fatalf("%s: buildCodecs must fail", tc.name)
			}
		})
	}

	// 逐把独立：同一非法形态施加到任意一把都必须 fail-fast，且错误定位到
	// 该场景字段名（§1.4：五场景密钥独立，泄露一枚不殃及其余）。
	perScenario := []struct {
		field string
		mut   func(*config.SignKeyConfig)
	}{
		{"sign_key.session", func(s *config.SignKeyConfig) { s.Session.Key = shortKey }},
		{"sign_key.login", func(s *config.SignKeyConfig) { s.Login.Key = shortKey }},
		{"sign_key.ticket", func(s *config.SignKeyConfig) { s.Ticket.Key = shortKey }},
		{"sign_key.cookie", func(s *config.SignKeyConfig) { s.Cookie.Key = shortKey }},
		{"sign_key.sync_payload", func(s *config.SignKeyConfig) { s.SyncPayload.Key = shortKey }},
	}
	for _, sc := range perScenario {
		t.Run("per-scenario/"+sc.field, func(t *testing.T) {
			sk := testSignKeyConfig(t)
			sc.mut(&sk)
			_, err := buildCodecs(&config.Config{SignKey: sk})
			if err == nil {
				t.Fatalf("%s: buildCodecs must fail", sc.field)
			}
			if !strings.Contains(err.Error(), sc.field) {
				t.Errorf("%s: error = %q, want field name in message", sc.field, err)
			}
		})
	}
}

// TestBootstrapCloseOrderNoPanic：优雅关闭顺序（stopBackground 停 watcher /
// 队列 → closeInfra 关 DB / Redis）在部分装配产物为 nil 时也必须安全、
// 可重复调用；队列走"先 drain 后停 worker"（§5.2）。不启动真实监听、
// 不连真实外部服务（watcher 未 Start、rdb 懒连接仅释放句柄）。
func TestBootstrapCloseOrderNoPanic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 全空 assembled：nil 安全。
	(&assembled{}).close(ctx)

	// 仅队列：Close 会 flush 剩余任务并停 worker，不 panic。
	q := asyncqueue.New(noopExecutor{}, asyncqueue.Options{
		Capacity:      8,
		Workers:       1,
		BatchSize:     8,
		FlushInterval: time.Hour,
	})
	deps := &assembled{queue: q}
	deps.close(ctx)
	if deps.queue != nil {
		t.Error("close must release queue reference")
	}
	// 重复关闭同样安全（幂等）。
	deps.close(ctx)

	// watcher（未 Start：Close 因未建立订阅直接幂等返回，不连 Redis）+
	// 队列 + Redis 客户端共存：close 第一段 stopBackground 释放 watcher /
	// 队列引用，第二段 closeInfra 释放 DB / Redis 引用——完整复现 serve
	// 的优雅关闭两段顺序（先停后台，再关基础设施）。
	w := settings.NewWatcher(nil, nil)
	q2 := asyncqueue.New(noopExecutor{}, asyncqueue.Options{
		Capacity:      8,
		Workers:       1,
		BatchSize:     8,
		FlushInterval: time.Hour,
	})
	deps2 := &assembled{watcher: w, queue: q2, rdb: redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})}
	deps2.close(ctx)
	if deps2.watcher != nil || deps2.queue != nil {
		t.Error("stopBackground must release watcher and queue references before closeInfra")
	}
	if deps2.rdb != nil {
		t.Error("closeInfra must release redis reference after background stops")
	}
	// 完整产物重复关闭同样安全（watcher.Close / Queue.Close 幂等）。
	deps2.close(ctx)
}

// noopExecutor 忽略批次，仅供关闭顺序测试。
type noopExecutor struct{}

func (noopExecutor) Execute(context.Context, []asyncqueue.Task) {}

// TestAssembleEngineAndTerminal 用 Fake 配置装配 factor 注册表 / Terminal /
// Engine（不连 DB / Redis）：断言 4 个已实现 kind 可解析、pending 4 条不参与
// 完整性断言、Terminal 五注入均非 nil（§3.8 行 390、§7.3 行 983-1004）。
func TestAssembleEngineAndTerminal(t *testing.T) {
	codecs, err := buildCodecs(&config.Config{SignKey: testSignKeyConfig(t)})
	if err != nil {
		t.Fatalf("buildCodecs: %v", err)
	}
	q := asyncqueue.New(noopExecutor{}, asyncqueue.Options{
		Capacity:      8,
		Workers:       1,
		BatchSize:     8,
		FlushInterval: time.Hour,
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = q.Close(ctx)
	})

	deps := &assembled{
		codecs:   codecs,
		settings: settings.NewStore(nil, nil),
		queue:    q,
		sink:     service.NewLoginEventWriter(eventlog.NewWriter(q)),
	}
	cfg := &config.Config{
		Authloft: config.AuthloftConfig{Root: "https://authloft.example.com", RpID: "authloft.example.com"},
	}
	users := repo.NewUserRepo(nil)
	creds := repo.NewCredentialRepo(nil)
	webauthnRepo := repo.NewWebauthnRepo(nil)

	engine, terminal, registry, err := buildEngine(cfg, deps, users, creds, webauthnRepo)
	if err != nil {
		t.Fatalf("buildEngine: %v", err)
	}
	if engine == nil || terminal == nil || registry == nil {
		t.Fatal("buildEngine must return non-nil engine / terminal / registry")
	}

	if err := registry.AssertComplete(); err != nil {
		t.Fatalf("AssertComplete: %v", err)
	}
	for _, kind := range []factor.FactorKind{
		factor.FactorPassword, factor.FactorWebAuthn, factor.FactorTOTP, factor.FactorRecovery,
	} {
		if _, err := registry.Get(kind); err != nil {
			t.Fatalf("Get(%s): %v", kind, err)
		}
	}
	for _, kind := range []factor.FactorKind{
		factor.FactorOTPSMS, factor.FactorOTPEmail, factor.FactorThirdParty, factor.FactorDevice,
	} {
		if _, err := registry.Get(kind); !errors.Is(err, factor.ErrKindNotRegistered) {
			t.Fatalf("Get(%s) err = %v, want ErrKindNotRegistered (pending kind)", kind, err)
		}
	}

	if terminal.Sessions == nil || terminal.OIDC == nil || terminal.Events == nil ||
		terminal.Sync == nil || terminal.Settings == nil {
		t.Fatalf("terminal 五注入存在 nil: %+v", terminal)
	}
}

// TestAssembleRealChain（env-skip）：真连装配链 config→DB→migrate up→Redis
// →密钥→settings 预热 + watcher→队列 + sink——assemble 成功后 DB ping 通、
// §4 全部 11 张表存在（migrate 步骤真实执行）、Redis PING 通；复跑 assemble
// 幂等（版本已最新时 migrate up 秒过不报错，§3.16）。测后清空全表并自证零残留。
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
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d.close(shutCtx)
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
	// 步骤 5-8：五把密钥 / settings 快照与 watcher / 队列 / sink 均已装配。
	if deps.codecs == nil || deps.codecs.Session == nil || deps.codecs.Login == nil ||
		deps.codecs.Ticket == nil || deps.codecs.Cookie == nil || deps.codecs.SyncPayload == nil {
		t.Fatalf("五把密钥 codec 未装配完整: %+v", deps.codecs)
	}
	if deps.settings == nil {
		t.Error("settings.Store 未装配")
	}
	if deps.watcher == nil {
		t.Error("settings.Watcher 未启动")
	}
	if deps.queue == nil {
		t.Error("asyncqueue.Queue 未装配")
	}
	if deps.sink == nil {
		t.Error("service.LoginEventWriter 未装配")
	}

	// 幂等：复跑整条 assemble（migrate up 版本已最新时秒过，§3.16）。
	deps2, err := assemble(ctx, cfg)
	if err != nil {
		t.Fatalf("复跑 assemble 不幂等: %v", err)
	}
	t.Cleanup(func() { closeDeps(deps2) })
}

// —— 以下为监听口径测试（§3.1 行 244-245：Go 1.26 标准库原生
// http.Server.Protocols，三模式）与 http.Server 装配断言 ——

// h2cPreface HTTP/2 客户端连接前言（RFC 7540 连接前言的 magic 部分；
// 服务端在读到前言后即回首个 SETTINGS 帧，据此验证明文 h2c / TLS h2
// 通路真实建立——客户端直接发 PRI * HTTP/2.0 前置知识请求）。
const h2cPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// h2FrameTypeSettings HTTP/2 帧类型：SETTINGS（RFC 7540 §6.5）——服务端
// 收到前言后首个下行帧。
const h2FrameTypeSettings = 0x04

// genSelfSignedCert 测试内生成自签证书（ecdsa P-256，SAN 含 127.0.0.1），
// 落 t.TempDir——证书仅测试内生成、不进仓库。
func genSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509 cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// serveAndReadH2Settings 在 ln 上运行 srv（h2c 用 Serve、TLS 用 ServeTLS
// ——certFile/keyFile 为证书路径），客户端发 HTTP/2 连接前言后读服务端
// 首个下行帧，断言为 SETTINGS——三模式监听测试的共同实证（帧头 9 字节：
// 长度 3 + 类型 1 + 标志 1 + 流 ID 4，RFC 7540 §4.1）。tlsConf 为 nil 即
// 明文 h2c 前置知识模式。
func serveAndReadH2Settings(t *testing.T, srv *http.Server, ln net.Listener, tlsConf *tls.Config, certFile, keyFile string) {
	t.Helper()
	go func() {
		if tlsConf != nil {
			_ = srv.ServeTLS(ln, certFile, keyFile)
		} else {
			_ = srv.Serve(ln)
		}
	}()

	dialAddr := ln.Addr().String()
	var conn net.Conn
	var err error
	if tlsConf != nil {
		dialer := &tls.Dialer{Config: tlsConf, NetDialer: &net.Dialer{Timeout: 2 * time.Second}}
		conn, err = dialer.DialContext(context.Background(), "tcp", dialAddr)
	} else {
		conn, err = net.DialTimeout("tcp", dialAddr, 2*time.Second)
	}
	if err != nil {
		t.Fatalf("dial %s: %v", dialAddr, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(h2cPreface)); err != nil {
		t.Fatalf("write h2 preface: %v", err)
	}
	var hdr [9]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read first server frame header: %v", err)
	}
	if hdr[3] != h2FrameTypeSettings {
		t.Errorf("first server frame type = 0x%02x, want 0x%02x (SETTINGS)", hdr[3], h2FrameTypeSettings)
	}
}

// TestListenModeH2CPriorKnowledge 三模式之一（§3.1 行 244）：未配 cert+key
// → 明文 HTTP/1.1 + H2C——客户端直接发 `PRI * HTTP/2.0` 前置知识请求能通
// （服务端回 SETTINGS 帧）。
func TestListenModeH2CPriorKnowledge(t *testing.T) {
	cfg := &config.Config{
		Server:   config.ServerConfig{Listen: ":0"},
		Authloft: config.AuthloftConfig{Root: "https://authloft.example.com", RpID: "r"},
	}
	srv, err := newHTTPServer(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("newHTTPServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serveAndReadH2Settings(t, srv, ln, nil, "", "")
}

// TestListenModeTLSALPNH2 三模式之二（§3.1 行 244）：已配 cert+key →
// HTTP/1.1(TLS) + H2(TLS)——TLS ALPN 协商到 h2 且 H2 通路能通（前置知识
// 前言到达后服务端回 SETTINGS 帧；协商协议为 h2 直接实证）。
func TestListenModeTLSALPNH2(t *testing.T) {
	certPath, keyPath := genSelfSignedCert(t)
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:        ":0",
			MinTLSVersion: "1.3",
			CertFile:      certPath,
			KeyFile:       keyPath,
		},
		Authloft: config.AuthloftConfig{Root: "https://authloft.example.com", RpID: "r"},
	}
	srv, err := newHTTPServer(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("newHTTPServer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	tlsConf := &tls.Config{NextProtos: []string{"h2"}, InsecureSkipVerify: true}
	serveAndReadH2Settings(t, srv, ln, tlsConf, certPath, keyPath)

	// ALPN 协商结果为 h2 的直接实证：独立握手读 ConnectionState。
	conn, err := tls.Dial("tcp", ln.Addr().String(), tlsConf)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Errorf("ALPN negotiated = %q, want h2", got)
	}
}

// TestListenModeTLSMinVersionRejectsOld 三模式之三（§3.1 行 244、§3.2
// 约定 5）：min_tls_version="1.2" 时 TLS1.0 / TLS1.1 握手失败；TLS1.2
// 在下限之上握手成功。
func TestListenModeTLSMinVersionRejectsOld(t *testing.T) {
	certPath, keyPath := genSelfSignedCert(t)
	cfg := &config.Config{
		Server: config.ServerConfig{
			Listen:        ":0",
			MinTLSVersion: "1.2",
			CertFile:      certPath,
			KeyFile:       keyPath,
		},
		Authloft: config.AuthloftConfig{Root: "https://authloft.example.com", RpID: "r"},
	}
	srv, err := newHTTPServer(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatalf("newHTTPServer: %v", err)
	}
	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLSConfig.MinVersion = %v, want tls.VersionTLS12", srv.TLSConfig)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() { _ = srv.ServeTLS(ln, certPath, keyPath) }()

	for _, maxVer := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{
			MaxVersion:         maxVer,
			InsecureSkipVerify: true,
		})
		if err == nil {
			conn.Close()
			t.Errorf("TLS max version %d handshake must fail under min_tls_version 1.2", maxVer)
		}
	}
	// TLS1.2 在下限之上：握手成功。
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Errorf("TLS 1.2 handshake should succeed, got %v", err)
	} else {
		conn.Close()
	}
}

// —— Connect 前缀链全等效（requestid → logger → metrics → origin，
// §3.3 行 304）——Connect 域流量计入 /metrics 与访问日志的装配层实证 ——

// connectTestHandler 构造带已注册 Connect service 的顶层分流 handler
// （与生产 buildHandler 同链：mux 前缀 requestid → logger → metrics →
// origin → handler）。
func connectTestHandler(t *testing.T, csrv *connect.Server) http.Handler {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h, _ := buildHandler(&config.Config{
		Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com"},
	}, csrv)
	return h
}

// metricsRequestsTotal 从 /metrics 文本读 requests_total。/metrics 挂 gin
// 全局链（读取请求自身也被 gin 版 Metrics 计数），读数是 handler 执行时的
// 快照、不含本次读请求自身——增量断言须把上一次读请求算进去。
func metricsRequestsTotal(t *testing.T, h http.Handler) int {
	t.Helper()
	rec := doRequest(h, http.MethodGet, "/metrics", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics: status = %d, want %d", rec.Code, http.StatusOK)
	}
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if v, ok := strings.CutPrefix(line, "requests_total "); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				t.Fatalf("parse requests_total %q: %v", v, err)
			}
			return n
		}
	}
	t.Fatalf("/metrics body missing requests_total: %q", rec.Body.String())
	return 0
}

// TestConnectDomainMetricsAndAccessLog Connect 域流量计入 /metrics 与访问
// 日志（ServeMux 分流后 Connect 请求不经 gin 全局链，但前缀链
// HTTPMetrics 与 gin 版 Metrics 共用同一组包级原子变量——读 /metrics 文本
// 断言 Connect 请求（origin 403 拒绝与 200 放行均计）真实计入；访问日志由
// HTTPLogger 输出（与 gin 版共用 logAccess），含 request_id / method /
// path / status 且 request_id 与响应头一致。
func TestConnectDomainMetricsAndAccessLog(t *testing.T) {
	lc := &accessLogCap{}
	old := slog.Default()
	slog.SetDefault(slog.New(lc))
	t.Cleanup(func() { slog.SetDefault(old) })

	csrv := connect.NewServer(1 << 20)
	csrv.Register("/api.test.v1.TService/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h := connectTestHandler(t, csrv)

	// 基线读数（本读请求完成后再 +1，不进自身读数快照）。
	base := metricsRequestsTotal(t, h)

	// 无 Origin 写请求 → 前缀链 origin 403（metrics 照计数、logger 记 403）。
	rec403 := doRequest(h, http.MethodPost, "/api.test.v1.TService/Do", nil)
	if rec403.Code != http.StatusForbidden {
		t.Fatalf("no origin: status = %d, want %d (body %s)", rec403.Code, http.StatusForbidden, rec403.Body.String())
	}
	if rec403.Header().Get("X-Request-Id") == "" {
		t.Error("X-Request-Id is empty on 403, want non-empty (requestid 等效)")
	}

	// 同源 → 200 ×2（HTTPMetrics 每请求 +1）。
	var lastID string
	for i := 0; i < 2; i++ {
		rec := doRequest(h, http.MethodPost, "/api.test.v1.TService/Do", map[string]string{
			"Origin": assembledRootOrigin, "Content-Type": "application/json",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("connect success %d: status = %d, want %d", i, rec.Code, http.StatusOK)
		}
		lastID = rec.Header().Get("X-Request-Id")
	}
	if lastID == "" {
		t.Fatal("X-Request-Id is empty on connect success")
	}

	// /metrics 增量 = 3 次 Connect 请求（403 也计）+ 1 次基线读自身完成。
	after := metricsRequestsTotal(t, h)
	if after-base != 4 {
		t.Errorf("requests_total delta = %d, want 4 (3 次 connect 请求 + 1 次基线读自身；base=%d after=%d)", after-base, base, after)
	}

	// 访问日志：403 与 200 各有 Connect 访问记录，request_id/method/status 正确。
	var got403, got200WithID bool
	for _, attrs := range lc.attrs {
		if attrs["path"] != "/api.test.v1.TService/Do" {
			continue
		}
		switch attrs["status"] {
		case "403":
			got403 = true
			if attrs["request_id"] == "" {
				t.Error("403 access log request_id is empty, want non-empty")
			}
			if attrs["method"] != http.MethodPost {
				t.Errorf("403 access log method = %q, want POST", attrs["method"])
			}
		case "200":
			if attrs["request_id"] == lastID {
				got200WithID = true
			}
		}
	}
	if !got403 {
		t.Errorf("no access record with status 403 for connect request: %v", lc.attrs)
	}
	if !got200WithID {
		t.Errorf("no access record with status 200 and request_id %q: %v", lastID, lc.attrs)
	}
}

// TestConnectDomainPanicRequestCounted panic 的 Connect 请求也计数
// （HTTPMetrics defer 累加，§3.3 行 302）：生产路径 panic 由 connect-go
// WithRecover 在 handler 内归一为正常返回（defer 照常执行）；本用例注册
// 裸 handler 模拟 panic 穿过前缀链 unwind（http.Server 连接级恢复），
// defer 同样计数。
func TestConnectDomainPanicRequestCounted(t *testing.T) {
	csrv := connect.NewServer(1 << 20)
	csrv.Register("/api.boom.v1.Boom/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		panic("connect boom")
	}))
	h := connectTestHandler(t, csrv)

	base := metricsRequestsTotal(t, h)
	func() {
		defer func() { _ = recover() }() // 模拟连接级恢复：panic 已穿过前缀链 HTTPMetrics 的 defer
		doRequest(h, http.MethodPost, "/api.boom.v1.Boom/Do", map[string]string{
			"Origin": assembledRootOrigin, "Content-Type": "application/json",
		})
	}()
	after := metricsRequestsTotal(t, h)
	if after-base != 2 { // 1 次 panic 请求 + 1 次基线读自身完成
		t.Errorf("requests_total delta = %d, want 2 (panic 请求也计数；base=%d after=%d)", after-base, base, after)
	}
}

// TestNewHTTPServerTLSProtocols http.Server 装配的 TLS 形态（§3.1 行 245）：
// 已配 cert+key → Protocols 为 HTTP/1.1 + H2(TLS)（SetHTTP1 + SetHTTP2，
// 不含 UnencryptedHTTP2）；min_tls_version "1.3" → TLSConfig.MinVersion =
// VersionTLS13、"1.2" → VersionTLS12、空 → TLSConfig nil（标准库默认）；
// 非法取值 fail-fast（正常路径在 config.Validate 已拦，防自造实例绕过）。
func TestNewHTTPServerTLSProtocols(t *testing.T) {
	certPath, keyPath := genSelfSignedCert(t)
	baseCfg := func() *config.Config {
		return &config.Config{
			Server: config.ServerConfig{
				Listen:   ":0",
				CertFile: certPath,
				KeyFile:  keyPath,
			},
			Authloft: config.AuthloftConfig{Root: "https://authloft.example.com", RpID: "r"},
		}
	}

	cfg := baseCfg()
	cfg.Server.MinTLSVersion = "1.3"
	srv, err := newHTTPServer(cfg, http.NotFoundHandler())
	if err != nil {
		t.Fatalf("newHTTPServer: %v", err)
	}
	if !srv.Protocols.HTTP1() || !srv.Protocols.HTTP2() || srv.Protocols.UnencryptedHTTP2() {
		t.Errorf("tls mode: Protocols = HTTP1:%v HTTP2:%v UH2:%v, want true/true/false", srv.Protocols.HTTP1(), srv.Protocols.HTTP2(), srv.Protocols.UnencryptedHTTP2())
	}
	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("TLSConfig.MinVersion = %v, want tls.VersionTLS13", srv.TLSConfig)
	}

	cfg = baseCfg()
	cfg.Server.MinTLSVersion = "1.2"
	srv, err = newHTTPServer(cfg, http.NotFoundHandler())
	if err != nil {
		t.Fatalf("newHTTPServer (1.2): %v", err)
	}
	if srv.TLSConfig == nil || srv.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLSConfig.MinVersion = %v, want tls.VersionTLS12", srv.TLSConfig)
	}

	// min 为空 → 标准库默认（不设 TLSConfig）。
	cfg = baseCfg()
	srv, err = newHTTPServer(cfg, http.NotFoundHandler())
	if err != nil {
		t.Fatalf("newHTTPServer (default min): %v", err)
	}
	if srv.TLSConfig != nil {
		t.Errorf("TLSConfig = %+v, want nil for empty min_tls_version", srv.TLSConfig)
	}

	// 非法取值 → fail-fast（配 cert+key 使映射真正走到非法分支）。
	cfg = baseCfg()
	cfg.Server.MinTLSVersion = "bogus"
	if _, err := newHTTPServer(cfg, http.NotFoundHandler()); err == nil {
		t.Error("bogus min_tls_version must fail-fast")
	}
}
