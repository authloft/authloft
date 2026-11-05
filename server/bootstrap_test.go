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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/asyncqueue"
	"authloft/internal/cache"
	"authloft/internal/config"
	"authloft/internal/connect"
	"authloft/internal/eventlog"
	"authloft/internal/factor"
	"authloft/internal/oidc"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/service"
	"authloft/internal/session"
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
// assemble 链消费 DB / Redis / sign_key 五键 / authloft（buildEngine 里
// webauthn 的 RPID 与 RPOrigins）；oidc.jwt_keys 按 §3.2 约定 6（安装期
// 写入后 Validate 必填）一并填齐，接线后夹具无需再改。测试内生成密钥，
// fail-fast 校验是既定口径——修夹具不放宽校验。server / argon2 / log
// 链不消费，零值即可。
func assembleConfig(t *testing.T, dsn, redisAddr string) *config.Config {
	t.Helper()
	return &config.Config{
		DB: config.DBConfig{
			DSN:             dsn,
			MaxOpenConns:    10,
			MaxIdleConns:    5,
			ConnMaxLifetime: config.Duration{Duration: time.Minute},
		},
		Redis:    config.RedisConfig{Addr: redisAddr, DB: 0, PoolSize: 10},
		Authloft: config.AuthloftConfig{Root: "https://authloft.example.com", RpID: "authloft.example.com"},
		SignKey:  testSignKeyConfig(t),
		OIDC: config.OIDCConfig{
			JWTKeys: []config.OIDCKey{{Kid: "1", PrivateKeyPEM: testOIDCKeyPEM()}},
		},
	}
}

// testOIDCKeyPEM 返回一次现场生成并缓存的合法 OIDC 签名私钥
// （std base64(PKCS#8 RSA 2048 PEM)，§3.2 约定 6：与对称 sign_key 严格
// 分离）。与 internal/config 包 config_test.go 的 testOIDCKey 同口径
// （跨包私有不共享，保持同口径副本）；测试内生成，私钥字面量不落仓库。
func testOIDCKeyPEM() string {
	testOIDCKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			testOIDCKeyErr = err
			return
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			testOIDCKeyErr = err
			return
		}
		testOIDCKeyVal = base64.StdEncoding.EncodeToString(
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	})
	if testOIDCKeyErr != nil {
		panic(testOIDCKeyErr) // 夹具初始化失败即快速失败
	}
	return testOIDCKeyVal
}

var (
	testOIDCKeyOnce sync.Once
	testOIDCKeyVal  string
	testOIDCKeyErr  error
)

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
	cfg := assembleConfig(t, "test:123456@tcp(127.0.0.1:1)/test?timeout=500ms", "127.0.0.1:1")
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
// Engine（不连 DB / Redis）：断言 6 个已实现 kind（含 otp_sms /
// otp_email）可解析、pending 2 条（thirdparty / device）不参与完整性断言、
// Terminal 五注入均非 nil（§3.8 行 390、§7.3 行 983-1004）。
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
		// 共享单例由调用方构造注入（不连外部服务，rdb / repo 传
		// nil 与生产 assemble 注入真源同构）；otp 发送桥还需要
		// providerLoader（settings 键 → Loader → NewSender）。
		providerLoader: provider.NewLoader(repo.NewProviderRepo(nil), nil, provider.LoaderOptions{}),
		sessionTokens:  session.NewTokens(codecs.Session),
		epochStore:     cache.NewEpochStore(nil, nil),
		codeIssuer:     oidc.NewCodeIssuer(cache.NewOIDCCodeStore(nil), codecs.Ticket),
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
		factor.FactorOTPSMS, factor.FactorOTPEmail,
	} {
		if _, err := registry.Get(kind); err != nil {
			t.Fatalf("Get(%s): %v", kind, err)
		}
	}
	// pendingKinds 剩 thirdparty / device 两条（otp 两条已解锁）。
	for _, kind := range []factor.FactorKind{
		factor.FactorThirdParty, factor.FactorDevice,
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

// TestBuildEngineWebauthnDegraded D6 / §8.3 行 1069 启动期初始化失败降级：
// rp_id 为 IP（合法 config 形态——config.Validate 只查非空，管理员手工改
// config 的场景）导致 webauthn.New 库 RPID 校验失败时，buildEngine **不报
// 错**（程序不退出、其余功能可用）：webauthn 不注册进注册表（Get 返回
// ErrKindNotRegistered——登录方式列表与 MFA 开放集合随之不含 webauthn，
// dispatch 对未注册 kind 返回 method_disabled），其余五因子正常注册，
// AssertComplete 仅以降级清单显式放行 webauthn 时通过。
func TestBuildEngineWebauthnDegraded(t *testing.T) {
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
		codecs:         codecs,
		settings:       settings.NewStore(nil, nil),
		queue:          q,
		sink:           service.NewLoginEventWriter(eventlog.NewWriter(q)),
		providerLoader: provider.NewLoader(repo.NewProviderRepo(nil), nil, provider.LoaderOptions{}),
		sessionTokens:  session.NewTokens(codecs.Session),
		epochStore:     cache.NewEpochStore(nil, nil),
		codeIssuer:     oidc.NewCodeIssuer(cache.NewOIDCCodeStore(nil), codecs.Ticket),
	}
	// rp_id 为 IP：go-webauthn 库校验拒绝（must be a domain and not an IP）。
	cfg := &config.Config{
		Authloft: config.AuthloftConfig{Root: "https://192.168.10.2:8080", RpID: "192.168.10.2"},
	}

	engine, terminal, registry, err := buildEngine(cfg, deps, repo.NewUserRepo(nil), repo.NewCredentialRepo(nil), repo.NewWebauthnRepo(nil))
	if err != nil {
		t.Fatalf("buildEngine must degrade instead of failing (D6): %v", err)
	}
	if engine == nil || terminal == nil || registry == nil {
		t.Fatal("buildEngine must return non-nil engine / terminal / registry")
	}

	// webauthn 因子未注册（禁用），其余五因子正常。
	if _, err := registry.Get(factor.FactorWebAuthn); !errors.Is(err, factor.ErrKindNotRegistered) {
		t.Fatalf("Get(webauthn) err = %v, want ErrKindNotRegistered (degraded)", err)
	}
	for _, kind := range []factor.FactorKind{
		factor.FactorPassword, factor.FactorTOTP, factor.FactorRecovery,
		factor.FactorOTPSMS, factor.FactorOTPEmail,
	} {
		if _, err := registry.Get(kind); err != nil {
			t.Errorf("Get(%s): %v (degradation must not affect other factors)", kind, err)
		}
	}
	// 完整性断言：无参（全量）仍报缺失 webauthn，仅降级清单放行时通过。
	if err := registry.AssertComplete(); !errors.Is(err, factor.ErrRegistryIncomplete) {
		t.Fatalf("AssertComplete() err = %v, want ErrRegistryIncomplete (webauthn truly missing)", err)
	}
	if err := registry.AssertComplete(factor.FactorWebAuthn); err != nil {
		t.Fatalf("AssertComplete(webauthn) err = %v, want nil (degraded kind excluded)", err)
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

	cfg := assembleConfig(t, dsn, addr)
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

// doPostForm 发 application/x-www-form-urlencoded POST（OIDC 端点唯一
// Content-Type 例外，接口文档 §4.3），装配测试用。
func doPostForm(h http.Handler, target string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// decodeOIDCJSON 解出 OIDC 端点响应体顶层 JSON（原生格式，无 §1.0 信封）。
func decodeOIDCJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal oidc body %q: %v", rec.Body.String(), err)
	}
	return body
}

// buildWiredDeps 构造不连库的完整装配产物（接线测试共用）：
// 共享单例（sessionTokens / epochStore / codeIssuer）+ RS256 JWT + 登录
// 单引擎，db 留 nil——测试只打不碰库的端点路径（discovery / JWKS /
// 空表单 400 / 空 client_id 401，均在查库前返回）。
func buildWiredDeps(t *testing.T, cfg *config.Config) *assembled {
	t.Helper()
	codecs, err := buildCodecs(&config.Config{SignKey: testSignKeyConfig(t)})
	if err != nil {
		t.Fatalf("buildCodecs: %v", err)
	}
	q := asyncqueue.New(noopExecutor{}, asyncqueue.Options{
		Capacity: 8, Workers: 1, BatchSize: 8, FlushInterval: time.Hour,
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = q.Close(ctx)
	})
	deps := &assembled{
		codecs:         codecs,
		settings:       settings.NewStore(nil, nil),
		queue:          q,
		sink:           service.NewLoginEventWriter(eventlog.NewWriter(q)),
		providerLoader: provider.NewLoader(repo.NewProviderRepo(nil), nil, provider.LoaderOptions{}),
		sessionTokens:  session.NewTokens(codecs.Session),
		epochStore:     cache.NewEpochStore(nil, nil),
		codeIssuer:     oidc.NewCodeIssuer(cache.NewOIDCCodeStore(nil), codecs.Ticket),
	}
	engine, _, _, err := buildEngine(cfg, deps, repo.NewUserRepo(nil), repo.NewCredentialRepo(nil), repo.NewWebauthnRepo(nil))
	if err != nil {
		t.Fatalf("buildEngine: %v", err)
	}
	deps.engine = engine
	// iss = authloft.root（§14.1 行 1626 与 discovery 逐字相同）。
	deps.oidcJWT, err = oidc.NewJWT([]config.OIDCKey{{Kid: "1", PrivateKeyPEM: testOIDCKeyPEM()}}, cfg.Authloft.Root)
	if err != nil {
		t.Fatalf("oidc.NewJWT: %v", err)
	}
	return deps
}

// TestOIDCRoutesWired：OIDC REST 端点经 buildHandlerWithSSO 注册
// 到 gin 链、不经 Connect、不套 §1.0 信封——discovery / JWKS 200 原生 JSON、
// token 空表单 400 RFC 错误体、revoke 空 client_id 401；X-Request-Id 由 gin
// 链 requestid 统一回写（§1.1）。
func TestOIDCRoutesWired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com"}}
	deps := buildWiredDeps(t, cfg)
	h, _ := buildHandlerWithSSO(cfg, connect.NewServer(defaultReadMaxBytes), deps)

	// discovery：200，issuer 与 JWT iss 逐字相同（§14.1）。
	rec := doRequest(h, http.MethodGet, "/.well-known/openid-configuration", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if got := decodeOIDCJSON(t, rec)["issuer"]; got != assembledRootOrigin {
		t.Errorf("discovery issuer = %v, want %q", got, assembledRootOrigin)
	}

	// JWKS：200，发布列表内密钥公钥（kid "1"、RS256，§14.1 行 1627）。
	rec = doRequest(h, http.MethodGet, "/.well-known/jwks.json", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("jwks: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"RS256"`) || !strings.Contains(rec.Body.String(), `"1"`) {
		t.Errorf("jwks body missing RS256 / kid: %s", rec.Body.String())
	}

	// token：空表单 → 400，RFC 6749 错误体 error=invalid_request（grant_type
	// 缺失，不碰库即返回）。
	rec = doPostForm(h, "/api/oidc/token", url.Values{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("token empty form: status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if got := decodeOIDCJSON(t, rec)["error"]; got != "invalid_request" {
		t.Errorf("token error = %v, want invalid_request (RFC 错误体)", got)
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("token 400 response missing X-Request-Id (gin 链 requestid)")
	}

	// revoke：client_id 缺失 → 401 invalid_client（RFC 7009 回落 RFC 6749
	// §5.2，revoker.go 行 42 在查库前返回）。
	rec = doPostForm(h, "/api/oidc/revoke", url.Values{"token": {"x"}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoke empty client: status = %d, want 401 (body %s)", rec.Code, rec.Body.String())
	}
	if got := decodeOIDCJSON(t, rec)["error"]; got != "invalid_client" {
		t.Errorf("revoke error = %v, want invalid_client", got)
	}
}

// TestAssembleAccountRoutesWired：AccountService Connect handler 经
// buildHandlerWithSSO 挂入顶层 ServeMux 前缀链（registerAccount）——路由
// 前缀已注册（handler 非 nil 的装配等效断言）；无会话 GetProfile 穿透
// origin 前缀链 + session 拦截器抵达 handler，返回 401 unauthenticated
// （§1.2 行 96 全接口需 al_session；拦截器对匿名放行、401 由 handler 判定）；
// UpdateProfile 为生成 Unimplemented 桩。
func TestAssembleAccountRoutesWired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com"}}
	deps := buildWiredDeps(t, cfg)
	csrv := connect.NewServer(defaultReadMaxBytes)
	h, _ := buildHandlerWithSSO(cfg, csrv, deps)

	// 装配断言：account 域前缀已注册（sso 域零回归仍在）。
	var hasAccount, hasSSO bool
	for _, rt := range csrv.Routes() {
		if rt.Prefix == "/api.account.v1.AccountService/" {
			hasAccount = true
		}
		if rt.Prefix == "/api.sso.v1.SsoService/" {
			hasSSO = true
		}
	}
	if !hasAccount {
		t.Fatal("AccountService 路由未注册（registerAccount 未挂载）")
	}
	if !hasSSO {
		t.Error("SsoService 路由丢失（registerSSO 零回归）")
	}

	// doPostJSON 打带空 JSON 对象 body 的同源 Connect 请求（doRequest 不带
	// body，connect-go 对 zero-length JSON 请求体报 invalid_argument）。
	doPostJSON := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader("{}"))
		req.Header.Set("Origin", assembledRootOrigin)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 无会话 GetProfile → 401 unauthenticated（路由可达：非 404 / 403）。
	rec := doPostJSON("/api.account.v1.AccountService/GetProfile")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GetProfile without session: status = %d, want %d (body %s)", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if got := decodeOIDCJSON(t, rec)["code"]; got != "unauthenticated" {
		t.Errorf("GetProfile code = %v, want unauthenticated (body %s)", got, rec.Body.String())
	}

	// UpdateProfile（本卡桩）→ unimplemented。
	rec = doPostJSON("/api.account.v1.AccountService/UpdateProfile")
	if got := decodeOIDCJSON(t, rec)["code"]; got != "unimplemented" {
		t.Errorf("UpdateProfile code = %v, want unimplemented (body %s)", got, rec.Body.String())
	}
}

// TestAssembleAdminRoutesWired：AdminService Connect handler 经
// buildHandlerWithSSO 挂入顶层 ServeMux 前缀链（registerAdmin）——admin 前缀
// 已注册且 handler 非 nil 的装配断言；无会话请求穿透 origin 前缀链 + session
// 拦截器后被 admin 拦截器拦下 → 401 unauthenticated（§5 行 1145：401 由 admin
// 拦截器判定，与 account 域 handler 自判不同——桩方法匿名同样先 401）；sso /
// account 两域零回归仍在。
func TestAssembleAdminRoutesWired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com"}}
	deps := buildWiredDeps(t, cfg)
	csrv := connect.NewServer(defaultReadMaxBytes)
	h, _ := buildHandlerWithSSO(cfg, csrv, deps)

	// 装配断言：admin 域前缀已注册且 handler 非 nil；sso / account 零回归。
	var hasAdmin, hasAccount, hasSSO bool
	for _, rt := range csrv.Routes() {
		switch rt.Prefix {
		case "/api.admin.v1.AdminService/":
			hasAdmin = rt.Handler != nil
		case "/api.account.v1.AccountService/":
			hasAccount = true
		case "/api.sso.v1.SsoService/":
			hasSSO = true
		}
	}
	if !hasAdmin {
		t.Fatal("AdminService 路由未注册或 handler 为 nil（registerAdmin 未挂载）")
	}
	if !hasAccount {
		t.Error("AccountService 路由丢失（registerAccount 零回归）")
	}
	if !hasSSO {
		t.Error("SsoService 路由丢失（registerSSO 零回归）")
	}

	// doPostJSON 打带空 JSON 对象 body 的同源 Connect 请求（口径同 account 用例）。
	doPostJSON := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader("{}"))
		req.Header.Set("Origin", assembledRootOrigin)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 无会话 ListProviders → 401 unauthenticated（路由可达：非 404 / 403，
	// admin 拦截器判定）。
	rec := doPostJSON("/api.admin.v1.AdminService/ListProviders")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("ListProviders without session: status = %d, want %d (body %s)", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if got := decodeOIDCJSON(t, rec)["code"]; got != "unauthenticated" {
		t.Errorf("ListProviders code = %v, want unauthenticated (body %s)", got, rec.Body.String())
	}

	// GetSettings（桩）匿名同样先被 admin 拦截器 401（拦截链先于 handler 桩）。
	rec = doPostJSON("/api.admin.v1.AdminService/GetSettings")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GetSettings without session: status = %d, want %d (body %s)", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if got := decodeOIDCJSON(t, rec)["code"]; got != "unauthenticated" {
		t.Errorf("GetSettings code = %v, want unauthenticated (body %s)", got, rec.Body.String())
	}
}

// TestAssembleRPCRoutesWired：rpc 域两个 Connect handler（UserService /
// TokenService）经 buildHandlerWithSSO 挂入顶层 ServeMux 前缀链（registerRPC
// → csrv.RegisterRPC，强制包 CaptureRawBody）。缺三头拒绝用例走「读
// GetUserProfile + 写 UpdateUserProfile + DecodeSession 三 procedure × 缺任一
// 头」表驱动：拦截器三头检查先于 nonce 去重 / client 查询 / 签名（§7 行
// 1383），不触达 buildWiredDeps 的 nil db / nil rdb——403 permission_denied
// 即证明路由 + HMAC 拦截器已挂载（403≠404）；rpc 域 origin 免检（§1.1 行
// 79 例外），请求不带 Origin。sso / account / admin 前缀零回归。
func TestAssembleRPCRoutesWired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com"}}
	deps := buildWiredDeps(t, cfg)
	csrv := connect.NewServer(defaultReadMaxBytes)
	h, _ := buildHandlerWithSSO(cfg, csrv, deps)

	// 装配断言：rpc 域两前缀已注册且 handler 非 nil；sso / account / admin 零回归。
	gotPrefix := map[string]bool{}
	for _, rt := range csrv.Routes() {
		gotPrefix[rt.Prefix] = rt.Handler != nil
	}
	for _, prefix := range []string{
		"/api.rpc.v1.UserService/",
		"/api.rpc.v1.TokenService/",
		"/api.sso.v1.SsoService/",
		"/api.account.v1.AccountService/",
		"/api.admin.v1.AdminService/",
	} {
		if !gotPrefix[prefix] {
			t.Errorf("路由 %s 未注册或 handler 为 nil（registerRPC / 零回归断言失败）", prefix)
		}
	}

	// 缺三头拒绝（读 / 写 / DecodeSession 三 procedure × 缺任一头）：JSON 空对象
	// body（connect-go 先解码再进拦截链），不带 Origin（rpc 域免检）。
	doPostJSONNoOrigin := func(target string, headers map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	full := map[string]string{
		"X-Client-ID": "web-1",
		"X-Nonce-ID":  "n-1",
		"X-Signature": "deadbeef",
	}
	for _, procedure := range []string{
		"/api.rpc.v1.UserService/GetUserProfile",
		"/api.rpc.v1.UserService/UpdateUserProfile",
		"/api.rpc.v1.TokenService/DecodeSession",
	} {
		for missing := range full {
			headers := map[string]string{}
			for k, v := range full {
				if k != missing {
					headers[k] = v
				}
			}
			rec := doPostJSONNoOrigin(procedure, headers)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s missing %s: status = %d, want %d (body %s)", procedure, missing, rec.Code, http.StatusForbidden, rec.Body.String())
				continue
			}
			if got := decodeOIDCJSON(t, rec)["code"]; got != "permission_denied" {
				t.Errorf("%s missing %s: code = %v, want permission_denied (body %s)", procedure, missing, got, rec.Body.String())
			}
		}
	}
}

// TestAssembleGatewayRoutesWired：网关域 ANY /api/gateway/decode 经
// buildHandlerWithSSO 注册到 gin 链（registerGateway：/api 组 /gateway 子组 +
// Gateway 中间件）——buildWiredDeps 的 settings 为 NewStore(nil, nil)（种子
// 全量默认值，§5.6 行 1338 gateway_tokens 默认 []）→ 缺 / 任意 X-Gateway-Token
// 均 403 空 body（middleware 保守拒绝 + 豁免端点原生形态，§1.5 行 188；403≠404
// 即证明路由与中间件已挂载）；GET / POST 均 403（ANY 语义）；X-Request-Id 由
// gin 全局链 requestid 回写（§1.1）。sso / account / admin 前缀零回归。
func TestAssembleGatewayRoutesWired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com"}}
	deps := buildWiredDeps(t, cfg)
	csrv := connect.NewServer(defaultReadMaxBytes)
	h, _ := buildHandlerWithSSO(cfg, csrv, deps)

	// 零回归：sso / account / admin 前缀仍在。
	var hasSSO, hasAccount, hasAdmin bool
	for _, rt := range csrv.Routes() {
		switch rt.Prefix {
		case "/api.sso.v1.SsoService/":
			hasSSO = true
		case "/api.account.v1.AccountService/":
			hasAccount = true
		case "/api.admin.v1.AdminService/":
			hasAdmin = true
		}
	}
	if !hasSSO || !hasAccount || !hasAdmin {
		t.Fatalf("sso/account/admin 前缀零回归失败: sso=%v account=%v admin=%v", hasSSO, hasAccount, hasAdmin)
	}

	// 默认 gateway_tokens=[]：任意 / 缺 X-Gateway-Token 均 403 空 body。
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rec := doRequest(h, method, "/api/gateway/decode", map[string]string{"X-Gateway-Token": "whatever"})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s decode: status = %d, want %d (body %s)", method, rec.Code, http.StatusForbidden, rec.Body.String())
		}
		if rec.Body.Len() != 0 {
			t.Errorf("%s decode: body = %q, want empty (403 空体)", method, rec.Body.String())
		}
		if got := rec.Header().Get("X-Request-Id"); got == "" {
			t.Errorf("%s decode: X-Request-Id is empty, want non-empty (gin 全局链回写)", method)
		}
	}
	if rec := doRequest(h, http.MethodGet, "/api/gateway/decode", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("no gateway token: status = %d, want %d (缺凭据同无效)", rec.Code, http.StatusForbidden)
	}
}

// TestAssembleGatewaySettingsHotReload（env-skip 真连）：assemble 全链
//（settings 预热 + watcher）后 deps.settings 即 registerGateway 的
// gateway_tokens 动态源——默认 [] 拒绝；Store.Set 增配 tok-a 即对后续请求
// 放行（200 + X-Session-Status: invalid，会话令牌缺省恒 200）；换配 tok-b 后
// tok-a 失效 / tok-b 放行（每请求经 settings 快照读取，热更只对后续请求
// 生效，§5.6 行 1342）。清理口径同 TestAssembleRealChain。
func TestAssembleGatewaySettingsHotReload(t *testing.T) {
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	addr := os.Getenv("UC_TEST_REDIS_ADDR")
	if dsn == "" || addr == "" {
		t.Skip("UC_TEST_MYSQL_DSN / UC_TEST_REDIS_ADDR 未设置，跳过网关令牌热更真连用例")
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

	cfg := assembleConfig(t, dsn, addr)
	deps, err := assemble(ctx, cfg)
	if err != nil {
		t.Fatalf("装配链失败: %v", err)
	}
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		deps.close(shutCtx)
	})
	h, _ := buildHandlerWithSSO(cfg, connect.NewServer(defaultReadMaxBytes), deps)

	decode := func(gatewayToken string) *httptest.ResponseRecorder {
		headers := map[string]string{}
		if gatewayToken != "" {
			headers["X-Gateway-Token"] = gatewayToken
		}
		return doRequest(h, http.MethodGet, "/api/gateway/decode", headers)
	}

	// 预热默认 gateway_tokens=[] → 任意令牌 403。
	if rec := decode("tok-a"); rec.Code != http.StatusForbidden {
		t.Fatalf("默认空表: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// 增配 tok-a → 后续请求放行（200 + invalid；无会话令牌），未配的 tok-b 仍 403。
	if err := deps.settings.Set(ctx, settings.KeyGatewayTokens, []string{"tok-a"}, 0); err != nil {
		t.Fatalf("settings.Set tok-a: %v", err)
	}
	rec := decode("tok-a")
	if rec.Code != http.StatusOK {
		t.Fatalf("增配后 tok-a: status = %d, want %d (放行)", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("X-Session-Status"); got != "invalid" {
		t.Errorf("X-Session-Status = %q, want invalid (无会话令牌恒 200)", got)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty (纯响应头)", rec.Body.String())
	}
	if rec := decode("tok-b"); rec.Code != http.StatusForbidden {
		t.Errorf("未配置的 tok-b: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// 换配 tok-b → tok-a 失效 / tok-b 放行（热更对后续请求生效）。
	if err := deps.settings.Set(ctx, settings.KeyGatewayTokens, []string{"tok-b"}, 0); err != nil {
		t.Fatalf("settings.Set tok-b: %v", err)
	}
	if rec := decode("tok-a"); rec.Code != http.StatusForbidden {
		t.Errorf("换配后 tok-a: status = %d, want %d (旧令牌失效)", rec.Code, http.StatusForbidden)
	}
	if rec := decode("tok-b"); rec.Code != http.StatusOK {
		t.Errorf("换配后 tok-b: status = %d, want %d (新令牌放行)", rec.Code, http.StatusOK)
	}
}

// TestAssembleHTTPSDeploymentHotReload（env-skip 真连）：assemble
// 装配的 https_deployment 三态源（ssoHTTPSMode 喂 newSessionCookie →
// session 拦截器 / sso 登录终点）每请求读 settings 快照——默认档（迁移后
// 无该键 → 种子 auto）+ httptest 明文请求（无 X-Forwarded-Proto、无 TLS）
// → 拦截器防御性清 Cookie 无 Secure、SameSite=Lax（§1.9 行 292 明文
// 联动）；Store.Set 改 true → 下一请求即 Secure+None（后台改值立即生效，
// §1.9 行 306 逐请求判定，沿 cookie_name 热更口径）。观察点取 account 域
// 任意 Connect 路由无令牌请求——session 拦截器对未登录一律防御性清
// Cookie，Set-Cookie 属性即三态落点，无需构造有效会话。
func TestAssembleHTTPSDeploymentHotReload(t *testing.T) {
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	addr := os.Getenv("UC_TEST_REDIS_ADDR")
	if dsn == "" || addr == "" {
		t.Skip("UC_TEST_MYSQL_DSN / UC_TEST_REDIS_ADDR 未设置，跳过 https_deployment 热更真连用例")
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

	cfg := assembleConfig(t, dsn, addr)
	deps, err := assemble(ctx, cfg)
	if err != nil {
		t.Fatalf("装配链失败: %v", err)
	}
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		deps.close(shutCtx)
	})
	h, _ := buildHandlerWithSSO(cfg, connect.NewServer(defaultReadMaxBytes), deps)

	doClear := func(t *testing.T, hdr map[string]string) *http.Cookie {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api.account.v1.AccountService/GetProfile", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Connect-Protocol-Version", "1")
		req.Header.Set("Origin", assembledRootOrigin) // 同源 POST（CSRF 校验，既有用例口径）
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		for _, ck := range (&http.Response{Header: rec.Header()}).Cookies() {
			if ck.Name == "al_session" {
				return ck
			}
		}
		t.Fatalf("拦截器应防御性清 al_session（无令牌请求），Set-Cookie = %v", rec.Header().Values("Set-Cookie"))
		return nil
	}

	// 默认档 auto + 明文请求（无头无 TLS）→ 兜底明文（省略 Secure + Lax）。
	ck := doClear(t, nil)
	if ck.Secure || ck.SameSite != http.SameSiteLaxMode {
		t.Errorf("auto 明文兜底: Secure=%v SameSite=%v, want false/Lax", ck.Secure, ck.SameSite)
	}
	// auto + X-Forwarded-Proto: https 头（拦截器采集请求头注入信号）→ HTTPS。
	ck = doClear(t, map[string]string{"X-Forwarded-Proto": "https"})
	if !ck.Secure || ck.SameSite != http.SameSiteNoneMode {
		t.Errorf("auto + 头 https: Secure=%v SameSite=%v, want true/None", ck.Secure, ck.SameSite)
	}

	// 后台改 true → 下一请求（无头）立即 Secure+None（每请求读快照）。
	if err := deps.settings.Set(ctx, settings.KeyHttpsDeployment, settings.HTTPSDeploymentTrue, 0); err != nil {
		t.Fatalf("settings.Set https_deployment=true: %v", err)
	}
	ck = doClear(t, nil)
	if !ck.Secure || ck.SameSite != http.SameSiteNoneMode {
		t.Errorf("改 true 后: Secure=%v SameSite=%v, want true/None（热更立即生效）", ck.Secure, ck.SameSite)
	}
	// 后台改 false → 下一请求立即省略 Secure（无视头信号）。
	if err := deps.settings.Set(ctx, settings.KeyHttpsDeployment, settings.HTTPSDeploymentFalse, 0); err != nil {
		t.Fatalf("settings.Set https_deployment=false: %v", err)
	}
	ck = doClear(t, map[string]string{"X-Forwarded-Proto": "https"})
	if ck.Secure || ck.SameSite != http.SameSiteLaxMode {
		t.Errorf("改 false 后应无视头信号恒明文: Secure=%v SameSite=%v", ck.Secure, ck.SameSite)
	}
}

// TestAssembleWiresOIDCAndWhitelist（env-skip 真连）：assemble 装配
// provider 链 / 共享单例 / OIDC JWT 全部产物非 nil；Referer 白名单按 provider
// 数据判定（命中 200 / 未命中 403 两向）；OIDC discovery / jwks / token /
// revoke（真 client 认证 → 200 空 body，RFC 7009）全链可达；sso Connect
// 路由（registerSSO 复用共享单例后）照常挂载。用例开始清空全部表、结束后
// 清空并自证零残留（沿用 TestAssembleRealChain 口径），Redis provider 键
// 随用例清理。
func TestAssembleWiresOIDCAndWhitelist(t *testing.T) {
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

	cfg := assembleConfig(t, dsn, addr)
	deps, err := assemble(ctx, cfg)
	if err != nil {
		t.Fatalf("装配链失败: %v", err)
	}
	closeDeps := func(d *assembled) {
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		d.close(shutCtx)
	}
	t.Cleanup(func() { closeDeps(deps) })

	// 装配产物断言：provider 链 + 共享单例 + OIDC JWT。
	if deps.providerLoader == nil || deps.providerWhitelist == nil {
		t.Fatal("provider Loader / Whitelist 未装配")
	}
	if deps.sessionTokens == nil || deps.epochStore == nil || deps.codeIssuer == nil {
		t.Fatal("sessionTokens / epochStore / codeIssuer 共享单例未装配")
	}
	if deps.oidcJWT == nil {
		t.Fatal("oidcJWT 未装配")
	}
	if got := deps.oidcJWT.Issuer(); got != assembledRootOrigin {
		t.Errorf("oidcJWT issuer = %q, want %q (iss = authloft.root, §14.1)", got, assembledRootOrigin)
	}

	// 插入已启用 wechat_mp provider（Ext.app_id 进 Referer 白名单），
	// bump 版本号使白名单首查即读最新数据（§13.0 / §15.3 版本失效）。
	const wiredAppID = "wxwired0000000001"
	ext, err := repo.MarshalProviderExt(&providerpb.Ext{AppId: wiredAppID})
	if err != nil {
		t.Fatalf("marshal ext: %v", err)
	}
	now := time.Now()
	if err := deps.db.Create(&model.Provider{
		ProviderKey: "wx_test_mp", DisplayName: "Test MP", Category: "oauth",
		Type: "wechat_mp", IsEnabled: 1, Ext: ext, CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	if _, err := cache.NewProviderCache(deps.rdb).BumpVersion(ctx); err != nil {
		t.Fatalf("bump provider version: %v", err)
	}
	t.Cleanup(func() {
		_ = deps.rdb.Del(ctx, cache.ProviderVersionKey(), cache.ProviderRowKey("wx_test_mp")).Err()
	})

	h, apiGroup := buildHandlerWithSSO(cfg, connect.NewServer(defaultReadMaxBytes), deps)
	apiGroup.POST("/probe", ok)

	// Referer 白名单两向：命中已启用 provider 的 appid → 200；未知 appid → 403。
	rec := doRequest(h, http.MethodPost, "/api/probe", map[string]string{
		"Referer": "https://servicewechat.com/" + wiredAppID + "/1/page-frame.html",
	})
	if rec.Code != http.StatusOK {
		t.Errorf("referer with wired appid: status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	rec = doRequest(h, http.MethodPost, "/api/probe", map[string]string{
		"Referer": "https://servicewechat.com/wxunknown00000000/x",
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("referer with unknown appid: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// OIDC 全链：discovery issuer 逐字 = authloft.root。
	rec = doRequest(h, http.MethodGet, "/.well-known/openid-configuration", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery: status = %d, want 200", rec.Code)
	}
	if got := decodeOIDCJSON(t, rec)["issuer"]; got != assembledRootOrigin {
		t.Errorf("discovery issuer = %v, want %q", got, assembledRootOrigin)
	}
	// token 空表单 → 400 RFC 错误体。
	rec = doPostForm(h, "/api/oidc/token", url.Values{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("token empty form: status = %d, want 400", rec.Code)
	}
	if got := decodeOIDCJSON(t, rec)["error"]; got != "invalid_request" {
		t.Errorf("token error = %v, want invalid_request", got)
	}

	// revoke：插入真 oidc_client 后正确 client 认证 → 200 空 body（成功 /
	// 未知 / 已吊销统一 200，RFC 7009 §4.4）；错 secret → 401 invalid_client。
	const (
		oidcClientID     = "cid_wired_test"
		oidcClientSecret = "secret-wired-test"
	)
	if err := deps.db.Create(&model.OidcClient{
		ClientID: oidcClientID, ClientSecret: oidcClientSecret, IsEnabled: 1,
		RedirectURIs: []byte("[]"), Scopes: "openid profile email",
		AccessTokenTTL: 3600, RefreshTokenTTL: 2592000, CreatedAt: now, UpdatedAt: now,
	}).Error; err != nil {
		t.Fatalf("insert oidc_client: %v", err)
	}
	rec = doPostForm(h, "/api/oidc/revoke", url.Values{
		"token": {"unknown-token"}, "client_id": {oidcClientID}, "client_secret": {oidcClientSecret},
	})
	if rec.Code != http.StatusOK {
		t.Errorf("revoke valid client: status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("revoke body = %q, want empty (RFC 7009 不得自造信封)", rec.Body.String())
	}
	rec = doPostForm(h, "/api/oidc/revoke", url.Values{
		"token": {"x"}, "client_id": {oidcClientID}, "client_secret": {"wrong"},
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("revoke wrong secret: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	// sso Connect 路由零回归（registerSSO 复用共享单例后仍正常挂载）：同源
	// 请求穿过 origin 前缀链与 session 拦截器抵达 sso handler——空 body 的
	// 合法 Connect 请求得到非 404 / 非 403 的 Connect 响应（业务错误体）。
	rec = doRequest(h, http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", map[string]string{
		"Origin": assembledRootOrigin, "Content-Type": "application/json",
	})
	if rec.Code == http.StatusNotFound || rec.Code == http.StatusForbidden {
		t.Errorf("sso LoginDefault: status = %d, want non-404/403 (路由可达, body %s)", rec.Code, rec.Body.String())
	}
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
