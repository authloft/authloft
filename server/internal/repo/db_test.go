// repo 包 DB 初始化测试：非法 / 不可达 DSN 的 fail-fast 用例本地
// 可跑；真连用例 skip-on-no-env（UC_TEST_DB_DRIVER + UC_TEST_DB_DSN，
// 兼容读 UC_TEST_MYSQL_DSN），只 ping 不动任何表，无需清理。连接串只经
// 环境变量注入，代码不含主机 / 凭证信息。
package repo

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"authloft/internal/config"
)

// TestOpenBadDSN：DSN 结构非法（缺库名分隔符）→ "db: dsn" 错误，fail-fast
// 在解析期而非连接期。
func TestOpenBadDSN(t *testing.T) {
	_, err := Open(dbTestConfig(config.DriverMySQL, "not a dsn", 5, 2, time.Minute))
	if err == nil || !strings.Contains(err.Error(), "db: dsn") {
		t.Fatalf("err = %v, want \"db: dsn\" prefixed error", err)
	}
}

// TestOpenUnreachable：DB 不可达（保留端口 + 短超时）→ Open 建连后 ping
// 失败，返回 "db: open" 前缀错误。
func TestOpenUnreachable(t *testing.T) {
	_, err := Open(dbTestConfig(config.DriverMySQL, "test:123456@tcp(127.0.0.1:1)/test?timeout=500ms", 5, 2, time.Minute))
	if err == nil || !strings.Contains(err.Error(), "db: open") {
		t.Fatalf("err = %v, want \"db: open\" prefixed error", err)
	}
}

// TestOpenReal（env-skip）：真连测试实例（mysql 方言）——Open 成功、ping
// 通、连接池 MaxOpen / MaxIdle 两项按 cfg 注入（Stats 可观测项）。
func TestOpenReal(t *testing.T) {
	target := requireTestDB(t, config.DriverMySQL)
	db, err := Open(dbTestConfig(target.driver, target.dsn, 7, 3, time.Minute))
	if err != nil {
		t.Fatalf("Open 真连失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	st := db.Stats()
	if st.MaxOpenConnections != 7 {
		t.Errorf("MaxOpenConnections = %d, want 7", st.MaxOpenConnections)
	}
	// MaxIdleConns / ConnMaxLifetime 无运行期 getter（*sql.DB 只写不读），
	// 由 Open 的 Set 调用与代码审阅保证，不在运行期断言。
}

// TestOpenUnknownDriver：未知 driver 在工厂即报错（fail-fast 前置到建连），
// 错误带 Open 的 "db: dsn" 前缀（工厂只可能因 DSN 解析 / driver 非法报错）。
func TestOpenUnknownDriver(t *testing.T) {
	cfg := dbTestConfig(config.Driver("sqlite"), "test:123456@tcp(127.0.0.1:1)/test", 5, 2, time.Minute)
	_, err := Open(cfg)
	if err == nil || !strings.Contains(err.Error(), "db: dsn") {
		t.Fatalf("err = %v, want \"db: dsn\" prefixed error", err)
	}
}

// TestOpenPostgresUnreachable：PG 不可达（保留端口 1，连接拒绝即时返回）
// → Open 建连后 ping 失败，返回 "db: open" 前缀错误——与 mysql 路径同一
// fail-fast 口径。
func TestOpenPostgresUnreachable(t *testing.T) {
	cfg := dbTestConfig(config.DriverPostgres, "postgres://authloft:pass@127.0.0.1:1/authloft?sslmode=disable", 5, 2, time.Minute)
	_, err := Open(cfg)
	if err == nil || !strings.Contains(err.Error(), "db: open") {
		t.Fatalf("err = %v, want \"db: open\" prefixed error", err)
	}
}

// TestOpenPostgresReal（env-skip，激活方言为 postgres 时实跑）：Open 的
// postgres 路径全链路（工厂 + pgdialect 叠层 + 慢查钩子 + 连接池参数）。
func TestOpenPostgresReal(t *testing.T) {
	target := requireTestDB(t, config.DriverPostgres)
	db, err := Open(dbTestConfig(target.driver, target.dsn, 5, 2, time.Minute))
	if err != nil {
		t.Fatalf("Open postgres 真连失败: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

// TestSQLLoggerIgnoresErrNoRows：可选单行查询查无行属业务预期，不得产生
// 日志；真实 SQL 错误仍须记录；慢查询按阈值告警。
func TestSQLLoggerIgnoresErrNoRows(t *testing.T) {
	buf := &strings.Builder{}
	h := newSQLLogger(buf)
	fc := "SELECT * FROM user_credential LIMIT 1"

	h.AfterQuery(context.Background(), &bun.QueryEvent{
		StartTime: time.Now(), Query: fc, Err: sql.ErrNoRows,
	})
	if buf.Len() != 0 {
		t.Errorf("查无行不应输出日志, got %q", buf.String())
	}

	h.AfterQuery(context.Background(), &bun.QueryEvent{
		StartTime: time.Now(), Query: "SELECT 1",
		Err: errors.New("dial tcp: connection refused"),
	})
	if !strings.Contains(buf.String(), "connection refused") {
		t.Errorf("真实 SQL 错误应记录, got %q", buf.String())
	}

	buf.Reset()
	h.AfterQuery(context.Background(), &bun.QueryEvent{
		StartTime: time.Now().Add(-2 * slowQueryThreshold), Query: "SELECT 1",
	})
	if !strings.Contains(buf.String(), "SLOW SQL") {
		t.Errorf("慢查询应告警, got %q", buf.String())
	}
}
