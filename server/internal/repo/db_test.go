// repo 包 DB 初始化测试：非法 / 不可达 DSN 的 fail-fast 用例本地
// 可跑；真连用例 skip-on-no-env（UC_TEST_MYSQL_DSN），只 ping 不动任何表，
// 无需清理。连接串只经环境变量注入，代码不含主机 / 凭证信息。
package repo

import (
	"os"
	"strings"
	"testing"
	"time"

	"authloft/internal/config"
)

// dbTestConfig 构造只填 DB 段的自造 *config.Config（§3.2 约定 1 / §20：
// 测试传自造实例；Open 只读 DB 段）。
func dbTestConfig(dsn string, maxOpen, maxIdle int, lifetime time.Duration) *config.Config {
	return &config.Config{
		DB: config.DBConfig{
			DSN:             dsn,
			MaxOpenConns:    maxOpen,
			MaxIdleConns:    maxIdle,
			ConnMaxLifetime: config.Duration{Duration: lifetime},
		},
	}
}

// TestOpenBadDSN：DSN 结构非法（缺库名分隔符）→ "db: dsn" 错误，fail-fast
// 在解析期而非连接期。
func TestOpenBadDSN(t *testing.T) {
	_, err := Open(dbTestConfig("not a dsn", 5, 2, time.Minute))
	if err == nil || !strings.Contains(err.Error(), "db: dsn") {
		t.Fatalf("err = %v, want \"db: dsn\" prefixed error", err)
	}
}

// TestOpenUnreachable：DB 不可达（保留端口 + 短超时）→ gorm.Open 自动
// ping 失败，返回 "db: open" 前缀错误。
func TestOpenUnreachable(t *testing.T) {
	_, err := Open(dbTestConfig("test:123456@tcp(127.0.0.1:1)/test?timeout=500ms", 5, 2, time.Minute))
	if err == nil || !strings.Contains(err.Error(), "db: open") {
		t.Fatalf("err = %v, want \"db: open\" prefixed error", err)
	}
}

// TestOpenReal（env-skip）：真连 MariaDB 测试实例——Open 成功、ping 通、
// 连接池 MaxOpen / MaxIdle 两项按 cfg 注入（Stats 可观测项）。
func TestOpenReal(t *testing.T) {
	dsn := os.Getenv("UC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("环境变量 UC_TEST_MYSQL_DSN 未设置，跳过 DB 连接用例")
	}
	db, err := Open(dbTestConfig(dsn, 7, 3, time.Minute))
	if err != nil {
		t.Fatalf("Open 真连失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	st := sqlDB.Stats()
	if st.MaxOpenConnections != 7 {
		t.Errorf("MaxOpenConnections = %d, want 7", st.MaxOpenConnections)
	}
	// MaxIdleConns / ConnMaxLifetime 无运行期 getter（*sql.DB 只写不读），
	// 由 Open 的 Set 调用与代码审阅保证，不在运行期断言。
}
