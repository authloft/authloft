// Package migrate 提供 goose v3 迁移执行、安装判据与统一连接工厂
// （后端架构 §3.16）。
//
// 迁移 SQL 内嵌在 authloft/migrations 包随二进制分发（mysql / postgres
// 两个方言目录，版本号一一对应），版本表沿用 goose 默认的
// goose_db_version（无 dirty 标志：失败的迁移不记版本、重跑即重试同版本）。
// 统一连接工厂（NewDB）按 driver 产出裸 *sql.DB，repo / setup 与本包三处
// 建连共享；goose 方言与嵌入迁移目录按 driver 配对选择，bootstrap / setup
// 生产链路均经 UpDriver 按配置方言执行；Up 保留为存量 mysql 便捷入口
// （测试侧使用）。
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun/driver/pgdriver"

	"authloft/internal/config"
	"authloft/migrations"
)

// ErrCodeMigrationFailed 迁移失败的统一错误码字符串（§3.16：setup 路径
// error.code = migration_failed，细节进 error.message 与服务端日志），
// 由安装流程消费。
const ErrCodeMigrationFailed = "migration_failed"

// errNoSuchTable / pgNoSuchTable 「表不存在」码表：MariaDB 服务端错误码
// ER_NO_SUCH_TABLE（1146）与 PG SQLSTATE undefined_table（42P01）。
const (
	errNoSuchTable = 1146
	pgNoSuchTable  = "42P01"
)

// NewDB 统一连接工厂：按 driver 建立裸 *sql.DB（方言无关，bun / goose 等
// 方言层由调用方叠加）。repo.Open、本包、setup 三处建连共享，禁止再各自
// 内联驱动装配。DSN 结构校验归 config.validateDSN（启动期 fail-fast），
// 连接期错误由调用方 ping 兜底。mysql 路径强制 parseTime=true（见
// normalizeDSN）；pgdriver 原生返回 time.Time，无此问题。
//
// 工厂落位本包而非 repo：repo 的包内测试（*_repo_test.go）import 本包构造
// 测试 schema，repo→migrate 已存在，工厂若在 repo 会令 migrate→repo 成
// 测试期 import cycle；三处建连消费者（repo / setup / migrate）对本包 /
// config 的依赖方向均向下，无环。
func NewDB(driver config.Driver, dsn string) (*sql.DB, error) {
	switch driver {
	case config.DriverMySQL:
		normalized, err := normalizeDSN(dsn)
		if err != nil {
			return nil, err
		}
		return sql.Open("mysql", normalized)
	case config.DriverPostgres:
		return sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn))), nil
	default:
		return nil, fmt.Errorf("unsupported driver %q", driver)
	}
}

// normalizeDSN 规范化 MySQL DSN：强制 parseTime=true（驱动未开 parseTime 时
// 时间列扫描进 time.Time 失败；goose MySQL 方言的版本表存在性检查走
// GetMigration 回退查询，扫描 tstamp 列同样依赖——未开时误判版本表不存在，
// 后续 CREATE 撞 1050 表已存在）。只补参数不改语义。
func normalizeDSN(dsn string) (string, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return "", err
	}
	cfg.ParseTime = true
	return cfg.FormatDSN(), nil
}

// Up 在 dsn 上执行 migrate up（§3.16：幂等——版本已最新时 goose 只读
// 版本表、零变更秒过；单条迁移失败不记版本，重跑即重试同版本）。driver
// 现固定 mysql：存量测试便捷入口；生产链路（bootstrap / setup）走 UpDriver
// 按配置方言执行。
func Up(ctx context.Context, dsn string) error {
	return up(ctx, config.DriverMySQL, dsn)
}

// UpDriver 按 driver 执行 migrate up（bootstrap / setup 生产链路的方言
// 贯通入口；bootstrap 侧取 cfg.DB.EffectiveDriver()，与建连装配同源）。
func UpDriver(ctx context.Context, driver config.Driver, dsn string) error {
	return up(ctx, driver, dsn)
}

// up 按 driver 建连并选 goose 方言执行迁移。
func up(ctx context.Context, driver config.Driver, dsn string) error {
	db, err := NewDB(driver, dsn)
	if err != nil {
		return fmt.Errorf("%s: open: %w", ErrCodeMigrationFailed, err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("%s: ping: %w", ErrCodeMigrationFailed, err)
	}
	if err := gooseUp(ctx, db, driver); err != nil {
		return fmt.Errorf("%s: %w", ErrCodeMigrationFailed, err)
	}
	return nil
}

// Installed 报告系统是否已完成初始化（§3.16 已初始化判据）：
// 迁移版本表已到最新 且 管理员（user.id=1）存在，缺任一即视为未完成。
// 版本表 / 业务表尚不存在视为未初始化，不视为错误。
// driver 现固定 mysql：与 Up 同为存量 mysql 便捷入口（无生产调用方）；
// 生产链路按方言走 up()（内部判据已方言感知）。
func Installed(ctx context.Context, dsn string) (bool, error) {
	db, err := NewDB(config.DriverMySQL, dsn)
	if err != nil {
		return false, fmt.Errorf("open: %w", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return false, fmt.Errorf("ping: %w", err)
	}
	return installed(ctx, db, config.DriverMySQL)
}

// gooseUp 用嵌入的迁移文件把 db 迁移到最新版本：goose 方言与迁移文件
// 目录按 driver 配对选择（mysql → migrations/mysql，postgres →
// migrations/postgres，两目录版本号一一对应）。
func gooseUp(ctx context.Context, db *sql.DB, driver config.Driver) error {
	fsys, err := migrations.DialectFS(string(gooseDialect(driver)))
	if err != nil {
		return fmt.Errorf("select migrations: %w", err)
	}
	p, err := goose.NewProvider(gooseDialect(driver), db, fsys)
	if err != nil {
		return fmt.Errorf("new provider: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// gooseDialect goose Provider 方言按 driver 选择（§3.16）；空值与未知值
// 回落 mysql——driver 的合法性已在 config.validate 拦截，工厂对未知 driver
// 也会在建连期报错，此处不会先于上述两点被未校验值命中。
func gooseDialect(driver config.Driver) goose.Dialect {
	if driver == config.DriverPostgres {
		return goose.DialectPostgres
	}
	return goose.DialectMySQL
}

// UserTable 返回方言感知的 user 表标识符（§4.2）：user 是 PG 保留字，裸
// SQL 须写 "user"；MySQL 非保留字裸名合法（bun 生成的 SQL 由方言自动加
// 引号，裸 SQL 在此统一处理）。表名来自本函数的封闭取值，不经用户输入，
// 拼接无注入面。
func UserTable(driver config.Driver) string {
	if driver == config.DriverPostgres {
		return `"user"`
	}
	return "user"
}

// installed 判据内部实现：①迁移版本表最新（goose GetVersions 的 current
// 达到 target，空库 current=0）；②user.id = 1 存在（§4.2：该行为安装时
// 创建的账号，其存在代表已完成安装；管理员身份由 user_permission 的
// superadmin 权限点表达，本判据仅按安装账号存在性判定，不在此处查权限点）。
func installed(ctx context.Context, db *sql.DB, driver config.Driver) (bool, error) {
	fsys, err := migrations.DialectFS(string(gooseDialect(driver)))
	if err != nil {
		return false, fmt.Errorf("select migrations: %w", err)
	}
	p, err := goose.NewProvider(gooseDialect(driver), db, fsys)
	if err != nil {
		return false, fmt.Errorf("new provider: %w", err)
	}
	current, target, err := p.GetVersions(ctx)
	if err != nil {
		return false, fmt.Errorf("get versions: %w", err)
	}
	if current < target {
		return false, nil
	}
	var admins int
	err = db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE id = 1", UserTable(driver)),
	).Scan(&admins)
	if err != nil {
		if isNoSuchTable(err) {
			return false, nil
		}
		return false, fmt.Errorf("query admin: %w", err)
	}
	return admins > 0, nil
}

// isNoSuchTable 判断「表不存在」错误：MariaDB 1146 / PG 42P01。码表与
// repo.IsNoSuchTable 相同，但 repo 包内测试 import 本包，本包不能反向
// import repo 复用判定（测试期 import cycle），只能本地复制判据——两处
// 码表改动须同步。
func isNoSuchTable(err error) bool {
	var myErr *mysql.MySQLError
	if errors.As(err, &myErr) {
		return myErr.Number == errNoSuchTable
	}
	var pgErr pgdriver.Error
	return errors.As(err, &pgErr) && pgErr.Field('C') == pgNoSuchTable
}
