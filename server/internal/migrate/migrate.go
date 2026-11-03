// Package migrate 提供 goose v3 迁移执行与安装判据（后端架构 §3.16）。
//
// 迁移 SQL 内嵌在 authloft/migrations 包随二进制分发，版本表沿用 goose
// 默认的 goose_db_version（无 dirty 标志：失败的迁移不记版本、重跑即重试
// 同版本）。本包只提供 runner 能力；bootstrap / setup 的装配接线归后续实现。
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"

	"authloft/migrations"
)

// ErrCodeMigrationFailed 迁移失败的统一错误码字符串（§3.16：setup 路径
// error.code = migration_failed，细节进 error.message 与服务端日志），
// 由安装流程消费。
const ErrCodeMigrationFailed = "migration_failed"

// errNoSuchTable MariaDB 服务端错误码 ER_NO_SUCH_TABLE（1146）。
const errNoSuchTable = 1146

// openDB 解析并规范化 DSN 后建立连接。强制开启 parseTime：goose MySQL
// 方言的版本表存在性检查走 GetMigration 回退查询（扫描 tstamp 列进
// time.Time），驱动未开 parseTime 时该查询失败、误判版本表不存在，
// 后续 CREATE 会撞 1050 表已存在。
func openDB(dsn string) (*sql.DB, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	cfg.ParseTime = true
	return sql.Open("mysql", cfg.FormatDSN())
}

// Up 在 dsn 上执行 migrate up（§3.16：幂等——版本已最新时 goose 只读
// 版本表、零变更秒过；单条迁移失败不记版本，重跑即重试同版本）。
func Up(ctx context.Context, dsn string) error {
	db, err := openDB(dsn)
	if err != nil {
		return fmt.Errorf("%s: open: %w", ErrCodeMigrationFailed, err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("%s: ping: %w", ErrCodeMigrationFailed, err)
	}
	if err := gooseUp(ctx, db); err != nil {
		return fmt.Errorf("%s: %w", ErrCodeMigrationFailed, err)
	}
	return nil
}

// Installed 报告系统是否已完成初始化（§3.16 已初始化判据）：
// 迁移版本表已到最新 且 管理员（user.id=1）存在，缺任一即视为未完成。
// 版本表 / 业务表尚不存在视为未初始化，不视为错误。
func Installed(ctx context.Context, dsn string) (bool, error) {
	db, err := openDB(dsn)
	if err != nil {
		return false, fmt.Errorf("open: %w", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return false, fmt.Errorf("ping: %w", err)
	}
	return installed(ctx, db)
}

// gooseUp 用嵌入的迁移文件把 db 迁移到最新版本。
func gooseUp(ctx context.Context, db *sql.DB) error {
	p, err := goose.NewProvider(goose.DialectMySQL, db, migrations.FS)
	if err != nil {
		return fmt.Errorf("new provider: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// installed 判据内部实现：①迁移版本表最新（goose GetVersions 的 current
// 达到 target，空库 current=0）；②管理员 ID=1 存在（§4.2：管理员 = 安装时
// 创建的固定 ID 账号，无 is_admin 列，判定不在此处做角色展开）。
func installed(ctx context.Context, db *sql.DB) (bool, error) {
	p, err := goose.NewProvider(goose.DialectMySQL, db, migrations.FS)
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
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM user WHERE id = 1").Scan(&admins)
	if err != nil {
		if isNoSuchTable(err) {
			return false, nil
		}
		return false, fmt.Errorf("query admin: %w", err)
	}
	return admins > 0, nil
}

// isNoSuchTable 判断 MariaDB「表不存在」错误。
func isNoSuchTable(err error) bool {
	var myErr *mysql.MySQLError
	return errors.As(err, &myErr) && myErr.Number == errNoSuchTable
}
