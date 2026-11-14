// Package repo 提供数据库访问层基础设施（docs/后端架构.md §3.10 行 426）。
//
// 本文件只做 GORM 初始化与连接池；表结构映射归 repo/model/*，各实体读写
// 归 *_repo.go（后续实现）。schema 完全由 migrations/（goose，§3.16）管理：
// 本包绝不调用 AutoMigrate，并禁用迁移期外键约束——DDL 只有一个来源。
package repo

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"authloft/internal/config"
)

// Open 按 cfg 初始化 GORM（MariaDB）：DSN 来自 cfg.DB，连接池参数
// MaxOpenConns / MaxIdleConns / ConnMaxLifetime 逐项来自 cfg.DB（§3.2 行
// 268-272）。gorm.Config 禁外键（DisableForeignKeyConstraintWhenMigrating），
// 且本包从不调用 AutoMigrate（§3.10 行 426：禁用外键 / 自动迁移）。
// gorm.Open 默认自动 ping，连接不可达即报错——装配层 fail-fast。
func Open(cfg *config.Config) (*gorm.DB, error) {
	dsn, err := normalizeDSN(cfg.DB.DSN)
	if err != nil {
		return nil, fmt.Errorf("db: dsn: %w", err)
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   newGORMLogger(),
	})
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("db: pool: %w", err)
	}
	sqlDB.SetMaxOpenConns(cfg.DB.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.DB.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.DB.ConnMaxLifetime.Duration)
	return db, nil
}

// newGORMLogger 装配 GORM 的 SQL 日志。默认 logger 会把单行查询
// （Take / First）查无行时的 ErrRecordNotFound 连同调用文件行号打到 stderr；
// 凭证、资料、绑定等可选行在默认态本就不存在，这类 record not found 是
// 业务预期而非故障，需要静默。真实 SQL 错误与慢查询仍按 Warn 记录。
func newGORMLogger() logger.Interface {
	return gormLogger(os.Stderr)
}

func gormLogger(w io.Writer) logger.Interface {
	return logger.New(
		log.New(w, "", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)
}

// normalizeDSN 规范化 DSN：强制 parseTime=true，与 migrate 包 openDB 同口径
// （驱动未开 parseTime 时时间列扫描进 time.Time 失败）。只补参数不改语义。
func normalizeDSN(dsn string) (string, error) {
	c, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return "", err
	}
	c.ParseTime = true
	return c.FormatDSN(), nil
}
