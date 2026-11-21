// Package repo 提供数据库访问层基础设施（docs/后端架构.md §3.10）。
//
// 本文件只做 bun 初始化（bun.NewDB 包在统一连接工厂产出的 *sql.DB 上，
// 方言按 driver 选择）与连接池；裸连接经 migrate.NewDB 工厂建立（repo /
// migrate / setup 三处建连共享）。表结构映射归 repo/model/*，各实体读写归
// *_repo.go。schema 完全由 migrations/（goose，§3.16）管理：本包从不调用
// AutoMigrate，也不建外键——DDL 只有一个来源。
package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/feature"
	"github.com/uptrace/bun/dialect/mysqldialect"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/schema"

	"authloft/internal/config"
	"authloft/internal/migrate"
	"authloft/internal/partition"
	partitionmysql "authloft/internal/partition/mysql"
	partitionpostgres "authloft/internal/partition/postgres"
)

// slowQueryThreshold 慢查询告警阈值（沿用原数据层 logger Warn 口径）。
const slowQueryThreshold = 200 * time.Millisecond

// Open 按 cfg 初始化 bun：driver / DSN 来自 cfg.DB，连接池参数
// MaxOpenConns / MaxIdleConns / ConnMaxLifetime 逐项来自 cfg.DB（§3.2）。
// 裸连接经统一连接工厂（migrate.NewDB）建立，bun 方言按 driver 叠加。
// bun 只做查询构造不碰 schema，无外键 / 自动迁移问题面；迁移归
// migrations/（goose，§3.16）。建连后立即 ping——连接不可达即报错，
// 装配层 fail-fast。
func Open(cfg *config.Config) (*bun.DB, error) {
	driver := cfg.DB.EffectiveDriver()
	sqldb, err := migrate.NewDB(driver, cfg.DB.DSN)
	if err != nil {
		// 工厂只可能因 DSN 解析 / driver 非法而报错：驱动名经 import
		// 注册、pgdriver 走 OpenDB 无错误路径，sql.Open 对已注册驱动不失败。
		return nil, fmt.Errorf("db: dsn: %w", err)
	}
	db := bun.NewDB(sqldb, newDialect(driver))
	db.AddQueryHook(newSQLLogger(os.Stderr))
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("db: open: %w", err)
	}
	db.SetMaxOpenConns(cfg.DB.MaxOpenConns)
	db.SetMaxIdleConns(cfg.DB.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.DB.ConnMaxLifetime.Duration)
	return db, nil
}

// newDialect 按 driver 选 bun 方言：mysql 经 noReturningDialect 屏蔽
// RETURNING 能力位（CODE_GUIDE §3.5——插入后回读只走 LastInsertId）；
// postgres 原生 pgdialect，RETURNING 保留。driver 已由 EffectiveDriver
// 归一（空值回落 mysql），无空值分支。
func newDialect(driver config.Driver) schema.Dialect {
	if driver == config.DriverPostgres {
		return pgdialect.New()
	}
	return newMySQLDialect()
}

// noReturningDialect 屏蔽 MariaDB 10.5+ 自带的 INSERT/DELETE RETURNING
// 能力位。口径为「MySQL / MariaDB 无 RETURNING」（CODE_GUIDE §3.5）：插入
// 后回读只走 LastInsertId 回填自增 PK；若 RETURNING 位开启，INSERT 会因
// 零值 DEFAULT 占位列自动改拼 RETURNING 语句，并在 ON DUPLICATE KEY
// UPDATE 场景生成非法 SQL。
type noReturningDialect struct {
	schema.Dialect
}

func (d noReturningDialect) Features() feature.Feature {
	return d.Dialect.Features().Remove(feature.InsertReturning).Remove(feature.DeleteReturning)
}

// Init 透传内层 dialect 的版本探测；能力屏蔽在 Features() 读取侧生效，
// 内层重新加回的位不影响最终口径。
func (d noReturningDialect) Init(db *sql.DB) { d.Dialect.Init(db) }

// newMySQLDialect 构造 MySQL 方言（去除 RETURNING 能力位）。时间写入定位
// UTC：与 DSN 默认 loc=UTC 的驱动序列化口径一致（time.Time 经 bun 拼进 SQL
// 文本而非走驱动参数，需显式对齐，否则本地时区墙钟会进库）。
func newMySQLDialect() schema.Dialect {
	return noReturningDialect{mysqldialect.New(mysqldialect.WithTimeLocation("UTC"))}
}

// sqlLogger SQL 错误与慢查询日志（bun.QueryHook）。查无行时的 sql.ErrNoRows
// 是业务预期而非故障——凭证、资料、绑定等可选行在默认态本就不存在，需要
// 静默；真实 SQL 错误与慢查询仍按 Warn 记录。
type sqlLogger struct {
	logger *log.Logger
	slow   time.Duration
}

// newSQLLogger 装配 SQL 日志钩子，输出到 stderr。
func newSQLLogger(w io.Writer) bun.QueryHook {
	return &sqlLogger{logger: log.New(w, "", log.LstdFlags), slow: slowQueryThreshold}
}

func (h *sqlLogger) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	return ctx
}

// AfterQuery 对齐原数据层 logger 的优先级：错误日志优先（查无行静默），
// 无错误才判慢查询。
func (h *sqlLogger) AfterQuery(ctx context.Context, event *bun.QueryEvent) {
	if event.Err != nil {
		if errors.Is(event.Err, sql.ErrNoRows) {
			return
		}
		h.logger.Printf("SQL error: %v [%s]", event.Err, event.Query)
		return
	}
	if elapsed := time.Since(event.StartTime); elapsed > h.slow {
		h.logger.Printf("SLOW SQL >= %v [%s]", h.slow, event.Query)
	}
}

// requireChangedRow changed-rows 语义下的存在性判定：MySQL/MariaDB 的
// UPDATE 默认返回 changed-rows，同值重放 RowsAffected=0 与行不存在不可
// 区分——rows=0 时补 COUNT(*)，行仍在视为幂等成功，查无此行才返回
// sql.ErrNoRows。errPrefix 非空时包一层调用方错误前缀（事务内裸上抛的
// 调用点传空串）。model 传 (*T)(nil) 仅借表名，不参与 SET 构造。
func requireChangedRow(ctx context.Context, db bun.IDB, res sql.Result, model any, errPrefix, where string, args ...any) error {
	wrap := func(err error) error {
		if errPrefix == "" {
			return err
		}
		return fmt.Errorf("%s: %w", errPrefix, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return wrap(err)
	}
	if rows != 0 {
		return nil
	}
	n, err := db.NewSelect().Model(model).Where(where, args...).Count(ctx)
	if err != nil {
		return wrap(err)
	}
	if n == 0 {
		return wrap(sql.ErrNoRows)
	}
	return nil
}

// applyUpsert 为 INSERT 追加按方言分派的 upsert 子句。bun 的 On(...) 子句
// 原样拼接、不跨方言自动翻译，冲突分支须按方言各自生成：
//   - MySQL/MariaDB：ON DUPLICATE KEY UPDATE col = VALUES(col)——表上任意
//     唯一键（含主键）冲突即走更新分支，冲突列由唯一键承担，conflictKeys
//     不参与 SQL；
//   - PostgreSQL：ON CONFLICT (k, ...) DO UPDATE SET col = EXCLUDED.col
//     ——冲突列必须显式指定且与表上唯一键一致，conflictKeys 为其列表。
//
// 方言按 query 已装配 dialect 的能力位判定（与连接工厂同源，MySQL 侧经
// noReturningDialect 不改动本判定），调用方无需再传 driver。setCols 为冲突
// 时覆盖的列（代码常量，全为 [a-z0-9_] 命名，两方言裸标识符安全，不引用）。
func applyUpsert(q *bun.InsertQuery, conflictKeys []string, setCols []string) *bun.InsertQuery {
	isPG := q.Dialect().Features().Has(feature.InsertOnConflict)
	sets := make([]string, len(setCols))
	for i, col := range setCols {
		if isPG {
			sets[i] = col + " = EXCLUDED." + col
		} else {
			sets[i] = col + " = VALUES(" + col + ")"
		}
	}
	if isPG {
		return q.On("CONFLICT (" + strings.Join(conflictKeys, ", ") + ") DO UPDATE").
			Set(strings.Join(sets, ", "))
	}
	return q.On("DUPLICATE KEY UPDATE").Set(strings.Join(sets, ", "))
}

// NewPartitionManager 按 driver 分派 event_log 分区维护实现（方言只分担
// 分区枚举与 DDL，决策算法归 partition 包；分区设计见《后端架构》§4.6）。
// driver 取 EffectiveDriver 归一后的值，与连接装配同源；db 须为业务
// 同一连接工厂产出的 bun 连接，保证枚举与 DDL 落在目标库。
func NewPartitionManager(driver config.Driver, db *bun.DB) partition.PartitionManager {
	if driver == config.DriverPostgres {
		return partitionpostgres.New(db)
	}
	return partitionmysql.New(db)
}
