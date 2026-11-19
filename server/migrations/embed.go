// Package migrations 内嵌数据库迁移 SQL（后端架构 §3.16）：
// mysql/ 与 postgres/ 两个方言目录各自维护全量迁移（版本号一一对应），
// goose Provider 以 fs.FS 形式加载方言目录（NewProvider 第三参数），
// 迁移文件随二进制分发，部署零外部依赖。
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
)

// 方言目录名，取值与 goose 方言常量（DialectMySQL / DialectPostgres）一致，
// migrate 层可直传 gooseDialect 的返回值。
const (
	DialectMySQL    = "mysql"
	DialectPostgres = "postgres"
)

// FS 内嵌双方言目录全部迁移 SQL（形如 mysql/000001_init.sql：单文件内
// -- +goose Up / -- +goose Down 注解——goose v3 Provider API 将每个
// .sql 文件视为一条迁移，不支持 .up.sql/.down.sql 成对文件）。
// 注意根 FS 不可直接交给 goose Provider：其递归收集会同时命中两个方言
// 目录，同版本号报 duplicate migration，必须经 DialectFS 剥层。
//
//go:embed mysql/*.sql postgres/*.sql
var FS embed.FS

// DialectFS 返回以方言目录为根的 fs.FS（fs.Sub 剥掉方言目录层）：goose
// Provider 收集到的路径形如 000001_init.sql，与本目录单方言时期的形态
// 一致。dialect 取值见 DialectMySQL / DialectPostgres。
func DialectFS(dialect string) (fs.FS, error) {
	switch dialect {
	case DialectMySQL, DialectPostgres:
		return fs.Sub(FS, dialect)
	default:
		return nil, fmt.Errorf("migrations: unknown dialect %q", dialect)
	}
}
