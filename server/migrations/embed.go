// Package migrations 内嵌数据库迁移 SQL（后端架构 §3.16）：
// goose Provider 以 fs.FS 形式加载本目录（NewProvider 第三参数），
// 迁移文件随二进制分发，部署零外部依赖。
package migrations

import "embed"

// FS 内嵌本目录全部迁移 SQL（形如 000001_init.sql：单文件内
// -- +goose Up / -- +goose Down 注解——goose v3 Provider API 将每个
// .sql 文件视为一条迁移，不支持 .up.sql/.down.sql 成对文件）。
//
//go:embed *.sql
var FS embed.FS
