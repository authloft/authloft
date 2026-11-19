// Package model 存放 bun model，与后端架构 §4 数据模型一一对应。表结构由
// migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"time"

	"github.com/uptrace/bun"
)

// Setting settings 表映射（后端架构 §4.7 DDL）：k 主键（键名，与接口文档
// §5.6 完全同名）/ v JSON 编码值（标量也按 JSON 存）/ updated_at /
// updated_by（操作管理员 uid，0 = 启动预热补齐）。键名白名单与值类型校验归
// internal/settings（§3.12），本 model 不做约束。bun 不自动填充 updated_at，
// 由 repo 写入路径显式赋值。
type Setting struct {
	bun.BaseModel `bun:"table:settings"`

	K         string    `bun:"column:k,pk"`
	V         string    `bun:"column:v,notnull"`
	UpdatedAt time.Time `bun:"column:updated_at,notnull"`
	UpdatedBy int64     `bun:"column:updated_by,notnull,default:0"`
}
