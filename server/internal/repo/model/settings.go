// Package model 存放 GORM model，与后端架构 §4 数据模型一一对应。
// 表结构由 migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import "time"

// Setting settings 表映射（后端架构 §4.7 行 828-833 DDL）：
// k 主键（键名，与接口文档 §5.6 完全同名）/ v JSON 编码值（标量也按 JSON
// 存）/ updated_at / updated_by（操作管理员 uid，0 = 启动预热补齐）。
// 键名白名单与值类型校验归 internal/settings（§3.12），本 model 不做约束。
type Setting struct {
	K         string    `gorm:"column:k;primaryKey;size:64"`
	V         string    `gorm:"column:v;type:text;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
	UpdatedBy int64     `gorm:"column:updated_by;not null;default:0"`
}

// TableName 固定表名 settings（§4.7）。
func (Setting) TableName() string { return "settings" }
