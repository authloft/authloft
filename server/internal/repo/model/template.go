// template 表 GORM model（后端架构 §4.9 表结构）。表结构由 migrations/
// （goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import "time"

// Template template 表映射（§4.9）：DB 自定义模板，与常驻内存的内置模板
// 双轨共存（§3.13）。template_key 唯一（uk_template_key），是 Resolve 的
// 命中键；创建 / 更新时不得与内置模板 key 同名，保留字集合为启动扫描所得
// 全部内置 key，校验归上层，本 model 不做。不设版本号、不设内置标记列，
// 缓存失效靠写路径 DEL（§5.1）。
type Template struct {
	ID          int64     `gorm:"column:id;primaryKey;autoIncrement"`
	TemplateKey string    `gorm:"column:template_key;size:64;not null"`
	Name        string    `gorm:"column:name;size:128;not null;default:''"`
	Content     string    `gorm:"column:content;type:mediumtext;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
	UpdatedAt   time.Time `gorm:"column:updated_at;not null"`
}

// TableName 固定表名 template（§4.9）。
func (Template) TableName() string { return "template" }
