// template 表 bun model（后端架构 §4.9 表结构）。表结构由 migrations/
// （goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"time"

	"github.com/uptrace/bun"
)

// Template template 表映射（§4.9）：DB 自定义模板，与常驻内存的内置模板双轨
// 共存（§3.13）。template_key 唯一（uk_template_key），是 Resolve 的命中键；
// 创建 / 更新时不得与内置模板 key 同名，保留字集合为启动扫描所得全部内置
// key，校验归上层，本 model 不做。不设版本号、不设内置标记列，缓存失效靠
// 写路径 DEL（§5.1）。bun 不自动填充 created_at / updated_at，由 repo 写入
// 路径显式赋值。
type Template struct {
	bun.BaseModel `bun:"table:template"`

	ID          int64     `bun:"column:id,pk,autoincrement"`
	TemplateKey string    `bun:"column:template_key,notnull"`
	Name        string    `bun:"column:name,notnull,default:''"`
	Content     string    `bun:"column:content,notnull"`
	CreatedAt   time.Time `bun:"column:created_at,notnull"`
	UpdatedAt   time.Time `bun:"column:updated_at,notnull"`
}
