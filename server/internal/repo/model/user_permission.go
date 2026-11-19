// 表结构由迁移 DDL 维护（§3.16），model 只做列映射、不建表；索引由 DDL
// 建立，禁用 AutoMigrate（CODE_GUIDE §3.5）。
package model

import (
	"github.com/uptrace/bun"
)

// UserPermission 只留两列：行存在即持有权限点，额外列与索引均无消费者（§4.8）。
type UserPermission struct {
	bun.BaseModel `bun:"table:user_permission"`

	UserID int64  `bun:"column:user_id,pk,notnull"`
	Point  string `bun:"column:point,pk,notnull"`
}
