// 表结构由迁移 DDL 维护（§3.16），model 只做列映射、不建表；索引由 DDL
// 建立、不声明 index tag，禁用 AutoMigrate（CODE_GUIDE §3.5）。
package model

// UserPermission 只留两列：行存在即持有权限点，额外列与索引均无消费者（§4.8）。
type UserPermission struct {
	UserID int64  `gorm:"column:user_id;primaryKey;not null"`
	Point  string `gorm:"column:point;primaryKey;size:32;not null"`
}

// TableName 显式固定表名，避免 GORM 复数名推导。
func (UserPermission) TableName() string { return "user_permission" }
