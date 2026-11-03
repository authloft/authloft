// user_profile 表 GORM model（后端架构 §4.2 行 640-648 DDL）。表结构由
// migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import "time"

// UserProfile user_profile 表映射（§4.2 行 640-648）：
// user_id 主键与 user.id 一一对应；extra 为 msgpack 序列化的扩展资料
// （VARBINARY(2048)，接口文档 §3.1 以 JSON 对象透出——msgpack 编解码归
// service 层，repo 拿到什么字节存什么字节）；birthday DATE 可空、
// gender TINYINT 默认 0；updated_at NOT NULL。
type UserProfile struct {
	UserID    int64      `gorm:"column:user_id;primaryKey"`
	Gender    int8       `gorm:"column:gender;default:0"`
	Birthday  *time.Time `gorm:"column:birthday;type:date"`
	Locale    string     `gorm:"column:locale;size:16;default:''"`
	Timezone  string     `gorm:"column:timezone;size:64;default:''"`
	Extra     []byte     `gorm:"column:extra;type:varbinary(2048)"`
	UpdatedAt time.Time  `gorm:"column:updated_at;not null"`
}

// TableName 固定表名 user_profile（§4.2）。
func (UserProfile) TableName() string { return "user_profile" }
