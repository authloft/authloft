// user_profile 表 bun model（后端架构 §4.2 DDL）。表结构由 migrations/
// （goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"time"

	"github.com/uptrace/bun"
)

// UserProfile user_profile 表映射（§4.2）：user_id 主键与 user.id 一一对应；
// extra 为 msgpack 序列化的扩展资料（VARBINARY(2048)，接口文档 §3.1 以 JSON
// 对象透出——msgpack 编解码归 service 层，repo 拿到什么字节存什么字节）；
// birthday DATE 可空、gender TINYINT 默认 0；updated_at NOT NULL（bun 不自动
// 填充，由 repo 写入路径显式赋值）。
type UserProfile struct {
	bun.BaseModel `bun:"table:user_profile"`

	UserID    int64      `bun:"column:user_id,pk"`
	Gender    int8       `bun:"column:gender,default:0"`
	Birthday  *time.Time `bun:"column:birthday"`
	Locale    string     `bun:"column:locale,default:''"`
	Timezone  string     `bun:"column:timezone,default:''"`
	Extra     []byte     `bun:"column:extra"`
	UpdatedAt time.Time  `bun:"column:updated_at,notnull"`
}
