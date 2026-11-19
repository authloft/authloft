// user 表 bun model（后端架构 §4.2 DDL）。表结构由 migrations/（goose，
// §3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"time"

	"github.com/uptrace/bun"
)

// User user 表映射（§4.2）：username 必选且唯一（uk_username，设置后不可改，
// 需求 §4.1.1）；phone / email 可空且各自唯一（uk_phone / uk_email，SQL 唯一
// 键允许多个 NULL，用指针表达可空）；user_status 1 正常 0 禁用（列名避开
// API 信封保留字 status，接口文档 §1.0 既定口径）；epoch SMALLINT 安全版本号
// （§11.1：改密 / 重置 / 管理员禁用时递增，递增结果 > 30000 回绕为 1 跳过
// 0，由后端逻辑控制、不由 DB 控制）；last_login_at 由延迟写入队列合并更新
// （§5.2）。管理员 = 持有权限点的账号，user.id = 1 为安装时创建的账号（§4.2）。
//
// UserStatus 的 default:1 忠实映射 DDL 的 DEFAULT 1：Create 时零值列经
// DEFAULT 占位由 DB 默认值填充（CODE_GUIDE §3.5 bun 零值口径），业务无
// 「创建即禁用」场景（禁用入口是 §5.4 UpdateUserStatus 的 UPDATE，列级
// 更新不受 default tag 影响）。bun 不自动填充 created_at / updated_at，
// 由 repo 写入路径显式赋值。
type User struct {
	bun.BaseModel `bun:"table:user"`

	ID            int64      `bun:"column:id,pk,autoincrement"`
	Username      string     `bun:"column:username,notnull"`
	Phone         *string    `bun:"column:phone"`
	Email         *string    `bun:"column:email"`
	PhoneVerified int8       `bun:"column:phone_verified,notnull,default:0"`
	EmailVerified int8       `bun:"column:email_verified,notnull,default:0"`
	Nickname      string     `bun:"column:nickname,notnull,default:''"`
	AvatarURL     string     `bun:"column:avatar_url,notnull,default:''"`
	UserStatus    int8       `bun:"column:user_status,notnull,default:1"`
	MfaRequired   int8       `bun:"column:mfa_required,notnull,default:0"` // 用户自助两步验证开关（0 关闭 / 1 开启，§4.2）
	Epoch         int16      `bun:"column:epoch,notnull,default:0"`
	LastLoginAt   *time.Time `bun:"column:last_login_at"`
	CreatedAt     time.Time  `bun:"column:created_at,notnull"`
	UpdatedAt     time.Time  `bun:"column:updated_at,notnull"`
}
