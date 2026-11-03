// user 表 GORM model（后端架构 §4.2 行 620-638 DDL）。表结构由
// migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import "time"

// User user 表映射（§4.2 行 620-638）：
// username 必选且唯一（uk_username，设置后不可改，需求 §4.1.1）；
// phone / email 可空且各自唯一（uk_phone / uk_email，SQL 唯一键允许多个
// NULL，用指针表达可空）；user_status 1 正常 0 禁用（列名避开 API 信封
// 保留字 status，接口文档 §1.0 既定口径）；epoch
// SMALLINT 安全版本号（§11.1：改密 / 重置 / 管理员禁用时递增，递增结果
// > 30000 回绕为 1 跳过 0，由后端逻辑控制、不由 DB 控制）；last_login_at
// 由延迟写入队列合并更新（§5.2）。管理员 = user.id = 1 的固定账号
// （§4.2 行 687），无 is_admin 列、不设角色表。
//
// UserStatus 的 default:1 忠实映射 DDL 的 DEFAULT 1：Create 时零值字段
// 被 tag 值 1 显式写入 INSERT 并回填 struct（gorm@v1.31.2 callbacks/
// create.go:340-343 实证）——GORM struct 插入无法显式写 0，业务亦无
// 「创建即禁用」场景（禁用入口是 §5.4 UpdateUserStatus 的 UPDATE，
// 列级更新不受 default tag 影响）。
type User struct {
	ID            int64      `gorm:"column:id;primaryKey;autoIncrement"`
	Username      string     `gorm:"column:username;size:64;not null"`
	Phone         *string    `gorm:"column:phone;size:32"`
	Email         *string    `gorm:"column:email;size:128"`
	PhoneVerified int8       `gorm:"column:phone_verified;not null;default:0"`
	EmailVerified int8       `gorm:"column:email_verified;not null;default:0"`
	Nickname      string     `gorm:"column:nickname;size:128;not null;default:''"`
	AvatarURL     string     `gorm:"column:avatar_url;size:512;not null;default:''"`
	UserStatus    int8       `gorm:"column:user_status;not null;default:1"`
	MfaRequired   int8       `gorm:"column:mfa_required;not null;default:0"`
	Epoch         int16      `gorm:"column:epoch;not null;default:0"`
	LastLoginAt   *time.Time `gorm:"column:last_login_at"`
	CreatedAt     time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt     time.Time  `gorm:"column:updated_at;not null"`
}

// TableName 固定表名 user（§4.2）。
func (User) TableName() string { return "user" }
