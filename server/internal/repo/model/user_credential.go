// user_credential 表 GORM model（后端架构 §4.2 行 651-663 DDL）。表结构由
// migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import "time"

// UserCredential user_credential 表映射（§4.2 行 651-663）：统一凭证表，
// 一行一种凭证（行 680-684：password / totp / recovery_code 各一行，
// webauthn 每个凭据一行），新增凭证类型不加列。kind 取值
// password|totp|webauthn|recovery_code（§6.1 因子的凭证子集）；secret 按
// 明文字节存取（password=argon2id 串、totp=Base32 明文密钥，行 681-682，
// 哈希与编码归 security 层）；label 为用户自定义名称（如“MacBook Touch
// ID”）；meta 为 credential.CredentialMeta 的 Protobuf 序列化字节（接口
// 文档 §12.2；编解码封装在 repo 层，service 不直接拼 proto）；is_enabled
// 1 启用 0 停用；last_used_at 可空。idx_user_kind（行 662）非唯一——
// 「一行一种凭证」由 service 先查后写保证，表上不设数据库级约束。
//
// IsEnabled 的 default:1 忠实映射 DDL 的 DEFAULT 1：Create 时零值字段被
// tag 值 1 显式写入 INSERT 并回填 struct（同 model.User 的 UserStatus
// 口径，gorm@v1.31.2 callbacks/create.go:340-343）；停用入口
//（mfa_setting.go 用户自助停用 / 管理接口）走列级 UPDATE，不受 default
// tag 影响。
type UserCredential struct {
	ID         int64      `gorm:"column:id;primaryKey;autoIncrement"`
	UserID     int64      `gorm:"column:user_id;not null"`
	Kind       string     `gorm:"column:kind;size:32;not null"`
	Secret     []byte     `gorm:"column:secret;type:varbinary(1024);not null"`
	Label      string     `gorm:"column:label;size:128;not null;default:''"`
	Meta       []byte     `gorm:"column:meta;type:varbinary(2048)"`
	IsEnabled  int8       `gorm:"column:is_enabled;not null;default:1"`
	LastUsedAt *time.Time `gorm:"column:last_used_at"`
	CreatedAt  time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt  time.Time  `gorm:"column:updated_at;not null"`
}

// TableName 固定表名 user_credential（§4.2）。
func (UserCredential) TableName() string { return "user_credential" }
