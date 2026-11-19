// user_credential 表 bun model（后端架构 §4.2 DDL）。表结构由 migrations/
// （goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"time"

	"github.com/uptrace/bun"
)

// UserCredential user_credential 表映射（§4.2）：统一凭证表，一行一种凭证
// （password / totp / recovery_code 各一行，webauthn 每个凭据一行），新增
// 凭证类型不加列。kind 取值 password|totp|webauthn|recovery_code（§6.1 因子
// 的凭证子集）；secret 按明文字节存取（password=argon2id 串、totp=Base32
// 明文密钥，哈希与编码归 security 层）；label 为用户自定义名称（如"MacBook
// Touch ID"）；meta 为 credential.CredentialMeta 的 Protobuf 序列化字节
// （接口文档 §12.2；编解码封装在 repo 层，service 不直接拼 proto）；
// is_enabled 1 启用 0 停用；last_used_at 可空。idx_user_kind 非唯一——
// 「一行一种凭证」由 service 先查后写保证，表上不设数据库级约束。
//
// IsEnabled 的 default:1 忠实映射 DDL 的 DEFAULT 1：Create 时零值列经
// DEFAULT 占位由 DB 默认值填充（同 model.User 的 UserStatus 口径，
// CODE_GUIDE §3.5）；停用入口（管理接口）走列级 UPDATE。bun 不自动填充
// created_at / updated_at，由 repo 写入路径显式赋值。
type UserCredential struct {
	bun.BaseModel `bun:"table:user_credential"`

	ID         int64      `bun:"column:id,pk,autoincrement"`
	UserID     int64      `bun:"column:user_id,notnull"`
	Kind       string     `bun:"column:kind,notnull"`
	Secret     []byte     `bun:"column:secret,notnull"`
	Label      string     `bun:"column:label,notnull,default:''"`
	Meta       []byte     `bun:"column:meta"`
	IsEnabled  int8       `bun:"column:is_enabled,notnull,default:1"`
	LastUsedAt *time.Time `bun:"column:last_used_at"`
	CreatedAt  time.Time  `bun:"column:created_at,notnull"`
	UpdatedAt  time.Time  `bun:"column:updated_at,notnull"`
}
