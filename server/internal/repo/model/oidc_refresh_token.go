// oidc_refresh_token 表 GORM model（后端架构 §4.5 行 744-758 DDL）。表结构
// 由 migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import "time"

// OidcRefreshToken oidc_refresh_token 表映射（§4.5 行 745-757）：opaque
// Refresh Token 的 sha256 落库行（接口文档 §4.7 行 1133）。token_hash
// CHAR(64) 全局唯一（uk_token_hash），是查取与吊销的唯一入口；
// client_id / user_id / session_id 表达「与客户端和会话绑定」（需求 §4.5
// 行 244），idx_user / idx_session 支撑批量吊销。scopes 为逗号分隔的
// scope 列表，与接口文档 §5.5 `scopes[]` 的数组 ↔ 字符串转换归 service。
// revoked_at 可空：NULL = 未吊销，非 NULL = 已吊销（原子条件 UPDATE 写入，
// §14.3 行 1588 批量吊销 / 行 1589 单令牌吊销）；expires_at 为绝对过期
// 时刻（§4.7 行 1133 默认 30 天，由 service 计算）。token 生成与 sha256
// 计算归 OIDC service，repo 只存取哈希。
type OidcRefreshToken struct {
	ID        int64      `gorm:"column:id;primaryKey;autoIncrement"`
	TokenHash string     `gorm:"column:token_hash;size:64;not null"`            // 唯一（uk_token_hash）
	ClientID  string     `gorm:"column:client_id;size:64;not null"`             // 绑定的 OIDC 客户端
	UserID    int64      `gorm:"column:user_id;not null"`                       // 绑定的用户（idx_user）
	SessionID string     `gorm:"column:session_id;size:64;not null;default:''"` // 绑定的 SSO 会话（idx_session）
	Scopes    string     `gorm:"column:scopes;size:512;not null;default:''"`    // 逗号分隔 scope 列表
	RevokedAt *time.Time `gorm:"column:revoked_at"`                             // NULL = 未吊销
	ExpiresAt time.Time  `gorm:"column:expires_at;not null"`                    // 绝对过期时刻
	CreatedAt time.Time  `gorm:"column:created_at;not null"`                    // 由 GORM 创建时回填
}

// TableName 固定表名 oidc_refresh_token（§4.5）。
func (OidcRefreshToken) TableName() string { return "oidc_refresh_token" }
