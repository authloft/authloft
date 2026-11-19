// oidc_refresh_token 表 bun model（后端架构 §4.5 DDL）。表结构由 migrations/
// （goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"time"

	"github.com/uptrace/bun"
)

// OidcRefreshToken oidc_refresh_token 表映射（§4.5）：opaque Refresh Token
// 的 sha256 落库行（接口文档 §4.7）。token_hash CHAR(64) 全局唯一
// （uk_token_hash），是查取与吊销的唯一入口；client_id / user_id /
// session_id 表达「与客户端和会话绑定」（需求 §4.5），idx_user / idx_session
// 支撑批量吊销。scopes 为空格分隔的 scope 列表（RFC 6749 / 接口文档 §4.3），
// 与接口文档 §5.5 `scopes[]` 的数组 ↔ 字符串转换归 service。
// revoked_at 可空：NULL = 未吊销，非 NULL = 已吊销（原子条件 UPDATE 写入，
// §14.3 批量吊销 / 单令牌吊销）；expires_at 为绝对过期时刻（§4.7 默认 30 天，
// 由 service 计算）。token 生成与 sha256 计算归 OIDC service，repo 只存取
// 哈希。bun 不自动填充 created_at，由 repo 写入路径显式赋值。
type OidcRefreshToken struct {
	bun.BaseModel `bun:"table:oidc_refresh_token"`

	ID        int64      `bun:"column:id,pk,autoincrement"`
	TokenHash string     `bun:"column:token_hash,notnull"`            // 唯一（uk_token_hash）
	ClientID  string     `bun:"column:client_id,notnull"`             // 绑定的 OIDC 客户端
	UserID    int64      `bun:"column:user_id,notnull"`               // 绑定的用户（idx_user）
	SessionID string     `bun:"column:session_id,notnull,default:''"` // 绑定的 SSO 会话（idx_session）
	Scopes    string     `bun:"column:scopes,notnull,default:''"`     // 空格分隔 scope 列表（RFC 6749 / §4.3）
	RevokedAt *time.Time `bun:"column:revoked_at"`                    // NULL = 未吊销
	ExpiresAt time.Time  `bun:"column:expires_at,notnull"`            // 绝对过期时刻
	CreatedAt time.Time  `bun:"column:created_at,notnull"`            // 写入路径显式赋值
}
