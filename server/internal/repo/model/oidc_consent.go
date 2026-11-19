// oidc_consent 表 bun model（后端架构 §4.5 DDL）。表结构由 migrations/
// （goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"time"

	"github.com/uptrace/bun"
)

// OidcConsent oidc_consent 表映射（§4.5）：用户对 OIDC 客户端的长期授权记录
// （同意页落库），与 oidc_refresh_token.scopes（单次令牌快照）互不替代。
// (user_id, client_id) 唯一（uk_user_client），一个用户对一个客户端至多一行；
// scopes 为已授权 scope 并集、空格分隔（RFC 6749 / §4.5 口径），与
// oidc_client.scopes 的逗号分隔是两套口径，解析统一收进授权参数校验工具、
// 不散落调用点。授权记录只扩不缩（已授权项在同意页锁定不可取消），并集
// 计算归上层，repo 原样写回。bun 不自动填充 created_at / updated_at，由
// repo 写入路径显式赋值（冲突更新路径 created_at 不覆盖、updated_at 随行
// 刷新）。
type OidcConsent struct {
	bun.BaseModel `bun:"table:oidc_consent"`

	ID        int64     `bun:"column:id,pk,autoincrement"`
	UserID    int64     `bun:"column:user_id,notnull"`           // 引用 user.id（uk_user_client）
	ClientID  string    `bun:"column:client_id,notnull"`         // oidc_client.client_id（uk_user_client）
	Scopes    string    `bun:"column:scopes,notnull,default:''"` // 已授权 scope 并集，空格分隔
	CreatedAt time.Time `bun:"column:created_at,notnull"`        // 冲突更新不覆盖
	UpdatedAt time.Time `bun:"column:updated_at,notnull"`        // 冲突更新随行刷新
}
