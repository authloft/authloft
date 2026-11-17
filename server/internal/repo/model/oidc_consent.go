// oidc_consent 表 GORM model（后端架构 §4.5 DDL）。表结构由 migrations/
// （goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import "time"

// OidcConsent oidc_consent 表映射（§4.5）：用户对 OIDC 客户端的长期授权
// 记录（同意页落库），与 oidc_refresh_token.scopes（单次令牌快照）互不替代。
// (user_id, client_id) 唯一（uk_user_client），一个用户对一个客户端至多一行；
// scopes 为已授权 scope 并集、空格分隔（RFC 6749 / §4.5 口径），与
// oidc_client.scopes 的逗号分隔是两套口径，解析统一收进授权参数校验工具、
// 不散落调用点。授权记录只扩不缩（已授权项在同意页锁定不可取消），并集
// 计算归上层，repo 原样写回。
type OidcConsent struct {
	ID        int64     `gorm:"column:id;primaryKey;autoIncrement"`
	UserID    int64     `gorm:"column:user_id;not null"`                    // 引用 user.id（uk_user_client）
	ClientID  string    `gorm:"column:client_id;size:64;not null"`          // oidc_client.client_id（uk_user_client）
	Scopes    string    `gorm:"column:scopes;size:512;not null;default:''"` // 已授权 scope 并集，空格分隔
	CreatedAt time.Time `gorm:"column:created_at;not null"`                 // 由 GORM 创建时回填，冲突更新不覆盖
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`                 // 由 GORM 回填，冲突更新随行刷新
}

// TableName 固定表名 oidc_consent（§4.5）。
func (OidcConsent) TableName() string { return "oidc_consent" }
