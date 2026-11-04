// oidc_client 表 GORM model（后端架构 §4.5 行 726-742 DDL）。表结构由
// migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import "time"

// OidcClient oidc_client 表映射（§4.5 行 729-742）：在 SSO 客户端字段上
// 追加 OIDC 专属列。client_id 全局唯一（uk_client_id）、是唯一对外契约。
// redirect_uris 列为 client.RedirectUris（接口文档 §12.3 行 1723-1730）的
// Protobuf 序列化，编解码唯一出口在 repo.MarshalClientRedirectUris /
// ParseClientRedirectUris。scopes 为逗号分隔的 scope 列表（VARCHAR(512)），
// 与接口文档 §5.5 `scopes[]` 的数组 ↔ 字符串转换归 service；TTL 两列单位
// 秒（§4.5 行 736-737 默认 3600 / 2592000）。
//
// IsEnabled / Scopes / AccessTokenTTL / RefreshTokenTTL 的 default tag 忠实
// 映射 DDL 的 DEFAULT：Create 时零值字段被 tag 值显式写入 INSERT 并回填
// struct（gorm@v1.31.2 callbacks/create.go:340-343，与 user.go /
// provider.go 同口径）——struct 插入无法显式写 is_enabled=0 或 TTL=0，
// 对应调整走列级 UPDATE（Update）。
type OidcClient struct {
	ID              int64     `gorm:"column:id;primaryKey;autoIncrement"`
	ClientID        string    `gorm:"column:client_id;size:64;not null"`                              // 唯一对外标识（uk_client_id）
	ClientSecret    string    `gorm:"column:client_secret;size:64;not null"`                          // 密钥；生成策略归 service
	Name            string    `gorm:"column:name;size:128;not null;default:''"`                       // 展示名
	RedirectURIs    []byte    `gorm:"column:redirect_uris;type:varbinary(2048);not null"`             // client.RedirectUris 序列化后
	Scopes          string    `gorm:"column:scopes;size:512;not null;default:'openid,profile,email'"` // 逗号分隔 scope 列表
	AccessTokenTTL  int32     `gorm:"column:access_token_ttl;not null;default:3600"`                  // 秒
	RefreshTokenTTL int32     `gorm:"column:refresh_token_ttl;not null;default:2592000"`              // 秒
	IsEnabled       int8      `gorm:"column:is_enabled;not null;default:1"`
	CreatedAt       time.Time `gorm:"column:created_at;not null"`
	UpdatedAt       time.Time `gorm:"column:updated_at;not null"`
}

// TableName 固定表名 oidc_client（§4.5）。
func (OidcClient) TableName() string { return "oidc_client" }
