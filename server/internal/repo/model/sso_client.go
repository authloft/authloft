// sso_client 表 GORM model（后端架构 §4.4 行 713-724 DDL）。表结构由
// migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import "time"

// SsoClient sso_client 表映射（§4.4 行 713-724）：SSO 客户端回调白名单
// 的最小集合。client_id 全局唯一（uk_client_id）、是唯一对外契约，逻辑
// 引用一律用它、不引用 id（与 provider_key 同口径）。redirect_uris 列为
// client.RedirectUris（接口文档 §12.3 行 1723-1730）的 Protobuf 序列化，
// 编解码唯一出口在 repo.MarshalClientRedirectUris /
// ParseClientRedirectUris（§12.0 行 1627：固定结构走 Protobuf）。
//
// IsEnabled 的 default:1 忠实映射 DDL 的 DEFAULT 1：Create 时零值字段被
// tag 值显式写入 INSERT 并回填 struct（gorm@v1.31.2 callbacks/create.go:
// 340-343，与 user.go / provider.go 同口径）——struct 插入无法显式写
// is_enabled=0，禁用入口走列级 UPDATE（Update）。
type SsoClient struct {
	ID           int64     `gorm:"column:id;primaryKey;autoIncrement"`
	ClientID     string    `gorm:"column:client_id;size:64;not null"`        // 唯一对外标识（uk_client_id）
	ClientSecret string    `gorm:"column:client_secret;size:64;not null"`    // 密钥；生成策略归 service
	Name         string    `gorm:"column:name;size:128;not null;default:''"` // 展示名
	RedirectURIs []byte    `gorm:"column:redirect_uris;not null"`            // client.RedirectUris 序列化后
	IsEnabled    int8      `gorm:"column:is_enabled;not null;default:1"`     // 启用态
	CreatedAt    time.Time `gorm:"column:created_at;not null"`
	UpdatedAt    time.Time `gorm:"column:updated_at;not null"`
}

// TableName 固定表名 sso_client（§4.4）。
func (SsoClient) TableName() string { return "sso_client" }
