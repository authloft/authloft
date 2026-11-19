// oidc_client 表 bun model（后端架构 §4.5 DDL）。表结构由 migrations/
// （goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"time"

	"github.com/uptrace/bun"
)

// OidcClient oidc_client 表映射（§4.5）：在 SSO 客户端字段上追加 OIDC 专属
// 列。client_id 全局唯一（uk_client_id）、是唯一对外契约。redirect_uris 列
// 为 client.RedirectUris（接口文档 §12.3）的 Protobuf 序列化，编解码唯一
// 出口在 repo.MarshalClientRedirectUris / ParseClientRedirectUris。scopes 为
// 逗号分隔的 scope 列表（VARCHAR(512)），与接口文档 §5.5 `scopes[]` 的数组
// ↔ 字符串转换归 service；TTL 两列单位秒（§4.5 默认 3600 / 2592000）。
//
// IsEnabled / Scopes / AccessTokenTTL / RefreshTokenTTL 的 default tag 忠实
// 映射 DDL 的 DEFAULT：Create 时零值列经 DEFAULT 占位由 DB 默认值填充
// （与 user.go / provider.go 同口径，CODE_GUIDE §3.5）——struct 插入无法
// 显式写 is_enabled=0 或 TTL=0，对应调整走列级 UPDATE。bun 不自动填充
// created_at / updated_at，由 repo 写入路径显式赋值。
type OidcClient struct {
	bun.BaseModel `bun:"table:oidc_client"`

	ID              int64     `bun:"column:id,pk,autoincrement"`
	ClientID        string    `bun:"column:client_id,notnull"`                               // 唯一对外标识（uk_client_id）
	ClientSecret    string    `bun:"column:client_secret,notnull"`                           // 密钥；生成策略归 service
	Name            string    `bun:"column:name,notnull,default:''"`                         // 展示名
	RedirectURIs    []byte    `bun:"column:redirect_uris,notnull"`                           // client.RedirectUris 序列化后
	Scopes          string    `bun:"column:scopes,notnull,default:\"openid,profile,email\""` // 逗号分隔 scope 列表
	AccessTokenTTL  int32     `bun:"column:access_token_ttl,notnull,default:3600"`           // 秒
	RefreshTokenTTL int32     `bun:"column:refresh_token_ttl,notnull,default:2592000"`       // 秒
	IsEnabled       int8      `bun:"column:is_enabled,notnull,default:1"`
	TemplateKey     string    `bun:"column:template_key,notnull,default:''"` // 绑定的模板 key；空回落默认壳（§4.5 / §8.1）
	TemplateVars    string    `bun:"column:template_vars"`                   // 模板变量 JSON 原文，空按 {} 注入
	CreatedAt       time.Time `bun:"column:created_at,notnull"`
	UpdatedAt       time.Time `bun:"column:updated_at,notnull"`
}
