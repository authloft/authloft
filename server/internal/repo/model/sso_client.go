// sso_client 表 bun model（后端架构 §4.4 DDL）。表结构由 migrations/（goose，
// §3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"time"

	"github.com/uptrace/bun"
)

// SsoClient sso_client 表映射（§4.4）：SSO 客户端回调白名单的最小集合。
// client_id 全局唯一（uk_client_id）、是唯一对外契约，逻辑引用一律用它、
// 不引用 id（与 provider_key 同口径）。redirect_uris 列为
// client.RedirectUris（接口文档 §12.3）的 Protobuf 序列化，编解码唯一出口
// 在 repo.MarshalClientRedirectUris / ParseClientRedirectUris（§12.0：固定
// 结构走 Protobuf）。
//
// IsEnabled 的 default:1 忠实映射 DDL 的 DEFAULT 1：Create 时零值列经
// DEFAULT 占位由 DB 默认值填充（与 user.go / provider.go 同口径，CODE_GUIDE
// §3.5）——struct 插入无法显式写 is_enabled=0，禁用入口走列级 UPDATE。
// bun 不自动填充 created_at / updated_at，由 repo 写入路径显式赋值。
type SsoClient struct {
	bun.BaseModel `bun:"table:sso_client"`

	ID           int64  `bun:"column:id,pk,autoincrement"`
	ClientID     string `bun:"column:client_id,notnull"`       // 唯一对外标识（uk_client_id）
	ClientSecret string `bun:"column:client_secret,notnull"`   // 密钥；生成策略归 service
	Name         string `bun:"column:name,notnull,default:''"` // 展示名
	RedirectURIs []byte `bun:"column:redirect_uris,notnull"`   // client.RedirectUris 序列化后
	// 应用级登录配置（接口文档 §5.5）：login_methods / auth_providers 分别
	// 为 client.ClientLoginMethods / ClientAuthProviders 的 Protobuf 序列化
	//（编解码出口 repo.MarshalClientLoginMethods / ParseClientLoginMethods
	// 与 repo.MarshalClientAuthProviders / ParseClientAuthProviders）；
	// 空 = 未配置 = 跟随全局（§2.1）。列 NOT NULL 无默认值：Create 前须经
	// repo 编解码出口取非 nil 字节，nil 会被写为 NULL 触发 MySQL 1048
	//（同 RedirectURIs 口径）。
	LoginMethods  []byte `bun:"column:login_methods,notnull"`
	AuthProviders []byte `bun:"column:auth_providers,notnull"`
	// 登录完成且未传回跳地址时的默认回跳地址（§5.5）；空串 = 未配置，维持
	// 默认落点。
	DefaultRedirectURI string    `bun:"column:default_redirect_uri,notnull,default:''"`
	IsEnabled          int8      `bun:"column:is_enabled,notnull,default:1"`    // 启用态
	TemplateKey        string    `bun:"column:template_key,notnull,default:''"` // 绑定的模板 key；空回落默认壳（§4.4 / §8.1）
	TemplateVars       string    `bun:"column:template_vars"`                   // 模板变量 JSON 原文，空按 {} 注入
	CreatedAt          time.Time `bun:"column:created_at,notnull"`
	UpdatedAt          time.Time `bun:"column:updated_at,notnull"`
}
