// provider 表 bun model（后端架构 §4.1 DDL）。表结构由 migrations/（goose，
// §3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"time"

	"github.com/uptrace/bun"
)

// Provider provider 表映射（§4.1）：外部服务统一表，跨类型共有属性（用于
// 筛选、排序、索引）作真实列，凭证 / 端点 / 存储配置 / 厂商长尾字段全部
// 序列化进 ext（provider.Ext proto，接口文档 §12.1；编解码唯一出口在
// repo.MarshalProviderExt / ParseProviderExt）。provider_key 全局唯一
// （uk_provider_key）、是唯一对外契约（[a-z0-9_]，创建后不可改，§4.1 读写
// 约定），逻辑引用一律用它、不引用 id。icon_url 由管理员自行上传到任意可
// 访问位置后手填绝对 URL（无上传接口、无本地图标回落，§4.1）。union_provider
// 指向 Union ID 归属的虚拟 Provider（§12.7）。
//
// default tag 列忠实映射 DDL 的 DEFAULT：Create 时零值列经 DEFAULT 占位由
// DB 默认值填充（CODE_GUIDE §3.5 bun 零值口径）——业务无「插入即禁用」
// 场景，禁用入口走列级 UPDATE。bun 不自动填充 created_at / updated_at，
// 由 repo 写入路径显式赋值。
type Provider struct {
	bun.BaseModel `bun:"table:provider"`

	ID             int64     `bun:"column:id,pk,autoincrement"`
	ProviderKey    string    `bun:"column:provider_key,notnull"`            // 全局唯一标识，逻辑引用使用
	UnionProvider  string    `bun:"column:union_provider,notnull"`          // Union ID 归属 Provider
	DisplayName    string    `bun:"column:display_name,notnull"`            // 展示名，如"QQ""阿里云短信"
	Category       string    `bun:"column:category,notnull"`                // oauth|captcha|sms|email|storage|notify|union
	Type           string    `bun:"column:type,notnull"`                    // qq|wechat_mp|turnstile|aliyun_sms|s3|local|...
	EnableSignin   int8      `bun:"column:enable_signin,notnull,default:1"` // 允许用于登录
	EnableSignup   int8      `bun:"column:enable_signup,notnull,default:1"` // 允许该渠道建号；关闭则未绑定用户不能建号（登录仍返回 binding_required）
	AutoBind       int8      `bun:"column:auto_bind,notnull,default:0"`     // 按邮箱/手机号自动绑定已有账号
	AutoBindFields string    `bun:"column:auto_bind_fields,notnull,default:\"email,phone\""`
	IsEnabled      int8      `bun:"column:is_enabled,notnull,default:1"`
	SortOrder      int32     `bun:"column:sort_order,notnull,default:0"`
	IconURL        string    `bun:"column:icon_url,notnull,default:''"` // 列表接口直接用，避免每次反序列化（§4.1）
	Ext            []byte    `bun:"column:ext"`                         // provider.Ext 序列化后（Protobuf，业务上限 1 MiB，写入前校验，见 §4.0）；可空列，nil 即 NULL
	Remark         string    `bun:"column:remark,notnull,default:''"`
	CreatedAt      time.Time `bun:"column:created_at,notnull"`
	UpdatedAt      time.Time `bun:"column:updated_at,notnull"`
}
