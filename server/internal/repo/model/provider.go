// provider 表 GORM model（后端架构 §4.1 行 584-610 DDL）。表结构由
// migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import "time"

// Provider provider 表映射（§4.1）：外部服务统一表，跨类型共有属性
// （用于筛选、排序、索引）作真实列，凭证 / 端点 / 存储配置 / 厂商长尾
// 字段全部序列化进 ext（provider.Ext proto，接口文档 §12.1；编解码唯一
// 出口在 repo.MarshalProviderExt / ParseProviderExt）。provider_key 全局
// 唯一（uk_provider_key）、是唯一对外契约（[a-z0-9_]，创建后不可改，
// §4.1 行 615 读写约定），逻辑引用一律用它、不引用 id。icon_url 由管理
// 员自行上传到任意可访问位置后手填绝对 URL（无上传接口、无本地图标
// 回落，§4.1 行 613）。union_provider 指向 Union ID 归属的虚拟 Provider
// （§12.7）。
//
// default tag 列忠实映射 DDL 的 DEFAULT：Create 时零值字段被 tag 值显式
// 写入 INSERT 并回填 struct（gorm@v1.31.2 callbacks/create.go:340-343，
// 与 user.go 同口径）——struct 插入无法显式写 enable_signin=0 一类的
// 禁用零值，禁用入口走列级 UPDATE（Update / Save，不受 default tag
// 影响）。
type Provider struct {
	ID             int64     `gorm:"column:id;primaryKey;autoIncrement"`
	ProviderKey    string    `gorm:"column:provider_key;size:64;not null"`    // 全局唯一标识，逻辑引用使用
	UnionProvider  string    `gorm:"column:union_provider;size:64;not null"`  // Union ID 归属 Provider
	DisplayName    string    `gorm:"column:display_name;size:128;not null"`   // 展示名，如"QQ""阿里云短信"
	Category       string    `gorm:"column:category;size:32;not null"`        // oauth|captcha|sms|email|storage|notify|union
	Type           string    `gorm:"column:type;size:64;not null"`            // qq|wechat_mp|turnstile|aliyun_sms|s3|local|...
	EnableSignin   int8      `gorm:"column:enable_signin;not null;default:1"` // 允许用于登录
	EnableSignup   int8      `gorm:"column:enable_signup;not null;default:1"` // 允许该渠道建号；关闭则未绑定用户不能建号（登录仍返回 binding_required）
	AutoBind       int8      `gorm:"column:auto_bind;not null;default:0"`     // 按邮箱/手机号自动绑定已有账号
	AutoBindFields string    `gorm:"column:auto_bind_fields;size:128;not null;default:'email,phone'"`
	IsEnabled      int8      `gorm:"column:is_enabled;not null;default:1"`
	UiGroup        string    `gorm:"column:ui_group;size:32;not null;default:'social'"` // social|enterprise|dev|other
	SortOrder      int32     `gorm:"column:sort_order;not null;default:0"`
	IconURL        string    `gorm:"column:icon_url;size:512;not null;default:''"` // 列表接口直接用，避免每次反序列化（§4.1 行 613）
	Ext            []byte    `gorm:"column:ext"`                                  // provider.Ext 序列化后（Protobuf，业务上限 1 MiB，写入前校验，见 §4.0）；可空列，nil 即 NULL
	Remark         string    `gorm:"column:remark;size:512;not null;default:''"`
	CreatedAt      time.Time `gorm:"column:created_at;not null"`
	UpdatedAt      time.Time `gorm:"column:updated_at;not null"`
}

// TableName 固定表名 provider（§4.1）。
func (Provider) TableName() string { return "provider" }
