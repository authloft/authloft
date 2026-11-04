// user_thirdparty_bind 表 GORM model（后端架构 §4.3 行 692-705 DDL）。
// 表结构由 migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import "time"

// UserThirdpartyBind user_thirdparty_bind 表映射（§4.3）：第三方身份与
// 用户的绑定关系。(provider_key, open_id) 唯一（uk_provider_openid）——
// 同一三方身份全局只能绑一个用户，登录 / 绑定链路 §12.5 步骤 4 的判重
// 依据（已绑其他 uid → target_taken，接口文档 §3.7.1）。provider_key
// 引用 provider.provider_key、不存渠道类型（§4.3 行 695 注释）。Union
// 归并不设独立列：由额外一行 Union Provider（category=union）绑定记录承担，
// 该行 open_id 即 unionid 值（§4.3 / §12.7）。extra 只存"便于排障的渠道原始返回"
// （msgpack），不参与任何业务判定（§4.3 行 708）——repo 只透传字节，
// 编解码与超 1 MiB 整条丢弃降级归上层。表无 updated_at（绑定行不可变，
// 只有创建与解绑删除）。
type UserThirdpartyBind struct {
	ID          int64     `gorm:"column:id;primaryKey;autoIncrement"`
	UserID      int64     `gorm:"column:user_id;not null"`
	ProviderKey string    `gorm:"column:provider_key;size:64;not null"` // 引用 provider.provider_key，不存渠道类型
	OpenID      string    `gorm:"column:open_id;size:128;not null"`
	Nickname    string    `gorm:"column:nickname;size:128;not null;default:''"`
	AvatarURL   string    `gorm:"column:avatar_url;size:512;not null;default:''"`
	Extra       []byte    `gorm:"column:extra"` // msgpack 序列化的第三方原始资料（仅排查用）；可空列，nil 即 NULL
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
}

// TableName 固定表名 user_thirdparty_bind（§4.3）。
func (UserThirdpartyBind) TableName() string { return "user_thirdparty_bind" }
