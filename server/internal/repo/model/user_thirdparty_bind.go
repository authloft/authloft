// user_thirdparty_bind 表 bun model（后端架构 §4.3 DDL）。表结构由
// migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"time"

	"github.com/uptrace/bun"
)

// UserThirdpartyBind user_thirdparty_bind 表映射（§4.3）：第三方身份与用户
// 的绑定关系。(provider_key, open_id) 唯一（uk_provider_openid）——同一三方
// 身份全局只能绑一个用户，登录 / 绑定链路 §12.5 步骤 4 的判重依据（已绑
// 其他 uid → target_taken，接口文档 §3.7.1）。provider_key 引用
// provider.provider_key、不存渠道类型（§4.3 注释）。Union 归并不设独立列：
// 由额外一行 Union Provider（category=union）绑定记录承担，该行 open_id 即
// unionid 值（§4.3 / §12.7）。extra 只存"便于排障的渠道原始返回"（msgpack），
// 不参与任何业务判定（§4.3）——repo 只透传字节，编解码与超 1 MiB 整条丢弃
// 降级归上层。表无 updated_at（绑定行不可变，只有创建与解绑删除）。
type UserThirdpartyBind struct {
	bun.BaseModel `bun:"table:user_thirdparty_bind"`

	ID          int64     `bun:"column:id,pk,autoincrement"`
	UserID      int64     `bun:"column:user_id,notnull"`
	ProviderKey string    `bun:"column:provider_key,notnull"` // 引用 provider.provider_key，不存渠道类型
	OpenID      string    `bun:"column:open_id,notnull"`
	Nickname    string    `bun:"column:nickname,notnull,default:''"`
	AvatarURL   string    `bun:"column:avatar_url,notnull,default:''"`
	Extra       []byte    `bun:"column:extra"`              // msgpack 序列化的第三方原始资料（仅排查用）；可空列，nil 即 NULL
	CreatedAt   time.Time `bun:"column:created_at,notnull"` // bun 不自动填充，由 repo 写入路径显式赋值
}
