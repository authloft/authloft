// event_log 表 bun model（后端架构 §4.6 DDL）。表结构由 migrations/（goose，
// §3.16）管理，本包只做列映射，绝不建表。
package model

import (
	"time"

	"github.com/uptrace/bun"
)

// EventLog event_log 表映射（§4.6）：登录日志与审计日志合并表，用 event 字段
// 区分两类视图。四个索引（idx_actor_time / idx_user_time / idx_event_time /
// idx_time）由迁移 DDL 维护，model 不重复声明。actor_type=user|admin|system；
// system 事件（如 oidc_authorize_no_state）的 actor_id / user_id 均为 0
// （§4.6），故两列带 default:0 而非无默认 NOT NULL——写入方不必为系统事件
// 编造用户 id。detail 为 msgpack 序列化附加信息（接口文档 §12.0），可空列：
// nil 即 NULL，非 nil 原样字节透传；msgpack 编解码归 eventlog 层，repo 不碰。
// created_at 无 DB 默认值，bun 亦不自动填充——零值由 repo 写入前填充。
type EventLog struct {
	bun.BaseModel `bun:"table:event_log"`

	ID        int64     `bun:"column:id,pk,autoincrement"`
	Event     string    `bun:"column:event,notnull"`                // 事件名（login_success|change_password|...）
	ActorType string    `bun:"column:actor_type,notnull"`           // user|admin|system
	ActorID   int64     `bun:"column:actor_id,notnull,default:0"`   // user=uid；admin=管理员 uid；system=0
	UserID    int64     `bun:"column:user_id,notnull,default:0"`    // 被操作对象；自身操作 = actor_id
	ClientID  string    `bun:"column:client_id,notnull,default:''"` // OIDC 客户端，登录类事件填充
	AMR       string    `bun:"column:amr,notnull,default:''"`       // 通过的认证方法，如 pwd,otp,mfa
	IP        string    `bun:"column:ip,notnull,default:''"`        // 客户端 IP
	UA        string    `bun:"column:ua,notnull,default:''"`        // User-Agent
	Target    string    `bun:"column:target,notnull,default:''"`    // 操作目标，如 provider_key
	Detail    []byte    `bun:"column:detail"`                       // msgpack；nil 即 NULL
	CreatedAt time.Time `bun:"column:created_at,notnull"`           // 零值由 repo 写入前填充
}
