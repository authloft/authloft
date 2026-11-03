// event_log 表 GORM model（后端架构 §4.6 行 763-806 DDL）。表结构由
// migrations/（goose，§3.16）管理，本包只做列映射，绝不建表。
package model

import "time"

// EventLog event_log 表映射（§4.6 行 768-785）：登录日志与审计日志合并表，
// 用 event 字段区分两类视图。四个索引（idx_actor_time / idx_user_time /
// idx_event_time / idx_time）由迁移 DDL 维护，model 不重复声明。
// actor_type=user|admin|system；system 事件（如 oidc_authorize_no_state）
// 的 actor_id / user_id 均为 0（§4.6 行 792），故两列带 default:0 而非
// 无默认 NOT NULL——写入方不必为系统事件编造用户 id。detail 为 msgpack
// 序列化附加信息（接口文档 §12.0 行 1631），可空列：nil 即 NULL，非 nil
// 原样字节透传；msgpack 编解码归 eventlog 层，repo 不碰。
//
// default tag 列（actor_id / user_id / client_id / amr / ip / ua / target）
// 忠实映射 DDL 的 DEFAULT：Create 时零值字段被 tag 值显式写入 INSERT 并
// 回填 struct（gorm@v1.31.2 callbacks/create.go:298-343，与 user.go /
// provider.go 同口径）。
type EventLog struct {
	ID        int64     `gorm:"column:id;primaryKey;autoIncrement"`
	Event     string    `gorm:"column:event;size:48;not null"`                // 事件名（login_success|change_password|...）
	ActorType string    `gorm:"column:actor_type;size:16;not null"`           // user|admin|system
	ActorID   int64     `gorm:"column:actor_id;not null;default:0"`           // user=uid；admin=管理员 uid；system=0
	UserID    int64     `gorm:"column:user_id;not null;default:0"`            // 被操作对象；自身操作 = actor_id
	ClientID  string    `gorm:"column:client_id;size:64;not null;default:''"` // OIDC 客户端，登录类事件填充
	AMR       string    `gorm:"column:amr;size:128;not null;default:''"`      // 通过的认证方法，如 pwd,otp,mfa
	IP        string    `gorm:"column:ip;size:64;not null;default:''"`        // 客户端 IP
	UA        string    `gorm:"column:ua;size:512;not null;default:''"`       // User-Agent
	Target    string    `gorm:"column:target;size:128;not null;default:''"`   // 操作目标，如 provider_key
	Detail    []byte    `gorm:"column:detail;size:2048"`                      // msgpack；nil 即 NULL
	CreatedAt time.Time `gorm:"column:created_at;not null"`                   // 零值由 repo 写入前填充
}

// TableName 固定表名 event_log（§4.6）。
func (EventLog) TableName() string { return "event_log" }
