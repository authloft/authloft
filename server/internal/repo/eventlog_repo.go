// event_log 批量写入（后端架构 §3.10 行 416：eventlog_repo.go → 批量
// INSERT（§4.6），供队列 flusher 调用；§5.2 行 867：事件日志走延迟写入
// 队列攒批）。DDL 归 migrations/（§3.16），本文件只做批量写、不建表；
// 事务边界在 service / 队列（§3.10）。detail 列按 []byte 原样透传——msgpack
// 编解码归 eventlog / asyncqueue 层（接口文档 §12.0 行 1631），repo 不引
// 编码库、不做事件白名单校验（事件常量归 eventlog 层）。
package repo

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"authloft/internal/repo/model"
)

// EventLogBatchSize 单次批量 INSERT 的最大行数，与 §5.2 行 882「满 200 条
// 或 2 秒 flush」的攒批口径一致（时间维度由队列层控制，repo 只按条数分批）。
const EventLogBatchSize = 200

// EventLogRepo event_log 表数据访问（§3.10：表与文件对应
// event_log → eventlog_repo.go）。
type EventLogRepo struct {
	db *gorm.DB
}

// NewEventLogRepo 按 GORM 连接构造。
func NewEventLogRepo(db *gorm.DB) *EventLogRepo {
	return &EventLogRepo{db: db}
}

// BatchInsert 批量插入事件日志行（供队列 flusher 调用），按
// EventLogBatchSize 分批执行；nil / 空切片 no-op 返回 nil。created_at 为
// NOT NULL，调用方未给（零值）时由本方法统一填当前时刻——理由：flusher
// 攒批投递时只关心事件本身，统一在落地入口填充可保证列恒非空且同批时间
// 一致，避免调用方遗漏；非零值原样保留。detail 为 nil 时落 NULL，非 nil
// 原样写字节；本方法不改写其余字段。
func (r *EventLogRepo) BatchInsert(ctx context.Context, rows []model.EventLog) error {
	if len(rows) == 0 {
		return nil
	}
	now := time.Now()
	for i := range rows {
		if rows[i].CreatedAt.IsZero() {
			rows[i].CreatedAt = now
		}
	}
	if err := r.db.WithContext(ctx).CreateInBatches(rows, EventLogBatchSize).Error; err != nil {
		return fmt.Errorf("eventlog repo: batch insert: %w", err)
	}
	return nil
}
