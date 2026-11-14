// reset_audit.go 重置密码审计事件投递（docs/后端架构.md §7.4 行 1026）：
// 结构化满足 orchestrator.SetPassDeps.Audit，本包不 import orchestrator。
package eventlog

import (
	"context"
	"strings"
	"time"

	"authloft/internal/repo/model"
)

// ResetAuditSink 把重置密码审计事件投递到延迟队列（docs/后端架构.md §7.4
// 行 1026「异步写审计」）：事件形态复用 eventlog 既有任务——
// EventResetPassword + DetailPwdEpoch（§4.6 行 770/799），实现
// orchestrator.ResetAuditSink（装配接线）。
type ResetAuditSink struct {
	logs *Writer
}

// RecordReset 非阻塞投递；队列满 / 关闭由 Writer 静默降级（§5.2
// 行 893），不影响重置主链路。
func (s ResetAuditSink) RecordReset(_ context.Context, uid int64, epoch int16, amr []string) {
	if s.logs == nil {
		return
	}
	s.logs.PushEvent(model.EventLog{
		Event:     EventResetPassword,
		ActorType: ActorTypeUser,
		ActorID:   uid,
		UserID:    uid,
		AMR:       strings.Join(amr, ","),
		Detail:    DetailPwdEpoch(int64(epoch)),
		CreatedAt: time.Now(),
	})
}

// NewResetAuditSink 注入事件投递器（装配层构造）。
func NewResetAuditSink(w *Writer) *ResetAuditSink {
	return &ResetAuditSink{logs: w}
}
