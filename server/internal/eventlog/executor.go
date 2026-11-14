// executor.go 延迟写入队列的执行器（docs/后端架构.md §5.2 行 886）：把
// 攒批后的任务落到 repo——model.EventLog 走 EventLogRepo.BatchInsert，
// last_login_at 走 UserRepo.UpdateLastLogin。
package eventlog

import (
	"context"
	"log/slog"

	"authloft/internal/asyncqueue"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// Executor 延迟写入队列的执行器（§5.2 行 886）：把攒批后的任务落到
// 已落地的 repo——model.EventLog 走 EventLogRepo.BatchInsert，last_login_at
// 走 UserRepo.UpdateLastLogin。执行失败只记日志（队列骨架不重试、不影响登录
// 主链路，§5.2 行 893）；真实重试策略归后续执行器卡。
type Executor struct {
	logs  *repo.EventLogRepo
	users *repo.UserRepo
}

func (e *Executor) Execute(ctx context.Context, tasks []asyncqueue.Task) {
	var rows []model.EventLog
	for _, task := range tasks {
		switch v := task.Value.(type) {
		case model.EventLog:
			rows = append(rows, v)
		case LastLoginTask:
			if err := e.users.UpdateLastLogin(ctx, v.UserID, v.At); err != nil {
				slog.Warn("asyncqueue: update last_login_at failed", "user_id", v.UserID, "error", err)
			}
		}
	}
	if len(rows) == 0 {
		return
	}
	if err := e.logs.BatchInsert(ctx, rows); err != nil {
		slog.Warn("asyncqueue: batch insert event_log failed", "rows", len(rows), "error", err)
	}
}

// NewExecutor 注入事件行与用户仓储（装配层构造）。
func NewExecutor(logs *repo.EventLogRepo, users *repo.UserRepo) *Executor {
	return &Executor{logs: logs, users: users}
}
