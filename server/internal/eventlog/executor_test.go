// executor_test.go 执行器的任务分流：只消费 model.EventLog 与 LastLoginTask，
// 其余任务类型原样忽略；空批次直接返回（队列骨架不重试、不影响主链路）。
// 两条落库分支的真实 SQL 行为由 repo 层环境变量门控用例覆盖
// （eventlog_repo_test.go / user_repo_test.go）。
package eventlog

import (
	"context"
	"testing"

	"authloft/internal/asyncqueue"
)

// TestExecutorIgnoresUnknownTasks 未识别的任务类型不进 event_log 批、也不触发
// last_login_at 更新：nil 仓储下执行不 panic 即为「未触碰仓储」的证据。
func TestExecutorIgnoresUnknownTasks(t *testing.T) {
	exec := NewExecutor(nil, nil)
	exec.Execute(context.Background(), []asyncqueue.Task{
		{Key: "other:1", Value: struct{ A int }{A: 1}},
		{Key: "other:2", Value: "raw"},
	})
}

// TestExecutorEmptyBatch 空批次直接返回。
func TestExecutorEmptyBatch(t *testing.T) {
	exec := NewExecutor(nil, nil)
	exec.Execute(context.Background(), nil)
}
