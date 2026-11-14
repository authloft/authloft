// combined.go 多执行器合并：同一批任务按序分发给每个执行器，各自只消费
// 认识的任务类型（docs/后端架构.md §5.2 行 872、§8.3 行 1049）。
package asyncqueue

import "context"

// Combined 把同一批任务分发给多个执行器：每个执行器只消费自己
// 认识的任务类型（event_log / last_login 与 webauthn sign_count 互不干扰），
// 满足 asyncqueue 单执行器构造口径（§5.2 行 872、§8.3 行 1049）。
type Combined []Executor

func (c Combined) Execute(ctx context.Context, tasks []Task) {
	for _, exec := range c {
		exec.Execute(ctx, tasks)
	}
}

// NewCombined 按给定顺序组合执行器。
func NewCombined(execs ...Executor) Combined {
	return Combined(execs)
}
