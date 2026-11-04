package webauthn

// queue.go 断言通过后把 sign_count 投递延迟队列（§8.3 行 1049：不阻塞响应），
// 按 credential 同键合并取最大值（§5.2 行 872）。

import (
	"context"
	"strconv"

	"authloft/internal/asyncqueue"
)

// SignCountUpdate 延迟队列任务载荷（标准类型，不含库类型）。
type SignCountUpdate struct {
	ID        int64
	SignCount int64
}

// SignCountPusher 延迟队列窄接口（*asyncqueue.Queue 天然满足；测试用 Fake）。
type SignCountPusher interface {
	Push(task asyncqueue.Task) bool
}

// SignCountSink sign_count 落库窄接口（repo.WebauthnRepo 天然满足）。
type SignCountSink interface {
	UpdateSignCount(ctx context.Context, id int64, signCount int64) error
}

const signCountKeyPrefix = "webauthn:sign_count:"

// enqueueSignCount 非阻塞投递；队列满 / 未注入时丢弃，绝不因队列失败影响
// 认证结论（§5.2 行 895、§8.3 行 1049）。
func enqueueSignCount(q SignCountPusher, id int64, signCount int64) {
	if q == nil {
		return
	}
	q.Push(asyncqueue.Task{
		Key:   signCountKeyPrefix + strconv.FormatInt(id, 10),
		Value: SignCountUpdate{ID: id, SignCount: signCount},
	})
}

// SignCountExecutor 消费合并批次：对同一 credential 的多次更新取最大
// signCount 后落库（§5.2 行 872「同 credential 合并，取最大值」）。
// 装配方用本执行器构造 asyncqueue.Queue 即可获得该合并语义。
type SignCountExecutor struct {
	sink SignCountSink
}

// NewSignCountExecutor 构造执行器；sink 由装配方注入真实 repo。
func NewSignCountExecutor(sink SignCountSink) *SignCountExecutor {
	return &SignCountExecutor{sink: sink}
}

// Execute 实现 asyncqueue.Executor。错误由具体 sink 内部承担，骨架不重试、
// 不告警；取最大值后逐个落库。
func (e *SignCountExecutor) Execute(ctx context.Context, tasks []asyncqueue.Task) {
	if e == nil || e.sink == nil {
		return
	}
	maxByID := make(map[int64]int64, len(tasks))
	for _, t := range tasks {
		u, ok := t.Value.(SignCountUpdate)
		if !ok {
			continue
		}
		if cur, exists := maxByID[u.ID]; !exists || u.SignCount > cur {
			maxByID[u.ID] = u.SignCount
		}
	}
	for id, count := range maxByID {
		_ = e.sink.UpdateSignCount(ctx, id, count)
	}
}
