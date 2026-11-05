// Package asyncqueue 实现 docs/后端架构.md §5.2（行 858-894）的通用延迟
// 写入队列骨架：固定容量 ring buffer、非阻塞 Push、N worker、200 条/2s
// 攒批、同 key 合并、优雅关闭与 dropped 计数。具体任务类型与真实 Redis /
// MariaDB 执行器不在本包范围；本包只用标准库。
package asyncqueue

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrCloseTimeout 关闭超时后强制返回（§5.2 行 892：默认 10s）。此时队列
// 已停止接收，但不再等待仍在执行（慢 Executor）的在途批次。
var ErrCloseTimeout = errors.New("asyncqueue: close timeout")

// Task 队列任务的最小单元：Key 是合并键（§5.2 行 884），Value 是交给
// Executor 的最终值。Key 的具体语义（cache 键名、user_id、credential 等）
// 由后续任务类型决定，本骨架不解释 Key。
type Task struct {
	Key   string
	Value any
}

// Executor 合并后批次的唯一执行入口（§5.2 行 886）。真实 Redis pipeline /
// MariaDB 批量 INSERT-UPDATE 由后续实现承担。执行器错误处理与重试策略不在
// 本包范围，由具体执行器内部承担，故接口不返回
// error——骨架不重试、不告警，只保证合并与投递。
type Executor interface {
	Execute(ctx context.Context, tasks []Task)
}

// Queue 延迟写入队列。构造后 opts / exec 只读；运行期共享状态由 mu 与
// 两个 atomic 计数保护：Push 与 dispatch 竞争 ring buffer，Len / Dropped
// 无锁读取。
type Queue struct {
	exec Executor
	opts Options

	mu     sync.Mutex
	buf    []Task
	head   int
	tail   int
	count  int
	closed bool

	length  atomic.Int64
	dropped atomic.Uint64
	flushMs atomic.Int64

	notify  chan struct{}
	closeCh chan struct{}
	jobs    chan []Task

	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

// New 构造队列并立即启动 1 个 dispatch goroutine 与 opts.Workers 个执行
// worker（§5.2 行 878-886）。exec 必须非 nil；opts 零值字段回落 §5.2 默认值。
func New(exec Executor, opts Options) *Queue {
	q := newQueue(exec, opts)
	q.start()
	return q
}

// newQueue 只构造不启动（测试可直接检查 Push / Len / Dropped 的 ring 语义）。
func newQueue(exec Executor, opts Options) *Queue {
	opts = opts.withDefaults()
	q := &Queue{
		exec:    exec,
		opts:    opts,
		buf:     make([]Task, opts.Capacity),
		notify:  make(chan struct{}, 1),
		closeCh: make(chan struct{}),
		jobs:    make(chan []Task),
	}
	// flush 指标在构造处包一层计时（最小增量）：不改 dispatch /
	// worker 调度结构，executor 的真实执行耗时（Redis pipeline /
	// MariaDB 批量 INSERT-UPDATE）即为 flush 耗时的监控口径。
	q.exec = &timedExecutor{inner: exec, record: q.flushMs.Store}
	return q
}

func (q *Queue) start() {
	q.wg.Add(q.opts.Workers)
	for i := 0; i < q.opts.Workers; i++ {
		go q.worker()
	}
	go q.dispatch()
}

// Push 非阻塞写入固定容量 ring buffer（§5.2 行 878、891）。队列已满或已
// 关闭时直接丢弃、累加 dropped 计数并返回 false，绝不阻塞调用方（§5.2
// 行 893：绝不因队列失败影响登录主链路）。返回 true 表示已入队。
func (q *Queue) Push(task Task) bool {
	q.mu.Lock()
	if q.closed || q.count == len(q.buf) {
		q.mu.Unlock()
		q.dropped.Add(1)
		return false
	}
	q.buf[q.tail] = task
	q.tail = (q.tail + 1) % len(q.buf)
	q.count++
	q.length.Add(1)
	q.mu.Unlock()

	q.signal()
	return true
}

// Len 当前 ring buffer 中待处理的任务数（§5.2 行 894 可观测）。原子读，
// 与 Push / dispatch 并发安全；不含 dispatch 已取走、尚未 flush 的批次。
func (q *Queue) Len() int { return int(q.length.Load()) }

// Dropped 因队列满或已关闭而丢弃的任务总数（§5.2 行 893、894）。
func (q *Queue) Dropped() uint64 { return q.dropped.Load() }

// FlushMs 最近一次 flush 耗时（毫秒）：即 executor 执行一个合并批次的
// 真实耗时（Redis pipeline / MariaDB 批量 INSERT-UPDATE），供
// AdminService/GetStatus 监控（接口文档 §5.6 行 1277「flush 耗时」）。
// 与设置项 queue_flush_ms（攒批时间窗，§5.6）不同名不同义。
// 未发生过 flush 时为 0；多 worker 并发下为任意 worker 最近完成的批次。
func (q *Queue) FlushMs() int64 { return q.flushMs.Load() }

// timedExecutor flush 计时装饰器（最小增量）：透传执行并记录耗时
// 毫秒数，不改调度结构（§5.2 行 886 的执行入口语义不变）。
type timedExecutor struct {
	inner  Executor
	record func(int64)
}

func (t *timedExecutor) Execute(ctx context.Context, tasks []Task) {
	start := time.Now()
	t.inner.Execute(ctx, tasks)
	t.record(time.Since(start).Milliseconds())
}

// Close 优雅关闭（§5.2 行 892）：停止接收，由 dispatch 把 ring buffer 中
// 剩余任务全部 flush，再等待执行 worker 退出；超过 opts.CloseTimeout
// （默认 10s）或 ctx 结束则返回 ErrCloseTimeout / ctx.Err()，不无限等待。
// 幂等：重复调用返回首次结果。
func (q *Queue) Close(ctx context.Context) error {
	q.closeOnce.Do(func() {
		q.mu.Lock()
		q.closed = true
		q.mu.Unlock()

		close(q.closeCh)

		done := make(chan struct{})
		go func() {
			q.wg.Wait()
			close(done)
		}()

		timer := time.NewTimer(q.opts.CloseTimeout)
		defer timer.Stop()
		select {
		case <-done:
			q.closeErr = nil
		case <-ctx.Done():
			q.closeErr = ctx.Err()
		case <-timer.C:
			q.closeErr = ErrCloseTimeout
		}
	})
	return q.closeErr
}
