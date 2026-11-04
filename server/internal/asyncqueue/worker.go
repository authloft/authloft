package asyncqueue

import (
	"context"
	"time"
)

// dispatch 是唯一的攒批者（§5.2 行 882）：从 ring buffer 取任务，满
// opts.BatchSize 条或距上次 flush 满 opts.FlushInterval 时合并并投递给执行
// worker。全局唯一保证「同 key 只保留最终值」（§5.2 行 884）跨 worker 生效。
func (q *Queue) dispatch() {
	batch := make([]Task, 0, q.opts.BatchSize)
	timer := time.NewTimer(q.opts.FlushInterval)
	defer timer.Stop()
	defer close(q.jobs)

	flush := func() {
		if len(batch) == 0 {
			resetTimer(timer, q.opts.FlushInterval)
			return
		}
		merged := mergeTasks(batch)
		batch = batch[:0]
		q.jobs <- merged
		resetTimer(timer, q.opts.FlushInterval)
	}

	for {
		for len(batch) < q.opts.BatchSize {
			t, ok := q.pop()
			if !ok {
				break
			}
			batch = append(batch, t)
		}
		if len(batch) >= q.opts.BatchSize {
			flush()
			continue
		}

		select {
		case <-q.notify:
		case <-timer.C:
			flush()
		case <-q.closeCh:
			// 优雅关闭：停止接收后把 ring buffer 剩余任务按批次全部 flush
			// （§5.2 行 892），flush 完才关闭 jobs 让 worker 退出。
			for {
				for len(batch) < q.opts.BatchSize {
					t, ok := q.pop()
					if !ok {
						break
					}
					batch = append(batch, t)
				}
				if len(batch) == 0 {
					return
				}
				flush()
			}
		}
	}
}

// worker 调用注入的 Executor 执行合并批次；并发上限 = opts.Workers
// （§5.2 行 880、891），不会无界增长。
func (q *Queue) worker() {
	defer q.wg.Done()
	for tasks := range q.jobs {
		q.exec.Execute(context.Background(), tasks)
	}
}

// pop 从 ring buffer 取一个任务；O(1)，仅移动头指针并递减原子队列长度。
func (q *Queue) pop() (Task, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.count == 0 {
		return Task{}, false
	}
	task := q.buf[q.head]
	q.buf[q.head] = Task{}
	q.head = (q.head + 1) % len(q.buf)
	q.count--
	q.length.Add(-1)
	return task, true
}

// signal 唤醒 dispatch（缓冲 1，多次 Push 合并为一次唤醒，非阻塞）。
func (q *Queue) signal() {
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// mergeTasks 按 Key 合并，同 key 后写覆盖先写、只保留最终值（§5.2 行 884）；
// 保留首次出现顺序，便于测试与排查。
func mergeTasks(batch []Task) []Task {
	merged := make([]Task, 0, len(batch))
	index := make(map[string]int, len(batch))
	for _, task := range batch {
		if i, ok := index[task.Key]; ok {
			merged[i] = task
			continue
		}
		index[task.Key] = len(merged)
		merged = append(merged, task)
	}
	return merged
}

// resetTimer 安全重置 flush 定时器。本包不读取墙钟（§22 行 1913 要求时间
// 可注入；这里只用 Timer 做间隔触发，测试通过 Options 注入短间隔）。
func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}
