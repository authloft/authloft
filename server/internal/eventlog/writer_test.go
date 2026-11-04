package eventlog

import (
	"context"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"authloft/internal/asyncqueue"
	"authloft/internal/repo/model"
)

// captureExecutor 记录队列实际交给 Executor 的每一批任务；gate 非空时
// 阻塞在 Execute 内，用来占住 worker 制造满队列。
type captureExecutor struct {
	mu      sync.Mutex
	batches [][]asyncqueue.Task
	started chan struct{}
	gate    chan struct{}
}

func newCaptureExecutor() *captureExecutor {
	return &captureExecutor{started: make(chan struct{}, 1)}
}

func (c *captureExecutor) Execute(_ context.Context, tasks []asyncqueue.Task) {
	if c.gate != nil {
		select {
		case c.started <- struct{}{}:
		default:
		}
		<-c.gate
	}
	cp := append([]asyncqueue.Task(nil), tasks...)
	c.mu.Lock()
	c.batches = append(c.batches, cp)
	c.mu.Unlock()
}

func (c *captureExecutor) all() []asyncqueue.Task {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []asyncqueue.Task
	for _, batch := range c.batches {
		out = append(out, batch...)
	}
	return out
}

// closeQueue 关闭队列以 flush 剩余任务并等待 worker 退出。
func closeQueue(t *testing.T, q *asyncqueue.Queue) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := q.Close(ctx); err != nil {
		t.Fatalf("queue.Close: %v", err)
	}
}

// TestPushEventUniqueKeysNotMerged 校验 event_log 走攒批而非合并：同一批
// 的多行事件必须保留为多条任务（Key 唯一），值原样交给 Executor。
func TestPushEventUniqueKeysNotMerged(t *testing.T) {
	exec := newCaptureExecutor()
	q := asyncqueue.New(exec, asyncqueue.Options{
		Capacity:      64,
		Workers:       1,
		BatchSize:     100,
		FlushInterval: time.Hour,
	})
	w := NewWriter(q)

	rows := []model.EventLog{
		{Event: EventLoginSuccess, UserID: 1},
		{Event: EventChangePassword, UserID: 2},
		{Event: EventSettingsUpdate, UserID: 3},
	}
	for _, row := range rows {
		w.PushEvent(row)
	}
	closeQueue(t, q)

	tasks := exec.all()
	if len(tasks) != len(rows) {
		t.Fatalf("merged tasks = %d, want %d (event_log 应攒批不合并)", len(tasks), len(rows))
	}
	seen := map[string]bool{}
	for i, task := range tasks {
		if seen[task.Key] {
			t.Errorf("duplicate task key %q", task.Key)
		}
		seen[task.Key] = true
		row, ok := task.Value.(model.EventLog)
		if !ok {
			t.Fatalf("task[%d] value type = %T, want model.EventLog", i, task.Value)
		}
		if !reflect.DeepEqual(row, rows[i]) {
			t.Errorf("task[%d] row = %+v, want %+v", i, row, rows[i])
		}
	}
}

// TestPushLastLoginMergesByUserID 校验 last_login 任务 Key 为
// last_login:<user_id>：同 user_id 的多条只保留最新时间，不同 user_id 不
// 互相合并（§5.2 行 868）。
func TestPushLastLoginMergesByUserID(t *testing.T) {
	exec := newCaptureExecutor()
	q := asyncqueue.New(exec, asyncqueue.Options{
		Capacity:      64,
		Workers:       1,
		BatchSize:     100,
		FlushInterval: time.Hour,
	})
	w := NewWriter(q)

	older := time.Unix(1700000000, 0)
	newer := time.Unix(1700000100, 0)
	other := time.Unix(1700000200, 0)
	w.PushLastLogin(42, older)
	w.PushLastLogin(42, newer)
	w.PushLastLogin(43, other)
	closeQueue(t, q)

	tasks := exec.all()
	if len(tasks) != 2 {
		t.Fatalf("tasks = %d, want 2（同 user_id 应合并）", len(tasks))
	}
	got := map[int64]LastLoginTask{}
	for _, task := range tasks {
		v, ok := task.Value.(LastLoginTask)
		if !ok {
			t.Fatalf("value type = %T, want LastLoginTask", task.Value)
		}
		if wantKey := lastLoginTaskKeyPrefix + strconv.FormatInt(v.UserID, 10); task.Key != wantKey {
			t.Errorf("key = %q, want %q", task.Key, wantKey)
		}
		got[v.UserID] = v
	}
	if v := got[42]; !v.At.Equal(newer) {
		t.Errorf("uid=42 at = %v, want %v（应只保留最新时间）", v.At, newer)
	}
	if v := got[43]; !v.At.Equal(other) {
		t.Errorf("uid=43 at = %v, want %v", v.At, other)
	}
}

// TestPushDroppedWhenFullDoesNotBlock 校验队列满时 Writer 静默丢弃：不返回
// 错误（方法签名无 error）、不阻塞调用方，只累加 dropped（§5.2 行 893）。
func TestPushDroppedWhenFullDoesNotBlock(t *testing.T) {
	exec := newCaptureExecutor()
	exec.gate = make(chan struct{})
	q := asyncqueue.New(exec, asyncqueue.Options{
		Capacity:      1,
		Workers:       1,
		BatchSize:     1,
		FlushInterval: time.Hour,
	})
	defer closeQueue(t, q)
	defer close(exec.gate)

	w := NewWriter(q)
	w.PushEvent(model.EventLog{Event: EventLoginSuccess})
	select {
	case <-exec.started:
	case <-time.After(time.Second):
		t.Fatal("executor not started")
	}

	start := time.Now()
	w.PushEvent(model.EventLog{Event: EventLoginSuccess}) // 占满 ring（容量 1）
	w.PushEvent(model.EventLog{Event: EventLoginSuccess}) // 丢弃
	w.PushLastLogin(42, time.Unix(1700000000, 0))         // 丢弃
	w.PushLastLogin(43, time.Unix(1700000000, 0))         // 丢弃
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("4 Push took %s, want < 100ms（队列满不得阻塞登录链路）", elapsed)
	}
	if got := q.Dropped(); got == 0 {
		t.Fatal("dropped = 0, want > 0（队列满应静默丢弃并计数）")
	}
}

// TestNilQueueNoop 校验装配缺失时不 panic（投递失败不回流登录主链路）。
func TestNilQueueNoop(t *testing.T) {
	var w *Writer
	w.PushEvent(model.EventLog{Event: EventLoginSuccess})
	w.PushLastLogin(42, time.Now())

	NewWriter(nil).PushEvent(model.EventLog{Event: EventLoginSuccess})
	NewWriter(nil).PushLastLogin(42, time.Now())
}
