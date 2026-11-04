package asyncqueue

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeExecutor 记录每次 Execute 收到的批次；gate 非空时 Execute 阻塞到
// gate 关闭，用来模拟慢执行器并制造队列积压。
type fakeExecutor struct {
	mu      sync.Mutex
	calls   [][]Task
	ch      chan []Task
	gate    chan struct{}
	started chan struct{}
}

func newFakeExecutor() *fakeExecutor {
	return &fakeExecutor{
		ch:      make(chan []Task, 64),
		started: make(chan struct{}, 1),
	}
}

func (f *fakeExecutor) Execute(_ context.Context, tasks []Task) {
	if f.gate != nil {
		select {
		case f.started <- struct{}{}:
		default:
		}
		<-f.gate
	}
	cp := append([]Task(nil), tasks...)
	f.mu.Lock()
	f.calls = append(f.calls, cp)
	f.mu.Unlock()
	select {
	case f.ch <- cp:
	default:
	}
}

// snapshot 返回已记录批次的副本。
func (f *fakeExecutor) snapshot() [][]Task {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]Task, len(f.calls))
	for i, call := range f.calls {
		out[i] = append([]Task(nil), call...)
	}
	return out
}

// waitBatch 等待一次 Execute 批次；超时即失败。
func waitBatch(t *testing.T, f *fakeExecutor, timeout time.Duration) []Task {
	t.Helper()
	select {
	case batch := <-f.ch:
		return batch
	case <-time.After(timeout):
		t.Fatalf("no executor batch within %s", timeout)
		return nil
	}
}

// ① 满队列丢弃并计数：未启动 goroutine，直接检查 ring 语义（Capacity 4，
// 第 5 条起丢弃），不依赖调度时序（§5.2 行 891、893）。
func TestPushDropsWhenFull(t *testing.T) {
	q := newQueue(newFakeExecutor(), Options{Capacity: 4, Workers: 1})

	for i := 0; i < 10; i++ {
		want := i < 4
		if got := q.Push(Task{Key: strconv.Itoa(i), Value: i}); got != want {
			t.Fatalf("push %d accepted = %v, want %v", i, got, want)
		}
	}
	if got := q.Len(); got != 4 {
		t.Errorf("len = %d, want 4", got)
	}
	if got := q.Dropped(); got != 6 {
		t.Errorf("dropped = %d, want 6", got)
	}
}

// ⑦ Push 不阻塞：唯一 worker 被慢执行器占住、ring 已满时，连续 Push 仍
// 应立即返回（只做一次加锁 + 原子计数，绝不等 Executor）。
func TestPushDoesNotBlockOnSlowExecutor(t *testing.T) {
	f := newFakeExecutor()
	gate := make(chan struct{})
	f.gate = gate

	q := New(f, Options{Capacity: 8, Workers: 1, BatchSize: 1, FlushInterval: time.Hour})
	defer q.Close(context.Background())
	defer close(gate)

	q.Push(Task{Key: "busy"})
	select {
	case <-f.started:
	case <-time.After(time.Second):
		t.Fatal("executor not started")
	}

	start := time.Now()
	for i := 0; i < 1000; i++ {
		q.Push(Task{Key: "k" + strconv.Itoa(i), Value: i})
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("1000 Push took %s, want < 200ms", elapsed)
	}
	if got := q.Dropped(); got == 0 {
		t.Fatal("expected drops while queue is full and worker is blocked")
	}
}
