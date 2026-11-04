package asyncqueue

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

// ② 同 key 合并：同 key 只执行最终值，跨 key 全部保留（§5.2 行 884）。
func TestMergeSameKeyKeepsLastValue(t *testing.T) {
	f := newFakeExecutor()
	q := New(f, Options{Capacity: 64, Workers: 1, BatchSize: 200, FlushInterval: 100 * time.Millisecond})
	defer q.Close(context.Background())

	q.Push(Task{Key: "k1", Value: "v1"})
	q.Push(Task{Key: "k1", Value: "v2"})
	q.Push(Task{Key: "k2", Value: "v3"})

	batch := waitBatch(t, f, 2*time.Second)
	if len(batch) != 2 {
		t.Fatalf("merged batch len = %d, want 2", len(batch))
	}
	values := make(map[string]any, len(batch))
	for _, task := range batch {
		values[task.Key] = task.Value
	}
	if values["k1"] != "v2" || values["k2"] != "v3" {
		t.Fatalf("merged values = %v, want k1=v2, k2=v3", values)
	}
}

// ③ 满 200 条触发 flush：批次上限默认 200（§5.2 行 882）；测试把间隔设为
// 1h，确保只可能是「满批」触发。
func TestFlushWhenBatchFull(t *testing.T) {
	f := newFakeExecutor()
	q := New(f, Options{Capacity: 512, Workers: 1, BatchSize: 200, FlushInterval: time.Hour})
	defer q.Close(context.Background())

	for i := 0; i < 200; i++ {
		q.Push(Task{Key: strconv.Itoa(i), Value: i})
	}

	batch := waitBatch(t, f, 2*time.Second)
	if len(batch) != 200 {
		t.Fatalf("batch len = %d, want 200", len(batch))
	}
}

// ④ 满 2 秒（此处注入 50ms）触发 flush：未满批的单条任务也必须按时执行
// （§5.2 行 882）。
func TestFlushByInterval(t *testing.T) {
	f := newFakeExecutor()
	q := New(f, Options{Capacity: 16, Workers: 1, BatchSize: 200, FlushInterval: 50 * time.Millisecond})
	defer q.Close(context.Background())

	q.Push(Task{Key: "only", Value: 1})

	batch := waitBatch(t, f, 2*time.Second)
	if len(batch) != 1 || batch[0].Key != "only" {
		t.Fatalf("batch = %v, want one task key=only", batch)
	}
}

// ⑤ 关闭时 flush 剩余任务，且 Close 幂等（§5.2 行 892）。
func TestCloseFlushesRemaining(t *testing.T) {
	f := newFakeExecutor()
	q := New(f, Options{Capacity: 64, Workers: 1, BatchSize: 200, FlushInterval: time.Hour, CloseTimeout: 2 * time.Second})

	for i := 0; i < 5; i++ {
		q.Push(Task{Key: strconv.Itoa(i), Value: i})
	}
	if err := q.Close(context.Background()); err != nil {
		t.Fatalf("Close = %v, want nil", err)
	}

	batch := waitBatch(t, f, time.Second)
	if len(batch) != 5 {
		t.Fatalf("flush-on-close batch len = %d, want 5", len(batch))
	}
	if got := q.Dropped(); got != 0 {
		t.Errorf("dropped = %d, want 0", got)
	}

	// 幂等：第二次 Close 返回首次结果，不重复 flush、不阻塞。
	if err := q.Close(context.Background()); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
}

// ⑥ 关闭超时强退：慢 Executor 卡住时 Close 不得挂死，超时返回
// ErrCloseTimeout（§5.2 行 892）。
func TestCloseTimeoutForcesReturn(t *testing.T) {
	f := newFakeExecutor()
	gate := make(chan struct{})
	f.gate = gate
	defer close(gate)

	q := New(f, Options{Capacity: 16, Workers: 1, BatchSize: 1, FlushInterval: time.Hour, CloseTimeout: 50 * time.Millisecond})
	q.Push(Task{Key: "blocked", Value: 1})
	select {
	case <-f.started:
	case <-time.After(time.Second):
		t.Fatal("executor not started")
	}

	start := time.Now()
	if err := q.Close(context.Background()); !errors.Is(err, ErrCloseTimeout) {
		t.Fatalf("Close = %v, want ErrCloseTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Close took %s, want bounded by CloseTimeout", elapsed)
	}
	// 幂等：超时结果同样只计算一次。
	if err := q.Close(context.Background()); !errors.Is(err, ErrCloseTimeout) {
		t.Errorf("second Close = %v, want ErrCloseTimeout", err)
	}
}
