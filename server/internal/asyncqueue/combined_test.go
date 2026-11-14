// combined_test.go 多执行器合并的分发行为：同一批任务按构造顺序送达每个执行器，
// 每个执行器拿到完整任务切片（各自按类型过滤，§5.2 行 872）。
package asyncqueue

import (
	"context"
	"reflect"
	"testing"
)

// recordExecutor 记录调用顺序与收到的任务切片。
type recordExecutor struct {
	name  string
	order *[]string
	got   *[]Task
}

func (e recordExecutor) Execute(_ context.Context, tasks []Task) {
	*e.order = append(*e.order, e.name)
	*e.got = append([]Task(nil), tasks...)
}

// TestCombinedDispatchOrder 两个执行器按构造顺序各收到一次同一批任务。
func TestCombinedDispatchOrder(t *testing.T) {
	var order []string
	var got []Task
	c := NewCombined(
		recordExecutor{name: "first", order: &order, got: &got},
		recordExecutor{name: "second", order: &order, got: &got},
	)
	tasks := []Task{{Key: "k1", Value: 1}, {Key: "k2", Value: 2}}
	c.Execute(context.Background(), tasks)

	if !reflect.DeepEqual(order, []string{"first", "second"}) {
		t.Fatalf("order = %v, want [first second]", order)
	}
	if !reflect.DeepEqual(got, tasks) {
		t.Fatalf("tasks = %v, want %v", got, tasks)
	}
}

// TestCombinedEmpty 无执行器时静默返回（不 panic、不阻塞）。
func TestCombinedEmpty(t *testing.T) {
	NewCombined().Execute(context.Background(), []Task{{Key: "k1", Value: 1}})
}
