// DegradeState 单测：置位 / 清除 / 观测字段语义（本地可跑，不连 Redis）。
// 只记录不拦截是生产侧约束（读方法 err 原样透传），本文件只验证状态位
// 自身的转换与保留行为。
package cache

import (
	"testing"
	"time"
)

// TestDegradeStateSetClear 覆盖：初始未降级 → Set 置位并记录时间与原因 →
// Clear 清除但保留观测字段 → 再次 Set 覆盖。
func TestDegradeStateSetClear(t *testing.T) {
	s := &DegradeState{}
	if s.IsDegraded() {
		t.Fatal("初始不应处于降级态")
	}
	if !s.SetAt().IsZero() {
		t.Errorf("初始 SetAt 应为零值, got %v", s.SetAt())
	}
	if s.Reason() != "" {
		t.Errorf("初始 Reason 应为空串, got %q", s.Reason())
	}

	before := time.Now()
	s.Set("redis unreachable")
	if !s.IsDegraded() {
		t.Fatal("Set 后应处于降级态")
	}
	if s.Reason() != "redis unreachable" {
		t.Errorf("Reason = %q, want %q", s.Reason(), "redis unreachable")
	}
	if s.SetAt().Before(before) {
		t.Errorf("SetAt 应不早于置位时刻, got %v (before %v)", s.SetAt(), before)
	}

	s.Clear()
	if s.IsDegraded() {
		t.Fatal("Clear 后不应处于降级态")
	}
	if s.Reason() != "redis unreachable" {
		t.Errorf("Clear 后 Reason 应保留供观测, got %q", s.Reason())
	}
	if s.SetAt().IsZero() {
		t.Error("Clear 后 SetAt 应保留供观测最近一次故障")
	}

	s.Set("redis ping failed")
	if s.Reason() != "redis ping failed" {
		t.Errorf("再次置位应覆盖 Reason, got %q", s.Reason())
	}
	if s.SetAt().Before(before) {
		t.Errorf("再次置位应推进 SetAt, got %v", s.SetAt())
	}
}
