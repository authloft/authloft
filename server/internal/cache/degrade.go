// DegradeState Redis 软降级状态信号（后端架构 §5.3）：原子位 + 最近置位
// 时间。进程内单一实例、随 RedisClient 同生命周期（NewClient 创建并挂到
// 客户端上，恢复清除挂探活路径）。只记录、不拦截、不吞错——业务读路径仍
// 按既有逻辑拿 err 回源 DB，本状态仅用于存活探活与可观测性；消费方不得以
// 它替代错误判定，也不得依据它改变业务返回语义。
package cache

import (
	"sync/atomic"
	"time"
)

// DegradeState Redis 软降级状态：各读方法命令级故障置位、探活 PING 成功
// 清除。置位无锁幂等可重入——故障期每条失败读都会调用，只改原子量，不
// 放大开销。
type DegradeState struct {
	degraded atomic.Bool
	setAt    atomic.Int64 // 最近一次置位的 unix 纳秒时间戳（0 = 从未置位）
	reason   atomic.Value // 最近一次置位原因（string，仅描述用）
}

// IsDegraded 当前是否处于降级态。
func (s *DegradeState) IsDegraded() bool { return s.degraded.Load() }

// Set 置位降级状态并打点（时间与原因）。reason 仅用于日志 / 状态页描述，
// 不进错误链路。先记原因再置位：观察方看到 degraded 后读 Reason 必可见。
func (s *DegradeState) Set(reason string) {
	s.setAt.Store(time.Now().UnixNano())
	s.reason.Store(reason)
	s.degraded.Store(true)
}

// Clear 清除降级状态（Redis 恢复时由探活路径调用）。时间与原因保留供观测
// 最近一次故障，再次降级时覆盖。
func (s *DegradeState) Clear() { s.degraded.Store(false) }

// SetAt 最近一次置位时间（从未置位返回零值）。
func (s *DegradeState) SetAt() time.Time {
	if n := s.setAt.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// Reason 最近一次置位原因（从未置位返回空串）。
func (s *DegradeState) Reason() string {
	r, _ := s.reason.Load().(string)
	return r
}
