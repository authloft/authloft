package asyncqueue

import "time"

// 默认参数：docs/后端架构.md §5.2 行 880-882（N worker 默认 4、攒批满
// 200 条或距上次 flush 满 2 秒）、行 891（队列总长固定 8192）、行 892
// （优雅关闭超时默认 10s）。
const (
	defaultCapacity      = 8192
	defaultWorkers       = 4
	defaultBatchSize     = 200
	defaultFlushInterval = 2 * time.Second
	defaultCloseTimeout  = 10 * time.Second
)

// Options 队列参数，全部由调用方注入（§5.2 行 891「worker 数量与攒批参数
// 可配」）；零值字段回落上面 §5.2 默认值。
type Options struct {
	// Capacity ring buffer 容量（默认 8192）。
	Capacity int
	// Workers 执行 worker 数量，即 Executor 并发上限（默认 4）。
	Workers int
	// BatchSize 攒批上限，满即 flush（默认 200）。
	BatchSize int
	// FlushInterval 距上次 flush 的最长等待（默认 2s）。
	FlushInterval time.Duration
	// CloseTimeout Close 等待剩余任务 flush 的超时（默认 10s）。
	CloseTimeout time.Duration
}

// DefaultOptions 返回 §5.2 全默认参数。
func DefaultOptions() Options {
	return Options{
		Capacity:      defaultCapacity,
		Workers:       defaultWorkers,
		BatchSize:     defaultBatchSize,
		FlushInterval: defaultFlushInterval,
		CloseTimeout:  defaultCloseTimeout,
	}
}

// withDefaults 零值字段回落默认值（调用方只下发部分参数时仍可用）。
func (o Options) withDefaults() Options {
	d := DefaultOptions()
	if o.Capacity <= 0 {
		o.Capacity = d.Capacity
	}
	if o.Workers <= 0 {
		o.Workers = d.Workers
	}
	if o.BatchSize <= 0 {
		o.BatchSize = d.BatchSize
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = d.FlushInterval
	}
	if o.CloseTimeout <= 0 {
		o.CloseTimeout = d.CloseTimeout
	}
	return o
}
