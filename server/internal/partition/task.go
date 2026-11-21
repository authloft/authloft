// 分区维护定时任务：调度与分布式锁（后端架构 §4.6 清理段 / §3.1 装配层）。
// Start 立即跑一轮 + 按周期重复；每轮先经 Redis SET NX 抢固定键锁——多副本
// 部署下未抢到的实例跳过本轮（防并发分区 DDL），抢到的实例读 settings 两键
// 钳制兜底后执行 EnsurePartition / DropExcess。单轮失败只记日志，不影响
// 任务生命周期与后续轮次。
//
// 锁释放口径：不主动释放、过期自失效。理由：轮询周期（24h）远大于锁 TTL，
// 本实例无需为下一轮提前释放；主动释放需要比对锁值的 GET+DEL，反而引入
// 误删他人锁的竞态。TTL 只需大于单轮维护最长耗时：单轮有独立超时
// （roundTimeout），TTL 取其两倍余量，保证在途轮次必被超时先于锁过期中断。
package partition

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"authloft/internal/cache"
)

// DefaultInterval 分区维护默认周期（§4.6：每日滚动新增与淘汰）。
const DefaultInterval = 24 * time.Hour

// 锁与单轮的时长边界：roundTimeout 兜底单轮耗时，TTL 两倍余量——在途轮次
// 必先于锁过期被取消，锁不会在轮次进行中失效。
const (
	defaultLockTTL = 10 * time.Minute
	roundTimeout   = 5 * time.Minute
)

// 消费侧参数兜底：settings 写入侧已按 [1,365] 校验（§4.7），此处是读取侧
// 防线——缺键 / 类型异常 / 越界一律回落默认值，与 settings 两键默认值同源
// （7 天 / 26 个）。
const (
	defaultPartitionDays = 7
	defaultMaxPartitions = 26
)

// ParamSource 分区参数读取通道：生产由 *settings.Store 满足（GetInt64 既有
// 读方法，快照经 Preload 全量预热）；测试注入桩。键名经 TaskOptions 注入而
// 非本包硬编码——settings 键属主在 settings 包，本包不反向依赖（repo 依赖
// 本包接口，反向 import 会成环）。
type ParamSource interface {
	GetInt64(key string) (int64, bool)
}

// LockClient 抢锁通道：生产由 *cache.RedisClient 满足（SetNX）。只收窄到
// 抢锁一个动作——锁过期自失效、无主动释放，无需 DEL 通道。
type LockClient interface {
	SetNX(ctx context.Context, key string, value any, expiration time.Duration) cache.BoolResult
}

// TaskOptions 构造可调项。零值语义：LockKey 空取 cache.PartitionLockKey()，
// LockTTL / Interval 非正取 defaultLockTTL / DefaultInterval；DaysKey /
// MaxKey 由装配层必传（传空则每轮都走默认值兜底，不报错）。
type TaskOptions struct {
	DaysKey  string
	MaxKey   string
	LockKey  string
	LockTTL  time.Duration
	Interval time.Duration
}

// Task event_log 分区维护定时任务。生命周期：NewTask → Start（一次，立即
// 跑一轮 + 起 Ticker）→ Close（幂等，Start 前后均可安全调用）。
type Task struct {
	mgr      PartitionManager
	params   ParamSource
	locker   LockClient
	daysKey  string
	maxKey   string
	lockKey  string
	lockTTL  time.Duration
	interval time.Duration

	cancel    context.CancelFunc // 运行 ctx：Close 取消在途轮次并停 Ticker
	done      chan struct{}      // loop goroutine 退出标记（Start 前为 nil）
	closeOnce sync.Once
}

// NewTask 构造任务；mgr / params / locker 由装配层注入（依赖方向见
// TaskOptions 与各接口注释）。
func NewTask(mgr PartitionManager, params ParamSource, locker LockClient, opt TaskOptions) *Task {
	if opt.LockKey == "" {
		opt.LockKey = cache.PartitionLockKey()
	}
	if opt.LockTTL <= 0 {
		opt.LockTTL = defaultLockTTL
	}
	if opt.Interval <= 0 {
		opt.Interval = DefaultInterval
	}
	return &Task{
		mgr:      mgr,
		params:   params,
		locker:   locker,
		daysKey:  opt.DaysKey,
		maxKey:   opt.MaxKey,
		lockKey:  opt.LockKey,
		lockTTL:  opt.LockTTL,
		interval: opt.Interval,
	}
}

// Start 启动任务：立即跑一轮（兜底分区的积压分流等不到次日），随后按
// interval 周期触发。不等待首轮完成即返回，装配不被分区 DDL 阻塞；仅 ctx
// 已取消（进程关闭中）时上抛，让装配层走正常收口。须只调用一次。
func (t *Task) Start(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	runCtx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.done = make(chan struct{})
	go t.loop(runCtx)
	return nil
}

// loop 首轮 + 周期触发；退出即关 done（Close 等待的收口信号）。
func (t *Task) loop(runCtx context.Context) {
	defer close(t.done)
	t.runRound(runCtx)
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()
	for {
		select {
		case <-runCtx.Done():
			return
		case <-ticker.C:
			t.runRound(runCtx)
		}
	}
}

// runRound 单轮维护：抢锁 → 未抢到跳过（不报错）→ 读两键钳制兜底 →
// EnsurePartition + DropExcess（两者独立，前者失败不阻断后者）。错误只记
// 日志：分区维护是可重试的收敛过程，兜底分区承接期间的写入不丢（§4.6）。
// 后台协程无请求上下文，按 CODE_GUIDE §3.8 用包级 slog。
func (t *Task) runRound(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, roundTimeout)
	defer cancel()
	ok, err := t.locker.SetNX(ctx, t.lockKey, lockHolder(), t.lockTTL).Result()
	if err != nil {
		slog.Warn("partition: lock acquire failed, skip round", "error", err)
		return
	}
	if !ok {
		slog.Info("partition: lock busy, skip round", "key", t.lockKey)
		return
	}
	days, maxParts := t.readParams()
	slog.Info("partition: maintenance round start", "days", days, "max_partitions", maxParts)
	if err := t.mgr.EnsurePartition(ctx, time.Now(), days); err != nil {
		slog.Warn("partition: ensure partition failed", "error", err)
	}
	if err := t.mgr.DropExcess(ctx, maxParts); err != nil {
		slog.Warn("partition: drop excess failed", "error", err)
	}
}

// readParams 读 N/X 并钳制兜底：越界（含非正数）回落默认值而非钳到边界
// ——管理员配错时按默认节奏维护，比贴着上限（365 天 / 365 个分区）执行
// 更接近配置意图。
func (t *Task) readParams() (days, maxParts int) {
	days, maxParts = defaultPartitionDays, defaultMaxPartitions
	if v, ok := t.params.GetInt64(t.daysKey); ok && v >= minIntervalDays && v <= maxIntervalDays {
		days = int(v)
	}
	if v, ok := t.params.GetInt64(t.maxKey); ok && v >= minMaxPartitions && v <= maxMaxPartitions {
		maxParts = int(v)
	}
	return days, maxParts
}

// Close 优雅关闭（幂等，Start 前后均可安全调用）：取消运行 ctx 停 Ticker
// 并中断在途轮次，等 loop goroutine 退出。Start 前调用为 no-op（无在途
// goroutine）；Close 后任务终结，不再 Start。
func (t *Task) Close() error {
	t.closeOnce.Do(func() {
		if t.cancel != nil {
			t.cancel()
		}
		if t.done != nil {
			<-t.done
		}
	})
	return nil
}

// lockHolder 锁值仅作持锁标识（排障用），无消费方——锁的有效性完全由
// SET NX 原子性与 TTL 承载。
func lockHolder() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}
