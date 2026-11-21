// Watcher：订阅 al:settings:chg（后端架构 §5），收到通知后全量重载快照
// （§15.3：各实例秒级生效）。
//
// 版本比对取舍（允许简化）：不做增量 / 版本号比对，收到通知一律
// 全量重读 settings 表。理由：35 键单表全读 = 一条 SELECT，通知频率 =
// 管理员改配置（极低频），全量重载以可忽略的成本换取实现与语义的简单
// ——不存在「版本号推进了但键没变 / 键变了但版本号没推进」这类一致性
// 缝隙。
package settings

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"authloft/internal/cache"
)

// reloadTimeout 单次重载的兜底超时；DB 拥塞时放弃本次（数据未变坏，
// 下一次通知或轮询收敛），不阻塞后续通知的处理。
const reloadTimeout = 5 * time.Second

// subscribeTimeout 订阅确认的兜底窗口：Redis 故障期底层连接会在后台持续
// 重试、长时间不返回错误，订阅确认必须限时——超时即视为订阅失败转 DB 轮询
// 兜底，否则装配会卡死在 Start 上（软降级口径：后端架构 §5.3）。
const subscribeTimeout = 3 * time.Second

// DefaultPollInterval 订阅失败时 DB 轮询兜底的默认间隔：settings 变更是
// 极低频管理操作，故障期该量级的重载延迟可接受；LoadAll 为单表一条
// SELECT，DB 压力可忽略（后端架构 §5.3 / §15.3）。
const DefaultPollInterval = 10 * time.Minute

// Watcher 配置热更新订阅者。生命周期：NewWatcher → Start（建立订阅，或
// 订阅失败转 DB 轮询兜底）→ Close（优雅关闭：断订阅 / 停轮询、等后台
// goroutine 退出）。订阅与轮询二选一运行：Start 时一次性决策，避免双路径
// 同时重载。
type Watcher struct {
	rdb          *cache.RedisClient
	st           *Store
	sub          cache.PubSub
	pollInterval time.Duration

	subDone  chan struct{} // loop goroutine 退出标记（订阅路径）
	pollStop chan struct{} // 关闭即停轮询（轮询路径）
	pollDone chan struct{} // pollLoop goroutine 退出标记（轮询路径）

	closeOnce sync.Once
}

// NewWatcher 构造；rdb 与 st 由调用方注入（与 Store 共用连接与快照）。
// pollInterval 为订阅失败转 DB 轮询兜底的间隔，非正值取 DefaultPollInterval
// （仅测试需要缩短）。
func NewWatcher(rdb *cache.RedisClient, st *Store, pollInterval time.Duration) *Watcher {
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}
	return &Watcher{
		rdb:          rdb,
		st:           st,
		pollInterval: pollInterval,
		subDone:      make(chan struct{}),
	}
}

// Start 建立配置热更通道（后端架构 §5.3 软降级口径）：订阅确认走 Pub/Sub
// 路径（秒级生效）；确认失败（含限时窗口内未确认）不返回错误、不阻断装配
// ——告警后转 DB 轮询兜底（定时全量重载 settings 表）。仅 ctx 已取消（进程
// 关闭中）时上抛，让装配层走正常收口。
func (w *Watcher) Start(ctx context.Context) error {
	sctx, cancel := context.WithTimeout(ctx, subscribeTimeout)
	sub, err := w.rdb.Subscribe(sctx, cache.SettingsChgKey())
	cancel()
	if err == nil {
		w.sub = sub
		go w.loop()
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("settings: subscribe %s: %w", cache.SettingsChgKey(), err)
	}
	slog.Warn("settings: subscribe failed, falling back to db polling",
		"channel", cache.SettingsChgKey(),
		"interval", w.pollInterval,
		"error", err)
	w.startPolling()
	return nil
}

// startPolling 拉起 DB 轮询兜底 goroutine（仅订阅失败路径调用一次）。
func (w *Watcher) startPolling() {
	w.pollStop = make(chan struct{})
	w.pollDone = make(chan struct{})
	go w.pollLoop()
}

// pollLoop 定时全量重载 settings 表；重载失败只记日志继续等下一拍（快照
// 仍旧值，不致命）。首拍延迟一个间隔——装配期 Preload 已成功预热快照，
// 无需启动即重载。
func (w *Watcher) pollLoop() {
	defer close(w.pollDone)
	timer := time.NewTimer(w.pollInterval)
	defer timer.Stop()
	for {
		select {
		case <-w.pollStop:
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), reloadTimeout)
			if err := w.st.reload(ctx); err != nil {
				slog.Warn("settings: poll reload failed", "error", err)
			}
			cancel()
			timer.Reset(w.pollInterval)
		}
	}
}

// loop 消费通知：Channel 在 Close 后关闭，循环自然退出。重载失败只记
// 日志继续等下一次通知（快照仍旧值，不致命）。
func (w *Watcher) loop() {
	defer close(w.subDone)
	for range w.sub.Channel() {
		ctx, cancel := context.WithTimeout(context.Background(), reloadTimeout)
		if err := w.st.reload(ctx); err != nil {
			slog.Warn("settings: reload on chg notification failed", "error", err)
		}
		cancel()
	}
}

// Close 优雅关闭（幂等，Start 前后均可安全调用）：订阅路径停订阅等 loop
// 退出；轮询路径停定时器等 pollLoop 退出。
func (w *Watcher) Close() error {
	w.closeOnce.Do(func() {
		if w.sub != nil {
			w.sub.Stop()
			<-w.subDone
			w.sub = nil
		}
		if w.pollStop != nil {
			close(w.pollStop)
			<-w.pollDone
		}
	})
	return nil
}
