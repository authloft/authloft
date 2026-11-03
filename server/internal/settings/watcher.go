// Watcher：订阅 al:settings:chg（后端架构 §5 行 860），收到通知后全量
// 重载快照（§15.3 行 1684：各实例秒级生效）。
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
	"time"

	"github.com/redis/go-redis/v9"

	"authloft/internal/cache"
)

// reloadTimeout 单次重载的兜底超时；DB 拥塞时放弃本次（数据未变坏，
// 下一次通知或重启收敛），不阻塞后续通知的处理。
const reloadTimeout = 5 * time.Second

// Watcher 配置热更新订阅者。生命周期：NewWatcher → Start（建立订阅并
// 拉起后台 goroutine）→ Close（优雅关闭：断订阅、等 goroutine 退出）。
type Watcher struct {
	rdb  *redis.Client
	st   *Store
	sub  *redis.PubSub
	done chan struct{}
}

// NewWatcher 构造；rdb 与 st 由调用方注入（与 Store 共用连接与快照）。
func NewWatcher(rdb *redis.Client, st *Store) *Watcher {
	return &Watcher{rdb: rdb, st: st, done: make(chan struct{})}
}

// Start 订阅 al:settings:chg：Receive 确认订阅建立后拉起后台 goroutine。
// 订阅失败返回错误（fail-fast，与 cache.NewClient 的 PING 口径一致——
// Redis 不可达时装配期就该暴露）。
func (w *Watcher) Start(ctx context.Context) error {
	sub := w.rdb.Subscribe(ctx, cache.SettingsChgKey())
	if _, err := sub.Receive(ctx); err != nil {
		_ = sub.Close()
		return fmt.Errorf("settings: subscribe %s: %w", cache.SettingsChgKey(), err)
	}
	w.sub = sub
	go w.loop()
	return nil
}

// loop 消费通知：Channel 在 Close 后关闭，循环自然退出。重载失败只记
// 日志继续等下一次通知（快照仍旧值，不致命）；连续失败最终由重启闭环。
func (w *Watcher) loop() {
	defer close(w.done)
	for range w.sub.Channel() {
		ctx, cancel := context.WithTimeout(context.Background(), reloadTimeout)
		if err := w.st.reload(ctx); err != nil {
			slog.Warn("settings: reload on chg notification failed", "error", err)
		}
		cancel()
	}
}

// Close 优雅关闭（须在 Start 成功后调用）：关闭订阅 → Channel 关闭 →
// loop 退出 → done 关闭。重复调用返回 nil 幂等。
func (w *Watcher) Close() error {
	if w.sub == nil {
		return nil
	}
	err := w.sub.Close()
	<-w.done
	w.sub = nil
	return err
}
