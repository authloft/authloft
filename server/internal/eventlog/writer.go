// writer.go 是 event_log 与 user.last_login_at 投递到延迟写入队列的唯一
// 入口（docs/后端架构.md §3.12 行 448、§4.6 行 806、§5.2 行 858-894）。
// 本文件只做非阻塞 Push，不执行 SQL；真实批量 INSERT / UPDATE 由后续
// Executor 实现（不在本包范围）。
package eventlog

import (
	"strconv"
	"sync/atomic"
	"time"

	"authloft/internal/asyncqueue"
	"authloft/internal/repo/model"
)

// 任务 Key 前缀与合并语义（§5.2 行 864-870、884）：
//
//   - event_log：Key = "event_log:<递增序号>"，每行一个唯一 Key。event_log
//     在 §5.2 行 867 的策略是「攒批」而非合并；asyncqueue.mergeTasks 对同
//     Key 只保留最后一条，若共用固定 Key 会把同批事件折叠成一行。
//   - user.last_login_at：Key = "last_login:<user_id>"，同 user_id 合并、
//     只保留最新时间（§5.2 行 868）。同一批内的多条更新由队列合并为一条。
const (
	eventLogTaskKeyPrefix  = "event_log:"
	lastLoginTaskKeyPrefix = "last_login:"
)

// LastLoginTask 是 last_login_at 延迟更新的任务值；Executor 通过
// type switch 区分本类型与 model.EventLog。
type LastLoginTask struct {
	UserID int64
	At     time.Time
}

// Writer 事件投递器。Queue 由装配层注入并与其它延迟写入任务共用；
// seq 保证 event_log 任务 Key 全局唯一。
type Writer struct {
	queue *asyncqueue.Queue
	seq   atomic.Uint64
}

// NewWriter 注入延迟写入队列。
func NewWriter(queue *asyncqueue.Queue) *Writer {
	return &Writer{queue: queue}
}

// PushEvent 非阻塞投递一行 event_log（§5.2 行 867）。队列满或已关闭时
// asyncqueue 直接丢弃并累计 dropped，本方法不返回错误、不阻塞登录主链路
// （§5.2 行 893：降级由非关键写入自行承担）。
func (w *Writer) PushEvent(ev model.EventLog) {
	if w == nil || w.queue == nil {
		return
	}
	w.queue.Push(asyncqueue.Task{
		Key:   eventLogTaskKeyPrefix + strconv.FormatUint(w.seq.Add(1), 10),
		Value: ev,
	})
}

// PushLastLogin 非阻塞投递 user.last_login_at 更新（§5.2 行 868）。同
// user_id 的 Key 相同，队列合并后只保留最新时间；队列满时同样静默丢弃
// （§5.2 行 893）。
func (w *Writer) PushLastLogin(uid int64, at time.Time) {
	if w == nil || w.queue == nil {
		return
	}
	w.queue.Push(asyncqueue.Task{
		Key:   lastLoginTaskKeyPrefix + strconv.FormatInt(uid, 10),
		Value: LastLoginTask{UserID: uid, At: at},
	})
}
