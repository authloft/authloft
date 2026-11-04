package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"authloft/internal/asyncqueue"
	"authloft/internal/eventlog"
	"authloft/internal/repo/model"
	"authloft/internal/service/orchestrator"
)

// loginEventCapture 记录延迟队列交给 Executor 的任务。
type loginEventCapture struct {
	mu    sync.Mutex
	tasks []asyncqueue.Task
}

func (c *loginEventCapture) Execute(_ context.Context, tasks []asyncqueue.Task) {
	cp := append([]asyncqueue.Task(nil), tasks...)
	c.mu.Lock()
	c.tasks = append(c.tasks, cp...)
	c.mu.Unlock()
}

func (c *loginEventCapture) all() []asyncqueue.Task {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]asyncqueue.Task(nil), c.tasks...)
}

// newLoginEventWriter 构造测试用适配器与捕获执行器；不连 DB / Redis。
func newLoginEventWriter() (*LoginEventWriter, *loginEventCapture, *asyncqueue.Queue) {
	exec := &loginEventCapture{}
	q := asyncqueue.New(exec, asyncqueue.Options{
		Capacity:      64,
		Workers:       1,
		BatchSize:     100,
		FlushInterval: time.Hour,
	})
	return NewLoginEventWriter(eventlog.NewWriter(q)), exec, q
}

func closeLoginEventQueue(t *testing.T, q *asyncqueue.Queue) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := q.Close(ctx); err != nil {
		t.Fatalf("queue.Close: %v", err)
	}
}

// loginDetail 是 §4.6 行 798 的 detail 解码目标。
type loginDetail struct {
	Factor     string `msgpack:"factor"`
	MFAFactor  string `msgpack:"mfa_factor"`
	SessionID  string `msgpack:"session_id"`
	DeviceHint string `msgpack:"device_hint"`
}

// TestLoginEventWriterRecordMapsFields 校验 LoginEvent → login_success 行
// 的字段映射（actor/user/client/amr/detail）与 last_login 任务（§4.6 行
// 774-775、798、806）。
func TestLoginEventWriterRecordMapsFields(t *testing.T) {
	w, exec, q := newLoginEventWriter()
	const authTime = int64(1700000000)
	ev := orchestrator.LoginEvent{
		UID:      42,
		TID:      "tid-1",
		ClientID: "client-a",
		AMR:      []string{"pwd", "otp"},
		AuthTime: authTime,
	}
	if err := w.Record(context.Background(), ev); err != nil {
		t.Fatalf("Record: %v", err)
	}
	closeLoginEventQueue(t, q)

	tasks := exec.all()
	if len(tasks) != 2 {
		t.Fatalf("tasks = %d, want 2（1 条 event_log + 1 条 last_login）", len(tasks))
	}

	var (
		row     model.EventLog
		hasRow  bool
		lastKey string
		last    eventlog.LastLoginTask
		hasLast bool
	)
	for _, task := range tasks {
		switch v := task.Value.(type) {
		case model.EventLog:
			row, hasRow = v, true
		case eventlog.LastLoginTask:
			lastKey, last, hasLast = task.Key, v, true
		default:
			t.Fatalf("unexpected task value type %T", task.Value)
		}
	}
	if !hasRow || !hasLast {
		t.Fatalf("hasRow=%v hasLast=%v, want both", hasRow, hasLast)
	}

	if row.Event != eventlog.EventLoginSuccess {
		t.Errorf("event = %q, want %q", row.Event, eventlog.EventLoginSuccess)
	}
	if row.ActorType != eventlog.ActorTypeUser {
		t.Errorf("actor_type = %q, want %q", row.ActorType, eventlog.ActorTypeUser)
	}
	if row.ActorID != 42 || row.UserID != 42 {
		t.Errorf("actor_id/user_id = %d/%d, want 42/42", row.ActorID, row.UserID)
	}
	if row.ClientID != "client-a" {
		t.Errorf("client_id = %q, want client-a", row.ClientID)
	}
	if row.AMR != "pwd,otp" {
		t.Errorf("amr = %q, want pwd,otp", row.AMR)
	}
	// 本卡无请求上下文：ip/ua 写空串（DDL 默认 ''，§4.6 行 776-777）。
	if row.IP != "" || row.UA != "" {
		t.Errorf("ip/ua = %q/%q, want empty strings", row.IP, row.UA)
	}
	if row.Target != "" {
		t.Errorf("target = %q, want empty", row.Target)
	}
	if want := time.Unix(authTime, 0); !row.CreatedAt.Equal(want) {
		t.Errorf("created_at = %v, want %v", row.CreatedAt, want)
	}

	var detail loginDetail
	if err := msgpack.Unmarshal(row.Detail, &detail); err != nil {
		t.Fatalf("detail msgpack.Unmarshal: %v", err)
	}
	if detail.Factor != "pwd" || detail.MFAFactor != "otp" {
		t.Errorf("detail factor/mfa_factor = %q/%q, want pwd/otp", detail.Factor, detail.MFAFactor)
	}
	// LoginEvent 不含 session_id / device_hint：本卡写空串（不扩接口）。
	if detail.SessionID != "" || detail.DeviceHint != "" {
		t.Errorf("detail session_id/device_hint = %q/%q, want empty", detail.SessionID, detail.DeviceHint)
	}

	if want := "last_login:42"; lastKey != want {
		t.Errorf("last_login key = %q, want %q", lastKey, want)
	}
	if last.UserID != 42 {
		t.Errorf("last_login user_id = %d, want 42", last.UserID)
	}
	if want := time.Unix(authTime, 0); !last.At.Equal(want) {
		t.Errorf("last_login at = %v, want %v", last.At, want)
	}
}

// TestLoginEventWriterLastLoginMergeByUserID 校验同 user_id 的 last_login
// 任务 Key 相同、合并后只保留最新时间；event_log 仍逐行不合并（§5.2 行
// 867-868）。
func TestLoginEventWriterLastLoginMergeByUserID(t *testing.T) {
	w, exec, q := newLoginEventWriter()
	records := []orchestrator.LoginEvent{
		{UID: 42, ClientID: "client-a", AMR: []string{"pwd"}, AuthTime: 1700000000},
		{UID: 42, ClientID: "client-a", AMR: []string{"pwd", "otp"}, AuthTime: 1700000100},
		{UID: 43, ClientID: "client-b", AMR: []string{"pwd"}, AuthTime: 1700000200},
	}
	for _, ev := range records {
		if err := w.Record(context.Background(), ev); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	closeLoginEventQueue(t, q)

	var (
		eventRows int
		lastByUID = map[int64]eventlog.LastLoginTask{}
	)
	for _, task := range exec.all() {
		switch v := task.Value.(type) {
		case model.EventLog:
			eventRows++
		case eventlog.LastLoginTask:
			lastByUID[v.UserID] = v
		}
	}
	if eventRows != len(records) {
		t.Errorf("event_log rows = %d, want %d（逐行不合并）", eventRows, len(records))
	}
	if len(lastByUID) != 2 {
		t.Fatalf("last_login tasks = %d, want 2（同 user_id 应合并）", len(lastByUID))
	}
	if want := time.Unix(1700000100, 0); !lastByUID[42].At.Equal(want) {
		t.Errorf("uid=42 at = %v, want %v（只保留最新时间）", lastByUID[42].At, want)
	}
	if want := time.Unix(1700000200, 0); !lastByUID[43].At.Equal(want) {
		t.Errorf("uid=43 at = %v, want %v", lastByUID[43].At, want)
	}
}

// TestLoginEventWriterNilNoop 校验装配缺失时 Record 不报错、不 panic
// （投递失败不回流登录主链路）。
func TestLoginEventWriterNilNoop(t *testing.T) {
	ev := orchestrator.LoginEvent{UID: 42, AuthTime: 1700000000}
	var w *LoginEventWriter
	if err := w.Record(context.Background(), ev); err != nil {
		t.Errorf("nil writer Record: %v", err)
	}
	if err := NewLoginEventWriter(nil).Record(context.Background(), ev); err != nil {
		t.Errorf("nil logs Record: %v", err)
	}
}
