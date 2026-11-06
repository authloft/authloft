// events_test.go account 域 GetEvents 的单测。全部走 fake、不连
// DB / Redis：event 单值筛选透传与缺省不过滤（proto「查询参数缺省即不过
// 滤」）/ 仅本人 uid 维度 / 分页原样透传（归一职责在拼装层 + repo 双层，
// 本层不重复）/ 空结果 / 行与总数透传 / uid 防御哨兵 / repo 错误原样上抛。
package account

import (
	"context"
	"errors"
	"testing"

	"authloft/internal/eventlog"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// fakeEventStore EventStore 的 fake：记录每次收到的 query；err 非Nil 时
// 原样返回，否则返回预置 rows / total。
type fakeEventStore struct {
	got   []repo.EventLogListQuery
	rows  []model.EventLog
	total int64
	err   error
}

func (f *fakeEventStore) ListByUser(_ context.Context, q repo.EventLogListQuery) ([]model.EventLog, int64, error) {
	f.got = append(f.got, q)
	if f.err != nil {
		return nil, 0, f.err
	}
	return f.rows, f.total, nil
}

// TestGetEventsFilterPassThrough event 单值筛选透传：缺省空串 = 不过滤
// （该用户全部事件）；非空（登录记录 / 敏感操作类）原样透传 repo——
// 「仅成功记录」系数据源口径非查询期过滤，见 events.go 头注释。
func TestGetEventsFilterPassThrough(t *testing.T) {
	cases := []struct {
		name  string
		event string
	}{
		{"缺省空串不过滤", ""},
		{"筛登录记录", eventlog.EventLoginSuccess},
		{"筛敏感操作", eventlog.EventChangePassword},
		{"未知事件值原样透传", "no_such_event"},
	}
	for _, tc := range cases {
		f := &fakeEventStore{}
		s := NewEventsService(f)
		if _, _, err := s.GetEvents(context.Background(), 42, tc.event, 1, 20); err != nil {
			t.Fatalf("%s: GetEvents err = %v", tc.name, err)
		}
		if len(f.got) != 1 {
			t.Fatalf("%s: repo 调用次数 = %d, want 1", tc.name, len(f.got))
		}
		if f.got[0].Event != tc.event {
			t.Errorf("%s: Query.Event = %q, want %q", tc.name, f.got[0].Event, tc.event)
		}
	}
}

// TestGetEventsOnlySelf 仅本人：会话 uid 是唯一 user 维度，原样落 query。
func TestGetEventsOnlySelf(t *testing.T) {
	f := &fakeEventStore{}
	s := NewEventsService(f)
	if _, _, err := s.GetEvents(context.Background(), 7, eventlog.EventLoginSuccess, 1, 20); err != nil {
		t.Fatalf("GetEvents err = %v", err)
	}
	if len(f.got) != 1 || f.got[0].UserID != 7 {
		t.Errorf("Query.UserID = %+v, want 7", f.got)
	}
}

// TestGetEventsPagingPassThrough 分页原样透传：§1.7 归一职责在拼装层
// normalizeListPage（先归一 + 回显）与 repo normalize（二次兜底），本层
// 不重复归一——0 / 负 / 超限值也原样透传。
func TestGetEventsPagingPassThrough(t *testing.T) {
	cases := []struct{ page, pageSize int }{
		{1, 20},
		{3, 7},
		{0, 0},
		{-5, 999},
	}
	for _, tc := range cases {
		f := &fakeEventStore{}
		s := NewEventsService(f)
		if _, _, err := s.GetEvents(context.Background(), 42, "", tc.page, tc.pageSize); err != nil {
			t.Fatalf("分页(%d,%d): err = %v", tc.page, tc.pageSize, err)
		}
		if got := f.got[0]; got.Page != tc.page || got.PageSize != tc.pageSize {
			t.Errorf("分页(%d,%d): Query = (%d,%d), want 原样透传", tc.page, tc.pageSize, got.Page, got.PageSize)
		}
	}
}

// TestGetEventsEmptyResult 空结果：零行 + total 0 原样返回（§1.7 行 279
// 空页 items 省略——空 repeated 序列化省略由 proto 层天然成立，本层只回空切片）。
func TestGetEventsEmptyResult(t *testing.T) {
	f := &fakeEventStore{}
	s := NewEventsService(f)
	rows, total, err := s.GetEvents(context.Background(), 42, eventlog.EventLoginSuccess, 1, 20)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(rows) != 0 || total != 0 {
		t.Errorf("空结果 = (%d 行, total %d), want (0, 0)", len(rows), total)
	}
}

// TestGetEventsRowsAndTotal 行与过滤后总数原样透传。
func TestGetEventsRowsAndTotal(t *testing.T) {
	f := &fakeEventStore{
		rows: []model.EventLog{
			{ID: 2, Event: eventlog.EventLoginSuccess, IP: "1.2.3.4", UA: "ua"},
			{ID: 1, Event: eventlog.EventChangePassword},
		},
		total: 128,
	}
	s := NewEventsService(f)
	rows, total, err := s.GetEvents(context.Background(), 42, "", 6, 20)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(rows) != 2 || rows[0].ID != 2 || rows[1].ID != 1 {
		t.Errorf("行透传 = %+v", rows)
	}
	if total != 128 {
		t.Errorf("total = %d, want 128", total)
	}
}

// TestGetEventsInvalidUID uid <= 0（拼装层契约违约）→ ErrEventsInvalidRequest，
// repo 不被调用（仅本人防御，invalid_request 口径）。
func TestGetEventsInvalidUID(t *testing.T) {
	for _, uid := range []int64{0, -1} {
		f := &fakeEventStore{}
		s := NewEventsService(f)
		if _, _, err := s.GetEvents(context.Background(), uid, "", 1, 20); !errors.Is(err, ErrEventsInvalidRequest) {
			t.Errorf("uid %d: err = %v, want ErrEventsInvalidRequest", uid, err)
		}
		if len(f.got) != 0 {
			t.Errorf("uid %d: repo 不应被调用（次数 = %d）", uid, len(f.got))
		}
	}
}

// TestGetEventsRepoError repo 错误原样上抛（拼装层映射 internal）。
func TestGetEventsRepoError(t *testing.T) {
	boom := errors.New("eventlog repo: boom")
	f := &fakeEventStore{err: boom}
	s := NewEventsService(f)
	if _, _, err := s.GetEvents(context.Background(), 42, "", 1, 20); !errors.Is(err, boom) {
		t.Errorf("err = %v, want 原样上抛 boom", err)
	}
}
