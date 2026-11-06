// events.go account 域 GetEvents（本人事件日志）业务层（docs/
// 接口文档.md §3.7 行 1055-1058、§1.7 行 278-279、§4.2.2 行 1580「登录
// 日志」映射；proto api/account/v1/thirdparty.proto GetEventsRequest 行
// 113 消息注释「查询参数缺省即不过滤，一律 optional」）。
//
// 职责边界（单方法）：
//   - GetEvents：本人事件日志（§3.7 行 1057）。仅本人：uid 固定由拼装层
//     从会话注入，本层仅按该 uid 查询（repo ListByUser 的 user_id
//     过滤天然成立）；proto GetEventsRequest 结构上不含任何 uid / actor
//     字段，契约上不可查他人。event 单值筛选：空 = 不过滤（该用户全部
//     事件），非空 = 精确匹配（repo Where event = ?；§1.7 行 278「后端
//     不做白名单强制校验」同款，未知值 = 空结果）。
//   - 分页沿 §1.7（page 从 1 起、pageSize 默认 20 上限 100）：拼装层
//     normalizeListPage 先归一且回显、repo normalize 二次兜底，本层原样
//     透传——与 admin GetUserEvents 全链同构（service/admin/user.go:395）。
//   - 排序 sort/order：GetEventsRequest 有字段保留，但本方法不应用——沿
//     admin GetUserEvents 先例（handler 不透传、repo ListByUser 固定
//     id DESC 保证分页全序稳定）；sort 值域核对留待真后端联调。
//
// 「仅成功记录」过滤口径（§3.7 行 1057）：**数据源口径，非查询期过滤**——
// eventlog 常量集（《后端架构》§4.6 行 770-792）不含 login_failed，登录
// 失败从不投递 event_log 行、login_success 仅登录成功时写入；event_log 行
// 亦无成功标志列，结构上不可也无从再加「成功」过滤。因此无论缺省全查还是
// 筛 login_success，登录记录子集天然仅含成功记录；event 缺省（全部事件）
// 中的非登录行（敏感操作等）不受该口径影响。
//
// 失败形态：纯读方法、非信封域——错误走可判别哨兵（handler 转 Connect
// 错误体 + ErrorInfo）；repo 错误原样透传（拼装层映射 internal，
// admin GetUserEvents 同款）。
package account

import (
	"context"
	"errors"

	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// EventStore event_log 读取窄接口（§20 依赖注入）：*repo.EventLogRepo 天然
// 满足（ListByUser 为既有方法，不扩公共接口），测试可传 fake。
type EventStore interface {
	ListByUser(ctx context.Context, q repo.EventLogListQuery) ([]model.EventLog, int64, error)
}

// ErrEventsInvalidRequest uid 缺失 / 非正（拼装层契约：必须注入会话 uid，
// <= 0 即违约）——handler 转 Connect 错误体 + ErrorInfo(account,
// invalid_request)，§1.6 封闭集成员。
var ErrEventsInvalidRequest = errors.New("account events: invalid request")

// EventsService account 域本人事件日志业务层。
type EventsService struct {
	events EventStore
}

// NewEventsService 构造。
func NewEventsService(events EventStore) *EventsService {
	return &EventsService{events: events}
}

// GetEvents（§3.7 行 1057）：返回该用户当页事件行与过滤后总数；行 →
// proto UserEventItem 投影（含 detail msgpack → JSON 对象、created_at →
// Unix 秒）归拼装层。本层不做行级加工。
func (s *EventsService) GetEvents(ctx context.Context, uid int64, event string, page, pageSize int) ([]model.EventLog, int64, error) {
	if uid <= 0 {
		return nil, 0, ErrEventsInvalidRequest
	}
	return s.events.ListByUser(ctx, repo.EventLogListQuery{
		UserID:   uid,
		Event:    event,
		Page:     page,
		PageSize: pageSize,
	})
}

// compile 时断言生产实现满足窄接口（profile.go 同款）。
var _ EventStore = (*repo.EventLogRepo)(nil)
