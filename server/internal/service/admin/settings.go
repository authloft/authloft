// settings.go 实现 AdminService 系统配置 / 事件 / 工具族 5 方法
// （GetSettings / SetSettings / ListEvents / DecodeToken / GetStatus，
// 接口文档 §5.6 行 1270-1277）的业务层（docs/后端架构.md §3.9
// 行 390、§18 行 1792 分层 handler → service/admin/settings.go →
// settings.Store / repo/eventlog_repo.go / asyncqueue.Queue）。
//
// 职责边界：
//   - GetSettings：Store.Snapshot → 35 键全键投影（键名与默认值唯一真相 =
//     §5.6 四张表，与 internal/settings 常量表逐键一致，键名零自造）；投影
//     到 SettingsResponse 在 dto.AdminSettings（§3.5 裁剪在 dto）。
//   - SetSettings：全量替换语义（proto flat 消息 + protojson 零值省略 →
//     每字段即键、缺省视为零值写回；前端设置页以 GET 结果为底稿改后整体
//     回写，settings.proto SetSettingsRequest 注释同口径）。35 键整体经
//     Store.SetMany 落库（白名单 + 值类型校验在 settings.Validate；交叉
//     约束不做，§5.6 行 1342 前端与管理员自律），PUBLISH al:settings:chg
//     由 SetMany 完成 → watcher 热更天然生效。写后投递审计
//     eventlog.EventSettingsUpdate（actor=admin，actor_id=会话 uid，
//     「settings_update 审计事件」按待用口径落地；detail 经
//     eventlog.DetailSettingsUpdate 只含变更项 keys/before/after）。
//   - ListEvents：统一事件视图（§5.6 行 1275），六筛选 + 分页 §1.7 透传
//     repo.EventLogRepo.List（最小增量，排序口径同 user_repo
//     orderClause）。响应投影复用 dto.AdminEventItem。
//   - DecodeToken：排障工具（§5.6 行 1276）。purpose 取值即 security 包
//     §11.6.1 AAD purpose 口径（login|session|cookie，零自造）；login →
//     token.LoginTokenPayload、session → token.SessionTokenPayload，经
//     security.Open 用装配的独立 Codec 解载荷，protojson（camelCase +
//     EmitUnpopulated，默认：排障视图零值字段恒可见）投影在
//     dto.AdminDecodePayload。载荷含敏感内容（session uid/sid、
//     login_token ch 等）：本层与 handler 均不落日志、错误信息不携带
//     payload 内容（错误文案固定，透传 security 包错误——其不含明文）。
//   - GetStatus：监控三字段（§5.6 行 1277）——asyncqueue.Queue.Len() /
//     Dropped() 既有 + FlushMs()（最小增量：executor 执行合并批次
//     的真实耗时）。
//
// Connect 错误形态映射归 handler（复用 mapWriteError 口径）；本层返回可判别
// 哨兵错误（同 provider.go 包注释）：ErrInvalidRequest（非法 purpose / 解码
// 失败）映射 invalid_argument + code=invalid_request（§1.6 封闭集合）；其余
// 错误原样上抛，由错误包装拦截器消毒为 internal。
package admin

import (
	"context"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	adminv1 "authloft/gen/go/api/admin/v1"
	"authloft/gen/go/token"
	"authloft/internal/eventlog"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/settings"
)

// SettingsStore settings 表读写窄接口（§20 依赖注入）：*settings.Store 天然
// 满足（Snapshot 全键只读；SetMany 单事务 UPSERT + PUBLISH 热更通知，
// watcher 全量重载使各实例快照收敛），测试可传 fake。
type SettingsStore interface {
	Snapshot() map[string]any
	SetMany(ctx context.Context, kv map[string]any, updatedBy int64) error
}

// EventLister event_log 统一事件视图读取窄接口：*repo.EventLogRepo
// 天然满足（List 最小增量），测试可传 fake。
type EventLister interface {
	List(ctx context.Context, q repo.EventAdminQuery) ([]model.EventLog, int64, error)
}

// TokenCodecs 三场景独立令牌编解码器（§1.4 / §11.6.1；bootstrap codecs
// 结构体的 admin 视图）。Cookie 当前无具名载荷 proto（见 DecodeToken cookie
// 分支注释），装配位保留——thirdparty 卡落地 LoginStatePayload 后直接消费。
type TokenCodecs struct {
	Session *security.Codec
	Login   *security.Codec
	Cookie  *security.Codec
}

// QueueMonitor 延迟写入队列只读指标窄接口（§5.2 行 894 + GetStatus 口径）：
// *asyncqueue.Queue 天然满足，测试可传 fake。
type QueueMonitor interface {
	Len() int
	Dropped() uint64
	FlushMs() int64
}

// EventListFilter ListEvents 入参（§5.6 行 1275 六筛选均可空 + §1.7 分页；
// optional 指针原样透传，nil 即不过滤）。
type EventListFilter struct {
	Event     string
	ActorType string
	ActorID   *int64
	UserID    *int64
	From      *int64
	To        *int64
	Page      int
	PageSize  int
	Sort      string
	Order     string
}

// QueueStatus GetStatus 三字段（tools.proto StatusResponse 数据源）。
type QueueStatus struct {
	QueueLength int64
	Dropped     uint64
	FlushMs     int64
}

// SettingsService admin 域系统配置 / 事件 / 工具族业务层。
type SettingsService struct {
	store  SettingsStore
	events EventLister
	audit  AuditSink
	codecs TokenCodecs
	queue  QueueMonitor
	now    func() time.Time
}

// NewSettingsService 构造；任一依赖为 nil 属程序错误（fail-fast，口径同
// NewUserService）。
func NewSettingsService(
	store SettingsStore, events EventLister, audit AuditSink,
	codecs TokenCodecs, queue QueueMonitor,
) *SettingsService {
	if store == nil {
		panic("admin service: NewSettingsService: nil SettingsStore")
	}
	if events == nil {
		panic("admin service: NewSettingsService: nil EventLister")
	}
	if audit == nil {
		panic("admin service: NewSettingsService: nil AuditSink")
	}
	if queue == nil {
		panic("admin service: NewSettingsService: nil QueueMonitor")
	}
	return &SettingsService{
		store:  store,
		events: events,
		audit:  audit,
		codecs: codecs,
		queue:  queue,
		now:    time.Now,
	}
}

// GetSettings（§5.6 行 1274，OUTCOME ①）：Store.Snapshot 全量只读副本，
// 35 键投影在 dto.AdminSettings。键集封闭（settings 白名单），本层零加工。
func (s *SettingsService) GetSettings() map[string]any {
	return s.store.Snapshot()
}

// SetSettings（§5.6 行 1274，OUTCOME ②）：全量替换——请求消息的每个字段
// 即一个 settings 键（protojson 零值省略 → 缺省视为零值写回，前端设置页
// 全量提交），35 键整批 SetMany 落库（updated_by=actor，热更由 SetMany 的
// PUBLISH al:settings:chg 通知各实例 watcher 全量重载，天然生效）。
// 写成功后投递审计 settings_update：detail 只含变更项（{keys, before,
// after}，§4.6 行 804），无变更时 keys/before/after 为空集但仍投递——每次
// 管理员动作都留痕（口径同 UserService.UpdateUserStatus 幂等重放审计）。
// 写入仅校验值类型（settings.Validate 在 SetMany 内），交叉约束不兜底
// （§5.6 行 1342）。
func (s *SettingsService) SetSettings(ctx context.Context, actor int64, req *adminv1.SetSettingsRequest) error {
	before := s.store.Snapshot()
	kv := settingsRequestValues(req)
	keys, beforeChanged, after := diffSettings(before, kv)
	if err := s.store.SetMany(ctx, kv, actor); err != nil {
		return err
	}
	s.audit.PushEvent(model.EventLog{
		Event:     eventlog.EventSettingsUpdate,
		ActorType: eventlog.ActorTypeAdmin,
		ActorID:   actor,
		// user_id：系统级配置变更无被操作用户，落 0（§4.6 行 771-772
		// actor/user 语义；user.go 单用户操作才有被操作对象，默认）。
		UserID:    0,
		Detail:    eventlog.DetailSettingsUpdate(keys, beforeChanged, after),
		CreatedAt: s.now(),
	})
	return nil
}

// settingsRequestValues 把全量提交的请求消息按 settings 键常量组 35 键
// map（键名与 §5.6 四张表逐字一致，零自造；repeated 字段空 = nil →
// settings.Validate 收敛为 []string 空切片清空该列表）。
func settingsRequestValues(req *adminv1.SetSettingsRequest) map[string]any {
	return map[string]any{
		settings.KeyPwdMinLength:          req.GetPwdMinLength(),
		settings.KeyPwdMaxLength:          req.GetPwdMaxLength(),
		settings.KeyPwdRequireClasses:     req.GetPwdRequireClasses(),
		settings.KeyPwdDisallowUsername:   req.GetPwdDisallowUsername(),
		settings.KeyPwdDisallowCommon:     req.GetPwdDisallowCommon(),
		settings.KeyAllowPasswordReset:    req.GetAllowPasswordReset(),
		settings.KeyOtpResendInterval:     req.GetOtpResendInterval(),
		settings.KeyOtpTtl:                req.GetOtpTtl(),
		settings.KeyOtpMaxAttempts:        req.GetOtpMaxAttempts(),
		settings.KeyOtpDailyLimitTarget:   req.GetOtpDailyLimitTarget(),
		settings.KeyOtpDailyLimitIP:       req.GetOtpDailyLimitIp(),
		settings.KeyLoginMethods:          req.GetLoginMethods(),
		settings.KeyAllowRegistration:     req.GetAllowRegistration(),
		settings.KeyAllowSignupPassword:   req.GetAllowSignupPassword(),
		settings.KeyAllowSignupPhone:      req.GetAllowSignupPhone(),
		settings.KeyAllowSignupEmail:      req.GetAllowSignupEmail(),
		settings.KeyMfaEnabled:            req.GetMfaEnabled(),
		settings.KeyMfaMethods:            req.GetMfaMethods(),
		settings.KeyPwdFailCapture:        req.GetPwdFailCapture(),
		settings.KeyPwdFailBan:            req.GetPwdFailBan(),
		settings.KeyPwdBanTtl:             req.GetPwdBanTtl(),
		settings.KeySessionTtl:            req.GetSessionTtl(),
		settings.KeyCookieName:            req.GetCookieName(),
		settings.KeySsoDomains:            req.GetSsoDomains(),
		settings.KeyQueueWorkers:          req.GetQueueWorkers(),
		settings.KeyQueueCapacity:         req.GetQueueCapacity(),
		settings.KeyQueueBatch:            req.GetQueueBatch(),
		settings.KeyQueueFlushMs:          req.GetQueueFlushMs(),
		settings.KeyCaptchaProviderKey:    req.GetCaptchaProviderKey(),
		settings.KeySmsProviderKey:        req.GetSmsProviderKey(),
		settings.KeyEmailProviderKey:      req.GetEmailProviderKey(),
		settings.KeyAvatarStorageProvider: req.GetAvatarStorageProvider(),
		settings.KeyGatewayTokens:         req.GetGatewayTokens(),
		settings.KeyEventlogRetentionDays: req.GetEventlogRetentionDays(),
		settings.KeyStaticBase:            req.GetStaticBase(),
	}
}

// diffSettings 变更项比对：按 settings.Defs() 表序遍历白名单键集，返回
// 值有变化的键列表与 before / after 片段（只含变更项，§4.6 行 804）。
// []string 按 slices.Equal 语义（nil 与空切片同值——proto 空 repeated 为
// nil、快照经 DecodeValue 归一为 []string{}，语义上均为清空）。
func diffSettings(before, next map[string]any) (keys []string, beforeChanged, after map[string]any) {
	beforeChanged = map[string]any{}
	after = map[string]any{}
	for _, d := range settings.Defs() {
		oldV, newV := before[d.Key], next[d.Key]
		if settingsValueEqual(oldV, newV) {
			continue
		}
		keys = append(keys, d.Key)
		beforeChanged[d.Key] = oldV
		after[d.Key] = newV
	}
	return keys, beforeChanged, after
}

// settingsValueEqual 快照 / 请求值比较（四类值域：int64 / bool / string /
// []string，§5.6 四张表全部键归入四类）。类型不符判不等（不可达路径，
// proto 字段类型与 settings 注册类型一致）。
func settingsValueEqual(a, b any) bool {
	switch av := a.(type) {
	case int64:
		bv, ok := b.(int64)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case []string:
		bv, ok := b.([]string)
		return ok && slices.Equal(av, bv)
	default:
		return false
	}
}

// ListEvents（§5.6 行 1275，OUTCOME ③）：统一事件视图六筛选 + 分页透传
// repo.EventLogRepo.List；分页归一在 handler（normalizeListPage）+ repo
// （normalize）双层兜底，排序防注入在 repo.orderClause。
func (s *SettingsService) ListEvents(ctx context.Context, f EventListFilter) ([]model.EventLog, int64, error) {
	return s.events.List(ctx, repo.EventAdminQuery{
		Event:     f.Event,
		ActorType: f.ActorType,
		ActorID:   f.ActorID,
		UserID:    f.UserID,
		From:      f.From,
		To:        f.To,
		Page:      f.Page,
		PageSize:  f.PageSize,
		Sort:      f.Sort,
		Order:     f.Order,
	})
}

// DecodeToken（§5.6 行 1276，OUTCOME ④）：purpose 即 security 包 §11.6.1
// AAD purpose 口径（跨 purpose 解令牌由 AAD 构造天然拒绝）。login /
// session 分别用装配的独立 Codec 解出载荷消息（proto.Message，由
// dto.AdminDecodePayload 经 protojson 转 Struct 投影）；失败（含篡改、
// 跨 purpose、未知 kid）一律 ErrInvalidRequest → invalid_request。
//
// cookie purpose（解 al_login_state）：其载荷 proto（LoginStatePayload）归
// thirdparty redirect/api 通道的后续实现（生成链
// 未跑、字段级 schema 在 docs 未落地），security.Open 需要载荷 proto 类型、
// 且 internal/security 不在本次改动范围（无法新增绕过类型的明文解密出口）→
// 当前按解码失败口径返回 ErrInvalidRequest（默认，待定；
// LoginStatePayload 落地后本分支收编为具名字段投影，
// TokenCodecs.Cookie 装配位已备）。错误文案固定、不携带 token 与 payload
// 内容；本方法任何路径不落日志。
func (s *SettingsService) DecodeToken(purpose, tokenStr string) (proto.Message, error) {
	// 解码失败（篡改 / 跨 purpose / 未知 kid / base64 损坏）统一转译干净
	// 哨兵 ErrInvalidRequest：security 包原始错误（含内部实现细节）不得
	// 直达客户端（§1.5 线上文案不携带内部信息），也不携带 token / payload
	// 内容（原错误经核实均为固定文案，转译后全链路无 payload 泄漏面）。
	switch purpose {
	case security.PurposeLogin:
		msg, err := security.Open[token.LoginTokenPayload](s.codecs.Login, security.PurposeLogin, tokenStr)
		if err != nil {
			return nil, ErrInvalidRequest
		}
		return msg, nil
	case security.PurposeSession:
		msg, err := security.Open[token.SessionTokenPayload](s.codecs.Session, security.PurposeSession, tokenStr)
		if err != nil {
			return nil, ErrInvalidRequest
		}
		return msg, nil
	default:
		// 含 PurposeCookie：载荷 schema 未落地（见方法注释）；其余取值
		//（空串、bind/ticket/sync_payload/oidc_code 等封闭集外的 DecodeToken
		// 口径）均为非法 purpose。
		return nil, ErrInvalidRequest
	}
}

// GetStatus（§5.6 行 1277）：队列三指标只读透传（Len 不含
// dispatch 已取走未 flush 的批次，FlushMs 未发生过 flush 时为 0——均沿
// asyncqueue 既有 / 增量口径）。
func (s *SettingsService) GetStatus() QueueStatus {
	return QueueStatus{
		QueueLength: int64(s.queue.Len()),
		Dropped:     s.queue.Dropped(),
		FlushMs:     s.queue.FlushMs(),
	}
}
