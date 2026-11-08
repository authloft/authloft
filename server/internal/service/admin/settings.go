// settings.go 实现 AdminService 系统配置 / 事件 / 工具族 5 方法
// （GetSettings / SetSettings / ListEvents / DecodeToken / GetStatus，
// 接口文档 §5.6 行 1270-1277）的业务层（docs/后端架构.md §3.9
// 行 390、§18 行 1792 分层 handler → service/admin/settings.go →
// settings.Store / repo/eventlog_repo.go / asyncqueue.Queue）。
//
// 职责边界：
//   - GetSettings：Store.Snapshot → 36 键全键投影（键名与默认值唯一真相 =
//     §5.6 四张表，与 internal/settings 常量表逐键一致，键名零自造）；投影
//     到 SettingsResponse 在 dto.AdminSettings（§3.5 裁剪在 dto）。
//   - SetSettings：部分更新（PATCH）语义——标量按 proto3 optional has 位
//     （生成物 *int64 / *bool / *string）判定：未设置 = 不修改（保留快照
//     现值），显式设值 = 覆盖（含 0 / false / 空串，口径同 §3.2 行 837
//     UpdateProfile）；四个 repeated 键各带一个 has_* 伴生标志（protojson
//     下 [] 与字段缺省同解为 nil，无法自带 has 位），标志取 true = 该列表
//     在场，按请求中的数组整组替换，空数组 / 缺省数组即清空该列表；
//     标志缺省 / 显式 false = 不修改。仅把在场键组经
//     Store.SetMany 落库（白名单 + 值类型校验在 settings.Validate——
//     https_deployment 三态值域校验同在其内，非法值 → invalid_request，
//     §5.6 行 1361；交叉约束不做，§5.6 行 1342 前端与管理员自律），
//     PUBLISH al:settings:chg
//     由 SetMany 完成 → watcher 热更天然生效。写后投递审计
//     eventlog.EventSettingsUpdate（actor=admin，actor_id=会话 uid，
//     「settings_update 审计事件」按待用口径落地；detail 经
//     eventlog.DetailSettingsUpdate 只含在场键中的变更项 keys/before/after）。
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
	"errors"
	"fmt"
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
// 结构体的 admin 视图）。Cookie 解 al_login_state（本实现起消费
// token.LoginStatePayload，见 DecodeToken cookie 分支）。
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
// 36 键投影在 dto.AdminSettings。键集封闭（settings 白名单），本层零加工。
func (s *SettingsService) GetSettings() map[string]any {
	return s.store.Snapshot()
}

// SetSettings（§5.6 行 1274，OUTCOME ②）：部分更新（PATCH）——请求里
// 「在场」的键才写入：optional 标量指针非 nil 即 has 位置位（显式 0 /
// false / 空串同样写回，口径同 §3.2 行 837 UpdateProfile）；四个 repeated
// 键以各自的 has_* 伴生标志取 true 为在场，按请求数组整组替换——数组为
// 空 / 缺省即清空该列表，标志缺省或显式 false 则不修改。未在场键保留
// 快照现值。settingsRequestValues 只产出在场键 map，
// SetMany 仅 UPSERT 这批键（updated_by=actor；PUBLISH al:settings:chg
// 通知各实例 watcher 全量重载，热更天然生效；空 map 在 Store.SetMany
// 内直接返回，不触库也不发通知）。
// 写成功后投递审计 settings_update：detail 只含在场键里的变更项
// （{keys, before, after}，§4.6 行 804），无变更（含空请求）时
// keys/before/after 为空集但仍投递——每次管理员动作都留痕（口径同
// UserService.UpdateUserStatus 幂等重放审计）。写入仅校验值类型
// （settings.Validate 在 SetMany 内），交叉约束不兜底（§5.6 行 1342）；
// 校验失败（settings.ErrInvalidValue：白名单外 / 类型不符 /
// https_deployment 三态值域外）转译本层哨兵 ErrInvalidRequest
// （§5.6 行 1361 SetSettings 非法值 → invalid_request：裸错误
// 直传会被 handler mapWriteError 判不中而误落 500），其余错误原样透传。
func (s *SettingsService) SetSettings(ctx context.Context, actor int64, req *adminv1.SetSettingsRequest) error {
	before := s.store.Snapshot()
	kv := settingsRequestValues(req) // 只含在场键；未设置字段不进 map
	keys, beforeChanged, after := diffSettings(before, kv)
	if err := s.store.SetMany(ctx, kv, actor); err != nil {
		if errors.Is(err, settings.ErrInvalidValue) {
			return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
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

// settingsRequestValues 把请求消息按 has 位投影成「待写入」 settings 键 map
// （键名与 §5.6 四张表逐字一致，零自造；has_* 伴生标志本身不是 settings 键）：
//   - 标量（*int64 / *bool / *string）：ptr != nil = 显式设值，写入其值
//     ——含 0 / false / 空串（pwd_ban_ttl 调 0、cookie_name 清空可表达）；
//     nil = 未设置，不进 map，保留快照现值；
//   - repeated（[]string）：proto3 无 has 位，protojson 下显式 [] 与字段
//     缺省同解为 nil，故每个列表配一个 has_* 伴生标志；标志取 true =
//     列表在场，按数组整组替换（nil / 空数组归一为非 nil 空切片 → 清空
//     该列表），标志缺省 / 显式 false = 不进 map、保留现值。
//
// nil 请求按空请求处理（无任何 has 位）；https_deployment 三态值域校验在
// settings.Validate 内，非法值 → invalid_request（§5.6 行 1361）。
func settingsRequestValues(req *adminv1.SetSettingsRequest) map[string]any {
	kv := make(map[string]any, 36)
	if req == nil {
		return kv
	}
	putOptional(kv, settings.KeyPwdMinLength, req.PwdMinLength)
	putOptional(kv, settings.KeyPwdMaxLength, req.PwdMaxLength)
	putOptional(kv, settings.KeyPwdRequireClasses, req.PwdRequireClasses)
	putOptional(kv, settings.KeyPwdDisallowUsername, req.PwdDisallowUsername)
	putOptional(kv, settings.KeyPwdDisallowCommon, req.PwdDisallowCommon)
	putOptional(kv, settings.KeyAllowPasswordReset, req.AllowPasswordReset)
	putOptional(kv, settings.KeyOtpResendInterval, req.OtpResendInterval)
	putOptional(kv, settings.KeyOtpTtl, req.OtpTtl)
	putOptional(kv, settings.KeyOtpMaxAttempts, req.OtpMaxAttempts)
	putOptional(kv, settings.KeyOtpDailyLimitTarget, req.OtpDailyLimitTarget)
	putOptional(kv, settings.KeyOtpDailyLimitIP, req.OtpDailyLimitIp)
	putList(kv, settings.KeyLoginMethods, req.GetHasLoginMethods(), req.GetLoginMethods())
	putOptional(kv, settings.KeyAllowRegistration, req.AllowRegistration)
	putOptional(kv, settings.KeyAllowSignupPassword, req.AllowSignupPassword)
	putOptional(kv, settings.KeyAllowSignupPhone, req.AllowSignupPhone)
	putOptional(kv, settings.KeyAllowSignupEmail, req.AllowSignupEmail)
	putOptional(kv, settings.KeyMfaEnabled, req.MfaEnabled)
	putList(kv, settings.KeyMfaMethods, req.GetHasMfaMethods(), req.GetMfaMethods())
	putOptional(kv, settings.KeyPwdFailCapture, req.PwdFailCapture)
	putOptional(kv, settings.KeyPwdFailBan, req.PwdFailBan)
	putOptional(kv, settings.KeyPwdBanTtl, req.PwdBanTtl)
	putOptional(kv, settings.KeySessionTtl, req.SessionTtl)
	putOptional(kv, settings.KeyCookieName, req.CookieName)
	putList(kv, settings.KeySsoDomains, req.GetHasSsoDomains(), req.GetSsoDomains())
	putOptional(kv, settings.KeyQueueWorkers, req.QueueWorkers)
	putOptional(kv, settings.KeyQueueCapacity, req.QueueCapacity)
	putOptional(kv, settings.KeyQueueBatch, req.QueueBatch)
	putOptional(kv, settings.KeyQueueFlushMs, req.QueueFlushMs)
	putOptional(kv, settings.KeyCaptchaProviderKey, req.CaptchaProviderKey)
	putOptional(kv, settings.KeySmsProviderKey, req.SmsProviderKey)
	putOptional(kv, settings.KeyEmailProviderKey, req.EmailProviderKey)
	putOptional(kv, settings.KeyAvatarStorageProvider, req.AvatarStorageProvider)
	putList(kv, settings.KeyGatewayTokens, req.GetHasGatewayTokens(), req.GetGatewayTokens())
	putOptional(kv, settings.KeyEventlogRetentionDays, req.EventlogRetentionDays)
	putOptional(kv, settings.KeyStaticBase, req.StaticBase)
	putOptional(kv, settings.KeyHttpsDeployment, req.HttpsDeployment)
	return kv
}

// putOptional 按 has 位写入标量键：指针非 nil 才写，值取指针所指（显式零值
// 同样写入）。泛型只覆盖请求的 int64 / bool / string 三类标量，逐键显式表
// 而非反射，避免把「未设置」误投影成零值写回。
func putOptional[T any](kv map[string]any, key string, ptr *T) {
	if ptr != nil {
		kv[key] = *ptr
	}
}

// putList repeated 键：has_* 伴生标志取 true 才写入（在场判据见
// settingsRequestValues）；数组为空 / 缺省时归一为非 nil 空切片——
// settings.Validate 会再收敛一次，落库 JSON "[]" 而非 "null"，
// DecodeValue / watcher reload 不会因 null fail-fast（store.go 口径）。
func putList(kv map[string]any, key string, present bool, v []string) {
	if !present {
		return
	}
	if len(v) == 0 {
		v = []string{}
	}
	kv[key] = v
}

// diffSettings 变更项比对：按 settings.Defs() 表序遍历「本批在场键」，返回
// 值有变化的键列表与 before / after 片段（只含变更项，§4.6 行 804）。
// PATCH 语义下 next 只含在场键：未在场键必须跳过（若拿 next 里的 nil 与
// 快照现值比较，所有未提交键都会被误判为「改成零值」）。
// []string 按 slices.Equal 语义（nil 与空切片同值——proto 空 repeated 为
// nil、快照经 DecodeValue 归一为 []string{}，语义上均为清空）。
func diffSettings(before, next map[string]any) (keys []string, beforeChanged, after map[string]any) {
	beforeChanged = map[string]any{}
	after = map[string]any{}
	for _, d := range settings.Defs() {
		newV, ok := next[d.Key]
		if !ok {
			continue // 未在场键：保留现值，不参与落库 / 变更集
		}
		oldV := before[d.Key]
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
// session / cookie 分别用装配的独立 Codec 解出载荷消息（proto.Message，
// 由 dto.AdminDecodePayload 经 protojson 转 Struct 投影）；失败（含篡改、
// 跨 purpose、未知 kid）一律 ErrInvalidRequest → invalid_request。
//
// cookie purpose（解 al_login_state）：载荷为
// token.LoginStatePayload（state 带前缀 / b 场景 uid / 10 分钟 exp，后端
// 架构 §12.4 行 1485、生成链产物），经 security.Open 具名解出投影。
// 错误文案固定、不携带 token 与 payload 内容；本方法任何路径不落日志。
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
	case security.PurposeCookie:
		msg, err := security.Open[token.LoginStatePayload](s.codecs.Cookie, security.PurposeCookie, tokenStr)
		if err != nil {
			return nil, ErrInvalidRequest
		}
		return msg, nil
	default:
		// 空串、bind/ticket/sync_payload/oidc_code 等封闭集外的 DecodeToken
		// 口径均为非法 purpose。
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
