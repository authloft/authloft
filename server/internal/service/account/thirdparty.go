// thirdparty.go account 域三方绑定族四方法的业务层（docs/后端架构.md
// §3.9 行 406「account 域」、§12.6 BindToCurrentUser 绑定内核、§12.7 Union
// 归并、§13.2b；docs/接口文档.md §3.7 / §3.7.1、§1.3 行 152-155、§2.8）。
//
// 职责边界（四方法 + 一个共用内核）：
//   - GetThirdpartyBindings：{items, available} 双列表（§3.7 行 953-959）。
//     items = 该用户全部绑定行（含 Union 归并行——行 961「items 中非 Union
//     项的数量」即 Union 行照常出现、由前端按 type 识别置灰解绑）；available
//     数据源与 §2.7.1 登录快照同构（渠道注册表 category=oauth 枚举 →
//     Loader.ListByType），过滤 is_enabled=1 且 enable_signin=1、排除已绑定、
//     Union Provider 不出现（§12.7），排序 sort_order ASC + provider_key ASC。
//   - UnbindThirdparty：{providerKey} 解绑（行 954）。判定口径（行 961）：
//     (kind=password 且 is_enabled=1) OR (其余非 Union 绑定数 ≥ 1)，否则
//     invalid_request；Union Provider 行不可单独解绑（§12.7 行 1547）；
//     删除走 BindRepo.UnbindWithUnionCascade 单事务级联（既有同款机制）；
//     审计 thirdparty_unbind（actor=user，沿 admin 先例改自服口径）。
//   - ThirdpartyOauth：redirect 绑定通道 A（§3.7.1 A 行 969-1003）。解
//     al_login_state 校验 state 一致 + b 前缀（前缀不符 invalid_request）+
//     Cookie uid == 当前会话 uid（不一致 invalid_request 防串号）→
//     Exchange / FetchUser 现算身份 → BindToCurrentUser。失败为可判别哨兵
//     错误（handler 转 Connect 错误体 + ErrorInfo，行 996）；成功
//     {providerKey, displayName}。不签发 login_token、不 Set-Cookie、
//     不重建会话（行 1000）。
//   - GetThirdpartyTicket：扫码绑定通道 B 的长轮询（§3.7.1 B 行 1005-1053），
//     同构 service/qrcode.go GetLoginTicket（poll ≤15 剩余寿命钳制、五态、
//     GETDEL 原子取走、scanned SETNX 幂等回写），差异五点：需会话；scene
//     双重校验（ticket 载荷 scene=bind 前置拒绝 + GETDEL 命中后校验
//     TicketResult.scene=bind——「bind 的 ticket 不会被登录轮询接口接受，
//     反之亦然」，行 1052）；命中后用**当前会话 uid** + thirdparty_identity
//     走 BindToCurrentUser（绑定判定只在 PC 端轮询时进行，行 1051）；
//     success 响应带 bind 字段 {providerKey, displayName}（行 1040）；失败类
//     结论在信封 status、ticket 只报 failed（行 1044），target_taken 附固定
//     文案（行 987）。不签发 login_token、不 Set-Cookie（行 1049）。
//
// BindToCurrentUser 绑定内核（§12.6 行 1531-1551 六步；两通道共用）：
// ①载体校验由两通道各自完成（redirect 解 Cookie / qrcode 由 ticket scene
// 在拉码时定）；②Provider is_enabled=1 且 enable_signin=1，否则
// provider_disabled（绑定不检查 enable_signup、不触发 MFA——行 1548-1549）；
// ③identity 由通道给定（redirect 现算 / qrcode 取 TicketResult.thirdparty_
// identity）；④查 user_thirdparty_bind 三分支：已绑当前 uid → 幂等 success、
// 已绑他人 → target_taken、未绑 → 写入（含 Union 联动 §12.7 行 1560 同事务
// 追加 Union 行、extra 落 Raw）；⑤写成功投递 thirdparty_bind 审计（主链路零
// 同步写库；幂等分支无状态变化不投递——§3.7.1 A 行 983 审计挂在「未绑定」
// 分支）；⑥返回 success + provider_key / display_name。
//
// 业务失败形态：信封域方法（GetThirdpartyTicket）一律走信封 status（§1.6
// 封闭集，零自造）；其余三方法返回可判别哨兵错误（handler 转 Connect 错误体
// + ErrorInfo；内部 / 上游故障 ErrFailed 由 handler 映射 internal 无
// ErrorInfo——§1.6 行 273「其余域映射为 Connect internal」）。
package account

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"gorm.io/gorm"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
	"authloft/internal/cache"
	"authloft/internal/eventlog"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
)

// 域常量（字面量均为文档封闭集成员；跨包私有常量按后端架构 §3.5「各落一份」
// 先例——admin/user.go、pages/methods.go 同款，注释标注同源出处）。
const (
	// sceneBind TicketPayload.scene / TicketResult.scene 的绑定取值
	//（§11.6.4 行 1328；同 service/qrcode.go sceneBind）。
	sceneBind = "bind"
	// ticketStatusScanned / ticketStatusSuccess / ticketStatusFailed
	// TicketResult.status（§11.6.5 行 1346；同 service/qrcode.go）。
	ticketStatusScanned = "scanned"
	ticketStatusSuccess = "success"
	ticketStatusFailed  = "failed"
	// statusExpired / statusPending 轮询三态（§1.6 行 263；顶层与 ticket
	// 同步）。
	statusExpired = "expired"
	statusPending = "pending"
	// thirdpartyTicketMaxPoll 长轮询上限（§2.8 行 729「poll ≤15 秒」唯一定义
	// 处；同 service/qrcode.go qrcodeMaxPoll）。
	thirdpartyTicketMaxPoll = 15 * time.Second
	// statusProviderDisabled §1.6 封闭集成员（orchestrator 未导出的补位；
	// 同 service/thirdparty.go；state_mismatch 仅 handler ErrorInfo 用，不落
	// 本包信封域）。
	statusProviderDisabled = "provider_disabled"
	// providerCategoryOAuth / providerCategoryUnion provider 表 category 取值
	//（§12.7 行 1542；注册表无导出常量——admin handler / pages 同款字面量）。
	providerCategoryOAuth = "oauth"
	providerCategoryUnion = "union"
	statePrefixBind       = "b" // §12.4 行 1477（同 service.StatePrefixBind）
	kindPassword          = "password"
	extraMaxBytes         = 1 << 20       // §4.3 行 708；同 service/thirdparty.go
	bindTakenMessage      = "该账号已被其他账号绑定" // §3.7.1 A 行 987
)

// 可判别哨兵错误（handler 转 Connect 错误体 + ErrorInfo，§1.6 封闭集成员；
// ErrFailed 例外——handler 映射 internal 无 ErrorInfo，§1.6 行 273）。
var (
	// ErrInvalidRequest 参数缺失 / 前缀不符 / uid 串号 / 判定不满足。
	ErrInvalidRequest = errors.New("account thirdparty: invalid request")
	// ErrUnauthenticated 无有效会话（401）。
	ErrUnauthenticated = errors.New("account thirdparty: authentication required")
	// ErrStateMismatch al_login_state 校验失败（缺失 / 不一致 / 过期）。
	ErrStateMismatch = errors.New("account thirdparty: state mismatch")
	// ErrProviderDisabled 提供商未启用 / 不允许登录 / 未配置。
	ErrProviderDisabled = errors.New("account thirdparty: provider disabled")
	// ErrTargetTaken 三方身份已绑他人（§3.7.1）。
	ErrTargetTaken = errors.New("account thirdparty: target taken")
	// ErrFailed 上游 Exchange / FetchUser 或基础设施故障（映射 internal）。
	ErrFailed = errors.New("account thirdparty: failed")
)

// ProviderLoader 绑定内核与列表的 provider 实例读取窄接口（§20）：*provider.Loader
// 天然满足（Get 同登录链路缓存；ListByType 同 §2.7.1 登录快照数据源）。
type ProviderLoader interface {
	Get(ctx context.Context, providerKey string) (*provider.Provider, error)
	ListByType(ctx context.Context, providerType string) ([]*provider.Provider, error)
}

// ProviderFinder provider 行直查窄接口（解绑的 category / union_provider 实时
// 判定，不走 Loader LRU——沿 admin 域先例）：*repo.ProviderRepo 天然满足。
type ProviderFinder interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
}

// BindStore user_thirdparty_bind 表读写窄接口（§20）：*repo.BindRepo 天然满足
// （FindByProviderOpenID / ListByUserID / CreateWithUnion / UnbindWithUnionCascade
// 均既有，§12.7 行 1560 创建方向 + 既有级联解绑方向）。
type BindStore interface {
	FindByProviderOpenID(ctx context.Context, providerKey, openID string) (*model.UserThirdpartyBind, error)
	ListByUserID(ctx context.Context, userID int64) ([]model.UserThirdpartyBind, error)
	CreateWithUnion(ctx context.Context, b *model.UserThirdpartyBind, unionProviderKey, unionID string) error
	UnbindWithUnionCascade(ctx context.Context, id, userID int64, unionProviderKey string) error
}

// CredentialReader user_credential 表读取窄接口（解绑判定的 hasPassword 半边，
// §3.7 行 961）：*repo.CredentialRepo 天然满足。
type CredentialReader interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
}

// TicketStore al:ticket:{ticket_id} 读写窄接口（§11.6.5；GetThirdpartyTicket
// 用 Take / Wait / WriteScanned，与 service.QRCode 同一实例）：*cache.TicketStore
// 天然满足。
type TicketStore interface {
	WriteScanned(ctx context.Context, id string, res *token.TicketResult) (cache.TicketWriteResult, error)
	Take(ctx context.Context, id string) (*token.TicketResult, error)
	Wait(ctx context.Context, id string, timeout time.Duration) error
}

// AuditSink 审计事件投递（*eventlog.Writer 满足 PushEvent；非阻塞，队列满由
// Writer 静默降级，§5.2 行 893 不影响主链路）。
type AuditSink interface {
	PushEvent(ev model.EventLog)
}

// AdapterFactory 渠道适配器构造（*provider.NewAdapter 天然满足；单独注入
// 便于测试传 fake，同 service.ThirdpartyAdapterFactory 口径）。
type AdapterFactory func(p *provider.Provider) (provider.AuthAdapter, error)

// Deps 依赖注入（§20）；装配层构造（bootstrap buildEngine）。
type Deps struct {
	Loader     ProviderLoader
	Providers  ProviderFinder
	Binds      BindStore
	Creds      CredentialReader
	NewAdapter AdapterFactory
	Tickets    TicketStore
	// TicketCodec sign_key.ticket（§11.6.4）：GetThirdpartyTicket 解 ticket 串。
	TicketCodec *security.Codec
	// CookieCodec sign_key.cookie（§12.4 行 1487）：ThirdpartyOauth 解
	// al_login_state。
	CookieCodec *security.Codec
	// Audit thirdparty_bind / thirdparty_unbind 审计投递（nil = 跳过，测试用）。
	Audit AuditSink
	// Metas 渠道注册表枚举（available 数据源，§2.7.1 同构）；nil = 全局注册表
	//（provider.Types + Lookup，各渠道包 init 自注册，§15.3）。
	Metas func() []provider.Meta
	// Now 时钟注入（缺省 time.Now）。
	Now func() time.Time
}

// ThirdpartyService account 域三方绑定族业务层。
type ThirdpartyService struct {
	deps Deps
	now  func() time.Time
}

// NewThirdpartyService 构造。
func NewThirdpartyService(d Deps) *ThirdpartyService {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return &ThirdpartyService{deps: d, now: now}
}

// compile 时断言生产实现满足各窄接口（签名漂移在编译期暴露）。
var (
	_ ProviderLoader   = (*provider.Loader)(nil)
	_ ProviderFinder   = (*repo.ProviderRepo)(nil)
	_ BindStore        = (*repo.BindRepo)(nil)
	_ CredentialReader = (*repo.CredentialRepo)(nil)
	_ TicketStore      = (*cache.TicketStore)(nil)
	_ AuditSink        = (*eventlog.Writer)(nil)
)

// BindIdentity 绑定内核的三方身份输入（§12.6 步骤 3 的统一形态：redirect
// 通道现算 ExternalIdentity、qrcode 通道从 TicketResult.thirdparty_identity
// 取，两源各经转换函数归一到本结构；providerKey 由通道载体给定、
// 经参数显式传入内核，不采信 identity 内嵌值——resolveBind 用 p.Key 同口径）。
type BindIdentity struct {
	OpenID    string
	UnionID   string
	Nickname  string
	AvatarURL string
	Raw       map[string]any
}

// bindIdentityFromExternal redirect 通道身份转换（adapter.FetchUser 产物）。
func bindIdentityFromExternal(id *provider.ExternalIdentity) BindIdentity {
	if id == nil {
		return BindIdentity{}
	}
	return BindIdentity{
		OpenID:    id.OpenID,
		UnionID:   id.UnionID,
		Nickname:  id.Nickname,
		AvatarURL: id.AvatarURL,
		Raw:       id.Raw,
	}
}

// bindIdentityFromTicket qrcode 通道身份转换（TicketResult.thirdparty_identity，
// §11.6.5 行 1356-1362；raw 为 structpb 承载的第三方原始资料，绑定场景落
// extra——§11.6.5 行 1361）。
func bindIdentityFromTicket(id *token.ThirdpartyIdentity) BindIdentity {
	if id == nil {
		return BindIdentity{}
	}
	var raw map[string]any
	if r := id.GetRaw(); r != nil {
		raw = r.AsMap()
	}
	return BindIdentity{
		OpenID:    id.GetOpenId(),
		UnionID:   id.GetUnionId(),
		Nickname:  id.GetNickname(),
		AvatarURL: id.GetAvatarUrl(),
		Raw:       raw,
	}
}

// BindOutcome 绑定完成产物（§12.6 步骤 ⑥：provider_key / display_name；
// ThirdpartyOauth 的响应体 §3.7.1 A 行 977 / 轮询信封的 bind 字段行 1040）。
type BindOutcome struct {
	ProviderKey string
	DisplayName string
}

// BoundItem GetThirdpartyBindings 的已绑定条目（§3.7 行 953）：
// {providerKey, displayName, type, channel, icon, createdAt}。
type BoundItem struct {
	ProviderKey string
	DisplayName string
	Type        string
	Channel     string
	Icon        string
	CreatedAt   int64
}

// BindOption GetThirdpartyBindings 的可绑定条目（§3.7 行 953）：
// {providerKey, displayName, type, channel, icon, uiGroup, sortOrder}。
type BindOption struct {
	ProviderKey string
	DisplayName string
	Type        string
	Channel     string
	Icon        string
	UiGroup     string
	SortOrder   int64
}

// BindingsResult GetThirdpartyBindings 产物：items = 已绑定（含 Union 归并行），
// available = 可绑定。
type BindingsResult struct {
	Items     []BoundItem
	Available []BindOption
}

// GetThirdpartyBindings 双列表（§3.7 行 953-959，OUTCOME ②）。
func (s *ThirdpartyService) GetThirdpartyBindings(ctx context.Context, uid int64) (*BindingsResult, error) {
	rows, err := s.deps.Binds.ListByUserID(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("account thirdparty: list binds: %w", err)
	}

	// items：全部绑定行原样投影（Union 行照常出现——行 961「items 中非 Union
	// 项」；provider 行缺失时仅投影绑定行自带字段，脏数据不放大为错误）。
	items := make([]BoundItem, 0, len(rows))
	bound := make(map[string]bool, len(rows))
	for i := range rows {
		bound[rows[i].ProviderKey] = true
		it := BoundItem{
			ProviderKey: rows[i].ProviderKey,
			CreatedAt:   rows[i].CreatedAt.Unix(),
		}
		if p, err := s.deps.Loader.Get(ctx, rows[i].ProviderKey); err == nil && p.Row != nil {
			it.DisplayName = p.Row.DisplayName
			it.Type = p.Row.Type
			it.Icon = p.Row.IconURL
			// channel 取值与 §2.7.1 登录快照一致（经注入 metas 同源查询；type
			// 未登记渠道注册表的行——含 Union 虚拟 Provider——落空串，前端
			// items 渲染不消费 channel）。
			it.Channel = s.channelOfType(p.Row.Type)
		}
		items = append(items, it)
	}

	// available：§2.7.1 登录快照同构数据源（注册表 category=oauth 枚举 →
	// ListByType），过滤 is_enabled=1 且 enable_signin=1、排除已绑定、Union
	// Provider 不出现（行 958）。
	avail := make([]BindOption, 0)
	for _, meta := range s.metas() {
		if meta.Category != providerCategoryOAuth {
			continue
		}
		ps, err := s.deps.Loader.ListByType(ctx, meta.Type)
		if err != nil {
			return nil, fmt.Errorf("account thirdparty: list providers %q: %w", meta.Type, err)
		}
		for _, p := range ps {
			if !p.Enabled() || p.Row == nil || p.Row.EnableSignin != 1 {
				continue
			}
			if p.Row.Category == providerCategoryUnion || bound[p.Key] {
				continue
			}
			avail = append(avail, BindOption{
				ProviderKey: p.Key,
				DisplayName: p.Row.DisplayName,
				Type:        p.Type,
				Channel:     string(meta.Channel),
				Icon:        p.Row.IconURL,
				UiGroup:     p.Row.UiGroup,
				SortOrder:   int64(p.Row.SortOrder),
			})
		}
	}
	// 排序与 §2.7.1 登录快照同一全序：sort_order ASC, provider_key ASC。
	sort.Slice(avail, func(i, j int) bool {
		if avail[i].SortOrder != avail[j].SortOrder {
			return avail[i].SortOrder < avail[j].SortOrder
		}
		return avail[i].ProviderKey < avail[j].ProviderKey
	})
	return &BindingsResult{Items: items, Available: avail}, nil
}

// UnbindThirdparty 解绑（§3.7 行 954，OUTCOME ③）。允许条件（行 961 判定
// 口径）：解绑后仍持有 kind=password 且 is_enabled=1 的凭证，或仍绑定至少
// 1 个非 Union 的第三方 Provider；Union Provider 行不可单独解绑（§12.7
// 行 1547）。删除走 UnbindWithUnionCascade（Union 连带，既有同款机制）；
// 成功投递 thirdparty_unbind 审计（actor=user，detail={provider_key, open_id}，
// §4.6 行 822——沿 admin 先例的自服口径）。
func (s *ThirdpartyService) UnbindThirdparty(ctx context.Context, uid int64, providerKey string) error {
	if uid <= 0 {
		return ErrUnauthenticated
	}
	if providerKey == "" {
		return fmt.Errorf("%w: empty provider key", ErrInvalidRequest)
	}
	p, err := s.deps.Providers.FindByKey(ctx, providerKey)
	if err != nil {
		return err // 含包装的 gorm.ErrRecordNotFound → 404（admin 先例：绑定行引用 provider_key，无从解绑）
	}
	if p.Category == providerCategoryUnion {
		return fmt.Errorf("%w: union provider row", ErrInvalidRequest) // §12.7 行 1547
	}
	rows, err := s.deps.Binds.ListByUserID(ctx, uid)
	if err != nil {
		return fmt.Errorf("account thirdparty: list binds for unbind: %w", err)
	}
	var target *model.UserThirdpartyBind
	for i := range rows {
		if rows[i].ProviderKey == providerKey {
			target = &rows[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("account thirdparty: unbind: user %d has no binding for %q: %w", uid, providerKey, gorm.ErrRecordNotFound)
	}

	// 解绑判定（行 954/961「解绑后」口径）：password OR 其余非 Union 绑定
	//（排除自身行；Union 行不计入——provider 行缺失的脏数据行按非 Union
	// 计数，与 UnbindWithUnionCascade 的保守口径一致）。
	allowed, err := s.canUnbind(ctx, uid, rows, providerKey)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%w: unbind would leave no sign-in method", ErrInvalidRequest)
	}

	if err := s.deps.Binds.UnbindWithUnionCascade(ctx, target.ID, uid, p.UnionProvider); err != nil {
		return err // 行不存在 / 归属不符 → 包装的 gorm.ErrRecordNotFound（→ 404）
	}
	if s.deps.Audit != nil {
		s.deps.Audit.PushEvent(model.EventLog{
			Event:     eventlog.EventThirdpartyUnbind,
			ActorType: eventlog.ActorTypeUser,
			ActorID:   uid,
			UserID:    uid,
			Target:    providerKey,
			Detail:    eventlog.DetailThirdpartyBind(providerKey, target.OpenID),
			CreatedAt: s.now(),
		})
	}
	return nil
}

// canUnbind 解绑判定（§3.7 行 961）：password 凭证存在且启用，或除目标行外
// 仍有 ≥1 个非 Union 绑定行。
func (s *ThirdpartyService) canUnbind(ctx context.Context, uid int64, rows []model.UserThirdpartyBind, providerKey string) (bool, error) {
	row, err := s.deps.Creds.FindByUserAndKind(ctx, uid, kindPassword)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return false, fmt.Errorf("account thirdparty: load password credential: %w", err)
		}
	} else if row.IsEnabled == 1 {
		return true, nil
	}
	for i := range rows {
		if rows[i].ProviderKey == providerKey {
			continue
		}
		union, err := s.isUnionRow(ctx, rows[i].ProviderKey)
		if err != nil {
			return false, err
		}
		if !union {
			return true, nil
		}
	}
	return false, nil
}

// isUnionRow 判定绑定行的 provider 是否 Union（category=union，§12.7）；
// provider 行缺失（脏数据）按非 Union 计数——与 UnbindWithUnionCascade 事务内
// 的保守口径一致（宁可多算不可漏算「仍有绑定」）。
func (s *ThirdpartyService) isUnionRow(ctx context.Context, providerKey string) (bool, error) {
	p, err := s.deps.Providers.FindByKey(ctx, providerKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("account thirdparty: load provider %q for unbind check: %w", providerKey, err)
	}
	return p.Category == providerCategoryUnion, nil
}

// OauthInput ThirdpartyOauth 入参（§3.7.1 A 行 990-994）。StateCookie 为
// handler 从请求 Cookie 头解析的 al_login_state 值；UID 为当前会话 uid。
type OauthInput struct {
	ProviderKey string
	Code        string
	State       string
	StateCookie string
	UID         int64
}

// ThirdpartyOauth redirect 绑定通道 A（§3.7.1 A 行 969-1003，OUTCOME ④）：
// 载体校验 → Provider 校验 → 现算身份 → 绑定内核。失败为可判别哨兵错误
// （handler 转 Connect 错误体 + ErrorInfo，行 996）；成功返回绑定产物——
// 本接口不返回登录信封、不签发 login_token、不 Set-Cookie（行 1000，由
// handler 层保证；本方法无任何 Cookie 下发产物）。
func (s *ThirdpartyService) ThirdpartyOauth(ctx context.Context, in OauthInput) (*BindOutcome, error) {
	if in.UID == 0 {
		return nil, ErrUnauthenticated
	}
	if in.ProviderKey == "" || in.Code == "" {
		return nil, fmt.Errorf("%w: empty provider or code", ErrInvalidRequest)
	}
	// ①载体校验（§12.6 行 1534）：b 前缀不符 → invalid_request；Cookie 缺失 /
	// state 不一致 / 过期 → state_mismatch（§1.6 行 253）；Cookie uid 与当前
	// 会话 uid 不一致 → invalid_request（行 1002 防「发起 A、回调时会话已换
	// B」串号）。绑定通道不删 al_login_state（行 1000 不 Set-Cookie；state
	// 一次性由 10 分钟 exp 兜底，§12.4 行 1485）。
	if !strings.HasPrefix(in.State, statePrefixBind) {
		return nil, fmt.Errorf("%w: state prefix", ErrInvalidRequest)
	}
	payload, err := security.Open[token.LoginStatePayload](s.deps.CookieCodec, security.PurposeCookie, in.StateCookie)
	if err != nil {
		return nil, ErrStateMismatch
	}
	if payload.GetState() != in.State || payload.GetState() == "" {
		return nil, ErrStateMismatch
	}
	if s.now().Unix() >= payload.GetExp() {
		return nil, ErrStateMismatch
	}
	if payload.GetUid() != in.UID {
		return nil, fmt.Errorf("%w: cookie uid mismatch", ErrInvalidRequest)
	}

	// ②Provider 校验 + 通道限 redirect（行 1001：仅支持 channel=redirect）。
	p, err := s.deps.Loader.Get(ctx, in.ProviderKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %q not found", ErrProviderDisabled, in.ProviderKey)
		}
		return nil, fmt.Errorf("account thirdparty: load provider: %w", err)
	}
	if !p.Enabled() || p.Row == nil || p.Row.EnableSignin != 1 {
		return nil, fmt.Errorf("%w: %q", ErrProviderDisabled, in.ProviderKey)
	}
	adapter, err := s.deps.NewAdapter(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrProviderDisabled, in.ProviderKey, err)
	}
	if adapter.Channel() != provider.ChannelRedirect {
		return nil, fmt.Errorf("%w: channel %q not redirect", ErrInvalidRequest, adapter.Channel())
	}

	// ③现算身份（Exchange / FetchUser，§12.6 行 1537）；上游故障 ErrFailed
	//（handler 映射 internal，§1.6 行 273）。
	tok, err := adapter.Exchange(ctx, provider.ExchangeInput{Code: in.Code})
	if err != nil {
		return nil, fmt.Errorf("%w: exchange: %w", ErrFailed, err)
	}
	identity, err := adapter.FetchUser(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch user: %w", ErrFailed, err)
	}
	if identity == nil || identity.OpenID == "" {
		return nil, fmt.Errorf("%w: empty identity", ErrFailed)
	}

	// ④-⑥ 绑定内核（provider 已装载并通过步骤 ②校验，复用同一实例不二次读）。
	outcome, fail := s.bindWith(ctx, in.UID, p, bindIdentityFromExternal(identity))
	return s.bindFailure(fail, outcome)
}

// TicketInput GetThirdpartyTicket 入参（§3.7.1 B 行 1027-1033）。UID 为当前
// 会话 uid（handler 注入；0 = 无会话——绑定判定拒绝）。
type TicketInput struct {
	Ticket string
	Poll   int64
	UID    int64
}

// GetThirdpartyTicket 扫码绑定长轮询（§3.7.1 B 行 1012-1026，OUTCOME ⑤）：
// 同构 service/qrcode.go GetLoginTicket，差异五点见包注释。业务失败也走
// 信封 status（HTTP 200，§1.3 / §1.6）；不签发 login_token、不 Set-Cookie。
func (s *ThirdpartyService) GetThirdpartyTicket(ctx context.Context, in TicketInput) *ssov1.LoginFlowResponse {
	payload, err := security.Open[token.TicketPayload](s.deps.TicketCodec, security.PurposeTicket, in.Ticket)
	if err != nil || payload.GetTicketId() == "" {
		return &ssov1.LoginFlowResponse{Status: orchestrator.StatusInvalidRequest}
	}
	id := payload.GetTicketId()
	envelope := func(status, ticketStatus string, bind *ssov1.BindResult, msg *string) *ssov1.LoginFlowResponse {
		resp := &ssov1.LoginFlowResponse{
			Status: status,
			Ticket: &ssov1.TicketStatus{Status: ticketStatus, TicketId: id},
		}
		if bind != nil {
			resp.Bind = bind
		}
		if msg != nil {
			resp.Error = &ssov1.SsoError{Message: msg}
		}
		return resp
	}

	// expired 终态（§2.8 行 748：now ≥ exp → 双 expired；终态不消费已写入的
	// 结果，键随 TTL 自然消亡）。
	now := s.now().Unix()
	if now >= payload.GetExp() {
		return envelope(statusExpired, statusExpired, nil, nil)
	}
	// ticket 载荷 scene=bind 前置校验（行 1052「bind 的 ticket 不会被登录
	// 轮询接口接受，反之亦然」；scene 由服务端加密保护，GetLoginTicket 对
	// scene=login 同款拒绝）。
	if payload.GetScene() != sceneBind {
		return &ssov1.LoginFlowResponse{Status: orchestrator.StatusInvalidRequest}
	}

	// 命中 GETDEL（§2.8 行 746：原子取走即删，一次性消费）。
	res, err := s.deps.Tickets.Take(ctx, id)
	if err != nil {
		return envelope(orchestrator.StatusFailed, ticketStatusFailed, nil, nil)
	}
	// 长轮询（§2.8 行 729：poll ≤15 服务端钳制；等待窗口不超过票据剩余寿命，
	// 超后由 expired 终态表达）。
	if res == nil && in.Poll > 0 {
		wait := time.Duration(in.Poll) * time.Second
		if wait > thirdpartyTicketMaxPoll {
			wait = thirdpartyTicketMaxPoll
		}
		if remain := time.Duration(payload.GetExp()-now) * time.Second; wait > remain {
			wait = remain
		}
		if werr := s.deps.Tickets.Wait(ctx, id, wait); werr == nil {
			res, err = s.deps.Tickets.Take(ctx, id)
			if err != nil {
				return envelope(orchestrator.StatusFailed, ticketStatusFailed, nil, nil)
			}
		}
	}
	if res == nil {
		// 未命中键：now ≥ exp → expired；否则 pending（已扫码则 Take 已取到
		// 走 scanned 分支）。
		if s.now().Unix() >= payload.GetExp() {
			return envelope(statusExpired, statusExpired, nil, nil)
		}
		return envelope(statusPending, statusPending, nil, nil)
	}

	switch res.GetStatus() {
	case ticketStatusScanned:
		// 轮询消费了 scanned 标记：原样补写回（WriteScanned SETNX 幂等），
		// 后续轮询仍见 scanned；complete 的 CAS 覆盖路径不受影响（§2.8 同款；
		// 回写失败仅记日志不阻断——GetLoginTicket 同口径）。
		if _, werr := s.deps.Tickets.WriteScanned(ctx, id, res); werr != nil {
			slog.Warn("account thirdparty: rewrite scanned marker failed", "ticket_id", id, "error", werr)
		}
		return envelope(ticketStatusScanned, ticketStatusScanned, nil, nil)
	case ticketStatusSuccess:
		// OUTCOME ⑤②：GETDEL 命中后校验 TicketResult.scene=bind（confirm 误写
		// 登录票据 / 跨场景写键的防护，行 1052；结论已消费，ticket 只报 failed）。
		if res.GetScene() != sceneBind {
			return envelope(orchestrator.StatusInvalidRequest, ticketStatusFailed, nil, nil)
		}
		identity := bindIdentityFromTicket(res.GetThirdpartyIdentity())
		if identity.OpenID == "" {
			return envelope(orchestrator.StatusFailed, ticketStatusFailed, nil, nil)
		}
		// provider_key：写入方回显优先，缺省回落 ticket 载荷（pollBinding 同款）。
		pk := res.GetProviderKey()
		if pk == "" {
			pk = payload.GetProviderKey()
		}
		outcome, fail := s.BindToCurrentUser(ctx, in.UID, pk, identity)
		if fail != "" {
			// 命中但失败：结论在信封 status、ticket 只报 failed（行 1044）；
			// target_taken 附固定文案（行 987 / 行 1044 示例）。
			var msg *string
			if fail == orchestrator.StatusTargetTaken {
				m := bindTakenMessage
				msg = &m
			}
			return envelope(fail, ticketStatusFailed, nil, msg)
		}
		return envelope(ticketStatusSuccess, ticketStatusSuccess, &ssov1.BindResult{
			Ok:          true,
			ProviderKey: outcome.ProviderKey,
			DisplayName: outcome.DisplayName,
		}, nil)
	default:
		// 失败类：写入方已把具体结论落 TicketResult.status，本侧原样上抛信封
		//（§1.6 行 264；写入方为 LoginOauth bind 分支——仅 failed 类）。
		return envelope(res.GetStatus(), ticketStatusFailed, nil, nil)
	}
}

// BindToCurrentUser 绑定内核（§12.6 行 1531-1543 六步；OUTCOME ①）。两通道
// 共用：redirect 由 ThirdpartyOauth 在载体校验后调用（provider 已装载时走
// bindWith 装载复用）；qrcode 由轮询命中后调用。返回 (outcome, failStatus)：
// failStatus 非空表示以该 §1.6 信封状态失败（redirect 通道经 bindFailure 转
// 哨兵错误，qrcode 通道原样进信封）。
func (s *ThirdpartyService) BindToCurrentUser(ctx context.Context, uid int64, providerKey string, identity BindIdentity) (*BindOutcome, string) {
	if uid <= 0 || providerKey == "" {
		return nil, orchestrator.StatusInvalidRequest
	}
	// ②Provider 校验（§12.6 行 1536：is_enabled=1 且 enable_signin=1，否则
	// provider_disabled；绑定不检查 enable_signup——行 1549）。
	p, err := s.deps.Loader.Get(ctx, providerKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, statusProviderDisabled
		}
		return nil, orchestrator.StatusFailed
	}
	return s.bindWith(ctx, uid, p, identity)
}

// bindWith 装载完成的内核主体（p 已过步骤 ②校验的调用方复用；p 非法回退
// provider_disabled——防御性，与 §12.6 步骤顺序一致）。
func (s *ThirdpartyService) bindWith(ctx context.Context, uid int64, p *provider.Provider, identity BindIdentity) (*BindOutcome, string) {
	if uid <= 0 || identity.OpenID == "" {
		return nil, orchestrator.StatusInvalidRequest
	}
	if p == nil || !p.Enabled() || p.Row == nil || p.Row.EnableSignin != 1 {
		return nil, statusProviderDisabled
	}
	// ④查 user_thirdparty_bind（provider_key + open_id）三分支（§12.6 行
	// 1538-1541）。
	row, err := s.deps.Binds.FindByProviderOpenID(ctx, p.Key, identity.OpenID)
	switch {
	case err == nil:
		if row.UserID == uid {
			// 已绑当前 uid → 幂等 success（行 1539；无状态变化不投递审计，
			// §3.7.1 A 行 983 审计挂「未绑定」分支）。
			return &BindOutcome{ProviderKey: p.Key, DisplayName: p.Row.DisplayName}, ""
		}
		return nil, orchestrator.StatusTargetTaken // 已绑他人（行 1540）
	case errors.Is(err, gorm.ErrRecordNotFound):
		// 未绑定 → 写入（行 1541：extra 落 Raw；Union 联动 §12.7 行 1560 同
		// 事务追加 Union 行——open_id=unionid；并发被抢唯一键 → target_taken）。
		b := &model.UserThirdpartyBind{
			UserID:      uid,
			ProviderKey: p.Key,
			OpenID:      identity.OpenID,
			Nickname:    identity.Nickname,
			AvatarURL:   identity.AvatarURL,
			Extra:       encodeExtra(identity.Raw),
		}
		if err := s.deps.Binds.CreateWithUnion(ctx, b, p.Row.UnionProvider, identity.UnionID); err != nil {
			if errors.Is(err, repo.ErrBindDuplicate) {
				return nil, orchestrator.StatusTargetTaken
			}
			return nil, orchestrator.StatusFailed
		}
		// ⑤投递 thirdparty_bind 审计（§12.6 行 1542：延迟队列，主链路零同步
		// 写库；detail={provider_key, open_id}，§4.6 行 822）。
		if s.deps.Audit != nil {
			s.deps.Audit.PushEvent(model.EventLog{
				Event:     eventlog.EventThirdpartyBind,
				ActorType: eventlog.ActorTypeUser,
				ActorID:   uid,
				UserID:    uid,
				Target:    p.Key,
				Detail:    eventlog.DetailThirdpartyBind(p.Key, identity.OpenID),
				CreatedAt: s.now(),
			})
		}
		return &BindOutcome{ProviderKey: p.Key, DisplayName: p.Row.DisplayName}, ""
	default:
		return nil, orchestrator.StatusFailed
	}
}

// bindFailure redirect 通道的内核失败态 → 哨兵错误（§3.7.1 A 行 996：失败为
// Connect 错误体，ErrorInfo.code 取 §1.6 对应值）。outcome 非 nil 时原样放行
// （幂等 / 写入成功共用）。
func (s *ThirdpartyService) bindFailure(fail string, outcome *BindOutcome) (*BindOutcome, error) {
	if outcome != nil {
		return outcome, nil
	}
	switch fail {
	case orchestrator.StatusInvalidRequest:
		return nil, ErrInvalidRequest
	case orchestrator.StatusTargetTaken:
		return nil, ErrTargetTaken
	case statusProviderDisabled:
		return nil, ErrProviderDisabled
	default:
		return nil, ErrFailed // failed 等未知态 → internal（§1.6 行 273）
	}
}

// metas 渠道注册表枚举（available 数据源）；deps.Metas 注入优先，缺省读全局
// 注册表（§15.3；pages/methods.go registeredMetas 同款回退）。
func (s *ThirdpartyService) metas() []provider.Meta {
	if s.deps.Metas != nil {
		return s.deps.Metas()
	}
	out := make([]provider.Meta, 0)
	for _, t := range provider.Types() {
		if m, ok := provider.Lookup(t); ok {
			out = append(out, m)
		}
	}
	return out
}

// channelOfType 经注入 metas 查 type 的交互通道（§2.7.1 同源取值
// redirect / qrcode / api；未登记 → 空串）。
func (s *ThirdpartyService) channelOfType(providerType string) string {
	for _, m := range s.metas() {
		if m.Type == providerType {
			return string(m.Channel)
		}
	}
	return ""
}

// encodeExtra 三方原始资料 → extra 列 msgpack 字节（§12.6 行 1541「extra 落
// Raw」；§4.3 行 708「仅排查用、不参与任何业务判定」；service/thirdparty.go
// 同名私有函数跨包不可复用，按 §3.5 各落一份）：raw 为空 / 编码失败 / 超
// 1 MiB 返回 nil（整条丢弃降级，绑定主链路不受影响）。
func encodeExtra(raw map[string]any) []byte {
	if len(raw) == 0 {
		return nil
	}
	b, err := msgpack.Marshal(raw)
	if err != nil || len(b) > extraMaxBytes {
		return nil
	}
	return b
}
