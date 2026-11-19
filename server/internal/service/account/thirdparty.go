// account 域三方绑定族业务层：四方法 + 共用绑定内核 BindToCurrentUser（两通道共用）。
// 绑定不改变登录态，不签发 login_token、不 Set-Cookie、不重建会话；scene 双重校验
// 防止 bind 票据被登录轮询接口接受。业务失败：轮询结论走信封 status，其余走可判别
// 哨兵错误由 handler 转 Connect 错误体 + ErrorInfo。
package account

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"database/sql"
	"github.com/vmihailenco/msgpack/v5"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
	"authloft/internal/cache"
	"authloft/internal/eventlog"
	"authloft/internal/logx"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
)

// 域常量：字面量均为封闭集成员；跨包私有常量各落一份，注释标注同源出处。
const (
	// sceneBind 绑定场景取值（同 service/qrcode.go）。
	sceneBind = "bind"
	// ticketStatus* TicketResult 状态取值（同 service/qrcode.go）。
	ticketStatusScanned = "scanned"
	ticketStatusSuccess = "success"
	ticketStatusFailed  = "failed"
	// statusExpired / statusPending 轮询三态（顶层与 ticket 同步）。
	statusExpired = "expired"
	statusPending = "pending"
	// thirdpartyTicketMaxPoll 长轮询上限 15s（同 service/qrcode.go）。
	thirdpartyTicketMaxPoll = 15 * time.Second
	// statusProviderDisabled 封闭集补位；state_mismatch 仅 handler 用，不落本包信封域。
	statusProviderDisabled = "provider_disabled"
	// providerCategoryOAuth / Union provider 表 category 取值（注册表无导出常量）。
	providerCategoryOAuth = "oauth"
	providerCategoryUnion = "union"
	statePrefixBind       = "b" // §12.4 行 1477（同 service.StatePrefixBind）
	kindPassword          = "password"
	extraMaxBytes         = 1 << 20       // §4.3 行 708；同 service/thirdparty.go
	bindTakenMessage      = "该账号已被其他账号绑定" // §3.7.1 A 行 987
)

// 可判别哨兵错误：handler 转 Connect 错误体 + ErrorInfo；ErrFailed 例外（映射 internal 无 ErrorInfo）。
var (
	// ErrInvalidRequest 参数缺失 / 前缀不符 / uid 串号 / 判定不满足。
	ErrInvalidRequest = errors.New("account thirdparty: invalid request")
	// ErrUnauthenticated 无有效会话（401）。
	ErrUnauthenticated = errors.New("account thirdparty: authentication required")
	// ErrStateMismatch al_login_state 校验失败（缺失 / 不一致 / 过期）。
	ErrStateMismatch = errors.New("account thirdparty: state mismatch")
	// ErrProviderDisabled 提供商未启用 / 不允许登录 / 未配置。
	ErrProviderDisabled = errors.New("account thirdparty: provider disabled")
	// ErrTargetTaken 三方身份已绑他人。
	ErrTargetTaken = errors.New("account thirdparty: target taken")
	// ErrFailed 上游 Exchange / FetchUser 或基础设施故障（映射 internal）。
	ErrFailed = errors.New("account thirdparty: failed")
)

// ProviderLoader provider 实例读取窄接口（Get 走登录链路缓存，ListByType 同登录快照数据源）。
type ProviderLoader interface {
	Get(ctx context.Context, providerKey string) (*provider.Provider, error)
	ListByType(ctx context.Context, providerType string) ([]*provider.Provider, error)
}

// ProviderFinder provider 行直查窄接口（解绑实时判定，不走 Loader LRU——沿 admin 先例）。
type ProviderFinder interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
}

// BindStore 绑定表读写窄接口（含 Union 创建 / 级联解绑既有能力）。
type BindStore interface {
	FindByProviderOpenID(ctx context.Context, providerKey, openID string) (*model.UserThirdpartyBind, error)
	ListByUserID(ctx context.Context, userID int64) ([]model.UserThirdpartyBind, error)
	CreateWithUnion(ctx context.Context, b *model.UserThirdpartyBind, unionProviderKey, unionID string) error
	UnbindWithUnionCascade(ctx context.Context, id, userID int64, unionProviderKey string) error
}

// CredentialReader 凭证读取窄接口（解绑判定的 hasPassword 半边）。
type CredentialReader interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
}

// TicketStore al:ticket 读写窄接口（Take / Wait / WriteScanned，与 qrcode 子包共用同一实例）。
type TicketStore interface {
	WriteScanned(ctx context.Context, id string, res *token.TicketResult) (cache.TicketWriteResult, error)
	Take(ctx context.Context, id string) (*token.TicketResult, error)
	Wait(ctx context.Context, id string, timeout time.Duration) error
}

// AuditSink 审计事件投递（非阻塞，队列满由 Writer 静默降级，不影响主链路）。
type AuditSink interface {
	PushEvent(ev model.EventLog)
}

// AdapterFactory 渠道适配器构造（单独注入便于测试传 fake）。
type AdapterFactory func(p *provider.Provider) (provider.AuthAdapter, error)

// Deps 依赖注入（装配层构造）。
type Deps struct {
	Loader     ProviderLoader
	Providers  ProviderFinder
	Binds      BindStore
	Creds      CredentialReader
	NewAdapter AdapterFactory
	Tickets    TicketStore
	// TicketCodec sign_key.ticket，GetThirdpartyTicket 解 ticket 串。
	TicketCodec *security.Codec
	// CookieCodec sign_key.cookie，ThirdpartyOauth 解 al_login_state。
	CookieCodec *security.Codec
	// Audit thirdparty_bind / thirdparty_unbind 审计投递（nil = 跳过，测试用）。
	Audit AuditSink
	// Metas 渠道注册表枚举（available 数据源）；nil = 全局注册表（各渠道 init 自注册）。
	Metas func() []provider.Meta
	// RootOrigin 回调地址拼装基准 {root}/sso/oauth/callback/{provider_key}，
	// 与授权请求 BuildAuthURL 使用的基准同源。未注入时令牌交换不携带该参数。
	RootOrigin string
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

// redirectURI 令牌交换携带的回调地址，必须与授权请求里的逐字一致：
// OAuth 规范以此为校验项，Gitee 等渠道缺该参数会直接返回 401
// invalid_request。root 去尾斜杠归一，与授权 URL 的拼装保持同源。
func (s *ThirdpartyService) redirectURI(providerKey string) string {
	if s.deps.RootOrigin == "" {
		return ""
	}
	return strings.TrimSuffix(s.deps.RootOrigin, "/") + "/sso/oauth/callback/" + providerKey
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

// BindIdentity 绑定内核的三方身份输入：redirect 现算 / qrcode 取 TicketResult 归一；
// providerKey 由通道载体显式传入，不采信 identity 内嵌值（resolveBind 用 p.Key 同口径）。
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

// bindIdentityFromTicket qrcode 通道身份转换（raw 为 structpb 承载的第三方原始资料）。
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

// BindOutcome 绑定完成产物（provider_key / display_name）。
type BindOutcome struct {
	ProviderKey string
	DisplayName string
}

// BoundItem GetThirdpartyBindings 的已绑定条目。
type BoundItem struct {
	ProviderKey string
	DisplayName string
	Type        string
	Channel     string
	Icon        string
	CreatedAt   int64
}

// BindOption GetThirdpartyBindings 的可绑定条目。
type BindOption struct {
	ProviderKey string
	DisplayName string
	Type        string
	Channel     string
	Icon        string
	UiGroup     string
	SortOrder   int64
}

// BindingsResult 双列表产物：items 已绑定（含 Union 归并行）、available 可绑定。
type BindingsResult struct {
	Items     []BoundItem
	Available []BindOption
}

// GetThirdpartyBindings 双列表查询。
func (s *ThirdpartyService) GetThirdpartyBindings(ctx context.Context, uid int64) (*BindingsResult, error) {
	rows, err := s.deps.Binds.ListByUserID(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("account thirdparty: list binds: %w", err)
	}

	// items 全部绑定行原样投影（Union 行照常出现；provider 行缺失时只投影绑定行自带字段）。
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
			// channel 与登录快照一致（经注入 metas 同源查询；未登记渠道落空串）。
			it.Channel = s.channelOfType(p.Row.Type)
		}
		items = append(items, it)
	}

	// available 与登录快照同构数据源，过滤启用 / 可登录、排除已绑定与 Union。
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
	// 排序与登录快照同一全序：sort_order ASC, provider_key ASC。
	sort.Slice(avail, func(i, j int) bool {
		if avail[i].SortOrder != avail[j].SortOrder {
			return avail[i].SortOrder < avail[j].SortOrder
		}
		return avail[i].ProviderKey < avail[j].ProviderKey
	})
	return &BindingsResult{Items: items, Available: avail}, nil
}

// UnbindThirdparty 解绑：解绑后仍须持有启用 password 凭证，或仍有 ≥1 个非 Union 绑定；
// Union Provider 行不可单独解绑。删除走单事务级联（Union 连带），成功后投递自服审计。
func (s *ThirdpartyService) UnbindThirdparty(ctx context.Context, uid int64, providerKey string) error {
	if uid <= 0 {
		return ErrUnauthenticated
	}
	if providerKey == "" {
		return fmt.Errorf("%w: empty provider key", ErrInvalidRequest)
	}
	p, err := s.deps.Providers.FindByKey(ctx, providerKey)
	if err != nil {
		return err // 含包装的 sql.ErrNoRows → 404（admin 先例：绑定行引用 provider_key，无从解绑）
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
		return fmt.Errorf("account thirdparty: unbind: user %d has no binding for %q: %w", uid, providerKey, sql.ErrNoRows)
	}

	// 解绑判定：password OR 其余非 Union 绑定（排除自身行；脏数据按非 Union 保守计数）。
	allowed, err := s.canUnbind(ctx, uid, rows, providerKey)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%w: unbind would leave no sign-in method", ErrInvalidRequest)
	}

	if err := s.deps.Binds.UnbindWithUnionCascade(ctx, target.ID, uid, p.UnionProvider); err != nil {
		return err // 行不存在 / 归属不符 → 包装的 sql.ErrNoRows（→ 404）
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

// canUnbind 解绑判定：password 凭证启用，或除目标行外仍有 ≥1 个非 Union 绑定行。
func (s *ThirdpartyService) canUnbind(ctx context.Context, uid int64, rows []model.UserThirdpartyBind, providerKey string) (bool, error) {
	row, err := s.deps.Creds.FindByUserAndKind(ctx, uid, kindPassword)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
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

// isUnionRow 判定绑定行的 provider 是否 Union；provider 行缺失（脏数据）
// 按非 Union 计数——与级联解绑事务内的保守口径一致（宁可多算不可漏算）。
func (s *ThirdpartyService) isUnionRow(ctx context.Context, providerKey string) (bool, error) {
	p, err := s.deps.Providers.FindByKey(ctx, providerKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("account thirdparty: load provider %q for unbind check: %w", providerKey, err)
	}
	return p.Category == providerCategoryUnion, nil
}

// OauthInput ThirdpartyOauth 入参：StateCookie 由 handler 从 Cookie 头解析，UID 为当前会话 uid。
type OauthInput struct {
	ProviderKey string
	Code        string
	State       string
	StateCookie string
	UID         int64
}

// ThirdpartyOauth redirect 绑定通道 A：载体校验 → Provider 校验 → 现算身份 → 绑定内核。
// 失败为可判别哨兵错误；不返回登录信封、不签发 login_token、不 Set-Cookie。
func (s *ThirdpartyService) ThirdpartyOauth(ctx context.Context, in OauthInput) (*BindOutcome, error) {
	if in.UID == 0 {
		return nil, ErrUnauthenticated
	}
	if in.ProviderKey == "" || in.Code == "" {
		return nil, fmt.Errorf("%w: empty provider or code", ErrInvalidRequest)
	}
	// ①载体校验：b 前缀不符 → invalid_request；Cookie 缺失 / state 不一致 / 过期 →
	// state_mismatch；Cookie uid 与会话 uid 不一致 → invalid_request（防换会话串号）。
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

	// ②Provider 校验 + 通道限 redirect。
	p, err := s.deps.Loader.Get(ctx, in.ProviderKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %q not found", ErrProviderDisabled, in.ProviderKey)
		}
		// 出站代理引用不可解析：行级 fail-closed（§15.4），按既有
		// provider_disabled 出口收敛，不新增取值。
		if errors.Is(err, provider.ErrProxyRefUnresolvable) {
			return nil, fmt.Errorf("%w: %q proxy ref unresolvable", ErrProviderDisabled, in.ProviderKey)
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

	// ③现算身份（Exchange / FetchUser）；上游故障 ErrFailed 由 handler 映射 internal。
	tok, err := adapter.Exchange(ctx, provider.ExchangeInput{
		Code:        in.Code,
		RedirectURI: s.redirectURI(in.ProviderKey),
	})
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

// TicketInput GetThirdpartyTicket 入参；UID 为当前会话 uid（handler 注入，0 = 无会话拒绝绑定）。
type TicketInput struct {
	Ticket string
	Poll   int64
	UID    int64
}

// GetThirdpartyTicket 扫码绑定长轮询：同构 service/qrcode.go GetLoginTicket。
// 业务失败走信封 status（HTTP 200）；不签发 login_token、不 Set-Cookie。
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

	// expired 终态：now ≥ exp → 双 expired（终态不消费已写入结果，键随 TTL 消亡）。
	now := s.now().Unix()
	if now >= payload.GetExp() {
		return envelope(statusExpired, statusExpired, nil, nil)
	}
	// ticket 载荷 scene=bind 前置校验（防跨场景；scene 由服务端加密保护）。
	if payload.GetScene() != sceneBind {
		return &ssov1.LoginFlowResponse{Status: orchestrator.StatusInvalidRequest}
	}

	// 命中 GETDEL：原子取走即删，一次性消费。
	res, err := s.deps.Tickets.Take(ctx, id)
	if err != nil {
		logx.Error(ctx, "account: bind ticket take failed",
			"ticket_id", id, "step", "take",
			"error", logx.RedactText(err.Error()))
		return envelope(orchestrator.StatusFailed, ticketStatusFailed, nil, nil)
	}
	// 长轮询：poll ≤15 服务端钳制，等待窗口不超过票据剩余寿命。
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
				logx.Error(ctx, "account: bind ticket take failed",
					"ticket_id", id, "step", "poll_take",
					"error", logx.RedactText(err.Error()))
				return envelope(orchestrator.StatusFailed, ticketStatusFailed, nil, nil)
			}
		} else {
			logx.Warn(ctx, "account: bind ticket long poll wait failed",
				"ticket_id", id, "step", "long_poll_wait",
				"error", logx.RedactText(werr.Error()))
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
		// scanned 标记消费后原样补写回（SETNX 幂等），后续轮询仍见 scanned；
		// complete 的 CAS 覆盖路径不受影响；回写失败仅记日志不阻断。
		if _, werr := s.deps.Tickets.WriteScanned(ctx, id, res); werr != nil {
			logx.Warn(ctx, "account thirdparty: rewrite scanned marker failed", "ticket_id", id, "error", werr)
		}
		return envelope(ticketStatusScanned, ticketStatusScanned, nil, nil)
	case ticketStatusSuccess:
		// GETDEL 命中后校验 scene=bind（防 confirm 误写 / 跨场景写键；结论已消费，ticket 只报 failed）。
		if res.GetScene() != sceneBind {
			return envelope(orchestrator.StatusInvalidRequest, ticketStatusFailed, nil, nil)
		}
		identity := bindIdentityFromTicket(res.GetThirdpartyIdentity())
		if identity.OpenID == "" {
			return envelope(orchestrator.StatusFailed, ticketStatusFailed, nil, nil)
		}
		// provider_key：写入方回显优先，缺省回落 ticket 载荷。
		pk := res.GetProviderKey()
		if pk == "" {
			pk = payload.GetProviderKey()
		}
		outcome, fail := s.BindToCurrentUser(ctx, in.UID, pk, identity)
		if fail != "" {
			// 命中但失败：结论在信封 status、ticket 只报 failed；target_taken 附固定文案。
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
		// 失败类：结论已落 TicketResult.status，本侧原样上抛信封。
		return envelope(res.GetStatus(), ticketStatusFailed, nil, nil)
	}
}

// BindToCurrentUser 绑定内核：两通道共用（redirect 载体校验后、qrcode 轮询命中后调用）。
// 返回 (outcome, failStatus)：failStatus 非空表示以该信封状态失败，redirect 通道经
// bindFailure 转哨兵错误，qrcode 通道原样进信封。
func (s *ThirdpartyService) BindToCurrentUser(ctx context.Context, uid int64, providerKey string, identity BindIdentity) (*BindOutcome, string) {
	if uid <= 0 || providerKey == "" {
		return nil, orchestrator.StatusInvalidRequest
	}
	// ②Provider 校验：is_enabled=1 且 enable_signin=1，否则 provider_disabled（不检查 enable_signup）。
	p, err := s.deps.Loader.Get(ctx, providerKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, statusProviderDisabled
		}
		// 出站代理引用不可解析：行级 fail-closed（§15.4），按既有
		// provider_disabled 出口收敛，不新增取值。
		if errors.Is(err, provider.ErrProxyRefUnresolvable) {
			return nil, statusProviderDisabled
		}
		return nil, orchestrator.StatusFailed
	}
	return s.bindWith(ctx, uid, p, identity)
}

// bindWith 装载完成的内核主体（p 已过 ②校验；p 非法回退 provider_disabled——防御性）。
func (s *ThirdpartyService) bindWith(ctx context.Context, uid int64, p *provider.Provider, identity BindIdentity) (*BindOutcome, string) {
	if uid <= 0 || identity.OpenID == "" {
		return nil, orchestrator.StatusInvalidRequest
	}
	if p == nil || !p.Enabled() || p.Row == nil || p.Row.EnableSignin != 1 {
		return nil, statusProviderDisabled
	}
	// ④查绑定三分支：已绑当前 uid 幂等 / 已绑他人 target_taken / 未绑写入。
	row, err := s.deps.Binds.FindByProviderOpenID(ctx, p.Key, identity.OpenID)
	switch {
	case err == nil:
		if row.UserID == uid {
			// 已绑当前 uid → 幂等 success（无状态变化不投递审计）。
			return &BindOutcome{ProviderKey: p.Key, DisplayName: p.Row.DisplayName}, ""
		}
		return nil, orchestrator.StatusTargetTaken // 已绑他人（行 1540）
	case errors.Is(err, sql.ErrNoRows):
		// 未绑定 → 写入（extra 落 Raw；Union 联动同事务追加行；并发抢唯一键 → target_taken）。
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
		// ⑤投递 thirdparty_bind 审计（延迟队列，主链路零同步写库）。
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

// bindFailure redirect 通道失败态 → 哨兵错误：failStatus 取封闭集对应值。
// outcome 非 nil 时原样放行（幂等 / 写入成功共用）。
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
// 统一注册表的登录快照接口 AdapterTypes（仅 oauth 渠道，§15.3）。
func (s *ThirdpartyService) metas() []provider.Meta {
	if s.deps.Metas != nil {
		return s.deps.Metas()
	}
	out := make([]provider.Meta, 0)
	for _, t := range provider.AdapterTypes() {
		if m, ok := provider.Lookup(t); ok {
			out = append(out, m)
		}
	}
	return out
}

// channelOfType 经注入 metas 查 type 的交互通道（redirect / qrcode / api；未登记 → 空串）。
func (s *ThirdpartyService) channelOfType(providerType string) string {
	for _, m := range s.metas() {
		if m.Type == providerType {
			return string(m.Channel)
		}
	}
	return ""
}

// encodeExtra 三方原始资料 → extra 列 msgpack 字节：raw 为空 / 编码失败 / 超 1 MiB
// 返回 nil（整条丢弃降级，绑定主链路不受影响；仅排查用，不参与业务判定）。
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
