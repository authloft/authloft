// qrcode.go 扫码三桩的业务层（docs/后端架构.md §3.9 行 406、
// §13.2-§13.3、§11.6.4-§11.6.5；docs/接口文档.md §2.8）：
//
//   - CreateQrcode：captcha 必检（Gate Challenge 恒触发）→ scene 分派
//     （bind 需 al_session，否则 401）→ ticket_id ≤24（§11.6.4）→
//     TicketPayload 经 sign_key.ticket 加密（purpose=ticket）→
//     GetwxacodeUnlimit（adapter 的 QRCodeSupporter）→ JPEG 75% 压缩
//     （internal/qrcode）→ Storage.Put（中转模式，storage_path JSONata
//     渲染，码图与 upload_mode 无关）。
//   - GetLoginTicket：解 ticket → expired 终态判定（无需存储）→ 长轮询
//     poll ≤15（cache.TicketStore.Wait）→ 命中 GETDEL（Take 原子取走）
//     → scene=login：建会话（Terminal.Complete，不另开 complete 端点）
//     / binding_required（用 thirdparty_identity 签发 login_token 精简
//     tp 载荷）；失败类结论在信封 status、ticket 只报 failed（§1.6 行
//     264）；成功时顶层 success + login 字段承载登录流程信封（§1.3 行
//     140）。
//   - ConfirmLoginTicket：已登录一端写入授权结果（§2.8 行 750-759）——
//     body session 与 Cookie 并存以 body 为准、同 uid 校验否则
//     invalid_request；校验会话 → 写 TicketResult{scene=login,
//     status=success}；写 ticket 不改变任何登录态（不建会话）。
//
// LoginOauth 的扫码两阶段写入（stage / ticketId 分支）归 thirdparty.go：
// 小程序端提交仅携带 ticket_id，服务端取本文件写入的快照键
// al:ticket:payload:{ticket_id}（§5.1 行 863、§11.6.4 行 1350）校验 scene /
// expiry / provider_key 后按 scene 分派写 al:ticket 结果（§13.2b）。
package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"gorm.io/gorm"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
	"authloft/internal/asyncqueue"
	"authloft/internal/cache"
	"authloft/internal/captcha"
	"authloft/internal/logx"
	"authloft/internal/provider"
	qrcodepkg "authloft/internal/qrcode"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
	"authloft/internal/storage"
)

// 扫码域常量（§11.6.4 / §2.8 / §11.6.5）。
const (
	// qrcodeTicketIDLen ticket_id 长度（§11.6.4 行 1342：24 字符以内，
	// 微信 scene 上限 32——本值唯一设计处）。
	qrcodeTicketIDLen = 24
	// qrcodeTicketTTL TicketPayload.exp 缺省（§11.6.4 行 1337：600s）。
	qrcodeTicketTTL = 600 * time.Second
	// qrcodeMaxPoll 长轮询上限（§2.8 行 729：poll ≤15 秒，全文档唯一定义处）。
	qrcodeMaxPoll = 15 * time.Second
	// ticketResultV TicketResult 结构版本（§11.6.5 行 1351：v=1）。
	ticketResultV = 1
	// channelQRCode TicketResult.channel（§11.6.5 行 1353：当前仅 qrcode）。
	channelQRCode = "qrcode"
	// sceneLogin / sceneBind TicketPayload.scene 取值（§11.6.4 行 1328）。
	sceneLogin = "login"
	sceneBind  = "bind"
	// ticketStatusScanned / ticketStatusSuccess / ticketStatusFailed
	// TicketResult.status（§11.6.5 行 1353：scanned | success | failed——
	// 失败类具体结论由写入方落本字段，轮询侧映射为 ticket 只报 failed）。
	ticketStatusScanned = "scanned"
	ticketStatusSuccess = "success"
	ticketStatusFailed  = "failed"
)

// 可判别哨兵错误（handler 转 Connect 错误体 + ErrorInfo，§1.6 封闭集成员）。
var (
	// ErrQrcodeInvalidRequest 参数缺失 / scene 非法 / 通道不支持。
	ErrQrcodeInvalidRequest = errors.New("qrcode: invalid request")
	// ErrQrcodeProviderDisabled 提供商未启用 / 不允许登录 / 未配置 / 拉码链故障。
	ErrQrcodeProviderDisabled = errors.New("qrcode: provider disabled")
	// ErrQrcodeUnauthenticated scene=bind 需要会话 / Confirm 会话缺失失效（401）。
	ErrQrcodeUnauthenticated = errors.New("qrcode: authentication required")
	// ErrQrcodeCaptchaRequired 拉码未携带 captcha（§2.8 行 703：每次拉码都要新的）。
	ErrQrcodeCaptchaRequired = errors.New("qrcode: captcha required")
	// ErrQrcodeCaptchaInvalid captcha 校验不通过 / 已使用。
	ErrQrcodeCaptchaInvalid = errors.New("qrcode: captcha invalid")
)

// TicketStore al:ticket:{ticket_id} 读写窄接口（§20）：*cache.TicketStore
// 天然满足；测试传 fake。
type TicketStore interface {
	WriteScanned(ctx context.Context, id string, res *token.TicketResult) (cache.TicketWriteResult, error)
	WriteComplete(ctx context.Context, id string, res *token.TicketResult) (cache.TicketWriteResult, error)
	Take(ctx context.Context, id string) (*token.TicketResult, error)
	Wait(ctx context.Context, id string, timeout time.Duration) error
}

// TicketPayloadStore al:ticket:payload:{ticket_id} 快照读写窄接口（§5.1 行
// 863、§11.6.4 行 1350）：*cache.TicketPayloadStore 天然满足；测试传
// fake。CreateQrcode 写（1 次、TTL = exp − iat），LoginOauth 扫码分支读。
type TicketPayloadStore interface {
	// Write 写快照（CreateQrcode 1 次，TTL = exp − iat，默认 600s）。
	Write(ctx context.Context, payload *token.TicketPayload) error
	// Read 读快照；缺失（不存在 / 已过期）返回 (nil, nil)。
	Read(ctx context.Context, ticketID string) (*token.TicketPayload, error)
}

// QRCodeStorageResolver 按 storage provider key 解析 Storage；
// *storage.Resolver 天然满足。
type QRCodeStorageResolver interface {
	Resolve(ctx context.Context, storageProviderKey string) (storage.Storage, error)
}

// QueuePusher 延迟写入队列（码图自动删除投递，§13.3）；*asyncqueue.Queue
// 天然满足。nil = 未装配（跳过投递）。
type QueuePusher interface {
	Push(task asyncqueue.Task) bool
}

// SessionVerifier 会话校验器（ConfirmLoginTicket 用，§11.1 四步）；
// *session.Verifier 天然满足。
type SessionVerifier interface {
	Verify(ctx context.Context, sessionToken string) (*token.SessionTokenPayload, error)
}

// QRCodeDeps 依赖注入（§20）；装配层构造（bootstrap buildEngine）。
type QRCodeDeps struct {
	Loader     ThirdpartyLoader
	NewAdapter ThirdpartyAdapterFactory
	// Gate captcha 唯一拦截点（§9.3 行 1110；Challenge 恒触发）。
	Gate *captcha.Gate
	// TicketCodec sign_key.ticket（§11.6.4：ticket 加密串）。
	TicketCodec *security.Codec
	// Tickets al:ticket 结果读写（§11.6.5）。
	Tickets TicketStore
	// TicketPayloads al:ticket:payload 快照读写（§5.1 行 863、§11.6.4 行
	// 1350）：CreateQrcode 1 次写入，TTL = exp − iat。
	TicketPayloads TicketPayloadStore
	// Storage storage provider 解析（§15.1）。
	Storage QRCodeStorageResolver
	// Queue 码图自动删除投递（§13.3；nil = 跳过）。
	Queue QueuePusher
	// Sessions ConfirmLoginTicket 会话校验。
	Sessions SessionVerifier
	// State binding_required 时签发 login_token（§11.6.5 行 1361）。
	State *orchestrator.State
	// Terminal success 时建会话（§2.8 行 746：1 次写，不另开 complete 端点）。
	Terminal *orchestrator.Terminal
	// NewTID login_token.tid 生成（缺省 security.RandomString(32)）。
	NewTID func() (string, error)
	// Now 时钟注入（缺省 time.Now）。
	Now func() time.Time
}

// QRCode 扫码三桩 service。
type QRCode struct {
	deps QRCodeDeps
	now  func() time.Time
}

// NewQRCode 构造。
func NewQRCode(d QRCodeDeps) *QRCode {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return &QRCode{deps: d, now: now}
}

// CreateQrcodeInput SsoService/CreateQrcode 入参（§2.8 行 707-717）。
type CreateQrcodeInput struct {
	ProviderKey string
	Scene       string // 空 = login
	// UID scene=bind 时的当前会话 uid（handler 从 ctx 取；0 = 无会话）。
	UID int64
	// Captcha 每次拉码都要新的（§2.5 统一提交格式）。
	Captcha *captcha.Submission
}

// CreateQrcodeOutput CreateQrcode 产物（§2.8 行 710）。
type CreateQrcodeOutput struct {
	Ticket    string // 加密的 TicketPayload
	TicketID  string
	QrcodeURL string
	ExpiresIn int64
}

// CreateQrcode 拉取小程序码（§2.8 行 702-719）。业务失败走可判别哨兵
// 错误（handler 转 Connect 错误体 + ErrorInfo）。
func (s *QRCode) CreateQrcode(ctx context.Context, in CreateQrcodeInput) (*CreateQrcodeOutput, error) {
	// captcha 必检（§2.8 行 703：必须携带；Challenge 恒触发，无阈值参与）。
	out, err := s.deps.Gate.Evaluate(ctx, captcha.Request{Challenge: true, Submission: in.Captcha})
	if err != nil {
		return nil, fmt.Errorf("qrcode: gate: %w", err)
	}
	switch out.Status {
	case captcha.StatusRequired:
		return nil, ErrQrcodeCaptchaRequired
	case captcha.StatusInvalid:
		return nil, ErrQrcodeCaptchaInvalid
	}

	// scene（§2.8 行 716）：login 默认｜bind 需 al_session，否则 401。
	scene := in.Scene
	if scene == "" {
		scene = sceneLogin
	}
	if scene != sceneLogin && scene != sceneBind {
		return nil, fmt.Errorf("%w: scene %q", ErrQrcodeInvalidRequest, in.Scene)
	}
	if scene == sceneBind && in.UID == 0 {
		return nil, ErrQrcodeUnauthenticated
	}

	// provider（§13.0：未配置 / 未启用按失败处理；channel 必 qrcode）。
	p, err := s.deps.Loader.Get(ctx, in.ProviderKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %q not found", ErrQrcodeProviderDisabled, in.ProviderKey)
		}
		return nil, fmt.Errorf("qrcode: load provider: %w", err)
	}
	if !p.Enabled() || p.Row == nil || p.Row.EnableSignin != 1 {
		return nil, fmt.Errorf("%w: %q", ErrQrcodeProviderDisabled, in.ProviderKey)
	}
	adapter, err := s.deps.NewAdapter(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrQrcodeProviderDisabled, in.ProviderKey, err)
	}
	if adapter.Channel() != provider.ChannelQRCode {
		return nil, fmt.Errorf("%w: channel %q", ErrQrcodeInvalidRequest, adapter.Channel())
	}
	fetcher, ok := adapter.(provider.QRCodeSupporter)
	if !ok {
		return nil, fmt.Errorf("%w: %q has no qrcode support", ErrQrcodeProviderDisabled, in.ProviderKey)
	}

	// ticket（§11.6.4：ticket_id ≤24、exp 600s、sign_key.ticket 加密）。
	ticketID, err := security.RandomString(qrcodeTicketIDLen)
	if err != nil {
		return nil, fmt.Errorf("qrcode: new ticket id: %w", err)
	}
	now := s.now()
	payload := &token.TicketPayload{
		TicketId:    ticketID,
		ProviderKey: p.Key,
		Scene:       scene,
		Iat:         now.Unix(),
		Exp:         now.Add(qrcodeTicketTTL).Unix(),
	}
	ticket, err := s.deps.TicketCodec.Seal(security.PurposeTicket, payload)
	if err != nil {
		return nil, fmt.Errorf("qrcode: seal ticket: %w", err)
	}

	// 写快照键 al:ticket:payload:{ticket_id}（1 次 Redis 写，§2.8 行 719、
	// §11.6.4 行 1350、§5.1 行 863）：TTL = exp − iat 与 ticket 同寿命；
	// 小程序端提交仅带 ticket_id（无加密串可解），LoginOauth 据此校验
	// scene / expiry / provider_key（§2.7.4）。写入失败即拉码失败——快照
	// 缺失的 ticket 无法完成扫码提交。
	if err := s.deps.TicketPayloads.Write(ctx, payload); err != nil {
		return nil, fmt.Errorf("qrcode: write ticket payload snapshot: %w", err)
	}

	// 拉码 → JPEG 75% 压缩（§13.2 行 1593）。
	raw, err := fetcher.FetchQrcode(ctx, ticketID)
	if err != nil {
		// 微信侧故障（配额 / 未发布等）按提供商失败收敛（§13.0 行 1576）。
		return nil, fmt.Errorf("%w: fetch wxacode: %v", ErrQrcodeProviderDisabled, err)
	}
	jpegBody, err := qrcodepkg.CompressJPEG(raw)
	if err != nil {
		return nil, fmt.Errorf("qrcode: compress: %w", err)
	}

	// Storage.Put 中转模式（§13.2 行 1593：码图始终走中转，与 upload_mode
	// 无关；storage_provider / storage_path 未配置按失败，§13.0）。
	st, key, err := s.storageFor(ctx, p, payload)
	if err != nil {
		return nil, err
	}
	url, err := st.Put(ctx, key, jpegBody, "image/jpeg")
	if err != nil {
		return nil, fmt.Errorf("qrcode: storage put: %w", err)
	}

	return &CreateQrcodeOutput{
		Ticket:    ticket,
		TicketID:  ticketID,
		QrcodeURL: url,
		ExpiresIn: int64(qrcodeTicketTTL / time.Second),
	}, nil
}

// storageFor 解析码图存储（§15.1：wechat_mp_scan 的 Ext.storage_provider
// 引用 storage 行；storage_path JSONata 渲染，内置 ticket_id / timestamp，
// timestamp 取 iat——轮询侧自动删除用同一模板重算，§13.3）。
func (s *QRCode) storageFor(ctx context.Context, p *provider.Provider, payload *token.TicketPayload) (storage.Storage, string, error) {
	if p.Ext == nil {
		return nil, "", fmt.Errorf("%w: %q nil ext", ErrQrcodeProviderDisabled, p.Key)
	}
	sp := p.Ext.GetStorageProvider()
	tpl := p.Ext.GetStoragePath()
	if sp == "" || tpl == "" {
		return nil, "", fmt.Errorf("%w: %q storage_provider / storage_path unset", ErrQrcodeProviderDisabled, p.Key)
	}
	st, err := s.deps.Storage.Resolve(ctx, sp)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrQrcodeProviderDisabled, err)
	}
	key, err := storage.RenderKey(tpl, payload.GetTicketId(), payload.GetIat())
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrQrcodeProviderDisabled, err)
	}
	return st, key, nil
}

// GetLoginTicketInput SsoService/GetLoginTicket 入参（§2.8 行 724-729）。
type GetLoginTicketInput struct {
	Ticket string
	Poll   int64 // 长轮询秒数，上限 15（服务端钳制）
}

// GetLoginTicketOutput GetLoginTicket 产物：信封（§1.3：顶层 status =
// 本次轮询结论、ticket = {status, ticketId}、success 时 login 字段承载
// 登录流程信封）+ SessionToken（PC 浏览器终点建会话后由 handler 经会话
// Cookie 构造器下发，与 LoginOauth redirect 通道同款出口）。
type GetLoginTicketOutput struct {
	Envelope     *ssov1.LoginFlowResponse
	SessionToken string
}

// GetLoginTicket 查询 / 长轮询 / 完成登录（§2.8 行 724-748）。业务失败
// 也走信封 status（HTTP 200，§1.3 / §1.6）。
func (s *QRCode) GetLoginTicket(ctx context.Context, in GetLoginTicketInput) *GetLoginTicketOutput {
	payload, err := security.Open[token.TicketPayload](s.deps.TicketCodec, security.PurposeTicket, in.Ticket)
	if err != nil || payload.GetTicketId() == "" {
		return &GetLoginTicketOutput{Envelope: &ssov1.LoginFlowResponse{Status: orchestrator.StatusInvalidRequest}}
	}
	id := payload.GetTicketId()
	echo := func(status string) *ssov1.TicketStatus {
		return &ssov1.TicketStatus{Status: status, TicketId: id}
	}
	envelope := func(status, ticketStatus string, login *ssov1.LoginFlowResponse) *GetLoginTicketOutput {
		return &GetLoginTicketOutput{Envelope: &ssov1.LoginFlowResponse{
			Status: status, Ticket: echo(ticketStatus), Login: login,
		}}
	}

	// expired 终态（§2.8 行 748：now > exp → 双 expired；终态不消费已写入
	// 的结果，键随 TTL 自然消亡）。
	now := s.now().Unix()
	if now >= payload.GetExp() {
		return envelope("expired", "expired", nil)
	}
	// bind 票据轮询走 AccountService/GetThirdpartyTicket（§13.2b 行 1607），
	// 本端点只服务 scene=login。
	if payload.GetScene() != sceneLogin {
		return &GetLoginTicketOutput{Envelope: &ssov1.LoginFlowResponse{Status: orchestrator.StatusInvalidRequest}}
	}

	// 命中 GETDEL（§2.8 行 746：原子取走即删，一次性消费）。
	res, err := s.deps.Tickets.Take(ctx, id)
	if err != nil {
		return envelope(orchestrator.StatusFailed, ticketStatusFailed, nil)
	}
	// 长轮询（§2.8 行 729：poll ≤15，服务端钳制；等待窗口不超过票据剩余
	// 寿命，超后由 expired 终态表达）。
	if res == nil && in.Poll > 0 {
		wait := time.Duration(in.Poll) * time.Second
		if wait > qrcodeMaxPoll {
			wait = qrcodeMaxPoll
		}
		if remain := time.Duration(payload.GetExp()-now) * time.Second; wait > remain {
			wait = remain
		}
		if werr := s.deps.Tickets.Wait(ctx, id, wait); werr == nil {
			res, err = s.deps.Tickets.Take(ctx, id)
			if err != nil {
				return envelope(orchestrator.StatusFailed, ticketStatusFailed, nil)
			}
		}
	}
	if res == nil {
		// 未命中键：now > exp → expired；否则 pending（§2.8 行 748——已扫码
		// 则同为 scanned：scanned 标记存在时上方 Take 已取到走 scanned 分支）。
		if s.now().Unix() >= payload.GetExp() {
			return envelope("expired", "expired", nil)
		}
		return envelope("pending", "pending", nil)
	}

	switch res.GetStatus() {
	case ticketStatusScanned:
		// 轮询消费了 scanned 标记：原样补写回（WriteScanned SETNX 幂等），
		// 后续轮询仍见 scanned；complete 的 CAS 覆盖路径不受影响（键值替换
		// 由 cache/lua/ticket_write.lua 保证原子）。
		if _, werr := s.deps.Tickets.WriteScanned(ctx, id, res); werr != nil {
			logx.Warn(ctx, "qrcode: rewrite scanned marker failed", "ticket_id", id, "error", werr)
		}
		return envelope(ticketStatusScanned, ticketStatusScanned, nil)
	case ticketStatusSuccess:
		return s.pollResult(ctx, payload, res)
	default:
		// 失败类：结论在信封 status（§1.6 行 264——写入方把具体失败落
		// TicketResult.status，本侧原样上抛），ticket 只报 failed。
		return envelope(res.GetStatus(), ticketStatusFailed, nil)
	}
}

// pollResult 处理结果就绪（ticket.status=success）：login_result 未绑定
// → binding_required 信封（§11.6.5 行 1361：用 thirdparty_identity 签发
// login_token）；已绑定 → Terminal.Complete 建会话（§2.8 行 746）。
func (s *QRCode) pollResult(ctx context.Context, payload *token.TicketPayload, res *token.TicketResult) *GetLoginTicketOutput {
	id := payload.GetTicketId()
	echo := &ssov1.TicketStatus{Status: ticketStatusSuccess, TicketId: id}
	lr := res.GetLoginResult()
	if lr.GetBindingRequired() || lr.GetUid() == 0 {
		inner := s.pollBinding(ctx, payload, res)
		return &GetLoginTicketOutput{Envelope: &ssov1.LoginFlowResponse{
			Status: ticketStatusSuccess, Ticket: echo, Login: inner,
		}}
	}

	// 建会话（1 次写，§2.8 行 746）：uid 的用户状态由写入方在 complete /
	// confirm 时校验（同口径），票据寿命（600s）内不重复校验。
	success, err := s.deps.Terminal.Complete(ctx, &token.LoginTokenPayload{
		Tid:    s.newTID(),
		Flow:   "login",
		Uid:    lr.GetUid(),
		Passed: []string{amrThirdParty},
		Amr:    []string{amrThirdParty},
	})
	if err != nil {
		return &GetLoginTicketOutput{Envelope: &ssov1.LoginFlowResponse{
			Status: orchestrator.StatusFailed, Ticket: &ssov1.TicketStatus{Status: ticketStatusFailed, TicketId: id},
		}}
	}
	inner := &ssov1.LoginFlowResponse{
		Status:        orchestrator.StatusSuccess,
		SessionId:     success.SessionID,
		SyncCookieUrl: success.SyncCookieURL,
		RedirectTo:    success.RedirectTo,
		UserId:        success.UserID,
	}
	s.enqueueAutoDelete(ctx, payload)
	return &GetLoginTicketOutput{
		Envelope:     &ssov1.LoginFlowResponse{Status: ticketStatusSuccess, Ticket: echo, Login: inner},
		SessionToken: success.SessionToken,
	}
}

// pollBinding 组装 binding_required 内层信封（§11.6.5 行 1361：thirdparty_
// identity → login_token 精简 tp 载荷〔无 raw〕+ binding.allowSignup 由
// enable_signup 映射）。内层失败类结论走内层 status（§1.6 行 264）。
func (s *QRCode) pollBinding(ctx context.Context, payload *token.TicketPayload, res *token.TicketResult) *ssov1.LoginFlowResponse {
	id := res.GetThirdpartyIdentity()
	if id == nil || id.GetOpenId() == "" {
		return &ssov1.LoginFlowResponse{Status: orchestrator.StatusFailed}
	}
	// provider_key：写入方回显优先，缺省回落 ticket 载荷（confirm 写入不
	// 回显 provider_key，§2.8 入参仅 ticket_id）。
	pk := res.GetProviderKey()
	if pk == "" {
		pk = payload.GetProviderKey()
	}
	p, err := s.deps.Loader.Get(ctx, pk)
	if err != nil {
		return &ssov1.LoginFlowResponse{Status: statusProviderDisabled}
	}
	lt := &token.LoginTokenPayload{
		Tid:    s.newTID(),
		Flow:   "login",
		Passed: []string{amrThirdParty},
		Amr:    []string{amrThirdParty},
		Tp: &token.ThirdParty{
			ProviderKey: pk,
			OpenId:      id.GetOpenId(),
			UnionId:     id.GetUnionId(),
			Nickname:    id.GetNickname(),
			AvatarUrl:   id.GetAvatarUrl(),
		},
	}
	signed, err := s.deps.State.Issue(lt)
	if err != nil {
		return &ssov1.LoginFlowResponse{Status: orchestrator.StatusFailed}
	}
	allowSignup := p.Row != nil && p.Row.EnableSignup == 1
	displayName := ""
	if p.Row != nil {
		displayName = p.Row.DisplayName
	}
	return &ssov1.LoginFlowResponse{
		Status:     orchestrator.StatusBindingRequired,
		LoginToken: signed,
		Binding:    orchestrator.BindingEnvelope(lt, displayName, allowSignup),
	}
}

// enqueueAutoDelete 码图自动删除投递（§13.3）：qrcode_auto_delete 开启时
// PC 端完成 SSO 后，用同一 storage_path 模板 + ticket_id + iat 重算 key
// （无需任何额外存储——iat 内嵌于加密 ticket）投延迟队列；队列满静默丢弃
// （删除失败不影响已完成的登录）。
func (s *QRCode) enqueueAutoDelete(ctx context.Context, payload *token.TicketPayload) {
	if s.deps.Queue == nil {
		return
	}
	p, err := s.deps.Loader.Get(ctx, payload.GetProviderKey())
	if err != nil || p == nil || p.Ext == nil || !p.Ext.GetQrcodeAutoDelete() {
		return
	}
	key, err := storage.RenderKey(p.Ext.GetStoragePath(), payload.GetTicketId(), payload.GetIat())
	if err != nil {
		logx.Warn(ctx, "qrcode: auto delete: render key failed", "ticket_id", payload.GetTicketId(), "error", err)
		return
	}
	s.deps.Queue.Push(asyncqueue.Task{
		Key: "qrcode-delete:" + key,
		Value: qrcodepkg.DeleteTask{
			StorageKey: p.Ext.GetStorageProvider(),
			ObjectKey:  key,
		},
	})
}

// ConfirmLoginTicketInput SsoService/ConfirmLoginTicket 入参（§2.8 行
// 750-757）。Session 为请求体 session_token；SessionUID 为会话拦截器从
// Cookie al_session 解出的 uid（0 = 无有效 Cookie 会话）。
type ConfirmLoginTicketInput struct {
	TicketID   string
	Session    string
	SessionUID int64
}

// ConfirmLoginTicket 已登录一端写入授权结果（§2.8 行 750-759）：body
// session 与 Cookie 并存以 body 为准、且必须与 Cookie 同一 uid（否则
// invalid_request）；写入 TicketResult{scene=login, status=success}——
// 写 ticket 不改变任何登录态（不建会话、不签 token）。
func (s *QRCode) ConfirmLoginTicket(ctx context.Context, in ConfirmLoginTicketInput) (*ssov1.TicketStatus, error) {
	if strings.TrimSpace(in.TicketID) == "" {
		return nil, fmt.Errorf("%w: empty ticket_id", ErrQrcodeInvalidRequest)
	}
	uid := in.SessionUID
	if in.Session != "" {
		// 以请求体为准（§2.8 行 757）；Cookie 侧有会话时必须同一 uid。
		p, err := s.deps.Sessions.Verify(ctx, in.Session)
		if err != nil {
			return nil, ErrQrcodeUnauthenticated
		}
		if in.SessionUID != 0 && in.SessionUID != p.GetId() {
			return nil, fmt.Errorf("%w: session uid mismatch", ErrQrcodeInvalidRequest)
		}
		uid = p.GetId()
	}
	if uid == 0 {
		return nil, ErrQrcodeUnauthenticated
	}

	// 写 TicketResult（§11.6.5 行 1372：直接写 status=success）。scene 按
	// §2.8 行 752 固定 login——本端点只服务登录场景（ticket_id 无法反解
	// scene，bind 票据误 confirm 的跨场景防护归 account 域轮询卡按
	// result.scene 校验）。expires_at 留 0：键 TTL 由 cache 侧回落 600s
	// 缺省（§11.6.4），不短于票据剩余寿命。provider_key 同理不可知（入参
	// 仅 ticket_id），轮询侧已从 ticket 载荷取 provider_key，不消费本字段。
	res := &token.TicketResult{
		V:         ticketResultV,
		Scene:     sceneLogin,
		Status:    ticketStatusSuccess,
		Channel:   channelQRCode,
		CreatedAt: s.now().Unix(),
		LoginResult: &token.LoginResult{
			Uid:             uid,
			BindingRequired: false,
		},
	}
	if _, err := s.deps.Tickets.WriteComplete(ctx, in.TicketID, res); err != nil {
		return nil, fmt.Errorf("qrcode: write ticket result: %w", err)
	}
	// 回显 {status:"success", ticket_id}（ticket.proto 行 72-73）；键上已
	// 存 success 时不覆盖（WriteComplete 语义），重复确认幂等成功。
	return &ssov1.TicketStatus{Status: ticketStatusSuccess, TicketId: in.TicketID}, nil
}

// newTID login_token.tid 生成（缺省同引擎 security.RandomString(32)）。
func (s *QRCode) newTID() string {
	newTID := s.deps.NewTID
	if newTID == nil {
		newTID = func() (string, error) { return security.RandomString(32) }
	}
	tid, err := newTID()
	if err != nil {
		return ""
	}
	return tid
}

// NewTicketResultSealer 构造生产 TicketSealer（cache.TicketSealer 实现，
// 装配层注入 cache.NewTicketStore）：TicketResult 按 protojson（§1.6 行
// 86 MarshalOptions）序列化后整值加密（复用 §11.6.1 封装、purpose=ticket，
// §11.6.5 行 1347——Redis 内不留明文）；读取方遇未知结构版本按失败处理
// （§11.6.5 行 1351）。protojson 字节经 BytesValue 包封进 §11.6.1 封装
// （该封装以 protobuf 消息为载荷单位，BytesValue 是服务端内部的字节
// 载体，不新增对外结构）。
func NewTicketResultSealer(codec *security.Codec) cache.TicketSealer {
	return &ticketResultSealer{codec: codec}
}

type ticketResultSealer struct {
	codec *security.Codec
}

// Seal protojson → 整值加密。
func (s *ticketResultSealer) Seal(res *token.TicketResult) (string, error) {
	if res == nil {
		return "", errors.New("qrcode: seal ticket result: nil result")
	}
	raw, err := protojson.Marshal(res)
	if err != nil {
		return "", fmt.Errorf("qrcode: marshal ticket result: %w", err)
	}
	sealed, err := s.codec.Seal(security.PurposeTicket, &wrapperspb.BytesValue{Value: raw})
	if err != nil {
		return "", fmt.Errorf("qrcode: seal ticket result: %w", err)
	}
	return sealed, nil
}

// Open 解密 → protojson → 版本校验（未知版本按失败处理）。
func (s *ticketResultSealer) Open(sealed string) (*token.TicketResult, error) {
	w, err := security.Open[wrapperspb.BytesValue](s.codec, security.PurposeTicket, sealed)
	if err != nil {
		return nil, fmt.Errorf("qrcode: open ticket result: %w", err)
	}
	res := &token.TicketResult{}
	if err := protojson.Unmarshal(w.GetValue(), res); err != nil {
		return nil, fmt.Errorf("qrcode: unmarshal ticket result: %w", err)
	}
	if res.GetV() != ticketResultV {
		return nil, fmt.Errorf("qrcode: unknown ticket result version %d", res.GetV())
	}
	return res, nil
}

// NewTicketPayloadSealer 构造快照 sealer（cache.TicketPayloadSealer 实现，
// 装配层注入 cache.NewTicketPayloadStore）：TicketPayload 全标量
// 字段，直接经 §11.6.1 封装整值加密（purpose=ticket，与 ticket 串同一
// 封装路径——§5.1 行 863「TicketPayload 加密快照」，无需 protojson +
// BytesValue 包封）。
func NewTicketPayloadSealer(codec *security.Codec) cache.TicketPayloadSealer {
	return &ticketPayloadSealer{codec: codec}
}

type ticketPayloadSealer struct {
	codec *security.Codec
}

// Seal 整值加密。
func (s *ticketPayloadSealer) Seal(p *token.TicketPayload) (string, error) {
	if p == nil {
		return "", errors.New("qrcode: seal ticket payload: nil payload")
	}
	return s.codec.Seal(security.PurposeTicket, p)
}

// Open 解密（§11.6.1 封装自带认证，篡改 / 跨 purpose 不可解）。
func (s *ticketPayloadSealer) Open(sealed string) (*token.TicketPayload, error) {
	p, err := security.Open[token.TicketPayload](s.codec, security.PurposeTicket, sealed)
	if err != nil {
		return nil, fmt.Errorf("qrcode: open ticket payload: %w", err)
	}
	return p, nil
}
