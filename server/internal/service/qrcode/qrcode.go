// qrcode.go 扫码拉码与轮询的业务层（docs/后端架构.md §3.9 行 406、
// §13.2-§13.3、§11.6.4-§11.6.5；docs/接口文档.md §2.8）：
//
//   - CreateQrcode：captcha 必检（场景「拉取小程序码」，§2.5 触发表第 7 行）
//     → scene 分派
//     （bind 需 al_session，否则 401）→ sso_client_id 携带时按首签口径解析
//     应用快照并校验 Provider 放行（§2.8，快照装 TicketPayload.sso）→
//     ticket_id ≤24（§11.6.4）→
//     TicketPayload 经 sign_key.ticket 加密（purpose=ticket）→ 快照键写入 →
//     拉码产出按 provider.Ext.qrcode_mode 分派（§2.8 / §13.2）：url（缺省）
//     GetwxacodeUnlimit（adapter 的 QRCodeSupporter）→ JPEG 75% 压缩
//     （internal/qrcode）→ Storage.Put（中转模式，storage_path JSONata
//     渲染，码图与 upload_mode 无关）；base64 拉码压缩后 base64 直发，
//     不写 Storage；ticket 不调微信拉码，以完整加密 ticket / ticket_id 替换
//     qrcode_format 模板的 {{TICKET}} / {{TICKET_ID}} 占位符（二选一），仅当
//     模板放 {{TICKET_ID}} 时才写 payload 快照。存储依赖与码图自动删除
//     仅 url 模式生效（§13.3）；未知模式收敛渠道不可用，不静默回落。
//   - GetLoginTicket：解 ticket → expired 终态判定（无需存储）→ 长轮询
//     poll ≤15（cache.TicketStore.Wait）→ 命中 GETDEL（Take 原子取走）
//     → scene=login：建会话（Terminal.Complete，不另开 complete 端点）
//     / binding_required（用 thirdparty_identity 签发 login_token 精简
//     tp 载荷）；失败类结论在信封 status、ticket 只报 failed（§1.6 行
//     264）；成功时顶层 success + login 字段承载登录流程信封（§1.3 行
//     140）。
//   - GetLoginTicket 命中 mfa_pending（非终态、只读不消费）：顶层
//     needs_step_up、ticket.status 仍报 scanned，并额外下发一枚带 OIDC
//     上下文的新 loginToken（§2.8），供前端据此走 §3.8 二次验证。
//
// 授权结果写入（ConfirmLoginTicket 与 LoginOauth 扫码分支）收敛到
// login_ticket.go 的统一写票 service，本文件只保留拉码与轮询。
//
// LoginOauth 的扫码两阶段写入（stage / ticketId 分支）归 thirdparty.go：
// 小程序端提交仅携带 ticket_id，服务端取本文件写入的快照键
// al:ticket:payload:{ticket_id}（§5.1 行 863、§11.6.4 行 1350）校验 scene /
// expiry / provider_key 后按 scene 分派写 al:ticket 结果（§13.2b）。
package qrcode

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"database/sql"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
	"authloft/internal/asyncqueue"
	"authloft/internal/captcha"
	"authloft/internal/logx"
	"authloft/internal/provider"
	qrcodepkg "authloft/internal/qrcode"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
	"authloft/internal/service/ssoapp"
	thirdpartysvc "authloft/internal/service/thirdparty"
	ticketsvc "authloft/internal/service/ticket"
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
	// statusNeedsStepUp 扫码轮询专属顶层 status（§1.6 行 282、§2.8 行 884）：
	// 只出现在 GetLoginTicket 顶层，不进登录信封、不作 ticket.status 取值。
	statusNeedsStepUp = "needs_step_up"
	// thirdpartyMethod login_methods 内的三方整体开关取值（§2.1 交集口径，
	// ssoapp 同名常量同口径；快照放行判定用）。
	thirdpartyMethod = "thirdparty"
	// 扫码三模式封闭集（§2.8 / §12.1：provider.Ext.qrcode_mode；空 = url
	// 存量行为不变）。
	qrcodeModeTicket = "ticket"
	qrcodeModeBase64 = "base64"
	qrcodeModeURL    = "url"
	// ticketPlaceholder ticket 模式模板的占位符（§2.8：区分大小写、可出现
	// 多次，替换值为完整加密 ticket——扫码端拿到的须是可用于 GetLoginTicket
	// 的凭证，登录闭环才成立；保存期校验见 §5.3）。
	ticketPlaceholder = "{{TICKET}}"
	// ticketIDPlaceholder ticket 模式模板的另一占位符：替换值为 ticket_id。
	// 模板改放它时扫码端只拿到 id，服务端须保留快照供按 id 反查；与
	// ticketPlaceholder 二选一即可，二者皆缺才算配置错误。
	ticketIDPlaceholder = "{{TICKET_ID}}"
)

// 可判别哨兵错误（handler 转 Connect 错误体 + ErrorInfo，§1.6 封闭集成员）。
var (
	// ErrQrcodeProviderDisabled 提供商未启用 / 不允许登录 / 未配置 / 拉码链故障。
	ErrQrcodeProviderDisabled = errors.New("qrcode: provider disabled")
	// ErrQrcodeCaptchaRequired 拉码未携带 captcha（§2.8 行 703：每次拉码都要新的）。
	ErrQrcodeCaptchaRequired = errors.New("qrcode: captcha required")
	// ErrQrcodeCaptchaInvalid captcha 校验不通过 / 已使用。
	ErrQrcodeCaptchaInvalid = errors.New("qrcode: captcha invalid")
)

// QrcodeCaptchaFailure 把 Gate.Evaluate 判定的当前生效 captcha 配置随可判别
// 哨兵错误透出，供上层经 connect.WithCaptchaConfig 并列进错误体 details
// （§2.5 行 631 / §9.1 行 1128 同源）。Config 直接取自该次判定的
// Outcome.Config——gate 这一处单一出口，本层不重新读取配置、不另造第二份；
// cause 保留原哨兵，errors.Is 仍可判别。
type QrcodeCaptchaFailure struct {
	Config captcha.Config
	cause  error
}

// Error 保留原哨兵文案；cause 缺失（含 nil 接收者）时返回固定文案，不 panic。
func (f *QrcodeCaptchaFailure) Error() string {
	if f == nil || f.cause == nil {
		return "qrcode: captcha failure"
	}
	return f.cause.Error()
}

func (f *QrcodeCaptchaFailure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.cause
}

// QRCodeStorageResolver 按 storage provider key 解析 Storage；
// *storage.Resolver 天然满足。
type QRCodeStorageResolver interface {
	Resolve(ctx context.Context, storageProviderKey string) (storage.Storage, error)
}

// QRCodeSsoResolver SSO 应用快照解析窄接口（§2.2 首签口径）：*
// ssoapp.Resolver 天然满足，装配层注入与引擎 / 三方域同一实例；nil 时携带
// sso_client_id 的请求按装配缺陷 fail-closed（不降级直登）。
type QRCodeSsoResolver interface {
	Snapshot(ctx context.Context, ssoClientID string) (*token.Sso, error)
}

// QueuePusher 延迟写入队列（码图自动删除投递，§13.3）；*asyncqueue.Queue
// 天然满足。nil = 未装配（跳过投递）。
type QueuePusher interface {
	Push(task asyncqueue.Task) bool
}

// QRCodeDeps 依赖注入（§20）；装配层构造（bootstrap buildEngine）。
type QRCodeDeps struct {
	Loader     thirdpartysvc.ThirdpartyLoader
	NewAdapter thirdpartysvc.ThirdpartyAdapterFactory
	// Gate captcha 唯一拦截点（§9.3；按场景查 §2.5 触发表判定）。
	Gate *captcha.Gate
	// TicketCodec sign_key.ticket（§11.6.4：ticket 加密串）。
	TicketCodec *security.Codec
	// Tickets al:ticket 结果读写（§11.6.5）。
	Tickets ticketsvc.TicketStore
	// TicketPayloads al:ticket:payload 快照读写（§5.1 行 863、§11.6.4 行
	// 1350）：CreateQrcode 至多 1 次写入（ticket 模式模板未放 {{TICKET_ID}}
	// 时跳过），TTL = exp − iat。
	TicketPayloads ticketsvc.TicketPayloadStore
	// SsoApps SSO 应用快照解析器（§2.2 首签口径；扫码链路应用上下文随
	// TicketPayload.sso 进票据，§2.8 / §11.6.4）。与引擎 / 三方域注入同一
	// 实例；nil 时携带 sso_client_id 的请求按装配缺陷 fail-closed。
	SsoApps QRCodeSsoResolver
	// Storage storage provider 解析（§15.1）。
	Storage QRCodeStorageResolver
	// Queue 码图自动删除投递（§13.3；nil = 跳过）。
	Queue QueuePusher
	// State needs_step_up 与 binding_required 时签发 login_token
	//（§11.6.5 行 1361、§2.8）。
	State *orchestrator.State
	// Terminal success 时建会话（§2.8 行 746：1 次写，不另开 complete 端点）。
	Terminal *orchestrator.Terminal
	// NewTID login_token.tid 生成（缺省 security.RandomString(32)）。
	NewTID func() (string, error)
	// Now 时钟注入（缺省 time.Now）。
	Now func() time.Time
}

// QRCode 扫码拉码与轮询 service。
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
	// SsoClientID SSO 应用标识（proto 字段 sso_client_id，编号 4）：仅
	// scene=login 携带——按首签口径解析快照（§2.2）并校验 Provider ∈ 快照
	// （不在 → 既有 provider_disabled），快照随 TicketPayload.sso 进票据
	// （§11.6.4），GetLoginTicket 完成登录写入 login_token.sso；缺省行为
	// 与现状一致。scene=bind 不携带（绑定流程不读应用配置）。
	SsoClientID string
}

// CreateQrcodeOutput CreateQrcode 产物（§2.8）：ticket / ticket_id /
// expires_in 三模式公共；QrcodeMode 显式回显本次生效模式（空配置归一为
// url），三产出字段 QrcodeURL / QrcodeContent / QrcodeBase64 按模式只填
// 其一（§2.8 字段填充矩阵），TipHTML 为 Ext qrcode_tip 配置的提示文案
// HTML 原文（三模式通用，配置则填）。
type CreateQrcodeOutput struct {
	Ticket        string // 加密的 TicketPayload
	TicketID      string
	QrcodeMode    string // 本次生效模式：ticket | base64 | url（空配置归一为 url）
	QrcodeURL     string // 仅 url 模式：Storage 中转后的码图 URL
	QrcodeContent string // 仅 ticket 模式：qrcode_format 模板替换占位符后的内容
	QrcodeBase64  string // 仅 base64 模式：JPEG 纯 base64（不含 data URL 前缀）
	TipHTML       string // Ext qrcode_tip 原文（三模式通用，配置则填）
	ExpiresIn     int64
}

// CreateQrcode 拉取小程序码（§2.8 行 702-719）。业务失败走可判别哨兵
// 错误（handler 转 Connect 错误体 + ErrorInfo）。
func (s *QRCode) CreateQrcode(ctx context.Context, in CreateQrcodeInput) (*CreateQrcodeOutput, error) {
	// scene（§2.8 行 716）：login 默认｜bind 需 al_session，否则 401。
	scene := in.Scene
	if scene == "" {
		scene = ticketsvc.SceneLogin
	}
	if scene != ticketsvc.SceneLogin && scene != ticketsvc.SceneBind {
		return nil, fmt.Errorf("%w: scene %q", ticketsvc.ErrQrcodeInvalidRequest, in.Scene)
	}
	if scene == ticketsvc.SceneBind && in.UID == 0 {
		return nil, ticketsvc.ErrQrcodeUnauthenticated
	}

	// provider（§13.0：未配置 / 未启用按失败处理；channel 必 qrcode）。
	p, err := s.deps.Loader.Get(ctx, in.ProviderKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %q not found", ErrQrcodeProviderDisabled, in.ProviderKey)
		}
		// 出站代理引用不可解析：行级 fail-closed（§15.4），按既有
		// provider_disabled 出口收敛，不新增取值。
		if errors.Is(err, provider.ErrProxyRefUnresolvable) {
			return nil, fmt.Errorf("%w: %q proxy ref unresolvable", ErrQrcodeProviderDisabled, in.ProviderKey)
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
		return nil, fmt.Errorf("%w: channel %q", ticketsvc.ErrQrcodeInvalidRequest, adapter.Channel())
	}
	fetcher, ok := adapter.(provider.QRCodeSupporter)
	if !ok {
		return nil, fmt.Errorf("%w: %q has no qrcode support", ErrQrcodeProviderDisabled, in.ProviderKey)
	}

	// captcha 判定（§2.5 触发表第 7 行）：是否必检由该 provider 的
	// need_captcha 配置决定（判定输入从 Ext 读取，判定仍在 Gate），
	// 故置于 provider 加载之后；登录与绑定共用同一配置。
	out, err := s.deps.Gate.Evaluate(ctx, captcha.Request{
		Scene:       captcha.SceneQrcodeFetch,
		NeedCaptcha: p.Ext != nil && p.Ext.GetNeedCaptcha(),
		Submission:  in.Captcha,
	})
	if err != nil {
		return nil, fmt.Errorf("qrcode: gate: %w", err)
	}
	switch out.Status {
	case captcha.StatusRequired:
		return nil, &QrcodeCaptchaFailure{cause: ErrQrcodeCaptchaRequired, Config: out.Config}
	case captcha.StatusInvalid:
		return nil, &QrcodeCaptchaFailure{cause: ErrQrcodeCaptchaInvalid, Config: out.Config}
	}

	// 应用上下文（§2.8）：仅 scene=login 携带 sso_client_id（bind 不携带——
	// 绑定流程不读应用配置）。非空时按首签口径解析快照（§2.2）并按 §2.1
	// 应用级过滤表校验 Provider 放行；缺省（直登 / 应用未配置）行为与现状
	// 一致。快照随 TicketPayload.sso 进票据，GetLoginTicket 完成登录写入
	// login_token.sso（§11.6.4）。
	ssoClientID := in.SsoClientID
	if scene == ticketsvc.SceneBind {
		ssoClientID = ""
	}
	var ssoSnap *token.Sso
	if ssoClientID != "" {
		snap, err := s.resolveSsoSnapshot(ctx, ssoClientID)
		if err != nil {
			return nil, err
		}
		if !ssoAllowsProvider(snap, in.ProviderKey) {
			return nil, fmt.Errorf("%w: %q", ErrQrcodeProviderDisabled, in.ProviderKey)
		}
		ssoSnap = snap
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
		// SSO 应用快照（§11.6.4：仅 scene=login 且拉码带 sso_client_id 时
		// 填充；nil = 直登 / 应用未配置，无快照链路与现状一致）。
		Sso: ssoSnap,
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
	// ticket 模式若模板未放 {{TICKET_ID}}，扫码端拿到完整加密 ticket、
	// 不走按 id 查快照的路径，故跳过写入；其余模式及含该占位符的 ticket
	// 模式必须写。mode 取归一值，未知模式不落入「跳过」分支，由分派处报错。
	mode := normalizeQrcodeMode(p.Ext.GetQrcodeMode())
	if mode != qrcodeModeTicket || strings.Contains(p.Ext.GetQrcodeFormat(), ticketIDPlaceholder) {
		if err := s.deps.TicketPayloads.Write(ctx, payload); err != nil {
			return nil, fmt.Errorf("qrcode: write ticket payload snapshot: %w", err)
		}
	}

	// 拉码产出按 provider Ext qrcode_mode 分派（§2.8 / §13.2：空值归一为
	// url；未知取值收敛为渠道不可用，不静默回落）。公共前置（captcha /
	// scene / provider 校验 / 快照写入 / ticket 签发）三模式一致，上文已完成。
	prod := &CreateQrcodeOutput{
		Ticket:    ticket,
		TicketID:  ticketID,
		ExpiresIn: int64(qrcodeTicketTTL / time.Second),
	}
	switch mode {
	case qrcodeModeTicket:
		// 不调微信拉码、不写 Storage：以 ticket / ticket_id 替换 qrcode_format
		// 模板占位符，二者可同时出现。模板二者皆缺保存期已拒绝（§5.3），
		// 运行期兜底收敛渠道不可用。
		content, rerr := renderTicketContent(p.Ext.GetQrcodeFormat(), ticket, ticketID)
		if rerr != nil {
			return nil, fmt.Errorf("%w: %v", ErrQrcodeProviderDisabled, rerr)
		}
		prod.QrcodeContent = content
	case qrcodeModeBase64:
		// 拉微信码 + JPEG 压缩后 base64 直发，不写 Storage（不要求存储配置）。
		jpeg, ferr := s.fetchAndCompress(ctx, fetcher, ticketID)
		if ferr != nil {
			return nil, ferr
		}
		prod.QrcodeBase64 = base64.StdEncoding.EncodeToString(jpeg)
	case qrcodeModeURL:
		// Storage.Put 中转模式（§13.2：码图始终走中转，与 upload_mode 无关；
		// storage_provider / storage_path 未配置按失败，§13.0）。存储门控在
		// 分支内部——ticket / base64 模式不要求存储配置。
		jpeg, ferr := s.fetchAndCompress(ctx, fetcher, ticketID)
		if ferr != nil {
			return nil, ferr
		}
		st, key, serr := s.storageFor(ctx, p, payload)
		if serr != nil {
			return nil, serr
		}
		url, perr := st.Put(ctx, key, jpeg, "image/jpeg")
		if perr != nil {
			return nil, fmt.Errorf("qrcode: storage put: %w", perr)
		}
		prod.QrcodeURL = url
	default:
		return nil, fmt.Errorf("%w: %q unknown qrcode mode", ErrQrcodeProviderDisabled, p.Ext.GetQrcodeMode())
	}
	prod.QrcodeMode = mode
	prod.TipHTML = p.Ext.GetQrcodeTip()
	return prod, nil
}

// fetchAndCompress 拉微信码 → JPEG 75% 压缩（§13.2），base64 / url 两分支
// 共用。微信侧故障（配额 / 未发布等）按提供商失败收敛（§13.0）。
func (s *QRCode) fetchAndCompress(ctx context.Context, fetcher provider.QRCodeSupporter, ticketID string) ([]byte, error) {
	raw, err := fetcher.FetchQrcode(ctx, ticketID)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch wxacode: %v", ErrQrcodeProviderDisabled, err)
	}
	jpegBody, err := qrcodepkg.CompressJPEG(raw)
	if err != nil {
		return nil, fmt.Errorf("qrcode: compress: %w", err)
	}
	return jpegBody, nil
}

// normalizeQrcodeMode 模式空值归一（§2.8 / §13.2：空 = url，存量行为不变）。
func normalizeQrcodeMode(mode string) string {
	if mode == "" {
		return qrcodeModeURL
	}
	return mode
}

// renderTicketContent ticket 模式的模板替换纯函数（§2.8 / §13.2）：
// {{TICKET}} 替换为完整加密 ticket，{{TICKET_ID}} 替换为 ticket_id
// （区分大小写、可出现多次、可同时出现）。二者皆缺视为配置错误——保存期已
// 拒绝（§5.3），运行期兜底报错由调用方收敛渠道不可用；只含其一须照常渲染。
func renderTicketContent(tpl, ticket, ticketID string) (string, error) {
	if !strings.Contains(tpl, ticketPlaceholder) && !strings.Contains(tpl, ticketIDPlaceholder) {
		return "", fmt.Errorf("qrcode: ticket mode: template missing %s / %s", ticketPlaceholder, ticketIDPlaceholder)
	}
	out := strings.ReplaceAll(tpl, ticketPlaceholder, ticket)
	return strings.ReplaceAll(out, ticketIDPlaceholder, ticketID), nil
}

// resolveSsoSnapshot 解析应用快照（§2.2 首签口径）：解析器缺位属装配缺陷，
// 与查无行 / 行不可用同样 fail-closed（invalid_request，不降级直登——防拼
// 接请求绕过应用限制）；其余故障按内部错误上抛（handler 转 CodeInternal）。
func (s *QRCode) resolveSsoSnapshot(ctx context.Context, clientID string) (*token.Sso, error) {
	if s.deps.SsoApps == nil {
		return nil, fmt.Errorf("%w: sso snapshot resolver not wired", ticketsvc.ErrQrcodeInvalidRequest)
	}
	snap, err := s.deps.SsoApps.Snapshot(ctx, clientID)
	if err != nil {
		if errors.Is(err, ssoapp.ErrClientNotFound) || errors.Is(err, ssoapp.ErrClientDisabled) {
			return nil, fmt.Errorf("%w: sso client %q", ticketsvc.ErrQrcodeInvalidRequest, clientID)
		}
		return nil, fmt.Errorf("qrcode: resolve sso snapshot: %w", err)
	}
	return snap, nil
}

// ssoAllowsProvider 应用快照对三方 Provider 的放行判定（§2.1 应用级过滤表，
// 三方 / 扫码 Provider 校验同表执行）：快照 nil = 直登 / 应用未配置全放行；
// thirdparty 整体开关看快照 methods 冻结集（已含全局 ∧ 应用交集）；providers
// nil = 应用未配置白名单跟随全局（行级可用性由调用方现查现判），空集 =
// 全局 thirdparty 关（整体拒绝），非空 = 应用白名单成员判定。
func ssoAllowsProvider(snap *token.Sso, providerKey string) bool {
	if snap == nil {
		return true
	}
	if !sliceContains(snap.GetMethods(), thirdpartyMethod) {
		return false
	}
	providers := snap.GetProviders()
	if providers == nil {
		return true
	}
	return sliceContains(providers, providerKey)
}

// sliceContains 成员判定。
func sliceContains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
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
	// OIDC 扫码 step-up 时回传的 OIDC 上下文（§2.8）；needs_step_up
	// 下发 loginToken 时写入其 oidc 载荷，非扫码场景为空。
	OIDC *token.Oidc
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
	if payload.GetScene() != ticketsvc.SceneLogin {
		return &GetLoginTicketOutput{Envelope: &ssov1.LoginFlowResponse{Status: orchestrator.StatusInvalidRequest}}
	}

	// 先读快照（Peek 不删除）：mfa_pending 为非终态，轮询只读、不 GETDEL
	// （§11.6.5 行 1424）；终态 success / failed 才在下方向下消费。
	res, err := s.deps.Tickets.Peek(ctx, id)
	if err != nil {
		logTicketFailure(ctx, id, "peek", err)
		return envelope(orchestrator.StatusFailed, ticketsvc.TicketStatusFailed, nil)
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
			res, err = s.deps.Tickets.Peek(ctx, id)
			if err != nil {
				logTicketFailure(ctx, id, "poll_peek", err)
				return envelope(orchestrator.StatusFailed, ticketsvc.TicketStatusFailed, nil)
			}
		} else {
			// 长轮询等待失败降级为立即返回，不能无痕。
			logx.Warn(ctx, "qrcode: long poll wait failed",
				"ticket_id", id, "step", "long_poll_wait",
				"error", logx.RedactText(werr.Error()))
		}
	}
	if res == nil {
		// 未命中键：now > exp → expired；否则 pending（§2.8 行 748——已扫码
		// 则同为 scanned：scanned 标记存在时上方 Peek 已取到走 scanned 分支）。
		if s.now().Unix() >= payload.GetExp() {
			return envelope("expired", "expired", nil)
		}
		return envelope("pending", "pending", nil)
	}

	switch res.GetStatus() {
	case ticketsvc.TicketStatusScanned:
		// 已扫码标记：原样补写回（WriteScanned SETNX 幂等），防中间态意外丢失，
		// 不产生新状态、不算业务写入（§2.8 行 863）。
		if _, werr := s.deps.Tickets.WriteScanned(ctx, id, res); werr != nil {
			logx.Warn(ctx, "qrcode: rewrite scanned marker failed", "ticket_id", id, "error", werr)
		}
		return envelope(ticketsvc.TicketStatusScanned, ticketsvc.TicketStatusScanned, nil)
	case ticketsvc.TicketStatusMFAPending:
		// 扫码 + 已启用 MFA 的中间态（§2.8 行 884、§13.2 行 1680）：顶层
		// needs_step_up、ticket.status 仍报 scanned；非终态，不消费快照。
		// 额外下发一枚新的 loginToken（载荷含 OIDC 上下文、uid、passed），
		// 前端改用它走 StartVerification / SubmitVerification（§2.8、
		// §3.8.1）；OIDC 不落 TicketResult，由本请求回传的 oidc 入参提供。
		uid := res.GetLoginResult().GetUid()
		if s.deps.State == nil || uid == 0 {
			return envelope(orchestrator.StatusFailed, ticketsvc.TicketStatusFailed, nil)
		}
		signed, err := s.deps.State.Issue(&token.LoginTokenPayload{
			Tid:    s.newTID(),
			Flow:   "login",
			Uid:    uid,
			Passed: []string{thirdpartysvc.AMRThirdParty},
			Amr:    []string{thirdpartysvc.AMRThirdParty},
			Oidc:   in.OIDC,
			// 票据载荷内的应用快照原样首签（§11.6.4：MFA 下发过滤与终点
			// 回跳随之生效）；nil = 无快照链路。
			Sso: payload.GetSso(),
		})
		if err != nil {
			logTicketFailure(ctx, id, "issue_login_token", err)
			return envelope(orchestrator.StatusFailed, ticketsvc.TicketStatusFailed, nil)
		}
		return &GetLoginTicketOutput{Envelope: &ssov1.LoginFlowResponse{
			Status:     statusNeedsStepUp,
			Ticket:     echo(ticketsvc.TicketStatusScanned),
			LoginToken: signed,
		}}
	case ticketsvc.TicketStatusSuccess:
		// 终态一次性消费（§11.6.5 行 1424）：GETDEL 原子取走即删；并发下
		// 被其他读取方先取走时，按键不存在得到 expired。
		taken, terr := s.deps.Tickets.Take(ctx, id)
		if terr != nil {
			logTicketFailure(ctx, id, "consume_success_ticket", terr)
			return envelope(orchestrator.StatusFailed, ticketsvc.TicketStatusFailed, nil)
		}
		if taken == nil {
			return envelope("expired", "expired", nil)
		}
		return s.pollResult(ctx, payload, taken)
	default:
		// 失败类终态：结论在信封 status（§1.6 行 264——写入方把具体失败落
		// TicketResult.status，本侧原样上抛），ticket 只报 failed；终态消费。
		if _, terr := s.deps.Tickets.Take(ctx, id); terr != nil {
			logTicketFailure(ctx, id, "consume_terminal_ticket", terr)
			return envelope(orchestrator.StatusFailed, ticketsvc.TicketStatusFailed, nil)
		}
		return envelope(res.GetStatus(), ticketsvc.TicketStatusFailed, nil)
	}
}

// pollResult 处理结果就绪（ticket.status=success）：login_result 未绑定
// → binding_required 信封（§11.6.5 行 1361：用 thirdparty_identity 签发
// login_token）；已绑定 → Terminal.Complete 建会话（§2.8 行 746）。
func (s *QRCode) pollResult(ctx context.Context, payload *token.TicketPayload, res *token.TicketResult) *GetLoginTicketOutput {
	id := payload.GetTicketId()
	echo := &ssov1.TicketStatus{Status: ticketsvc.TicketStatusSuccess, TicketId: id}
	lr := res.GetLoginResult()
	if lr.GetBindingRequired() || lr.GetUid() == 0 {
		inner := s.pollBinding(ctx, payload, res)
		return &GetLoginTicketOutput{Envelope: &ssov1.LoginFlowResponse{
			Status: ticketsvc.TicketStatusSuccess, Ticket: echo, Login: inner,
		}}
	}

	// 建会话（1 次写，§2.8 行 746）：uid 的用户状态由写入方在 complete /
	// confirm 时校验（同口径），票据寿命（600s）内不重复校验。应用快照
	// 原样入载荷（§11.6.4：终点回跳随之生效）。
	success, err := s.deps.Terminal.Complete(ctx, &token.LoginTokenPayload{
		Tid:    s.newTID(),
		Flow:   "login",
		Uid:    lr.GetUid(),
		Passed: []string{thirdpartysvc.AMRThirdParty},
		Amr:    []string{thirdpartysvc.AMRThirdParty},
		Sso:    payload.GetSso(),
	})
	if err != nil {
		logTicketFailure(ctx, id, "terminal_complete", err)
		return &GetLoginTicketOutput{Envelope: &ssov1.LoginFlowResponse{
			Status: orchestrator.StatusFailed, Ticket: &ssov1.TicketStatus{Status: ticketsvc.TicketStatusFailed, TicketId: id},
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
		Envelope:     &ssov1.LoginFlowResponse{Status: ticketsvc.TicketStatusSuccess, Ticket: echo, Login: inner},
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
		// 未注册 provider 属业务预期；DB / Redis 故障被压成
		// provider_disabled 会无痕，须单独记。
		if !errors.Is(err, sql.ErrNoRows) {
			logTicketFailure(ctx, payload.GetTicketId(), "poll_binding:load_provider", err)
		}
		return &ssov1.LoginFlowResponse{Status: thirdpartysvc.StatusProviderDisabled}
	}
	lt := &token.LoginTokenPayload{
		Tid:    s.newTID(),
		Flow:   "login",
		Passed: []string{thirdpartysvc.AMRThirdParty},
		Amr:    []string{thirdpartysvc.AMRThirdParty},
		// 票据载荷内的应用快照原样首签（§11.6.4）：binding_required 中间态
		// 经免密建号完成登录时快照延续；nil = 无快照链路。
		Sso: payload.GetSso(),
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
		logTicketFailure(ctx, payload.GetTicketId(), "poll_binding:issue_login_token", err)
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

// enqueueAutoDelete 码图自动删除投递（§13.3）：仅 url 模式生效（ticket /
// base64 不产码图、不投删除任务），qrcode_auto_delete 开启时 PC 端完成
// SSO 后，用同一 storage_path 模板 + ticket_id + iat 重算 key（无需任何
// 额外存储——iat 内嵌于加密 ticket）投延迟队列；队列满静默丢弃（删除失败
// 不影响已完成的登录）。
func (s *QRCode) enqueueAutoDelete(ctx context.Context, payload *token.TicketPayload) {
	if s.deps.Queue == nil {
		return
	}
	p, err := s.deps.Loader.Get(ctx, payload.GetProviderKey())
	if err != nil {
		// provider 加载失败（DB / Redis 故障）会让码图永不删除，此前静默
		// return；logx.Warn(ctx, ...) 自动带 request_id。
		logx.Warn(ctx, "qrcode: auto delete: load provider failed",
			"ticket_id", payload.GetTicketId(),
			"provider_key", payload.GetProviderKey(),
			"error", logx.RedactText(err.Error()),
		)
		return
	}
	if p == nil || p.Ext == nil {
		return // 无 Ext，业务预期
	}
	// 仅 url 模式产码图（§13.3）：ticket / base64 不写对象存储、无码图可删，
	// 不投删除任务（此处本就重读 provider，无额外 IO）。
	if normalizeQrcodeMode(p.Ext.GetQrcodeMode()) != qrcodeModeURL {
		return
	}
	if !p.Ext.GetQrcodeAutoDelete() {
		return // 未开启自动删除，业务预期
	}
	key, err := storage.RenderKey(p.Ext.GetStoragePath(), payload.GetTicketId(), payload.GetIat())
	if err != nil {
		logx.Warn(ctx, "qrcode: auto delete: render key failed", "ticket_id", payload.GetTicketId(), "error", err)
		return
	}
	if !s.deps.Queue.Push(asyncqueue.Task{
		Key: "qrcode-delete:" + key,
		Value: qrcodepkg.DeleteTask{
			StorageKey: p.Ext.GetStorageProvider(),
			ObjectKey:  key,
		},
	}) {
		// 队列层的节流 Warn 只给全局计数，这里补具体是哪张码图没被删。
		logx.Warn(ctx, "qrcode: auto delete enqueue dropped",
			"ticket_id", payload.GetTicketId(),
			"object_key", key,
		)
	}
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

// logTicketFailure 是扫码票据主链路「基础设施故障 → failed 信封」的统一
// 记录点：GetLoginTicket / pollResult / pollBinding 返回 HTTP 200 信封、不向
// handler 抛 error，Connect 的 NewErrorLogInterceptor 看不到，必须就地记一次
// 只记 ticket_id 与脱敏错误文本，不记票据值 / 载荷 / 会话令牌；
// 无 error 的业务终态（expired / pending / 客户端脏票据）不记。
func logTicketFailure(ctx context.Context, ticketID, step string, err error) {
	if err == nil {
		return
	}
	logx.Error(ctx, "qrcode: ticket step failed",
		"ticket_id", ticketID,
		"step", step,
		"error", logx.RedactText(err.Error()),
	)
}
