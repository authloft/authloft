// thirdparty.go 三方登录 redirect / api 通道的业务层
// （docs/后端架构.md §3.9 行 406「service/thirdparty.go」、§12.4-§12.5、
// docs/接口文档.md §2.7.2 Authorize / §2.7.4 LoginOauth / §2.7.5 绑定
// 中间态）。
//
// 职责边界：
//   - Authorize：Loader 查 provider（is_enabled + enable_signin）→ channel
//     限 redirect → 生成带前缀 state（§12.4 行 1477：l = 登录 / b = 绑定）
//     → BuildAuthURL（传 RedirectURI={root}/sso/oauth/callback/{key}
//     与 Scope=Ext.scopes，空则适配器默认）→ 签 al_login_state Cookie
//     （LoginStatePayload，purpose=cookie、10 分钟兜底，§11.6.1）返回
//     authorize_url。
//   - LoginOauth：redirect 通道校验 state Cookie（l 前缀 + 一致 + 未过期，
//     失败 state_mismatch 清 Cookie；§12.4 行 1493）→ Exchange / FetchUser →
//     查 user_thirdparty_bind（普通行 → Union 行归并 §12.7 → auto_bind
//     §12.5 行 1508）→ 已绑定：MFA 判定（mfa_required 信封 + login_token，
//     uid / passed / amr=thirdparty / oidc）或 Terminal.Complete 直接建会话
//     （api 通道 SessionInBody）；未绑定：binding_required + 重签 login_token
//     精简 tp 载荷（§12.5 行 1501：去掉 Raw，只留 pk/openid/unionid/
//     nickname/avatar）+ binding.allowSignup（enable_signup 映射）。
//   - 扫码两阶段写入（接口文档 §2.7.4 行 656-659「扫码两阶段
//     写入」）：stage=scanned 只带 providerKey+ticketId，取快照键
//     al:ticket:payload:{ticket_id}（CreateQrcode 写入，§2.8 行 719）校验
//     （存在 / scene 合法 / providerKey 匹配 / 未过期）→ WriteScanned（SET
//     NX 幂等，不覆盖 success）→ 票据状态应答 {status:"scanned"}；stage=
//     complete 带 ticketId：快照校验 → 既有 Exchange / FetchUser 链 → 按
//     scene 分派写 TicketResult（§13.2b：login → login_result；bind →
//     thirdparty_identity，不建会话 / 不查绑定 / 不写绑定关系）→
//     {status:"success", ticketId}；失败类 ticket failed + 信封 status；
//     MFA×扫码（行 653 / 750）：mfa_required 信封、不写 ticket。
//
// 业务失败在登录流程信封域（LoginOauth）一律走信封 status（§1.6 封闭集，
// 零自造）；Authorize 是普通 RPC，可判别哨兵错误由 handler 转 Connect
// 错误体 + ErrorInfo。al_login_state Cookie 属性（§1.9 行 303 / §12.4
// 行 1486）：HttpOnly; SameSite=Lax; Path=/ 会话级恒定，Secure 受
// settings 键 https_deployment 驱动（true → 带 Secure；false →
// 省略；auto 按请求信号推断——判定复用 session.ResolveHTTPS 唯一判定
// 点，与 al_session 同源联动；信号经 ctx 由 connect 装配层注入，connect
// 链 AnyRequest 只暴露 Header）。
package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/logx"
	"authloft/internal/provider"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
	"authloft/internal/session"
	"authloft/internal/settings"
)

// al_login_state Cookie 与 state 前缀常量（接口文档 §2.7.2 行 604-611、
// 后端架构 §12.4 行 1477 / 1485）。
const (
	// LoginStateCookieName Cookie 名。
	LoginStateCookieName = "al_login_state"
	// StatePrefixLogin scene=login 前缀（回调 SsoService/LoginOauth）。
	StatePrefixLogin = "l"
	// StatePrefixBind scene=bind 前缀（回调 AccountService/ThirdpartyOauth，
	// 此处只签发不校验——绑定校验归 §12.6 账号域）。
	StatePrefixBind = "b"
	// loginStateTTL Cookie 载荷内嵌的 10 分钟过期兜底（§12.4 行 1485）。
	loginStateTTL = 10 * time.Minute
	// stateRandomLen state 随机段长度（前缀 + 32 随机字符）。
	stateRandomLen = 32
	// amrThirdParty 三方登录的认证方法引用（§12.5：MFA 信封 amr）。
	amrThirdParty = "thirdparty"
	// stageScanned LoginOauth.stage 的 scanned 取值（§2.7.4 行 640：complete
	// 默认｜scanned 仅上报已扫码；其余取值按 complete 默认处理，跨版本可新增）。
	stageScanned = "scanned"
	// userStatusNormal user.user_status=1 正常，其余禁用（§4.2 行 630；
	// 先例 factor/password/factor.go:178 同款字面量口径）。
	userStatusNormal = 1
	// extraMaxBytes extra 列业务上限 1 MiB（§4.3 行 708：超限整条丢弃降级，
	// 不参与任何业务判定）。
	extraMaxBytes = 1 << 20
)

// 可判别哨兵错误（Authorize；handler 转 Connect 错误体 + ErrorInfo，
// §1.6 封闭集成员）。
var (
	// ErrThirdpartyInvalidRequest 参数缺失 / scene 非法 / 通道不支持。
	ErrThirdpartyInvalidRequest = errors.New("thirdparty: invalid request")
	// ErrThirdpartyProviderDisabled 提供商未启用 / 不允许用于登录 / 未配置。
	ErrThirdpartyProviderDisabled = errors.New("thirdparty: provider disabled")
	// ErrThirdpartyUnauthenticated scene=bind 需要会话（401，§2.7.2 行 583）。
	ErrThirdpartyUnauthenticated = errors.New("thirdparty: authentication required")
)

// ThirdpartyLoader Provider 实例读取窄接口（§20 依赖注入）：*provider.Loader
// 天然满足，测试可传 fake。
type ThirdpartyLoader interface {
	Get(ctx context.Context, providerKey string) (*provider.Provider, error)
}

// ThirdpartyBindStore 绑定行读写窄接口：*repo.BindRepo 天然满足
// （FindByProviderOpenID + CreateWithUnion 同事务创建方向，§12.7 行 1548）。
type ThirdpartyBindStore interface {
	FindByProviderOpenID(ctx context.Context, providerKey, openID string) (*model.UserThirdpartyBind, error)
	CreateWithUnion(ctx context.Context, b *model.UserThirdpartyBind, unionProviderKey, unionID string) error
}

// ThirdpartyUserLookup 用户读取窄接口（§12.5 行 1508 auto_bind 目标匹配
// email / phone + 已绑定路径的用户状态校验 FindByID）：*repo.UserRepo
// 天然满足。
type ThirdpartyUserLookup interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	FindByEmail(ctx context.Context, email string) (*model.User, error)
	FindByPhone(ctx context.Context, phone string) (*model.User, error)
}

// ThirdpartyAdapterFactory 渠道适配器构造（*provider.NewAdapter 天然满足；
// 单独注入便于测试传 fake adapter，不经全局注册表）。
type ThirdpartyAdapterFactory func(p *provider.Provider) (provider.AuthAdapter, error)

// ThirdpartyDeps 依赖注入（§20）；装配层构造（bootstrap buildEngine）。
type ThirdpartyDeps struct {
	Loader     ThirdpartyLoader
	Binds      ThirdpartyBindStore
	Users      ThirdpartyUserLookup
	NewAdapter ThirdpartyAdapterFactory
	State      *orchestrator.State
	Terminal   *orchestrator.Terminal
	// Settings 系统开关源，与引擎同源（§1.6 行 250 / §7.3 行 1031）；
	// nil 时按缺省值判定。
	Settings orchestrator.SettingsReader
	// Credentials 读取用户自选启用二次验证的凭据行（mfa_setting）。
	Credentials factor.CredentialRepo
	// Tickets al:ticket:{ticket_id} 结果读写（§11.6.5；扫码 ticket
	// 分支）。
	Tickets TicketStore
	// TicketPayloads al:ticket:payload:{ticket_id} 快照读取（§5.1 行 863、
	// §11.6.4 行 1350；扫码 ticket 分支——CreateQrcode 写、此处读）。
	TicketPayloads TicketPayloadStore
	// CookieCodec sign_key.cookie（§12.4 行 1487），al_login_state 加解密。
	CookieCodec *security.Codec
	// RootOrigin {al_root}（authloft.root，接口文档 §1.1 行 76）：redirect_uri
	// 拼装基准 {root}/sso/oauth/callback/{key}（§2.7.3 行 614 回调路径，
	// 装配接线经 bootstrap 注入，不自造第二套配置源）；空 = 未注入（旧测试
	// 装配），不携带 redirect_uri。
	RootOrigin string
	// HTTPSMode https_deployment 三态源（每请求读取，装配层注入 settings
	// 读取闭包；nil = 未接入本键 → Secure 恒定，沿旧默认）。
	// al_login_state 的 Secure 属性受其驱动（§1.9 行 303）。
	HTTPSMode func() string
	// NewTID login_token.tid 生成（缺省 security.RandomString(32)，同引擎）。
	NewTID func() (string, error)
	// Now 时钟注入（缺省 time.Now）。
	Now func() time.Time
}

// Thirdparty 三方登录通道 service。
type Thirdparty struct {
	deps ThirdpartyDeps
	now  func() time.Time
}

// NewThirdparty 构造。
func NewThirdparty(d ThirdpartyDeps) *Thirdparty {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return &Thirdparty{deps: d, now: now}
}

// AuthorizeInput SsoService/Authorize 入参（接口文档 §2.7.2 行 579-586）。
type AuthorizeInput struct {
	Provider string
	Scene    string // 空 / login / bind
	// UID scene=bind 时的当前会话 uid（handler 从 ctx 取；0 = 无会话）。
	UID int64
}

// AuthorizeOutput Authorize 产物；Cookie 为需下发的 al_login_state
// （nil = 无动作）。
type AuthorizeOutput struct {
	AuthorizeURL string
	Cookie       *http.Cookie
}

// Authorize 取三方授权 URL（§2.7.2）：只收 provider 与 scene 两个参数，
// 生成带前缀随机 state 写 Cookie 后返回 URL，由前端跳转（不做后端 302）。
func (s *Thirdparty) Authorize(ctx context.Context, in AuthorizeInput) (*AuthorizeOutput, error) {
	if strings.TrimSpace(in.Provider) == "" {
		return nil, fmt.Errorf("%w: empty provider", ErrThirdpartyInvalidRequest)
	}
	scene := in.Scene
	if scene == "" {
		scene = "login"
	}
	if scene != "login" && scene != "bind" {
		return nil, fmt.Errorf("%w: scene %q", ErrThirdpartyInvalidRequest, in.Scene)
	}
	// scene=bind 需 al_session（401 unauthenticated，§2.7.2 行 583）。
	if scene == "bind" && in.UID == 0 {
		return nil, ErrThirdpartyUnauthenticated
	}

	p, err := s.deps.Loader.Get(ctx, in.Provider)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %q not found", ErrThirdpartyProviderDisabled, in.Provider)
		}
		return nil, fmt.Errorf("thirdparty: load provider: %w", err)
	}
	if !p.Enabled() || p.Row == nil || p.Row.EnableSignin != 1 {
		return nil, fmt.Errorf("%w: %q", ErrThirdpartyProviderDisabled, in.Provider)
	}

	// 通道限 redirect（§2.7.2 本接口只服务跳转渠道；api 由宿主自行交互、
	// qrcode 拉码暂不实装）。
	adapter, err := s.deps.NewAdapter(p)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrThirdpartyProviderDisabled, in.Provider, err)
	}
	if adapter.Channel() != provider.ChannelRedirect {
		return nil, fmt.Errorf("%w: channel %q not redirect", ErrThirdpartyInvalidRequest, adapter.Channel())
	}

	state, err := s.newState(scene)
	if err != nil {
		return nil, fmt.Errorf("thirdparty: new state: %w", err)
	}
	url, err := adapter.BuildAuthURL(&provider.AuthContext{
		ProviderKey: in.Provider,
		RedirectURI: s.redirectURI(in.Provider),
		State:       state,
		// Scope 取 provider 配置（Ext.scopes）；空则适配器按渠道默认
		// （oauthcore.BuildAuthURL 的 defaultScope 缺省链）。
		Scope: p.Ext.GetScopes(),
	})
	if err != nil {
		return nil, fmt.Errorf("thirdparty: build auth url: %w", err)
	}

	ck, err := s.sealStateCookie(ctx, state, in.UID)
	if err != nil {
		return nil, fmt.Errorf("thirdparty: seal login state: %w", err)
	}
	return &AuthorizeOutput{AuthorizeURL: url, Cookie: ck}, nil
}

// redirectURI {root}/sso/oauth/callback/{provider_key}（§2.7.3 行 614 回调
// 路径）：root 去尾斜杠归一（与 oidc issuer 同款处理）；RootOrigin
// 未注入返回空（适配器不携带 redirect_uri，沿旧口径）。
func (s *Thirdparty) redirectURI(providerKey string) string {
	if s.deps.RootOrigin == "" {
		return ""
	}
	return strings.TrimSuffix(s.deps.RootOrigin, "/") + "/sso/oauth/callback/" + providerKey
}

// OauthInput SsoService/LoginOauth 入参（接口文档 §2.7.4 行 630-643）。
// StateCookie 为请求携带的 al_login_state Cookie 值（redirect 通道必经）。
type OauthInput struct {
	ProviderKey string
	Code        string
	State       string
	Stage       string
	TicketID    string
	LoginToken  string // 此处不消费（MFA 走 LoginDefault、建号走 Register）
	OIDC        *token.Oidc
	StateCookie string
}

// OauthOutput LoginOauth 产物。信封（Envelope）为响应主体；Cookie 为需下发
// 的 Set-Cookie（state 校验通过 / 失败即删，§2.7.2 行 611）；SessionToken
// 仅浏览器（redirect）终点非空（handler 经会话 Cookie 构造器下发，api 通道
// 改走信封 session_token 字段，SessionInBody=true）。
type OauthOutput struct {
	Envelope      *ssov1.LoginFlowResponse
	Cookie        *http.Cookie
	SessionToken  string
	SessionInBody bool
}

// LoginOauth 三方登录统一入口（§2.7.4）：redirect（浏览器回调）与 api
// （小程序 code）两通道；扫码提交（qrcode 通道，必带 ticketId）走两阶段
// 写入（stage=scanned / complete，§2.7.4 行 656-659）。
func (s *Thirdparty) LoginOauth(ctx context.Context, in OauthInput) *OauthOutput {
	// stage=scanned（§2.7.4 行 656-658）：只带 providerKey + ticketId，
	// 不需要任何凭证，独立分支（不进下述通道 / Exchange 链）。
	if in.Stage == stageScanned {
		return s.loginOauthScanned(ctx, in)
	}
	if strings.TrimSpace(in.ProviderKey) == "" || in.Code == "" {
		return s.envelope(orchestrator.StatusInvalidRequest)
	}

	p, err := s.deps.Loader.Get(ctx, in.ProviderKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return s.envelope(statusProviderDisabled)
		}
		return s.envelope(orchestrator.StatusFailed)
	}
	if !p.Enabled() || p.Row == nil || p.Row.EnableSignin != 1 {
		return s.envelope(statusProviderDisabled)
	}
	adapter, err := s.deps.NewAdapter(p)
	if err != nil {
		return s.envelope(statusProviderDisabled)
	}
	channel := adapter.Channel()
	// 通道判定（§13.2）：扫码提交（带 ticketId）必为 qrcode 通道（快照由
	// CreateQrcode 落、provider 必为扫码类）；qrcode 通道的提交必带
	// ticketId，无 ticketId 的 qrcode 请求不合规范。
	if in.TicketID != "" {
		if channel != provider.ChannelQRCode {
			return s.envelope(orchestrator.StatusInvalidRequest)
		}
	} else if channel != provider.ChannelRedirect && channel != provider.ChannelAPI {
		return s.envelope(orchestrator.StatusInvalidRequest)
	}

	// redirect 通道：校验 al_login_state（l 前缀、一致、未过期；§12.4 行
	// 1493），通过 / 失败即删 Cookie（§2.7.2 行 611）。b 前缀不由本接口
	// 处理（§2.7.4 行 653），统一并入 state_mismatch。扫码提交（qrcode
	// 通道）无 Cookie 语境不校验（小程序端无 Origin，Referer 白名单归
	// HTTP 层，§13.2 行 1606）。
	if channel == provider.ChannelRedirect {
		if !s.verifyLoginState(in.State, in.StateCookie) {
			return &OauthOutput{
				Envelope: &ssov1.LoginFlowResponse{Status: statusStateMismatch},
				Cookie:   s.clearStateCookie(ctx),
			}
		}
	}

	// 扫码 stage=complete（带 ticketId，§2.7.4 行 649 / 659）：快照校验 →
	// 既有 Exchange / FetchUser 链 → 按 scene 分派写 TicketResult（§13.2b）。
	if in.TicketID != "" {
		return s.loginOauthTicket(ctx, in, p, adapter)
	}

	// redirect_uri 与授权时一致（标准 OAuth 令牌交换校验项）；api
	// 通道适配器（wechat_mp code2session）不消费该字段，透传无害。
	tok, err := adapter.Exchange(ctx, provider.ExchangeInput{
		Code:        in.Code,
		RedirectURI: s.redirectURI(in.ProviderKey),
	})
	if err != nil {
		return s.oauthFail(ctx, channel, orchestrator.StatusFailed)
	}
	identity, err := adapter.FetchUser(ctx, tok)
	if err != nil || identity == nil || identity.OpenID == "" {
		return s.oauthFail(ctx, channel, orchestrator.StatusFailed)
	}

	// 三方身份 → uid 解析链（resolveBind / 用户状态校验 / auto_bind 写入，
	// 与扫码 ticket 分支共用，见 resolveLoginUID）。
	uid, failStatus := s.resolveLoginUID(ctx, p, identity)
	if failStatus != "" {
		return s.oauthFail(ctx, channel, failStatus)
	}

	payload := &token.LoginTokenPayload{
		Tid:    s.newTID(),
		Flow:   "login",
		Uid:    uid,
		Passed: []string{amrThirdParty},
		Amr:    []string{amrThirdParty},
		Oidc:   in.OIDC,
	}

	// 未绑定（uid=0）→ 绑定中间态（§12.5 行 1501）：重签 login_token 精简
	// tp 载荷（去掉 Raw，只留 pk / openid / unionid / nickname / avatar），
	// binding.allowSignup 由 enable_signup 映射（§2.7.5 行 678）。中间态
	// extra 空可接受（§12.5 行 1502，昵称头像已在 tp 中）。
	if uid == 0 {
		payload.Tp = &token.ThirdParty{
			ProviderKey: identity.ProviderKey,
			OpenId:      identity.OpenID,
			UnionId:     identity.UnionID,
			Nickname:    identity.Nickname,
			AvatarUrl:   identity.AvatarURL,
		}
		signed, err := s.deps.State.Issue(payload)
		if err != nil {
			return s.oauthFail(ctx, channel, orchestrator.StatusFailed)
		}
		allowSignup := p.Row.EnableSignup == 1
		return s.withStateCleared(ctx, channel, &OauthOutput{Envelope: &ssov1.LoginFlowResponse{
			Status:     orchestrator.StatusBindingRequired,
			LoginToken: signed,
			Binding:    orchestrator.BindingEnvelope(payload, p.Row.DisplayName, allowSignup),
		}})
	}

	// 已绑定 / Union 归并 / auto_bind 命中：该用户已启用 MFA →
	// status=mfa_required（§2.7.4 行 785），后续走 §3.8 StartVerification；
	// 不下发因子列表。
	required, err := s.mfaRequired(ctx, uid)
	if err != nil {
		// 依赖读取故障按 fail-closed 收敛：不建会话、返回失败信封。
		return s.oauthFail(ctx, channel, orchestrator.StatusFailed)
	}
	if required {
		signed, err := s.deps.State.Issue(payload)
		if err != nil {
			return s.oauthFail(ctx, channel, orchestrator.StatusFailed)
		}
		return s.withStateCleared(ctx, channel, &OauthOutput{Envelope: &ssov1.LoginFlowResponse{
			Status:     orchestrator.StatusMFARequired,
			LoginToken: signed,
		}})
	}

	success, err := s.deps.Terminal.Complete(ctx, payload)
	if err != nil {
		return s.oauthFail(ctx, channel, orchestrator.StatusFailed)
	}
	resp := &ssov1.LoginFlowResponse{
		Status:        orchestrator.StatusSuccess,
		SessionId:     success.SessionID,
		SyncCookieUrl: success.SyncCookieURL,
		RedirectTo:    success.RedirectTo,
		UserId:        success.UserID,
	}
	if channel == provider.ChannelAPI {
		// api 通道（小程序）：session_token 直接作为接口返回，不写 Cookie
		//（§13.1 行 1583）。
		resp.SessionToken = success.SessionToken
		return &OauthOutput{Envelope: resp, SessionInBody: true}
	}
	// redirect 通道：校验通过的 state Cookie 即删（§2.7.2 行 611）。
	return &OauthOutput{
		Envelope:     resp,
		Cookie:       s.clearStateCookie(ctx),
		SessionToken: success.SessionToken,
	}
}

// loginOauthScanned stage=scanned 分支（§2.7.4 行 656-658）：小程序端进入
// 页面先上报「已扫码」，只带 providerKey + ticketId、不需要任何凭证。服务端
// 取快照校验后写 al:ticket:{ticket_id} = TicketResult{status:"scanned"}
// （channel=qrcode，不含 login_result / thirdparty_identity）→ 返回票据状态
// 应答 {status:"scanned"}（取值沿用 ticket.status，非 §1.3 登录流程信封）。
// 重复上报幂等（WriteScanned SET NX）；已存在 success 时不覆盖。
func (s *Thirdparty) loginOauthScanned(ctx context.Context, in OauthInput) *OauthOutput {
	if strings.TrimSpace(in.ProviderKey) == "" || in.TicketID == "" {
		return s.envelope(orchestrator.StatusInvalidRequest)
	}
	payload, bad := s.ticketSnapshot(ctx, in)
	if bad != "" {
		return s.envelope(bad)
	}
	res := &token.TicketResult{
		V:           ticketResultV,
		Scene:       payload.GetScene(),
		Status:      ticketStatusScanned,
		ProviderKey: payload.GetProviderKey(),
		Channel:     channelQRCode,
		CreatedAt:   s.now().Unix(),
		ExpiresAt:   payload.GetExp(),
	}
	if _, err := s.deps.Tickets.WriteScanned(ctx, in.TicketID, res); err != nil {
		return s.envelope(orchestrator.StatusFailed)
	}
	return &OauthOutput{Envelope: &ssov1.LoginFlowResponse{Status: ticketStatusScanned}}
}

// loginOauthTicket stage=complete 带 ticketId 分支（§2.7.4 行 649 / 659、
// §13.2b 行 1616）：快照校验 → 既有 Exchange / FetchUser 链 → 按 scene 分派
// 写 TicketResult（scene 由快照加密保护，客户端不可篡改）：
//   - scene=login：既有 resolveBind / 用户状态校验 / auto_bind 解析链 →
//     login_result{uid, binding_required}（未绑定为 0/true，轮询方据此建会话
//     或签 login_token，§11.6.5 行 1368-1371）；未绑定另附 thirdparty_identity
//     （§11.6.5 行 1372 login binding_required=true 与 bind 共用）。
//   - scene=bind：只写 thirdparty_identity（含 raw，绑定要落 extra），
//     不建会话、不查绑定、不写绑定关系（绑定判定一律推迟到 PC 端轮询）。
//
// 成功返回 {status:"success", ticketId}；失败类结论落 TicketResult.status
// 整体覆盖（§13.2 行 1603），信封 status 同步、ticket 只报 failed（§2.8 行
// 743 同构）。MFA×扫码（§2.8 行 750、§13.2 行 1607）：用户已启用 MFA →
// mfa_required 信封、**不写 ticket**（授权结果不落键，PC 端轮询至 expired）。
func (s *Thirdparty) loginOauthTicket(ctx context.Context, in OauthInput, p *provider.Provider, adapter provider.AuthAdapter) *OauthOutput {
	snap, bad := s.ticketSnapshot(ctx, in)
	if bad != "" {
		return s.envelope(bad)
	}
	id := in.TicketID

	tok, err := adapter.Exchange(ctx, provider.ExchangeInput{Code: in.Code})
	if err != nil {
		return s.ticketFail(ctx, id, snap, orchestrator.StatusFailed)
	}
	identity, err := adapter.FetchUser(ctx, tok)
	if err != nil || identity == nil || identity.OpenID == "" {
		return s.ticketFail(ctx, id, snap, orchestrator.StatusFailed)
	}

	// scene=bind（§13.2b 行 1616）：不经 uid 解析链，无 MFA / 会话语义。
	if snap.GetScene() == sceneBind {
		return s.ticketDone(ctx, id, s.newTicketResult(snap, "", nil, identity))
	}

	// scene=login：既有解析链（与浏览器 / api 通道共用，见 resolveLoginUID）。
	uid, failStatus := s.resolveLoginUID(ctx, p, identity)
	if failStatus != "" {
		return s.ticketFail(ctx, id, snap, failStatus)
	}
	if uid == 0 {
		// 未绑定（§11.6.5 行 1361/1372）：login_result{uid:0,
		// binding_required:true} + thirdparty_identity——轮询方用其签发
		// login_token 并返回 binding_required 信封（本侧不签 token）。
		return s.ticketDone(ctx, id, s.newTicketResult(snap, "", &token.LoginResult{BindingRequired: true}, identity))
	}

	// 已绑定：该用户已启用 MFA → status=mfa_required、不写 ticket（§2.8
	// 行 750）——授权结果未定，PC 端轮询至 expired，小程序端收到即止；
	// 因子列表不下发，由 §3.8 StartVerification 提供。
	required, err := s.mfaRequired(ctx, uid)
	if err != nil {
		// 依赖读取故障按 fail-closed 收敛：写 ticket failed，不返回
		// mfa_required（不得把故障当成「无需二次验证」继续签发）。
		return s.ticketFail(ctx, id, snap, orchestrator.StatusFailed)
	}
	if required {
		signed, err := s.deps.State.Issue(&token.LoginTokenPayload{
			Tid:    s.newTID(),
			Flow:   "login",
			Uid:    uid,
			Passed: []string{amrThirdParty},
			Amr:    []string{amrThirdParty},
			Oidc:   in.OIDC,
		})
		if err != nil {
			return s.envelope(orchestrator.StatusFailed)
		}
		return &OauthOutput{Envelope: &ssov1.LoginFlowResponse{
			Status:     orchestrator.StatusMFARequired,
			LoginToken: signed,
		}}
	}

	// 建会话推迟到 PC 端轮询（§2.8 行 746：GetLoginTicket 命中后
	// Terminal.Complete），本侧只写 login_result{uid, binding_required:false}。
	return s.ticketDone(ctx, id, s.newTicketResult(snap, "", &token.LoginResult{Uid: uid}, identity))
}

// ticketSnapshot 读快照并校验（§2.7.4 行 658、§11.6.4 行 1350）：快照存在
// （缺失即不存在 / 已过期）、ticket_id 自洽、scene 合法（login / bind——
// scene 与本次扫码用途一致，用途由快照加密保护、不由客户端指定）、
// providerKey 匹配、未过期（键 TTL 与 ticket 同寿命，此处防御性复判）。
// 返回 status 非空表示以该信封状态拒绝（infra 故障 failed，其余
// invalid_request）。
func (s *Thirdparty) ticketSnapshot(ctx context.Context, in OauthInput) (*token.TicketPayload, string) {
	payload, err := s.deps.TicketPayloads.Read(ctx, in.TicketID)
	if err != nil {
		return nil, orchestrator.StatusFailed
	}
	if payload == nil ||
		payload.GetTicketId() != in.TicketID ||
		(payload.GetScene() != sceneLogin && payload.GetScene() != sceneBind) ||
		payload.GetProviderKey() != in.ProviderKey ||
		s.now().Unix() >= payload.GetExp() {
		return nil, orchestrator.StatusInvalidRequest
	}
	return payload, ""
}

// newTicketResult 组装 TicketResult（§11.6.5）：v / scene / provider_key 取
// 快照（scene 不由客户端指定）、channel 固定 qrcode、expires_at 与 ticket.exp
// 一致；status 缺省按 login_result / thirdparty_identity 的存在取 success；
// lr 为 nil 且 identity 为 nil 的空结果仅 scanned 分支自组装。
func (s *Thirdparty) newTicketResult(snap *token.TicketPayload, status string, lr *token.LoginResult, identity *provider.ExternalIdentity) *token.TicketResult {
	if status == "" {
		status = ticketStatusSuccess
	}
	res := &token.TicketResult{
		V:           ticketResultV,
		Scene:       snap.GetScene(),
		Status:      status,
		ProviderKey: snap.GetProviderKey(),
		Channel:     channelQRCode,
		CreatedAt:   s.now().Unix(),
		ExpiresAt:   snap.GetExp(),
		LoginResult: lr,
	}
	// thirdparty_identity：bind 场景（绑定要落 extra，含 raw）与 login
	// binding_required=true 共用（§11.6.5 行 1372）；已绑定登录不填。
	if snap.GetScene() == sceneBind || (lr != nil && lr.GetBindingRequired()) {
		res.ThirdpartyIdentity = tpIdentity(identity)
	}
	return res
}

// ticketDone 写 stage=complete 成功结果（WriteComplete 整体覆盖 scanned，
// 已存在 success 不覆盖——重复提交幂等成功）并组装 {status:"success",
// ticketId} 应答（§2.7.4 行 649；写入失败按 failed 收敛，PC 端轮询至 expired）。
func (s *Thirdparty) ticketDone(ctx context.Context, id string, res *token.TicketResult) *OauthOutput {
	if _, err := s.deps.Tickets.WriteComplete(ctx, id, res); err != nil {
		logx.Warn(ctx, "thirdparty: write ticket result failed", "ticket_id", id, "error", err)
		return s.envelope(orchestrator.StatusFailed)
	}
	return &OauthOutput{Envelope: &ssov1.LoginFlowResponse{
		Status: orchestrator.StatusSuccess,
		Ticket: &ssov1.TicketStatus{Status: ticketStatusSuccess, TicketId: id},
	}}
}

// ticketFail 写 failed 类票据结果并组装失败应答（§13.2 行 1603：结论落
// TicketResult.status，轮询方原样上抛信封 status、ticket 只报 failed）。
// 写入失败仅记日志、不改变应答（PC 端轮询至 expired，不阻塞小程序端结论）。
func (s *Thirdparty) ticketFail(ctx context.Context, id string, snap *token.TicketPayload, status string) *OauthOutput {
	if _, err := s.deps.Tickets.WriteComplete(ctx, id, s.newTicketResult(snap, status, nil, nil)); err != nil {
		logx.Warn(ctx, "thirdparty: write ticket result failed", "ticket_id", id, "error", err)
	}
	return &OauthOutput{Envelope: &ssov1.LoginFlowResponse{
		Status: status,
		Ticket: &ssov1.TicketStatus{Status: ticketStatusFailed, TicketId: id},
	}}
}

// resolveLoginUID 三方身份 → uid 解析链（浏览器 / api 通道与扫码 ticket
// 分支共用）：resolveBind（普通行 → Union 归并 → auto_bind）→ 已绑定 /
// 归并 / auto_bind 命中的用户状态校验（R1-1，置于 auto_bind 写入之前——
// 禁用用户不产生绑定副作用；查询失败按 failed 收敛）→ auto_bind 命中直接
// 绑定（§12.5 行 1508；并发被抢 target_taken §1.6 行 256；extra 落 Raw
// R1-3，§4.3 行 708 超限 / 编码失败整条丢弃降级）。失败返回 failStatus
// （信封域失败类），成功返回 uid（0 = 未绑定）。
func (s *Thirdparty) resolveLoginUID(ctx context.Context, p *provider.Provider, identity *provider.ExternalIdentity) (uid int64, failStatus string) {
	uid, matched, out := s.resolveBind(ctx, p, identity)
	if out != nil {
		return 0, out.Envelope.GetStatus()
	}
	if uid != 0 {
		user, uerr := s.deps.Users.FindByID(ctx, uid)
		if uerr != nil {
			return 0, orchestrator.StatusFailed
		}
		if user.UserStatus != userStatusNormal {
			return 0, statusUserDisabled
		}
	}
	if matched {
		if err := s.deps.Binds.CreateWithUnion(ctx, &model.UserThirdpartyBind{
			UserID:      uid,
			ProviderKey: identity.ProviderKey,
			OpenID:      identity.OpenID,
			Nickname:    identity.Nickname,
			AvatarURL:   identity.AvatarURL,
			Extra:       encodeExtra(identity.Raw),
		}, p.Row.UnionProvider, identity.UnionID); err != nil {
			return 0, orchestrator.StatusTargetTaken
		}
	}
	return uid, ""
}

// mfaRequired 判定三方身份对应的用户是否需二次验证（§2.7.4 行 785、
// §2.8 行 750）：与引擎同口径，依据系统开关与用户启用状态（策略强制列 ∨
// 自选启用凭据行），不下发因子列表；因子视图由验证内核 StartVerification
// 提供（§3.8）。
//
// 返回 error 表示依赖读取故障，调用方必须以失败信封拒绝本次登录：读取
// 故障不得被解释为「无需二次验证」。用户行的任何读取错误都不得放行（仓储
// 对 not-found 也按错误返回）；仅 mfa_setting 凭据行不存在属正常语义
// （该用户未启用自选 MFA），返回 (false, nil)。
func (s *Thirdparty) mfaRequired(ctx context.Context, uid int64) (bool, error) {
	// uid=0 / 依赖未接入（单测裁剪装配）：无判定输入，按无需 MFA 处理。
	if uid == 0 || s.deps.Users == nil {
		return false, nil
	}
	enabled := true
	if s.deps.Settings != nil {
		if v, ok := s.deps.Settings.GetBool(settings.KeyMfaEnabled); ok {
			enabled = v
		}
	}
	if !enabled {
		return false, nil
	}
	user, err := s.deps.Users.FindByID(ctx, uid)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, nil
	}
	if user.MfaRequired == 1 {
		return true, nil
	}
	// 凭据仓储未接入与引擎同口径：装配裁剪而非运行期故障。
	if s.deps.Credentials == nil {
		return false, nil
	}
	c, err := s.deps.Credentials.FindByUserAndKind(ctx, uid, "mfa_setting")
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	if c == nil {
		return false, nil
	}
	return c.IsEnabled == 1, nil
}

// tpIdentity 三方身份 → TicketResult.thirdparty_identity（§11.6.5 行
// 1372-1378：open_id / union_id / nickname / avatar_url / raw；raw 为第三方
// 原始资料，任意 JSON 经 structpb 承载——oidc/credential 先例，
// 空 map 落 nil）。
func tpIdentity(identity *provider.ExternalIdentity) *token.ThirdpartyIdentity {
	if identity == nil {
		return nil
	}
	var raw *structpb.Struct
	if len(identity.Raw) > 0 {
		if s, err := structpb.NewStruct(identity.Raw); err == nil {
			raw = s
		}
	}
	return &token.ThirdpartyIdentity{
		OpenId:    identity.OpenID,
		UnionId:   identity.UnionID,
		Nickname:  identity.Nickname,
		AvatarUrl: identity.AvatarURL,
		Raw:       raw,
	}
}

// encodeExtra 三方原始资料 → extra 列 msgpack 字节（R1-3；§4.3 行 708
// 「仅排查用、不参与任何业务判定」；先例 dto/rpc.go EncodeRPCProfileExtra
// 同款 msgpack.Marshal(map)）：raw 为空 / 编码失败 / 超 1 MiB 返回 nil
// （整条丢弃降级，绑定主链路不受影响）。
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

// LoginOauth 信封域状态（§1.6 封闭集合成员，orchestrator 未导出的补位；
// 零自造——state_mismatch 行 252 / provider_disabled 行 259 /
// user_disabled 行 253）。
const (
	statusStateMismatch    = "state_mismatch"
	statusProviderDisabled = "provider_disabled"
	statusUserDisabled     = "user_disabled"
)

// resolveBind 三方身份 → 用户解析链（§12.5 步骤 4 / §12.7 行 1548-1549 /
// §12.5 行 1508）：普通行 (provider_key, openid) → provider 关联 Union 行
// (union_provider, unionid) → auto_bind=1 按 auto_bind_fields 匹配 email /
// phone。返回 (uid, matched, out)：out 非 nil 表示直接以该信封终止
// （auto_bind 写入失败的 target_taken）；matched=true 时调用方完成登录前
// 需写入绑定行。
func (s *Thirdparty) resolveBind(ctx context.Context, p *provider.Provider, identity *provider.ExternalIdentity) (int64, bool, *OauthOutput) {
	row, err := s.deps.Binds.FindByProviderOpenID(ctx, p.Key, identity.OpenID)
	if err == nil {
		return row.UserID, false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, false, s.envelope(orchestrator.StatusFailed)
	}

	// Union 归并（§12.7 行 1549）：普通行未命中且关联 Union Provider、
	// 适配器返回 unionid → 按 (union_provider, unionid) 命中归并到同一账号。
	if p.Row != nil && p.Row.UnionProvider != "" && identity.UnionID != "" {
		urow, uerr := s.deps.Binds.FindByProviderOpenID(ctx, p.Row.UnionProvider, identity.UnionID)
		if uerr == nil {
			return urow.UserID, false, nil
		}
		if !errors.Is(uerr, gorm.ErrRecordNotFound) {
			return 0, false, s.envelope(orchestrator.StatusFailed)
		}
	}

	// auto_bind（§12.5 行 1508）：默认关闭；按 auto_bind_fields（默认
	// email,phone）匹配已有用户直接绑定，跳过绑定页。接管风险由管理员
	// 自担（第三方返回的邮箱若未验证）。
	if p.Row != nil && p.Row.AutoBind == 1 {
		for _, field := range autoBindFields(p.Row.AutoBindFields) {
			var uid int64
			switch field {
			case "email":
				if identity.Email == "" {
					continue
				}
				u, uerr := s.deps.Users.FindByEmail(ctx, identity.Email)
				if uerr == nil {
					uid = u.ID
				} else if !errors.Is(uerr, gorm.ErrRecordNotFound) {
					return 0, false, s.envelope(orchestrator.StatusFailed)
				}
			case "phone":
				if identity.Phone == "" {
					continue
				}
				u, uerr := s.deps.Users.FindByPhone(ctx, identity.Phone)
				if uerr == nil {
					uid = u.ID
				} else if !errors.Is(uerr, gorm.ErrRecordNotFound) {
					return 0, false, s.envelope(orchestrator.StatusFailed)
				}
			default:
				continue
			}
			if uid != 0 {
				return uid, true, nil
			}
		}
	}
	return 0, false, nil
}

// autoBindFields 解析 auto_bind_fields 列（默认 email,phone，§12.5 行
// 1508）；空 / 全非法回落默认。
func autoBindFields(raw string) []string {
	if raw == "" {
		return []string{"email", "phone"}
	}
	var out []string
	for _, f := range strings.Split(raw, ",") {
		if f = strings.TrimSpace(f); f == "email" || f == "phone" {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return []string{"email", "phone"}
	}
	return out
}

// newState 生成带前缀的随机 state（§12.4 行 1477：l = 登录 / b = 绑定）。
func (s *Thirdparty) newState(scene string) (string, error) {
	prefix := StatePrefixLogin
	if scene == "bind" {
		prefix = StatePrefixBind
	}
	rnd, err := security.RandomString(stateRandomLen)
	if err != nil {
		return "", err
	}
	return prefix + rnd, nil
}

// sealStateCookie 签发 al_login_state（LoginStatePayload：state 带前缀、
// b 场景 uid、10 分钟 exp 兜底；§12.4 行 1485——不含 scene、不含 OIDC
// 上下文）。属性（§1.9 行 303）：HttpOnly; SameSite=Lax; Path=/ 会话级
// 恒定；Secure 受 https_deployment 驱动——判定为真 → 带 Secure；
// 判定为假 → 省略。判定走 session.ResolveHTTPS 唯一判定点（与 al_session
// 同源联动），auto 信号经 ctx（connect 装配层注入请求头）。
func (s *Thirdparty) sealStateCookie(ctx context.Context, state string, uid int64) (*http.Cookie, error) {
	now := s.now()
	payload := &token.LoginStatePayload{
		State: state,
		Uid:   uid,
		Iat:   now.Unix(),
		Exp:   now.Add(loginStateTTL).Unix(),
	}
	value, err := s.deps.CookieCodec.Seal(security.PurposeCookie, payload)
	if err != nil {
		return nil, err
	}
	return &http.Cookie{
		Name:     LoginStateCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.stateSecure(ctx),
		SameSite: http.SameSiteLaxMode,
	}, nil
}

// clearStateCookie 构造删除 Cookie（§2.7.2 行 611：校验通过或失败后立即
// 删除；同名同 Path、MaxAge=-1，Secure 与 sealStateCookie 同判定确保
// 属性一致——RFC 6265 删除匹配不看 Secure，对齐仅为一致性）。
func (s *Thirdparty) clearStateCookie(ctx context.Context) *http.Cookie {
	return &http.Cookie{
		Name:     LoginStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.stateSecure(ctx),
		SameSite: http.SameSiteLaxMode,
	}
}

// stateSecure al_login_state 的 Secure 判定（§1.9 行 303）：复用
// session.ResolveHTTPS（https_deployment 三态 + auto 请求信号，唯一判定
// 点）；deps.HTTPSMode 为 nil（未接入）→ 恒 true 沿旧默认。
func (s *Thirdparty) stateSecure(ctx context.Context) bool {
	return session.ResolveHTTPS(s.deps.HTTPSMode, session.RequestSignalFromContext(ctx))
}

// verifyLoginState 校验 redirect 通道的 state（§12.4 行 1493）：请求 state
// 必须为 l 前缀非空、与 Cookie 解出的载荷一致且未过期。
func (s *Thirdparty) verifyLoginState(state, cookieValue string) bool {
	if state == "" || !strings.HasPrefix(state, StatePrefixLogin) || cookieValue == "" {
		return false
	}
	payload, err := security.Open[token.LoginStatePayload](s.deps.CookieCodec, security.PurposeCookie, cookieValue)
	if err != nil {
		return false
	}
	if payload.GetState() != state || payload.GetState() == "" {
		return false
	}
	return s.now().Unix() < payload.GetExp()
}

// newTID login_token.tid 生成（缺省同引擎 security.RandomString(32)）。
func (s *Thirdparty) newTID() string {
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

// envelope 组装最小信封（status-only 失败态）。入口拒绝（通道判定前）无
// Cookie 语境，经此构造；通道判定后的终态一律走 withStateCleared /
// oauthFail。
func (s *Thirdparty) envelope(status string) *OauthOutput {
	return &OauthOutput{Envelope: &ssov1.LoginFlowResponse{Status: status}}
}

// withStateCleared redirect 通道的终态统一删 al_login_state
// （§12.4 行 1486「回调校验通过或失败后立即删除」——mismatch / success 之外
// 的 binding_required / mfa_required / failed / target_taken 等非成功终态
// 同样删除，防 state 复用重放）；api 通道无 Cookie 场景不动作。out 已带
// Cookie（mismatch）时保持原值。ctx 透传给 clearStateCookie 做 Secure
// 判定（https_deployment 驱动）。
func (s *Thirdparty) withStateCleared(ctx context.Context, channel provider.ThirdPartyChannel, out *OauthOutput) *OauthOutput {
	if channel == provider.ChannelRedirect && out.Cookie == nil {
		out.Cookie = s.clearStateCookie(ctx)
	}
	return out
}

// oauthFail 通道判定后的 status-only 终态（redirect 一律删 Cookie）。
func (s *Thirdparty) oauthFail(ctx context.Context, channel provider.ThirdPartyChannel, status string) *OauthOutput {
	return s.withStateCleared(ctx, channel, s.envelope(status))
}

// SignupState 实现 orchestrator.ThirdpartySignup 窄接口的查询半边：
// enable_signup 校验以 DB 列为准（§2.7.5 行 678 字段映射）；provider 不
// 存在 / 已禁用返回包装的 gorm.ErrRecordNotFound（调用方按 failed 收敛）。
func (s *Thirdparty) SignupState(ctx context.Context, providerKey string) (orchestrator.ThirdpartySignupState, error) {
	p, err := s.deps.Loader.Get(ctx, providerKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return orchestrator.ThirdpartySignupState{}, fmt.Errorf("thirdparty: signup state: %q not found: %w", providerKey, gorm.ErrRecordNotFound)
		}
		return orchestrator.ThirdpartySignupState{}, fmt.Errorf("thirdparty: signup state: %w", err)
	}
	if p.Row == nil || !p.Enabled() {
		return orchestrator.ThirdpartySignupState{}, fmt.Errorf("thirdparty: signup state: %q disabled: %w", providerKey, gorm.ErrRecordNotFound)
	}
	return orchestrator.ThirdpartySignupState{
		Enabled:  p.Row.EnableSignup == 1,
		UnionKey: p.Row.UnionProvider,
	}, nil
}

// CreateBind 写绑定行（+ Union 行同事务），实现 orchestrator.ThirdpartySignup
// 窄接口的写入半边；ErrBindDuplicate 判别归调用方（setpass tp 分支 →
// target_taken）。
func (s *Thirdparty) CreateBind(ctx context.Context, b *model.UserThirdpartyBind, unionProviderKey, unionID string) error {
	return s.deps.Binds.CreateWithUnion(ctx, b, unionProviderKey, unionID)
}
