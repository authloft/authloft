// login_ticket.go 统一写票 service（docs/接口文档.md §2.7.4 / §2.8、
// docs/后端架构.md §11.6.5）：扫码授权结果的写入收敛到本文件一处，由
// ConfirmLoginTicket 与 LoginOauth 扫码分支共用。写票时自行按目标用户的
// 二次验证启用状态判定，把 al:ticket:{ticket_id} 写为 success 或
// mfa_pending；写票不改变任何登录态（不建会话、不签 token），OIDC 上下文
// 不落本结构。
package ticket

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/logx"
	"authloft/internal/repo/model"
	"authloft/internal/service/mfapolicy"
	"authloft/internal/service/orchestrator"
	"authloft/internal/session"
)

// MFAUserLookup 写票时按 uid 读取用户行，判定二次验证启用状态；
// *repo.UserRepo 天然满足，测试可传 fake。
type MFAUserLookup interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
}

// LoginTicketDeps 依赖注入（§20）；装配层构造，测试可传 fake。
type LoginTicketDeps struct {
	// Tickets al:ticket 结果读写（§11.6.5）。
	Tickets TicketStore
	// TicketPayloads al:ticket:payload 快照读写（§11.6.4）：写票前校验
	// 快照存在、scene 合法，并取 provider_key / expires_at。
	TicketPayloads TicketPayloadStore
	// Sessions ConfirmLoginTicket 会话校验（§11.1 四步）。
	Sessions SessionVerifier
	// State 扫码分支校验 login_token（§7.3：uid != 0 且 passed 非空）。
	State *orchestrator.State
	// Users / Settings / Credentials 供二次验证判定（§2.8、§11.6.5）：
	// 口径统一为「系统已开放 ∧ user.mfa_required=1 ∧ 存在可用因子」，
	// 判定实现归 mfapolicy，与登录引擎 / 三方登录同源。
	Users       MFAUserLookup
	Settings    orchestrator.SettingsReader
	Credentials factor.CredentialRepo
	// Now 时钟注入（缺省 time.Now）。
	Now func() time.Time
}

// LoginTicket 统一写票 service（不挂 QRCode）。
type LoginTicket struct {
	deps LoginTicketDeps
	now  func() time.Time
}

// NewLoginTicket 构造。
func NewLoginTicket(d LoginTicketDeps) *LoginTicket {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return &LoginTicket{deps: d, now: now}
}

// WriteTicketInput 统一写票入参：TicketID 为票据标识；写入状态不随入参
// 传入，由 service 按目标用户的二次验证启用状态自行判定（§2.8、§11.6.5）。
// 目标 uid 二选一推导：
//   - ConfirmLoginTicket：Session（请求体 session_token）与 SessionUID
//     （Cookie 侧 uid）按 §2.8 校验，以 body 为准、两者须同一 uid；
//   - LoginOauth 扫码分支：LoginToken 为小程序端 mfa_required 信封携带的
//     login_token，经 State.Parse 恢复目标 uid（§7.3 防绕过主因子）。
type WriteTicketInput struct {
	TicketID   string
	Session    string
	SessionUID int64
	LoginToken string
}

// WriteTicket 自行按目标用户的二次验证启用状态写票（§2.8：ConfirmLoginTicket
// 与 LoginOauth 扫码分支共用同一写点）。success 为终态、mfa_pending 为非终态
// （轮询只读不消费）；MFA 判定依赖读取故障按 fail-closed 返回错误、不写票，
// 不把查询故障解释为「无需二次验证」；写入失败返回可判别哨兵错误，由
// handler 转 Connect 错误体。
func (s *LoginTicket) WriteTicket(ctx context.Context, in WriteTicketInput) (*ssov1.TicketStatus, error) {
	if strings.TrimSpace(in.TicketID) == "" {
		return nil, fmt.Errorf("%w: empty ticket_id", ErrQrcodeInvalidRequest)
	}
	uid, err := s.resolveUID(ctx, in)
	if err != nil {
		return nil, err
	}
	snap, err := s.deps.TicketPayloads.Read(ctx, in.TicketID)
	if err != nil {
		return nil, fmt.Errorf("login ticket: read ticket payload: %w", err)
	}
	if snap == nil || snap.GetTicketId() != in.TicketID || snap.GetScene() != SceneLogin {
		return nil, fmt.Errorf("%w: %q payload", ErrQrcodeTicketInvalid, in.TicketID)
	}

	required, err := s.mfaRequired(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("login ticket: mfa required: %w", err)
	}
	status := TicketStatusSuccess
	if required {
		status = TicketStatusMFAPending
	}
	res := &token.TicketResult{
		V:           TicketResultV,
		Scene:       SceneLogin,
		Status:      status,
		ProviderKey: snap.GetProviderKey(),
		Channel:     ChannelQRCode,
		CreatedAt:   s.now().Unix(),
		ExpiresAt:   snap.GetExp(),
		LoginResult: &token.LoginResult{Uid: uid},
	}
	if _, err := s.deps.Tickets.WriteComplete(ctx, in.TicketID, res); err != nil {
		return nil, fmt.Errorf("login ticket: write ticket result: %w", err)
	}
	return &ssov1.TicketStatus{Status: status, TicketId: in.TicketID}, nil
}

// resolveUID 按主体凭证推导目标 uid：扫码分支校验 login_token 的
// uid != 0 与 passed 非空（§7.3），缺主因子不得把票据推进到 mfa_pending；
// 确认分支校验会话（§2.8：body session 为准、与 Cookie 同 uid）。
func (s *LoginTicket) resolveUID(ctx context.Context, in WriteTicketInput) (int64, error) {
	if in.LoginToken != "" {
		if s.deps.State == nil {
			return 0, errors.New("login ticket: login state not configured")
		}
		p, err := s.deps.State.Parse(in.LoginToken)
		if err != nil || p.GetUid() == 0 || len(p.GetPassed()) == 0 {
			return 0, fmt.Errorf("%w: login token", ErrQrcodeTicketInvalid)
		}
		return p.GetUid(), nil
	}

	uid := in.SessionUID
	if in.Session != "" {
		if s.deps.Sessions == nil {
			return 0, ErrQrcodeUnauthenticated
		}
		p, err := s.deps.Sessions.Verify(ctx, in.Session)
		if err != nil {
			// 解不开 / 过期 / epoch 不一致属预期未登录；epoch 读取链故障
			// （Redis / DB）被一并压成 ErrQrcodeUnauthenticated，且该哨兵
			// 不是 internal，统一错误日志也不触发，必须在此单独记录。
			// 已逐出与 handler/rpc 的失效分类同口径，同归未登录组、不记
			// 基础设施错误日志；当前逐出标记只读不写（无写入口），本分支
			// 实际不可达，显式列出以防逐出接入后被误判为读取链故障。
			if errors.Is(err, session.ErrSessionRevoked) {
				return 0, ErrQrcodeUnauthenticated
			}
			if !errors.Is(err, session.ErrNotAuthenticated) && !errors.Is(err, session.ErrSessionStale) {
				logx.Error(ctx, "ticket: session verify failed",
					"error", logx.RedactText(err.Error()),
				)
			}
			return 0, ErrQrcodeUnauthenticated
		}
		if in.SessionUID != 0 && in.SessionUID != p.GetId() {
			return 0, fmt.Errorf("%w: session uid mismatch", ErrQrcodeInvalidRequest)
		}
		uid = p.GetId()
	}
	if uid == 0 {
		return 0, ErrQrcodeUnauthenticated
	}
	return uid, nil
}

// mfaRequired 判定目标用户是否需二次验证（§2.8、§11.6.5）：与登录引擎 /
// 三方登录同口径，判定实现归 mfapolicy（§3.7）——系统已开放 ∧
// user.mfa_required=1 ∧ 存在可用因子（白名单 ∩ 已绑定）。
// 返回 error 表示依赖读取故障，调用方须 fail-closed 拒绝本次写票：查询
// 故障不得被解释为「无需二次验证」。
func (s *LoginTicket) mfaRequired(ctx context.Context, uid int64) (bool, error) {
	return mfapolicy.Required(ctx, mfapolicy.Deps{
		Users:    s.deps.Users,
		Creds:    s.deps.Credentials,
		Settings: s.deps.Settings,
	}, uid)
}
