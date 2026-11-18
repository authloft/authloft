// consent.go 同意 RPC 的两个 Connect handler（接口文档 §3.10）：会话鉴权 →
// 业务编排 → 错误归一。会话主体 / 认证时刻取会话载荷（§5.2），不接受入参 uid；
// Origin 跨站防护在装配层 HTTP 链统一完成（§1.1），本层不重复。
package account

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/gen/go/api/account/v1/accountv1connect"
	internalconnect "authloft/internal/connect"
	accountsvc "authloft/internal/service/account"
	"authloft/internal/session"
	"authloft/internal/settings"
)

// ConsentApprover 同意业务编排窄接口；*accountsvc.ConsentService 满足。
type ConsentApprover interface {
	Approve(ctx context.Context, in accountsvc.ApproveInput) (*accountsvc.ConsentOutput, error)
	Deny(ctx context.Context, clientID, redirectURI, state string) (*accountsvc.ConsentOutput, error)
}

// ConsentClaims 签名载荷所需的会话身份字段（§5.2 步骤 5：uid / amr / auth_time
// 取会话载荷）。
type ConsentClaims struct {
	UID      int64
	AMR      []string
	AuthTime int64
}

// ConsentClaimsReader 从请求读取并完整校验会话载荷，返回签名主体字段
// （§5.2：uid/amr/auth_time 取会话载荷）。ok=false 即无有效会话 → unauthenticated。
// 完整校验（解令牌 / exp / epoch）复用 session.Verifier，不与拦截器共享 ctx 身份
// 假设——同意签码是敏感写操作，独立复核会话状态（与 authorize 直签同口径）。
type ConsentClaimsReader interface {
	Claims(ctx context.Context, h http.Header) (ConsentClaims, bool)
}

// HeaderClaimsReader 生产实现：按 §1.2 优先级取 X-Authloft-Token → Cookie，
// 经 session.Verifier 四步校验后取载荷。Verifier 由装配层注入共享单例。
type HeaderClaimsReader struct {
	Verifier   *session.Verifier
	CookieName func() string
}

// Claims 取并校验请求头中的会话令牌；缺失 / 失效令牌返回 ok=false。
func (r *HeaderClaimsReader) Claims(ctx context.Context, h http.Header) (ConsentClaims, bool) {
	if r == nil || r.Verifier == nil {
		return ConsentClaims{}, false
	}
	tok := ""
	if v := strings.TrimSpace(h.Get("X-Authloft-Token")); v != "" {
		tok = v
	} else {
		name := "al_session"
		if r.CookieName != nil {
			if n := strings.TrimSpace(r.CookieName()); n != "" {
				name = n
			}
		}
		if ck, err := (&http.Request{Header: h}).Cookie(name); err == nil {
			tok = ck.Value
		}
	}
	if tok == "" {
		return ConsentClaims{}, false
	}
	p, err := r.Verifier.Verify(ctx, tok)
	if err != nil || p.GetId() == 0 {
		return ConsentClaims{}, false
	}
	return ConsentClaims{UID: p.GetId(), AMR: p.GetAmr(), AuthTime: p.GetIat()}, true
}

// ConsentHandler 在既有 account Handler 之上挂同意两方法。内嵌 *Handler 提升
// 其余全部 RPC，不改既有构造签名；未装配 consent / claims 时对应方法报
// unimplemented / internal，便于测试与降级装配。
type ConsentHandler struct {
	*Handler
	consent ConsentApprover
	claims  ConsentClaimsReader
}

// NewConsentHandler 构造挂同意方法的完整 AccountService handler。
func NewConsentHandler(base *Handler, consent ConsentApprover, claims ConsentClaimsReader) *ConsentHandler {
	return &ConsentHandler{Handler: base, consent: consent, claims: claims}
}

var _ accountv1connect.AccountServiceHandler = (*ConsentHandler)(nil)

// ConsentApprove 同意提交：会话鉴权 → 校验 → 写记录 → 签码 → 落点消息（§3.10）。
func (h *ConsentHandler) ConsentApprove(ctx context.Context, req *connect.Request[accountv1.ConsentApproveRequest]) (*connect.Response[accountv1.ConsentResponse], error) {
	claims, ok := h.consentClaims(ctx, req)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	if h.consent == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("account consent: service not configured"))
	}
	msg := req.Msg
	out, err := h.consent.Approve(ctx, accountsvc.ApproveInput{
		ClientID:            msg.GetClientId(),
		RedirectURI:         msg.GetRedirectUri(),
		Scope:               msg.GetScope(),
		SelectedScope:       msg.GetSelectedScope(),
		State:               msg.GetState(),
		Nonce:               msg.GetNonce(),
		CodeChallenge:       msg.GetCodeChallenge(),
		CodeChallengeMethod: msg.GetCodeChallengeMethod(),
		UID:                 claims.UID,
		AMR:                 claims.AMR,
		AuthTime:            claims.AuthTime,
		SessionToken:        sessionTokenOf(req.Header(), h.sessionCookieName()),
	})
	if err != nil {
		return nil, mapConsentError("approve", err)
	}
	return connect.NewResponse(&accountv1.ConsentResponse{
		RedirectTo:    out.RedirectTo,
		SyncCookieUrl: out.SyncCookieURL,
	}), nil
}

// ConsentDeny 同意拒绝：会话鉴权 → 校验 client / redirect → access_denied 落点。
func (h *ConsentHandler) ConsentDeny(ctx context.Context, req *connect.Request[accountv1.ConsentDenyRequest]) (*connect.Response[accountv1.ConsentResponse], error) {
	if _, ok := h.consentClaims(ctx, req); !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	if h.consent == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("account consent: service not configured"))
	}
	msg := req.Msg
	out, err := h.consent.Deny(ctx, msg.GetClientId(), msg.GetRedirectUri(), msg.GetState())
	if err != nil {
		return nil, mapConsentError("deny", err)
	}
	return connect.NewResponse(&accountv1.ConsentResponse{RedirectTo: out.RedirectTo}), nil
}

// requestWithHeader Connect 请求暴露 Header 的最小面，便于两方法共用会话读取。
type requestWithHeader interface {
	Header() http.Header
}

// consentClaims 读会话载荷并做会话鉴权；claims 未装配即无会话。
func (h *ConsentHandler) consentClaims(ctx context.Context, req requestWithHeader) (ConsentClaims, bool) {
	if h.claims == nil {
		return ConsentClaims{}, false
	}
	return h.claims.Claims(ctx, req.Header())
}

// sessionCookieName 与 session 拦截器同源的 Cookie 名（settings 键缺省 al_session）。
func (h *ConsentHandler) sessionCookieName() string {
	if h.Handler != nil && h.settings != nil {
		if v, ok := h.settings.GetString(settings.KeyCookieName); ok && v != "" {
			return v
		}
	}
	return "al_session"
}

// sessionTokenOf 取原始会话令牌串供多域名同步写入（§1.2 优先级）。
func sessionTokenOf(h http.Header, cookieName string) string {
	if v := strings.TrimSpace(h.Get("X-Authloft-Token")); v != "" {
		return v
	}
	if ck, err := (&http.Request{Header: h}).Cookie(cookieName); err == nil {
		return ck.Value
	}
	return ""
}

// mapConsentError 同意业务错误 → Connect 错误体（§1.5 / §3.10）：
// scope 类 → invalid_argument + ErrorInfo.code=invalid_scope；
// client / redirect 类 → invalid_argument + invalid_request；其余消毒为 internal。
func mapConsentError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrConsentInvalidScope):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_scope", err.Error()),
		)
	case errors.Is(err, accountsvc.ErrConsentInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_request", err.Error()),
		)
	default:
		return fmt.Errorf("account handler: consent %s: %w", op, err)
	}
}

// 编译期断言：ClaimsReader 生产实现满足窄接口。
var _ ConsentClaimsReader = (*HeaderClaimsReader)(nil)
