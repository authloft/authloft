// Package sso 实现 api.sso.v1.SsoService 的 Connect handler（docs/后端架构.md
// §3.4 行 316）：handler 只做请求绑定与组装，登录流程编排全部在
// orchestrator，图形码生成委托 internal/captcha。已落地 LoginDefault、
// Register、ResetPassword、CreateCaptchaImage（接口文档 §2.2-§2.5）、
// Authorize、LoginOauth（§2.7）与扫码三桩 CreateQrcode /
// GetLoginTicket / ConfirmLoginTicket（§2.8——编排全部在
// qrcodesvc.QRCode）；§3.8 二次验证 Start/Submit 挂在登录 / 扫码链路。
package sso

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"connectrpc.com/connect"

	commonv1 "authloft/gen/go/api/common/v1"
	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/api/sso/v1/ssov1connect"
	"authloft/internal/captcha"
	internalconnect "authloft/internal/connect"
	"authloft/internal/dto"
	"authloft/internal/logx"
	"authloft/internal/service/orchestrator"
	qrcodesvc "authloft/internal/service/qrcode"
	thirdpartysvc "authloft/internal/service/thirdparty"
	ticketsvc "authloft/internal/service/ticket"
	"authloft/internal/service/verification"
	"authloft/internal/session"
)

// 各端点固定 flow（接口文档 §2.2 行 415、§2.3 行 443、§2.4 行 460）。
const (
	loginFlow    = "login"
	registerFlow = "register"
	resetFlow    = "reset"
)

// Engine 登录单引擎窄接口（§20 依赖注入）：生产注入 *orchestrator.Engine，
// 测试可传 fake，不感知引擎内部依赖。
type Engine interface {
	Submit(ctx context.Context, flow string, req orchestrator.Request) *ssov1.LoginFlowResponse
}

// Handler SsoService 服务实现。内嵌生成的 unimplemented 基类，未实现方法
// 统一返回 Connect CodeUnimplemented。
type Handler struct {
	ssov1connect.UnimplementedSsoServiceHandler
	engine  Engine
	images  *captcha.ImageCaptcha
	cookies *session.Cookie
	// thirdparty 三方登录通道 service（oauth.go）；nil（测试 / 未装配）时
	// Authorize / LoginOauth 返回 unimplemented。
	thirdparty Thirdparty
	// qrcode 扫码拉码与轮询 service；nil（测试 / 未装配）时两个扫码
	// 方法返回 unimplemented。
	qrcode Qrcode
	// loginTicket 统一写票 service（ConfirmLoginTicket 与 LoginOauth 扫码
	// 分支共用）；nil（测试 / 未装配）时相关方法返回 unimplemented。
	loginTicket LoginTicketWriter
	// verification step-up 服务（§3.8）；nil（测试 / 未装配）时两个
	// 二次验证方法返回 unimplemented。
	verification Verification
}

// Verification step-up 服务窄接口（§20 依赖注入）：生产注入
// *verification.Service，测试可传 fake。
type Verification interface {
	Start(ctx context.Context, in verification.StartInput) (*verification.StartResult, *captcha.Failure, error)
	Submit(ctx context.Context, in verification.SubmitInput) (*verification.SubmitResult, error)
}

// LoginTicketWriter 统一写票窄接口（§20 依赖注入）：生产注入
// ticket 子包的写票实现，测试可传 fake；ConfirmLoginTicket 与 LoginOauth
// 扫码分支共用同一写票入口。
type LoginTicketWriter interface {
	WriteTicket(ctx context.Context, in ticketsvc.WriteTicketInput) (*ssov1.TicketStatus, error)
}

// New 构造 SsoService handler。images 为自绘图形码实现
// （CreateCaptchaImage 用，装配层注入 captcha.NewImageCaptcha）；cookies 为
// 会话 Cookie 属性构造器（登录终点建会话后经 Set-Cookie 下发
// al_session，复用 session 包同一构造器）；thirdparty 为三方登录通道
// service（oauth.go）；qrcode 为扫码三桩 service；末尾可变参数 v 注入
// step-up 服务（§3.8）。测试 / 未装配时均传 nil（不下发 / unimplemented），
// 既有五参数装配点与测试桩保持不变。
func New(engine Engine, images *captcha.ImageCaptcha, cookies *session.Cookie, thirdparty Thirdparty, qrcode Qrcode, v ...Verification) *Handler {
	h := &Handler{engine: engine, images: images, cookies: cookies, thirdparty: thirdparty, qrcode: qrcode}
	if len(v) > 0 {
		h.verification = v[0]
	}
	return h
}

// WithLoginTicket 注入统一写票 service；与 New 的可变参数装配点解耦，
// 既有装配点与测试桩保持不变。
func (h *Handler) WithLoginTicket(w LoginTicketWriter) *Handler {
	h.loginTicket = w
	return h
}

// withSessionTokenSink 注入登录终点的 session_token 写点：引擎仅
// 在 status=success 建会话后回调一次，此处经 connect.AddSessionCookie
// （与 session 拦截器续期同一 CallInfo 写头机制）+ session.Cookie.Set
// （同一属性构造器：HttpOnly 恒定；Secure/SameSite 受 settings 键
// https_deployment 驱动——HTTPS 判定 → Secure; SameSite=None；明文 →
// 省略 Secure、SameSite=Lax，§1.9 行 288/292）下发 Set-Cookie:
// al_session=<session_token>。auto 推断信号经 ctx 取自 session 拦截器注入
// 的 RequestSignal；测试直构 handler（无拦截器）时 ctx 无信号
// → auto 兜底明文，三态注入的构造器不受影响。失败态 / 中间态引擎不回调，
// 零 Set-Cookie、信封零 session_token。cookies 未注入（测试）时返回原 ctx。
func (h *Handler) withSessionTokenSink(ctx context.Context) context.Context {
	if h.cookies == nil {
		return ctx
	}
	return orchestrator.WithSessionTokenSink(ctx, func(sessionToken string) {
		internalconnect.AddSessionCookie(ctx, h.cookies.Set(sessionToken, session.RequestSignalFromContext(ctx)))
	})
}

// LoginDefault 统一提交端点（接口文档 §2.2 行 415-437）：把请求消息经 dto
// 转换为引擎入参，返回登录流程信封（§1.3）；业务失败走 HTTP 200 + 信封
// status，人机校验失败按 §1.5 例外走非 200 的 Connect 错误体。
func (h *Handler) LoginDefault(ctx context.Context, req *connect.Request[ssov1.LoginDefaultRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	return h.submit(ctx, loginFlow, dto.LoginDefault(req.Msg))
}

// Register 注册端点（接口文档 §2.3 行 441-455）：与 LoginDefault 同构，
// 仅 flow=register（引擎内走 challenge → verify → set_password）。
func (h *Handler) Register(ctx context.Context, req *connect.Request[ssov1.RegisterRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	return h.submit(ctx, registerFlow, dto.Register(req.Msg))
}

// ResetPassword 重置密码端点（接口文档 §2.4 行 459-471）：与 LoginDefault
// 同构，仅 flow=reset。
func (h *Handler) ResetPassword(ctx context.Context, req *connect.Request[ssov1.ResetPasswordRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	return h.submit(ctx, resetFlow, dto.Reset(req.Msg))
}

// errCaptchaSinkMissing 人机校验失败写点未注入：引擎在 captcha 失败时只会
// 返回 status=failed，调用方无从判别（§1.5 要求 captcha 失败走非 200 的
// Connect 错误体），故此处显式失败，不静默回落。
var errCaptchaSinkMissing = errors.New("sso: captcha failure sink not injected")

// captchaFailureSink 注入人机校验失败写点并回读校验：sink 为 nil 或写点
// 未真正挂到 ctx 链上时返回 errCaptchaSinkMissing。
func captchaFailureSink(ctx context.Context, sink func(*captcha.Failure)) (context.Context, error) {
	if sink == nil {
		return nil, errCaptchaSinkMissing
	}
	out := orchestrator.WithCaptchaFailureSink(ctx, sink)
	if _, ok := orchestrator.CaptchaFailureSinkFromContext(out); !ok {
		return nil, errCaptchaSinkMissing
	}
	return out, nil
}

// submit 三个登录端点的共用入口：注入人机校验失败写点后交给引擎；命中失败
// 时不返回信封，改由 encodeCaptchaFailure 编码非 200 的 Connect 错误体（§1.5）。
func (h *Handler) submit(ctx context.Context, flow string, in orchestrator.Request) (*connect.Response[ssov1.LoginFlowResponse], error) {
	var failure *captcha.Failure
	sinkCtx, err := captchaFailureSink(ctx, func(f *captcha.Failure) { failure = f })
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, internalconnect.InternalError(err))
	}
	resp := h.engine.Submit(h.withSessionTokenSink(sinkCtx), flow, in)
	if failure != nil {
		return nil, encodeCaptchaFailure(failure)
	}
	return connect.NewResponse(resp), nil
}

// encodeCaptchaFailure 把领域失败编码为 Connect 错误体：标准码
// invalid_argument，ErrorInfo.code 取失败码，details 并列当前生效的
// CaptchaConfig（§1.5 / §2.5）。
func encodeCaptchaFailure(f *captcha.Failure) error {
	message := "captcha required"
	if f.Code == captcha.StatusInvalid {
		message = "captcha invalid or used"
	}
	coded := internalconnect.WithErrorInfo(
		connect.NewError(connect.CodeInvalidArgument, errors.New(message)),
		internalconnect.NewErrorInfo("sso", f.Code, message),
	)
	return internalconnect.WithCaptchaConfig(coded, &commonv1.CaptchaConfig{
		ProviderKey: f.Config.ProviderKey,
		Type:        f.Config.Type,
		SiteKey:     f.Config.SiteKey,
	})
}

// errVerificationNotConfigured 未装配 step-up 服务（测试桩）。
var errVerificationNotConfigured = errors.New("verification service not configured")

// StartVerification（§3.8.1、§3.8.2，SsoService 组）：以 loginToken 为
// 唯一的主体凭证推导主体，下发挑战令牌与可用因子；扫码 step-up 取
// GetLoginTicket 在 needs_step_up 时下发的新 loginToken（§2.8）。
func (h *Handler) StartVerification(ctx context.Context, req *connect.Request[commonv1.StartVerificationRequest]) (*connect.Response[commonv1.StartVerificationResponse], error) {
	if h.verification == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errVerificationNotConfigured)
	}
	res, failure, err := h.verification.Start(ctx, verification.StartInput{
		Domain:     verification.DomainSSO,
		BizPurpose: verification.BizPurpose(req.Msg.GetBizPurpose()),
		Method:     req.Msg.GetMethod(),
		Operation:  req.Msg.GetOperation(),
		LoginToken: req.Msg.GetLoginToken(),
		Captcha:    verification.ParseCaptchaSubmission(req.Msg.GetCaptcha()),
	})
	if err != nil {
		return nil, mapVerificationError("sso", err)
	}
	if failure != nil {
		return nil, encodeCaptchaFailure(failure)
	}
	return connect.NewResponse(startVerificationResponse(res)), nil
}

// SubmitVerification（§3.8.1、§3.8.2，SsoService 组）：提交二次因子；通过后
// 复用登录终点收尾（建会话 + 多域名同步 / OIDC 跳转），成功返回
// status=success + redirectTo + syncCookieUrl。因子类失败按登录流程信封
// status 表达（HTTP 200），step-up 令牌类失败走 Connect 错误体（§3.8.5）。
func (h *Handler) SubmitVerification(ctx context.Context, req *connect.Request[commonv1.SubmitVerificationRequest]) (*connect.Response[commonv1.SubmitVerificationResponse], error) {
	if h.verification == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errVerificationNotConfigured)
	}
	res, err := h.verification.Submit(h.withSessionTokenSink(ctx), verification.SubmitInput{
		Domain:         verification.DomainSSO,
		ChallengeToken: req.Msg.GetChallengeToken(),
		Method:         req.Msg.GetMethod(),
		Payload:        req.Msg.GetPayload(),
		LoginToken:     req.Msg.GetLoginToken(),
	})
	if err != nil {
		if status, attemptsLeft := verificationFlowStatus(err); status != "" {
			out := &commonv1.SubmitVerificationResponse{Status: status}
			if attemptsLeft > 0 {
				v := attemptsLeft
				out.AttemptsLeft = &v
			}
			return connect.NewResponse(out), nil
		}
		return nil, mapVerificationError("sso", err)
	}
	return connect.NewResponse(&commonv1.SubmitVerificationResponse{
		Status:        res.Status,
		RedirectTo:    res.RedirectTo,
		SyncCookieUrl: res.SyncCookieURL,
		Amr:           res.AMR,
	}), nil
}

// verificationFlowStatus 判定因子类失败是否应以登录流程信封 status 表达
// （§3.8.5）：OTP / TOTP / WebAuthn 因子失败沿用 §1.6 封闭集合；step-up
// 令牌与主体凭证类失败仍走 Connect 错误体 + ErrorInfo.code。第二个返回值
// 为错码且键保留时的剩余尝试次数（§3.8.2、§1.6），零值即不展示。
func verificationFlowStatus(err error) (string, int64) {
	var ve *verification.Error
	if !errors.As(err, &ve) {
		return "", 0
	}
	switch ve.Code {
	case "invalid_code", "code_expired", "too_many_attempts", "method_disabled":
		return ve.Code, ve.AttemptsLeft
	}
	return "", 0
}

// mapVerificationError 把 step-up 领域失败映射为 Connect 错误体 +
// ErrorInfo（§1.5、§3.8.5）：verification_required / verification_invalid
// 走 failed_precondition；限流走 resource_exhausted 并带 retry_after；
// 其余走 invalid_argument；非领域错误原样上抛。
func mapVerificationError(domain string, err error) error {
	var ve *verification.Error
	if !errors.As(err, &ve) {
		return fmt.Errorf("sso handler: verification: %w", err)
	}
	connCode := connect.CodeInvalidArgument
	switch ve.Code {
	case "verification_required", "verification_invalid":
		connCode = connect.CodeFailedPrecondition
	case "too_many_requests":
		connCode = connect.CodeResourceExhausted
	}
	info := internalconnect.NewErrorInfo(domain, ve.Code, ve.Code)
	info.RetryAfter = ve.RetryAfter
	return internalconnect.WithErrorInfo(
		connect.NewError(connCode, errors.New(ve.Code)),
		info,
	)
}

// startVerificationResponse 领域结论 → §3.8.2 响应消息投影。
func startVerificationResponse(res *verification.StartResult) *commonv1.StartVerificationResponse {
	out := &commonv1.StartVerificationResponse{
		ChallengeToken: res.ChallengeToken,
		ExpiresIn:      res.ExpiresIn,
	}
	for i := range res.Methods {
		m := &res.Methods[i]
		out.Methods = append(out.Methods, &commonv1.VerificationMethod{
			Method:          m.Method,
			Usage:           m.Usage,
			Steps:           m.Steps,
			ChallengeFields: m.ChallengeFields,
			CodeLength:      m.CodeLength,
			ResendAfter:     m.ResendAfter,
			ExpiresIn:       m.ExpiresIn,
			Capability:      m.Capability,
			Providers:       m.Providers,
		})
	}
	if res.NextStepKind != "" {
		out.NextStep = &commonv1.VerificationNextStep{
			Kind:          res.NextStepKind,
			ChallengeData: res.ChallengeData,
		}
	}
	return out
}

// —— 三方登录通道（接口文档 §2.7.2 / §2.7.4）——
// 请求绑定、Cookie 头解析与 Set-Cookie 下发归本层，三方通道编排全部在
// thirdparty 子包。LoginOauth 的业务失败走登录流程信封 status（HTTP
// 200，§1.3 / §1.6）；Authorize 是普通 RPC，可判别哨兵错误转 Connect
// 错误体 + ErrorInfo。

// Thirdparty 三方登录通道 service 窄接口（§20 依赖注入）：生产注入
// thirdparty 子包实现，测试可传 fake。
type Thirdparty interface {
	Authorize(ctx context.Context, in thirdpartysvc.AuthorizeInput) (*thirdpartysvc.AuthorizeOutput, error)
	LoginOauth(ctx context.Context, in thirdpartysvc.OauthInput) *thirdpartysvc.OauthOutput
}

// errThirdpartyNotConfigured 未装配三方 service（测试桩）。
var errThirdpartyNotConfigured = errors.New("thirdparty service not configured")

// Authorize 取第三方授权 URL（接口文档 §2.7.2 行 593-613）：scene=bind 时
// 从 ctx 取会话 uid（session 拦截器注入；无会话由 service 判 401）；
// sso_client_id 从请求透传（三方链路应用上下文唯一入口，§2.7.2——service
// 装入 al_login_state 随链路传递，bind 场景由 service 剥离）；成功时经
// CallInfo 写点下发 Set-Cookie: al_login_state（与 session Cookie 同一写出
// 出口，interceptors.go 行 141「禁止另造第二套」）。
func (h *Handler) Authorize(ctx context.Context, req *connect.Request[ssov1.AuthorizeRequest]) (*connect.Response[ssov1.AuthorizeResponse], error) {
	if h.thirdparty == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errThirdpartyNotConfigured)
	}
	uid, _ := session.UIDFromContext(ctx)
	out, err := h.thirdparty.Authorize(ctx, thirdpartysvc.AuthorizeInput{
		Provider:    req.Msg.GetProvider(),
		Scene:       req.Msg.GetScene(),
		UID:         uid,
		SsoClientID: req.Msg.GetSsoClientId(),
	})
	if err != nil {
		return nil, mapThirdpartyError(err)
	}
	if out.Cookie != nil {
		internalconnect.AddSessionCookie(ctx, out.Cookie)
	}
	return connect.NewResponse(&ssov1.AuthorizeResponse{AuthorizeUrl: out.AuthorizeURL}), nil
}

// LoginOauth 三方登录统一入口（接口文档 §2.7.4 行 630-665）：请求 Cookie 头
// 解出 al_login_state 后经 dto 转 service 入参；信封原样返回（业务失败也
// HTTP 200）；state 校验通过 / 失败的删 Cookie 与浏览器终点的 al_session
// 下发共用 CallInfo 写头。
func (h *Handler) LoginOauth(ctx context.Context, req *connect.Request[ssov1.LoginOauthRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	if h.thirdparty == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errThirdpartyNotConfigured)
	}
	in := dto.LoginOauth(req.Msg)
	in.StateCookie = loginStateCookie(req)
	out := h.thirdparty.LoginOauth(ctx, in)
	// 扫码 + 已启用 MFA：小程序端返回 mfa_required 时经统一写票 service
	// 写票（写入状态由该 service 按目标用户的二次验证启用状态自行判定，
	// §2.8 行 884、§13.2 行 1680），PC 端轮询得 needs_step_up。目标 uid
	// 由小程序端信封携带的 loginToken 经写票 service 校验恢复；写入失败
	// 不改变本次响应，PC 端按票据过期兜底。
	if in.TicketID != "" && out.Envelope.GetStatus() == orchestrator.StatusMFARequired && h.loginTicket != nil {
		if _, err := h.loginTicket.WriteTicket(ctx, ticketsvc.WriteTicketInput{
			TicketID:   in.TicketID,
			LoginToken: out.Envelope.GetLoginToken(),
		}); err != nil {
			logx.Warn(ctx, "sso: write qrcode mfa pending failed", "ticket_id", in.TicketID, "error", err)
		}
	}
	if out.Cookie != nil {
		internalconnect.AddSessionCookie(ctx, out.Cookie)
	}
	// 浏览器（redirect）终点：session_token 经会话 Cookie 构造器下发
	// （与会话 Cookie 同款属性，Secure/SameSite 受 https_deployment 驱动，auto 信号
	// 经 ctx 取自 session 拦截器注入的 RequestSignal——§1.9 行 306-309 全部
	// 下发点逐请求判定）；api 通道（SessionInBody）已由 service
	// 写进信封。
	if out.SessionToken != "" && h.cookies != nil {
		internalconnect.AddSessionCookie(ctx, h.cookies.Set(out.SessionToken, session.RequestSignalFromContext(ctx)))
	}
	return connect.NewResponse(out.Envelope), nil
}

// loginStateCookie 从请求 Cookie 头解析 al_login_state（§2.7.4 redirect
// 通道校验源）；未携带返回空串。
func loginStateCookie(req *connect.Request[ssov1.LoginOauthRequest]) string {
	cookies, err := http.ParseCookie(req.Header().Get("Cookie"))
	if err != nil {
		return ""
	}
	for _, ck := range cookies {
		if ck.Name == thirdpartysvc.LoginStateCookieName {
			return ck.Value
		}
	}
	return ""
}

// mapThirdpartyError Authorize 的可判别哨兵错误 → Connect 错误体 +
// ErrorInfo（§1.5 行 197-210；code 取 §1.6 封闭集）。
func mapThirdpartyError(err error) error {
	switch {
	case errors.Is(err, thirdpartysvc.ErrThirdpartyUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, thirdpartysvc.ErrThirdpartyInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", "invalid_request", "invalid authorize request"))
	case errors.Is(err, thirdpartysvc.ErrThirdpartyProviderDisabled):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", "provider_disabled", "provider not available for signin"))
	default:
		return connect.NewError(connect.CodeInternal, internalconnect.InternalError(err))
	}
}

// —— 扫码三桩（接口文档 §2.8）——
// 请求绑定与信封 / TicketStatus 应答归本层，编排全部在 qrcodesvc.QRCode；
// 业务失败走可判别哨兵错误 → Connect 错误体 + ErrorInfo（CreateQrcode 是
// 普通 RPC；GetLoginTicket 的轮询结论走 HTTP 200 信封域，§1.3 / §1.6）。

// Qrcode 扫码拉码与轮询 service 窄接口（§20 依赖注入）：生产注入
// *qrcodesvc.QRCode，测试可传 fake；nil 时两个方法返回 unimplemented。
type Qrcode interface {
	CreateQrcode(ctx context.Context, in qrcodesvc.CreateQrcodeInput) (*qrcodesvc.CreateQrcodeOutput, error)
	GetLoginTicket(ctx context.Context, in qrcodesvc.GetLoginTicketInput) *qrcodesvc.GetLoginTicketOutput
}

// errQrcodeNotConfigured 未装配扫码 service（测试桩）。
var errQrcodeNotConfigured = errors.New("qrcode service not configured")

// errLoginTicketNotConfigured 未装配统一写票 service（测试桩）。
var errLoginTicketNotConfigured = errors.New("login ticket service not configured")

// CreateQrcode 拉取小程序码（接口文档 §2.8 行 702-719）：captcha 必检、
// 登录与绑定共用靠 scene 区分；响应 {ticket, ticketId, qrcodeMode,
// qrcodeUrl|qrcodeContent|qrcodeBase64, tipHtml, expiresIn}，三产出字段按
// qrcodeMode 只填其一（§2.8 字段填充矩阵）。业务失败 → Connect 错误体 +
// ErrorInfo。
func (h *Handler) CreateQrcode(ctx context.Context, req *connect.Request[ssov1.CreateQrcodeRequest]) (*connect.Response[ssov1.CreateQrcodeResponse], error) {
	if h.qrcode == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errQrcodeNotConfigured)
	}
	out, err := h.qrcode.CreateQrcode(ctx, dto.CreateQrcode(req.Msg))
	if err != nil {
		return nil, mapQrcodeError(err)
	}
	return connect.NewResponse(&ssov1.CreateQrcodeResponse{
		Ticket:        out.Ticket,
		TicketId:      out.TicketID,
		QrcodeMode:    out.QrcodeMode,
		QrcodeUrl:     out.QrcodeURL,
		QrcodeContent: out.QrcodeContent,
		QrcodeBase64:  out.QrcodeBase64,
		TipHtml:       out.TipHTML,
		ExpiresIn:     out.ExpiresIn,
	}), nil
}

// GetLoginTicket 查询 / 长轮询 / 完成登录（接口文档 §2.8 行 724-748）：
// 轮询结论走 HTTP 200 信封（顶层 status + ticket + 成功时 login 字段，
// §1.3 行 139-140）；命中建会话后的 session_token 经会话 Cookie 构造器
// Set-Cookie: al_session 下发（PC 浏览器轮询方，与 LoginOauth redirect
// 通道同一写出出口与属性）。
func (h *Handler) GetLoginTicket(ctx context.Context, req *connect.Request[ssov1.GetLoginTicketRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	if h.qrcode == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errQrcodeNotConfigured)
	}
	out := h.qrcode.GetLoginTicket(ctx, dto.GetLoginTicket(req.Msg))
	if out.SessionToken != "" && h.cookies != nil {
		internalconnect.AddSessionCookie(ctx, h.cookies.Set(out.SessionToken, session.RequestSignalFromContext(ctx)))
	}
	return connect.NewResponse(out.Envelope), nil
}

// ConfirmLoginTicket 已登录一端写入授权结果（接口文档 §2.8）：写点收敛到
// 统一写票 service，由该 service 按目标用户的二次验证启用状态自行判定写
// success / mfa_pending（§2.8、§11.6.5）；handler 只投影主体凭证，body
// session 与 Cookie al_session 并存以 body 为准（uid 一致性校验在 service），
// Cookie 侧 uid 经 session 拦截器解出注入 ctx。响应回显 {status, ticket_id}。
func (h *Handler) ConfirmLoginTicket(ctx context.Context, req *connect.Request[ssov1.ConfirmLoginTicketRequest]) (*connect.Response[ssov1.TicketStatus], error) {
	if h.loginTicket == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errLoginTicketNotConfigured)
	}
	uid, _ := session.UIDFromContext(ctx)
	st, err := h.loginTicket.WriteTicket(ctx, dto.ConfirmLoginTicket(req.Msg, uid))
	if err != nil {
		return nil, mapQrcodeError(err)
	}
	return connect.NewResponse(st), nil
}

// withQrcodeCaptchaConfig 把 service 透出的、与 gate 判定同源的当前生效配置
// 并列进 captcha 失败错误体 details（与登录/注册/重置域 encodeCaptchaFailure
// 同一结构：ErrorInfo + CaptchaConfig）。配置仅随哨兵错误载荷透传，本层不
// 重新读取、不另造第二配置源（§9.1 同源）。
func withQrcodeCaptchaConfig(err error, coded *connect.Error) *connect.Error {
	var f *qrcodesvc.QrcodeCaptchaFailure
	if errors.As(err, &f) {
		return internalconnect.WithCaptchaConfig(coded, &commonv1.CaptchaConfig{
			ProviderKey: f.Config.ProviderKey,
			Type:        f.Config.Type,
			SiteKey:     f.Config.SiteKey,
		})
	}
	return coded
}

// mapQrcodeError 扫码域哨兵错误 → Connect 错误体 + ErrorInfo（§1.5 行
// 197-210；code 取 §1.6 封闭集，人机校验两码一律引用 captcha 包常量）。
// scene 校验统一返回票据失效错误（ErrQrcodeTicketInvalid）。
func mapQrcodeError(err error) error {
	switch {
	case errors.Is(err, ticketsvc.ErrQrcodeUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, qrcodesvc.ErrQrcodeCaptchaRequired):
		coded := internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", captcha.StatusRequired, "captcha required for qrcode"))
		return withQrcodeCaptchaConfig(err, coded)
	case errors.Is(err, qrcodesvc.ErrQrcodeCaptchaInvalid):
		coded := internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", captcha.StatusInvalid, "captcha invalid or used"))
		return withQrcodeCaptchaConfig(err, coded)
	case errors.Is(err, ticketsvc.ErrQrcodeInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", "invalid_request", "invalid qrcode request"))
	case errors.Is(err, qrcodesvc.ErrQrcodeProviderDisabled):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", "provider_disabled", "provider not available for qrcode"))
	case errors.Is(err, ticketsvc.ErrQrcodeTicketInvalid):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", "token_invalid", "qrcode ticket invalid"))
	default:
		return connect.NewError(connect.CodeInternal, internalconnect.InternalError(err))
	}
}
