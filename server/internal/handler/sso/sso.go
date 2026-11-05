// Package sso 实现 api.sso.v1.SsoService 的 Connect handler（docs/后端架构.md
// §3.4 行 316）：handler 只做请求绑定与组装，登录流程编排全部在
// orchestrator，图形码生成委托 internal/captcha。已落地 LoginDefault、
// Register、ResetPassword、CreateCaptchaImage（接口文档 §2.2-§2.5）、
// Authorize、LoginOauth（§2.7）与扫码三桩 CreateQrcode /
// GetLoginTicket / ConfirmLoginTicket（§2.8——编排全部在
// service.QRCode）。
package sso

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/api/sso/v1/ssov1connect"
	"authloft/internal/captcha"
	internalconnect "authloft/internal/connect"
	"authloft/internal/dto"
	"authloft/internal/service"
	"authloft/internal/service/orchestrator"
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
	// qrcode 扫码三桩 service；nil（测试 / 未装配）时三个扫码
	// 方法返回 unimplemented。
	qrcode Qrcode
}

// New 构造 SsoService handler。images 为自绘图形码实现
// （CreateCaptchaImage 用，装配层注入 captcha.NewImageCaptcha）；cookies 为
// 会话 Cookie 属性构造器（登录终点建会话后经 Set-Cookie 下发
// al_session，复用 session 包同一构造器）；thirdparty 为三方登录通道
// service（oauth.go）；qrcode 为扫码三桩 service；测试 / 未装配时
// 均传 nil（不下发 / unimplemented）。
func New(engine Engine, images *captcha.ImageCaptcha, cookies *session.Cookie, thirdparty Thirdparty, qrcode Qrcode) *Handler {
	return &Handler{engine: engine, images: images, cookies: cookies, thirdparty: thirdparty, qrcode: qrcode}
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
// 转换为引擎入参，直接返回登录流程信封（§1.3）；业务失败也走 HTTP 200 +
// 信封 status，不经 Connect 错误体。
func (h *Handler) LoginDefault(ctx context.Context, req *connect.Request[ssov1.LoginDefaultRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	resp := h.engine.Submit(h.withSessionTokenSink(ctx), loginFlow, dto.LoginDefault(req.Msg))
	return connect.NewResponse(resp), nil
}

// Register 注册端点（接口文档 §2.3 行 441-455）：与 LoginDefault 同构，
// 仅 flow=register（引擎内走 challenge → verify → set_password）。
func (h *Handler) Register(ctx context.Context, req *connect.Request[ssov1.RegisterRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	resp := h.engine.Submit(h.withSessionTokenSink(ctx), registerFlow, dto.Register(req.Msg))
	return connect.NewResponse(resp), nil
}

// ResetPassword 重置密码端点（接口文档 §2.4 行 459-471）：与 LoginDefault
// 同构，仅 flow=reset。
func (h *Handler) ResetPassword(ctx context.Context, req *connect.Request[ssov1.ResetPasswordRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	resp := h.engine.Submit(h.withSessionTokenSink(ctx), resetFlow, dto.Reset(req.Msg))
	return connect.NewResponse(resp), nil
}

// —— 三方登录通道（接口文档 §2.7.2 / §2.7.4）——
// 请求绑定、Cookie 头解析与 Set-Cookie 下发归本层，三方通道编排全部在
// service.Thirdparty。LoginOauth 的业务失败走登录流程信封 status（HTTP
// 200，§1.3 / §1.6）；Authorize 是普通 RPC，可判别哨兵错误转 Connect
// 错误体 + ErrorInfo。

// Thirdparty 三方登录通道 service 窄接口（§20 依赖注入）：生产注入
// *service.Thirdparty，测试可传 fake。
type Thirdparty interface {
	Authorize(ctx context.Context, in service.AuthorizeInput) (*service.AuthorizeOutput, error)
	LoginOauth(ctx context.Context, in service.OauthInput) *service.OauthOutput
}

// errThirdpartyNotConfigured 未装配三方 service（测试桩）。
var errThirdpartyNotConfigured = errors.New("thirdparty service not configured")

// errThirdpartyInternal 未知异常的固定文案（§1.5：不暴露内部信息）。
var errThirdpartyInternal = errors.New("internal error")

// Authorize 取第三方授权 URL（接口文档 §2.7.2 行 593-613）：scene=bind 时
// 从 ctx 取会话 uid（session 拦截器注入；无会话由 service 判 401）；
// 成功时经 CallInfo 写点下发 Set-Cookie: al_login_state（与 session
// Cookie 同一写出出口，interceptors.go 行 141「禁止另造第二套」）。
func (h *Handler) Authorize(ctx context.Context, req *connect.Request[ssov1.AuthorizeRequest]) (*connect.Response[ssov1.AuthorizeResponse], error) {
	if h.thirdparty == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errThirdpartyNotConfigured)
	}
	uid, _ := session.UIDFromContext(ctx)
	out, err := h.thirdparty.Authorize(ctx, service.AuthorizeInput{
		Provider: req.Msg.GetProvider(),
		Scene:    req.Msg.GetScene(),
		UID:      uid,
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
		if ck.Name == service.LoginStateCookieName {
			return ck.Value
		}
	}
	return ""
}

// mapThirdpartyError Authorize 的可判别哨兵错误 → Connect 错误体 +
// ErrorInfo（§1.5 行 197-210；code 取 §1.6 封闭集）。
func mapThirdpartyError(err error) error {
	switch {
	case errors.Is(err, service.ErrThirdpartyUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, service.ErrThirdpartyInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", "invalid_request", "invalid authorize request"))
	case errors.Is(err, service.ErrThirdpartyProviderDisabled):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", "provider_disabled", "provider not available for signin"))
	default:
		return connect.NewError(connect.CodeInternal, errThirdpartyInternal)
	}
}

// —— 扫码三桩（接口文档 §2.8）——
// 请求绑定与信封 / TicketStatus 应答归本层，编排全部在 service.QRCode；
// 业务失败走可判别哨兵错误 → Connect 错误体 + ErrorInfo（CreateQrcode 是
// 普通 RPC；GetLoginTicket 的轮询结论走 HTTP 200 信封域，§1.3 / §1.6）。

// Qrcode 扫码三桩 service 窄接口（§20 依赖注入）：生产注入 *service.QRCode，
// 测试可传 fake；nil 时三个方法返回 unimplemented。
type Qrcode interface {
	CreateQrcode(ctx context.Context, in service.CreateQrcodeInput) (*service.CreateQrcodeOutput, error)
	GetLoginTicket(ctx context.Context, in service.GetLoginTicketInput) *service.GetLoginTicketOutput
	ConfirmLoginTicket(ctx context.Context, in service.ConfirmLoginTicketInput) (*ssov1.TicketStatus, error)
}

// errQrcodeNotConfigured 未装配扫码 service（测试桩）。
var errQrcodeNotConfigured = errors.New("qrcode service not configured")

// CreateQrcode 拉取小程序码（接口文档 §2.8 行 702-719）：captcha 必检、
// 登录与绑定共用靠 scene 区分；响应 {ticket, ticketId, qrcodeUrl,
// expiresIn}。业务失败 → Connect 错误体 + ErrorInfo。
func (h *Handler) CreateQrcode(ctx context.Context, req *connect.Request[ssov1.CreateQrcodeRequest]) (*connect.Response[ssov1.CreateQrcodeResponse], error) {
	if h.qrcode == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errQrcodeNotConfigured)
	}
	out, err := h.qrcode.CreateQrcode(ctx, dto.CreateQrcode(req.Msg))
	if err != nil {
		return nil, mapQrcodeError(err)
	}
	return connect.NewResponse(&ssov1.CreateQrcodeResponse{
		Ticket:    out.Ticket,
		TicketId:  out.TicketID,
		QrcodeUrl: out.QrcodeURL,
		ExpiresIn: out.ExpiresIn,
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

// ConfirmLoginTicket 已登录一端写入授权结果（接口文档 §2.8 行 750-759）：
// body session 与 Cookie al_session 并存以 body 为准（uid 一致性校验在
// service）；Cookie 侧 uid 经 session 拦截器解出注入 ctx（无有效 Cookie
// 会话为 0，service 判定）。响应回显 {status, ticket_id}。
func (h *Handler) ConfirmLoginTicket(ctx context.Context, req *connect.Request[ssov1.ConfirmLoginTicketRequest]) (*connect.Response[ssov1.TicketStatus], error) {
	if h.qrcode == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errQrcodeNotConfigured)
	}
	uid, _ := session.UIDFromContext(ctx)
	st, err := h.qrcode.ConfirmLoginTicket(ctx, dto.ConfirmLoginTicket(req.Msg, uid))
	if err != nil {
		return nil, mapQrcodeError(err)
	}
	return connect.NewResponse(st), nil
}

// mapQrcodeError 扫码域哨兵错误 → Connect 错误体 + ErrorInfo（§1.5 行
// 197-210；code 取 §1.6 封闭集——captcha_required / captcha_invalid 均为
// 成员）。
func mapQrcodeError(err error) error {
	switch {
	case errors.Is(err, service.ErrQrcodeUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, service.ErrQrcodeCaptchaRequired):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", "captcha_required", "captcha required for qrcode"))
	case errors.Is(err, service.ErrQrcodeCaptchaInvalid):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", "captcha_invalid", "captcha invalid or used"))
	case errors.Is(err, service.ErrQrcodeInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", "invalid_request", "invalid qrcode request"))
	case errors.Is(err, service.ErrQrcodeProviderDisabled):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("sso", "provider_disabled", "provider not available for qrcode"))
	default:
		return connect.NewError(connect.CodeInternal, errThirdpartyInternal)
	}
}
