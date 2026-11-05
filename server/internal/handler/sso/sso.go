// Package sso 实现 api.sso.v1.SsoService 的 Connect handler（docs/后端架构.md
// §3.4 行 316）：handler 只做请求绑定与组装，登录流程编排全部在
// orchestrator，图形码生成委托 internal/captcha。已落地 LoginDefault、
// Register、ResetPassword 与 CreateCaptchaImage（接口文档 §2.2-§2.5），
// 其余 5 个方法由生成的 UnimplementedSsoServiceHandler 返回 unimplemented。
package sso

import (
	"context"

	"connectrpc.com/connect"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/api/sso/v1/ssov1connect"
	"authloft/internal/captcha"
	"authloft/internal/dto"
	"authloft/internal/service/orchestrator"
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
// 统一返回 Connect CodeUnimplemented（本实现未覆盖的 7 个方法）。
type Handler struct {
	ssov1connect.UnimplementedSsoServiceHandler
	engine Engine
	images *captcha.ImageCaptcha
}

// New 构造 SsoService handler。images 为自绘图形码实现
// （CreateCaptchaImage 用，装配层注入 captcha.NewImageCaptcha）。
func New(engine Engine, images *captcha.ImageCaptcha) *Handler {
	return &Handler{engine: engine, images: images}
}

// LoginDefault 统一提交端点（接口文档 §2.2 行 415-437）：把请求消息经 dto
// 转换为引擎入参，直接返回登录流程信封（§1.3）；业务失败也走 HTTP 200 +
// 信封 status，不经 Connect 错误体。
func (h *Handler) LoginDefault(ctx context.Context, req *connect.Request[ssov1.LoginDefaultRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	resp := h.engine.Submit(ctx, loginFlow, dto.LoginDefault(req.Msg))
	return connect.NewResponse(resp), nil
}

// Register 注册端点（接口文档 §2.3 行 441-455）：与 LoginDefault 同构，
// 仅 flow=register（引擎内走 challenge → verify → set_password）。
func (h *Handler) Register(ctx context.Context, req *connect.Request[ssov1.RegisterRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	resp := h.engine.Submit(ctx, registerFlow, dto.Register(req.Msg))
	return connect.NewResponse(resp), nil
}

// ResetPassword 重置密码端点（接口文档 §2.4 行 459-471）：与 LoginDefault
// 同构，仅 flow=reset。
func (h *Handler) ResetPassword(ctx context.Context, req *connect.Request[ssov1.ResetPasswordRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	resp := h.engine.Submit(ctx, resetFlow, dto.Reset(req.Msg))
	return connect.NewResponse(resp), nil
}
