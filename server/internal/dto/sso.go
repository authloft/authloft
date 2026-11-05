// Package dto 负责跨端报文与内部调用参数之间的装配（docs/后端架构.md §3.5
// 行 333-348）：报文类型全部来自 proto/api/** 生成物，本层只做转换与裁剪，
// 不定义新的跨端结构。
package dto

import (
	"google.golang.org/protobuf/types/known/structpb"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
	internalcaptcha "authloft/internal/captcha"
	"authloft/internal/factor"
	"authloft/internal/service"
	"authloft/internal/service/orchestrator"
)

// LoginDefault 把 SsoService/LoginDefault 请求消息转换为编排引擎入参
// （docs/接口文档.md §2.2 行 419-426）：登录流程的状态机由 orchestrator
// 承担，handler 只经本函数做一次字段映射。
func LoginDefault(req *ssov1.LoginDefaultRequest) orchestrator.Request {
	if req == nil {
		return orchestrator.Request{}
	}
	p := req.GetPayload()
	return orchestrator.Request{
		LoginToken: req.GetLoginToken(),
		Method:     req.GetMethod(),
		Step:       req.GetStep(),
		Payload:    payload(p),
		Captcha:    captcha(p.GetCaptcha()),
		OIDC:       oidc(req.GetOidc()),
	}
}

// Register 把 SsoService/Register 请求消息转换为引擎入参（docs/接口文档.md
// §2.3 行 440-454：顶层与 §2.2 同构，仅 flow=register）。RegisterPayload 与
// LoginPayload 字段部分重合（无 credential），映射口径同 payload()。
func Register(req *ssov1.RegisterRequest) orchestrator.Request {
	if req == nil {
		return orchestrator.Request{}
	}
	p := req.GetPayload()
	return orchestrator.Request{
		LoginToken: req.GetLoginToken(),
		Method:     req.GetMethod(),
		Step:       req.GetStep(),
		Payload:    registerPayload(p),
		Captcha:    captcha(p.GetCaptcha()),
		OIDC:       oidc(req.GetOidc()),
	}
}

// registerPayload 映射 §2.3 行 446-450 的 RegisterPayload 字段
//（email / phone / captcha / code / username / password）。
func registerPayload(p *ssov1.RegisterPayload) *factor.Payload {
	if p == nil {
		return nil
	}
	return &factor.Payload{
		Username: p.GetUsername(),
		Password: p.GetPassword(),
		Phone:    p.GetPhone(),
		Email:    p.GetEmail(),
		Code:     p.GetCode(),
	}
}

// Reset 把 SsoService/ResetPassword 请求消息转换为引擎入参（docs/接口文档.md
// §2.4 行 458-470：顶层与 §2.2 同构，flow=reset）。ResetPayload 无
// username / credential，另有 set_password 的 password。
func Reset(req *ssov1.ResetPasswordRequest) orchestrator.Request {
	if req == nil {
		return orchestrator.Request{}
	}
	p := req.GetPayload()
	return orchestrator.Request{
		LoginToken: req.GetLoginToken(),
		Method:     req.GetMethod(),
		Step:       req.GetStep(),
		Payload:    resetPayload(p),
		Captcha:    captcha(p.GetCaptcha()),
		OIDC:       oidc(req.GetOidc()),
	}
}

// resetPayload 映射 §2.4 行 464-466 的 ResetPayload 字段
//（email / phone / captcha / code / password）。
func resetPayload(p *ssov1.ResetPayload) *factor.Payload {
	if p == nil {
		return nil
	}
	return &factor.Payload{
		Password: p.GetPassword(),
		Phone:    p.GetPhone(),
		Email:    p.GetEmail(),
		Code:     p.GetCode(),
	}
}

// LoginOauth 把 SsoService/LoginOauth 请求消息转换为三方登录 service 入参
// （docs/接口文档.md §2.7.4 行 630-643）：字段名与请求消息 snake_case 一一
// 对应；oidc 复用 LoginDefault 的映射（§2.7.4 行 642：localStorage 读回后
// 回传，服务端据此写入 login_token.oidc）。StateCookie 由 handler 从请求
// Cookie 头解析后填入（dto 不读 HTTP 头）。
func LoginOauth(req *ssov1.LoginOauthRequest) service.OauthInput {
	if req == nil {
		return service.OauthInput{}
	}
	return service.OauthInput{
		ProviderKey: req.GetProviderKey(),
		Code:        req.GetCode(),
		State:       req.GetState(),
		Stage:       req.GetStage(),
		TicketID:    req.GetTicketId(),
		LoginToken:  req.GetLoginToken(),
		OIDC:        oidc(req.GetOidc()),
	}
}

// CreateQrcode 把 SsoService/CreateQrcode 请求消息转换为扫码 service 入参
// （docs/接口文档.md §2.8 行 707-717）：provider_key / scene 直映；captcha
// 转 captcha.Submission（§2.5 统一提交格式，与引擎侧 CaptchaPayload 字段
// 同名）。UID 由 handler 从会话 ctx 取（bind 场景），dto 不读 HTTP 层。
func CreateQrcode(req *ssov1.CreateQrcodeRequest) service.CreateQrcodeInput {
	if req == nil {
		return service.CreateQrcodeInput{}
	}
	return service.CreateQrcodeInput{
		ProviderKey: req.GetProviderKey(),
		Scene:       req.GetScene(),
		Captcha:     captchaSubmission(req.GetCaptcha()),
	}
}

// GetLoginTicket 把 SsoService/GetLoginTicket 请求消息转换为扫码 service
// 入参（docs/接口文档.md §2.8 行 724-729）：ticket / poll 直映。
func GetLoginTicket(req *ssov1.GetLoginTicketRequest) service.GetLoginTicketInput {
	if req == nil {
		return service.GetLoginTicketInput{}
	}
	return service.GetLoginTicketInput{
		Ticket: req.GetTicket(),
		Poll:   req.GetPoll(),
	}
}

// ConfirmLoginTicket 把 SsoService/ConfirmLoginTicket 请求消息转换为扫码
// service 入参（docs/接口文档.md §2.8 行 750-757）：ticket_id / session 直映；
// sessionUID 为会话拦截器解出的 Cookie 侧 uid（handler 注入）。
func ConfirmLoginTicket(req *ssov1.ConfirmLoginTicketRequest, sessionUID int64) service.ConfirmLoginTicketInput {
	if req == nil {
		return service.ConfirmLoginTicketInput{}
	}
	return service.ConfirmLoginTicketInput{
		TicketID:   req.GetTicketId(),
		Session:    req.GetSession(),
		SessionUID: sessionUID,
	}
}

// captchaSubmission CaptchaPayload → captcha.Submission（§2.5 行 478-486
// 统一提交格式；与引擎侧 captcha() 同名字段直映，两套消费方各自的窄类型）。
func captchaSubmission(c *ssov1.CaptchaPayload) *internalcaptcha.Submission {
	if c == nil {
		return nil
	}
	return &internalcaptcha.Submission{
		ProviderKey: c.GetProviderKey(),
		Token:       c.GetToken(),
		ID:          c.GetId(),
		Answer:      c.GetAnswer(),
	}
}

// payload 映射 §2.6 各因子 payload 字段；无 payload 时返回 nil，交由引擎按
// method / step 判定缺失。
func payload(p *ssov1.LoginPayload) *factor.Payload {
	if p == nil {
		return nil
	}
	return &factor.Payload{
		Username:   p.GetUsername(),
		Password:   p.GetPassword(),
		Phone:      p.GetPhone(),
		Email:      p.GetEmail(),
		Code:       p.GetCode(),
		Credential: p.GetCredential(),
	}
}

// captcha 映射 §2.5 的统一提交格式；未提交时返回 nil。
func captcha(c *ssov1.CaptchaPayload) *factor.CaptchaInput {
	if c == nil {
		return nil
	}
	return &factor.CaptchaInput{
		ProviderKey: c.GetProviderKey(),
		Token:       c.GetToken(),
		ID:          c.GetId(),
		Answer:      c.GetAnswer(),
	}
}

// oidc 把 /auth/authorize 原样透传的 OIDC 参数（§2.2 行 426、§4.2 行
// 1059-1068）映射为 login_token.oidc 载荷（token.Oidc）。参数名为原始
// query 的 snake_case；Struct 为空或未包含任何已知参数时返回 nil，避免
// 终点以空 client_id / redirect_uri 签发授权码。
func oidc(s *structpb.Struct) *token.Oidc {
	if s == nil || len(s.GetFields()) == 0 {
		return nil
	}
	f := s.GetFields()
	o := &token.Oidc{
		ClientId:            structString(f, "client_id"),
		RedirectUri:         structString(f, "redirect_uri"),
		Scope:               structString(f, "scope"),
		Nonce:               structString(f, "nonce"),
		CodeChallenge:       structString(f, "code_challenge"),
		CodeChallengeMethod: structString(f, "code_challenge_method"),
		State:               structString(f, "state"),
	}
	if o.ClientId == "" && o.RedirectUri == "" && o.Scope == "" && o.Nonce == "" &&
		o.CodeChallenge == "" && o.CodeChallengeMethod == "" && o.State == "" {
		return nil
	}
	return o
}

// structString 读取 Struct 字符串字段；缺失或非字符串一律空串（OIDC 参数
// 均为字符串，非字符串值不参与判定）。
func structString(fields map[string]*structpb.Value, key string) string {
	v, ok := fields[key]
	if !ok || v == nil {
		return ""
	}
	return v.GetStringValue()
}
