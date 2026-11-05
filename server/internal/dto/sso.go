// Package dto 负责跨端报文与内部调用参数之间的装配（docs/后端架构.md §3.5
// 行 333-348）：报文类型全部来自 proto/api/** 生成物，本层只做转换与裁剪，
// 不定义新的跨端结构。
package dto

import (
	"google.golang.org/protobuf/types/known/structpb"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
	"authloft/internal/factor"
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
