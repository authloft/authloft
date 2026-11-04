// engine.go 是登录单引擎（docs/后端架构.md §7.2-§7.4 行 974-1013、
// docs/接口文档.md §2.2 行 414-437）。按固定六步推进：
// 解析 login_token → method/usage/step → 二次因子前置校验 → captcha gate →
// Start/Verify → 推进状态/重签 → 组装信封。
// 所有状态只写 login_token；落库/落 Redis 动作全部经注入的窄接口。
package orchestrator

import (
	"context"
	"errors"

	commonv1 "authloft/gen/go/api/common/v1"
	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
	"authloft/internal/captcha"
	"authloft/internal/factor"
	"authloft/internal/security"
)

// 登录流程域 status（docs/接口文档.md §1.6 行 228-273 的封闭集合子集）。
const (
	StatusNext            = "next"
	StatusSuccess         = "success"
	StatusMFARequired     = "mfa_required"
	StatusBindingRequired = "binding_required"
	StatusTokenInvalid    = "token_invalid"
	StatusTokenExpired    = "token_expired"
	StatusStepInvalid     = "step_invalid"
	StatusMethodDisabled  = "method_disabled"
	StatusSignupDisabled  = "signup_disabled"
	StatusResetDisabled   = "reset_disabled"
	StatusInvalidRequest  = "invalid_request"
	StatusFailed          = "failed"
)

const (
	endpointLogin    = "/api.sso.v1.SsoService/LoginDefault"
	endpointRegister = "/api.sso.v1.SsoService/Register"
	endpointReset    = "/api.sso.v1.SsoService/ResetPassword"
	challengeNonce   = 16
)

// PasswordFailures 读取同账号当日密码失败次数（触发阈值在 Gate 内按 settings 判定）。
type PasswordFailures interface {
	Count(ctx context.Context, userRef string) (int64, error)
}

// FactorDeps 是因子执行所需的注入依赖（不含任何存储句柄）。
type FactorDeps struct {
	CaptchaVerifier factor.CaptchaVerifier
	Limiter         factor.Limiter
	Users           factor.UserRepo
	Credentials     factor.CredentialRepo
}

// Request 是引擎单次调用入参。LoginToken 为空表示流程首步。
type Request struct {
	LoginToken string
	Method     string
	Step       string
	Payload    *factor.Payload
	Captcha    *factor.CaptchaInput
	OIDC       *token.Oidc
	// SessionInBody 对应无 Cookie 场景（小程序）：success 时返回 session_token（§2.7.4）。
	SessionInBody bool
}

// EngineDeps 构造引擎所需依赖。
type EngineDeps struct {
	State      *State
	Dispatcher *Dispatcher
	Gate       *captcha.Gate
	MFA        *MFABuilder
	Terminal   *Terminal
	Failures   PasswordFailures
	Factor     FactorDeps
	NewTID     func() (string, error)
}

// Engine 单引擎。
type Engine struct {
	state      *State
	dispatcher *Dispatcher
	gate       *captcha.Gate
	mfa        *MFABuilder
	terminal   *Terminal
	failures   PasswordFailures
	repo       FactorDeps
	newTID     func() (string, error)
}

// NewEngine 注入依赖；NewTID 为空时使用随机 UUID。
func NewEngine(d EngineDeps) *Engine {
	e := &Engine{
		state:      d.State,
		dispatcher: d.Dispatcher,
		gate:       d.Gate,
		mfa:        d.MFA,
		terminal:   d.Terminal,
		failures:   d.Failures,
		repo:       d.Factor,
		newTID:     d.NewTID,
	}
	if e.newTID == nil {
		e.newTID = func() (string, error) { return security.RandomString(32) }
	}
	return e
}

// Submit 推进一次登录请求。业务失败一律以信封 status 表达（§2.2 行 430-437），
// 未知异常在登录流程域映射为 failed + 兜底文案，不向 handler 抛错误。
func (e *Engine) Submit(ctx context.Context, flow string, req Request) *ssov1.LoginFlowResponse {
	p, status := e.loadPayload(flow, &req)
	if status != "" {
		return &ssov1.LoginFlowResponse{Status: status}
	}

	d, status := e.dispatcher.Resolve(ctx, flow, p, req.Method, req.Step)
	if status != "" {
		return &ssov1.LoginFlowResponse{Status: status}
	}
	p.Factor = string(d.Kind)

	// challenge 步与密码登录统一过 captcha gate（§2.2 第 4 步、§2.5）。
	outcome, err := e.evaluateCaptcha(ctx, d, req)
	if err != nil {
		return failed()
	}
	if outcome.Status != "" {
		return &ssov1.LoginFlowResponse{Status: outcome.Status, Captcha: captchaProto(outcome.Config)}
	}

	fctx := &factor.FactorContext{
		Context:         ctx,
		LoginToken:      req.LoginToken,
		Payload:         req.Payload,
		Captcha:         req.Captcha,
		CaptchaVerifier: e.repo.CaptchaVerifier,
		Limiter:         e.repo.Limiter,
		Users:           e.repo.Users,
		Credentials:     e.repo.Credentials,
	}
	if req.LoginToken != "" {
		fctx.Login = p
	}

	if req.Step == "challenge" {
		return e.start(ctx, flow, req, p, d, fctx)
	}
	return e.verify(ctx, flow, req, p, d, fctx)
}

// loadPayload 对应 §7.2 第 1 步：首次请求建状态，否则解析并校验 flow。
// 带 login_token 时 method 可省略，回退 login_token.factor（§2.2 行 421）。
func (e *Engine) loadPayload(flow string, req *Request) (*token.LoginTokenPayload, string) {
	if flow != "login" && flow != "register" && flow != "reset" {
		return nil, StatusInvalidRequest
	}
	if e.state == nil || e.dispatcher == nil {
		return nil, StatusFailed
	}
	if req.LoginToken != "" {
		p, err := e.state.Parse(req.LoginToken)
		if err != nil {
			if errors.Is(err, ErrTokenExpired) {
				return nil, StatusTokenExpired
			}
			return nil, StatusTokenInvalid
		}
		if !flowAccepts(flow, p.GetFlow()) {
			return nil, StatusTokenInvalid
		}
		if req.Method == "" {
			req.Method = p.GetFactor()
		}
		if req.Method == "" {
			return nil, StatusInvalidRequest
		}
		return p, ""
	}
	if req.Method == "" {
		return nil, StatusInvalidRequest
	}
	tid, err := e.newTID()
	if err != nil {
		return nil, StatusFailed
	}
	return &token.LoginTokenPayload{Tid: tid, Flow: flow, Oidc: req.OIDC}, ""
}

// flowAccepts register 接受 login/register 两个 flow（§7.4 行 1006-1013）；
// 其余端点只接受自己的 flow。
func flowAccepts(endpointFlow, payloadFlow string) bool {
	switch endpointFlow {
	case "login":
		return payloadFlow == "login"
	case "register":
		return payloadFlow == "login" || payloadFlow == "register"
	case "reset":
		return payloadFlow == "reset"
	default:
		return false
	}
}

// evaluateCaptcha 在 Start 之前完成拦截（§2.2 第 4 步）。
// WebAuthn 取 options（challenge 步）不需要人机校验（§2.5 行 526）。
func (e *Engine) evaluateCaptcha(ctx context.Context, d *Dispatched, req Request) (captcha.Outcome, error) {
	if e.gate == nil {
		return captcha.Outcome{}, nil
	}
	if d.Kind == factor.FactorWebAuthn && req.Step == "challenge" {
		return captcha.Outcome{}, nil
	}
	r := captcha.Request{
		Challenge: req.Step == "challenge",
		Password:  d.Kind == factor.FactorPassword && req.Step == "verify",
	}
	if req.Captcha != nil {
		r.Submission = &captcha.Submission{
			ProviderKey: req.Captcha.ProviderKey,
			Token:       req.Captcha.Token,
			ID:          req.Captcha.ID,
			Answer:      req.Captcha.Answer,
		}
	}
	if r.Password && e.failures != nil {
		userRef := ""
		if req.Payload != nil {
			userRef = req.Payload.Username
		}
		if userRef != "" {
			n, err := e.failures.Count(ctx, userRef)
			if err != nil {
				return captcha.Outcome{}, err
			}
			r.FailedAttempts = n
		}
	}
	return e.gate.Evaluate(ctx, r)
}

// start 对应 §2.2 第 5 步的 challenge 分支：执行因子 Start，重签 login_token，
// 返回 status=next。
func (e *Engine) start(ctx context.Context, flow string, req Request, p *token.LoginTokenPayload, d *Dispatched, fctx *factor.FactorContext) *ssov1.LoginFlowResponse {
	step, err := d.Factor.Start(fctx)
	if err != nil {
		return failed()
	}
	// 因子可直接以 status 终止（如 user_not_found），此时不签发 login_token。
	if step != nil && step.Status != "" {
		return &ssov1.LoginFlowResponse{Status: step.Status}
	}
	nonce, err := security.RandomString(challengeNonce)
	if err != nil {
		return failed()
	}
	purpose := flow
	target := targetOf(req.Payload)
	if d.Usage == factor.UsageSecondary {
		purpose = "mfa"
		// 二次因子目标只能取自 uid 绑定资料，由因子自行读取；这里不落请求参数。
		target = ""
	}
	p.Ch = &token.Challenge{Purpose: purpose, Target: target, Nonce: nonce}

	tok, err := e.state.Issue(p)
	if err != nil {
		return failed()
	}
	return &ssov1.LoginFlowResponse{
		Status:     StatusNext,
		LoginToken: tok,
		NextStep:   nextStep(flow, d.Kind, step),
	}
}

// verify 对应 §2.2 第 5-6 步：执行因子 Verify，推进 passed/uid/amr，
// 二次因子通过或主因子且未启用 MFA 时进入终点。
func (e *Engine) verify(ctx context.Context, flow string, req Request, p *token.LoginTokenPayload, d *Dispatched, fctx *factor.FactorContext) *ssov1.LoginFlowResponse {
	res, err := d.Factor.Verify(fctx)
	if err != nil {
		return failed()
	}
	if !res.Passed {
		status := res.Status
		if status == "" {
			status = StatusFailed
		}
		return &ssov1.LoginFlowResponse{
			Status: status,
			Error:  verifyError(res),
		}
	}

	if res.UID != 0 {
		p.Uid = res.UID
	}
	p.Passed = appendOnce(p.Passed, string(d.Kind))
	p.Amr = appendOnce(p.Amr, string(d.Kind))
	p.Ch = nil

	if d.Usage == factor.UsagePrimary {
		if p.Uid == 0 {
			return failed()
		}
		if e.mfa != nil {
			mfa, required, err := e.mfa.Build(ctx, p.Uid)
			if err != nil {
				return failed()
			}
			if required {
				tok, err := e.state.Issue(p)
				if err != nil {
					return failed()
				}
				return &ssov1.LoginFlowResponse{
					Status:     StatusMFARequired,
					LoginToken: tok,
					Mfa:        mfa,
				}
			}
		}
	}

	if e.terminal == nil {
		return failed()
	}
	success, err := e.terminal.Complete(ctx, p)
	if err != nil {
		return failed()
	}
	resp := &ssov1.LoginFlowResponse{
		Status:        StatusSuccess,
		SessionId:     success.SessionID,
		SyncCookieUrl: success.SyncCookieURL,
		RedirectTo:    success.RedirectTo,
		UserId:        success.UserID,
	}
	if req.SessionInBody {
		resp.SessionToken = success.SessionToken
	}
	return resp
}

// nextStep 组装 status=next 信封；endpoint 按 flow 固定（§7.3）。
func nextStep(flow string, kind factor.FactorKind, step *factor.StepResult) *ssov1.NextStep {
	ns := &ssov1.NextStep{Method: string(kind)}
	if step != nil {
		ns.Kind = string(step.Kind)
		ns.RetryAfter = step.RetryAfter
		ns.ExpiresIn = step.ExpiresIn
		ns.ChallengeData = step.ChallengeData
		ns.Fields = fieldsProto(step.Fields)
	}
	switch flow {
	case "register":
		ns.Endpoint = endpointRegister
	case "reset":
		ns.Endpoint = endpointReset
	default:
		ns.Endpoint = endpointLogin
	}
	return ns
}

func fieldsProto(in []factor.Field) []*ssov1.Field {
	if len(in) == 0 {
		return nil
	}
	out := make([]*ssov1.Field, 0, len(in))
	for _, f := range in {
		out = append(out, &ssov1.Field{
			Name:        f.Name,
			Label:       f.Label,
			Type:        f.Type,
			Required:    f.Required,
			Length:      f.Length,
			MaxAttempts: f.MaxAttempts,
		})
	}
	return out
}

func captchaProto(c captcha.Config) *commonv1.CaptchaConfig {
	return &commonv1.CaptchaConfig{ProviderKey: c.ProviderKey, Type: c.Type, SiteKey: c.SiteKey}
}

func verifyError(res *factor.VerifyResult) *ssov1.SsoError {
	out := &ssov1.SsoError{}
	if res == nil {
		return out
	}
	if res.RetryAfter > 0 {
		v := res.RetryAfter
		out.RetryAfter = &v
	}
	if res.AttemptsLeft > 0 {
		v := res.AttemptsLeft
		out.AttemptsLeft = &v
	}
	return out
}

func failed() *ssov1.LoginFlowResponse {
	return &ssov1.LoginFlowResponse{Status: StatusFailed}
}

func targetOf(p *factor.Payload) string {
	if p == nil {
		return ""
	}
	switch {
	case p.Phone != "":
		return p.Phone
	case p.Email != "":
		return p.Email
	default:
		return p.Username
	}
}

func appendOnce(list []string, v string) []string {
	for _, item := range list {
		if item == v {
			return list
		}
	}
	return append(list, v)
}
