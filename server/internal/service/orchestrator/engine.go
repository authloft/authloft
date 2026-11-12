// engine.go 是登录单引擎（docs/后端架构.md §7.2-§7.4 行 974-1013、
// docs/接口文档.md §2.2 行 414-437）。按固定六步推进：
// 解析 login_token → method/usage/step → 二次因子前置校验 → captcha gate →
// Start/Verify → 推进状态/重签 → 组装信封。
// 所有状态只写 login_token；落库/落 Redis 动作全部经注入的窄接口。
package orchestrator

import (
	"context"
	"errors"
	"strings"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
	"authloft/internal/captcha"
	"authloft/internal/factor"
	"authloft/internal/security"
	"authloft/internal/settings"

	"gorm.io/gorm"
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
	// set_password 步的字段级失败（§1.6 行 255-256，封闭集合成员）。
	StatusUsernameTaken = "username_taken"
	StatusTargetTaken   = "target_taken"
	StatusPasswordWeak  = "password_weak"
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

// UserRefResolver 由登录标识推导密码失败计数的 user_ref：生产装配
// 注入 factor/password 的共用实现——引擎读计数与因子写计数共用唯一定义
// （用户存在 → "{userID}"；不存在 → "{ip}|{sha256(identifier)}"，§8.1 行
// 1027）。未注入（nil）时跳过失败计数读取，渐进式保护第 1 级不触发。
type UserRefResolver interface {
	UserRef(ctx context.Context, identifier string) (string, error)
}

// FactorDeps 是因子执行所需的注入依赖（不含任何存储句柄）。
// captcha 由场景守卫在进入因子前判定（§9.3），不注入因子上下文。
type FactorDeps struct {
	Limiter     factor.Limiter
	Users       factor.UserRepo
	Credentials factor.CredentialRepo
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

// sessionTokenSinkKey 浏览器 Cookie 场景 session_token 写点的 ctx 注入键
// （私有类型，包外无法伪造同型键）。
type sessionTokenSinkKey struct{}

// WithSessionTokenSink 注入登录终点的 session_token 写点：引擎仅在
// status=success 终点建会话签发成功后以新令牌回调一次（失败态 / 中间态不
// 回调——零 Set-Cookie、信封零 session_token 由引擎侧天然成立）；与
// SessionInBody 互斥：SessionInBody=true（无 Cookie 场景，§1.3 行 135）时
// 令牌走信封 session_token 字段，写点不回调。落地方式归挂点方（sso handler
// 经 Set-Cookie: al_session 下发，§1.9 行 288）。
func WithSessionTokenSink(ctx context.Context, sink func(sessionToken string)) context.Context {
	return context.WithValue(ctx, sessionTokenSinkKey{}, sink)
}

// SessionTokenSinkFromContext 读取写点；未注入返回 false。
func SessionTokenSinkFromContext(ctx context.Context) (func(string), bool) {
	sink, ok := ctx.Value(sessionTokenSinkKey{}).(func(string))
	return sink, ok
}

// captchaFailureSinkKey 是人机校验失败写点的 ctx 注入键（与 session_token
// 写点同构，私有类型，包外无法伪造同型键）。
type captchaFailureSinkKey struct{}

// WithCaptchaFailureSink 注入人机校验失败写点：引擎在因子执行前判定失败时
// 以当前生效配置回调一次，供调用方按错误码与配置构造失败结果；放行时不回调。
func WithCaptchaFailureSink(ctx context.Context, sink func(*captcha.Failure)) context.Context {
	return context.WithValue(ctx, captchaFailureSinkKey{}, sink)
}

// CaptchaFailureSinkFromContext 读取写点；未注入返回 false。
func CaptchaFailureSinkFromContext(ctx context.Context) (func(*captcha.Failure), bool) {
	sink, ok := ctx.Value(captchaFailureSinkKey{}).(func(*captcha.Failure))
	return sink, ok
}

// EngineDeps 构造引擎所需依赖。
type EngineDeps struct {
	State      *State
	Dispatcher *Dispatcher
	Gate       *captcha.Gate
	Terminal   *Terminal
	Failures   PasswordFailures
	UserRef    UserRefResolver
	Factor     FactorDeps
	SetPass    *SetPassDeps
	NewTID     func() (string, error)
}

// Engine 单引擎。
type Engine struct {
	state      *State
	dispatcher *Dispatcher
	gate       *captcha.Gate
	terminal   *Terminal
	failures   PasswordFailures
	userRef    UserRefResolver
	repo       FactorDeps
	setpass    *SetPassDeps
	newTID     func() (string, error)
}

// NewEngine 注入依赖；NewTID 为空时使用随机 UUID。
func NewEngine(d EngineDeps) *Engine {
	e := &Engine{
		state:      d.State,
		dispatcher: d.Dispatcher,
		gate:       d.Gate,
		terminal:   d.Terminal,
		failures:   d.Failures,
		userRef:    d.UserRef,
		repo:       d.Factor,
		setpass:    d.SetPass,
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
	outcome, err := e.evaluateCaptcha(ctx, d, req, p)
	if err != nil {
		return failed()
	}
	if failure := captcha.FailureFrom(outcome); failure != nil {
		if sink, ok := CaptchaFailureSinkFromContext(ctx); ok {
			sink(failure)
		}
		// 失败不套登录信封：由调用方按错误码与配置构造失败结果（§1.5）。
		return failed()
	}

	fctx := &factor.FactorContext{
		Context:    ctx,
		LoginToken: req.LoginToken,
		// loadPayload 首步也会生成 tid / 选定 flow，Start 之前即可用
		// （主因子 challenge 需以 owner=tid、purpose=flow 写码，§10.1 行 1121）。
		Login:   p,
		Payload: req.Payload,
		Captcha: req.Captcha,
		// 验证内核调用边界（§3.8 / §6.3）：因子以 biz_purpose + subject +
		// challengeId 驱动，不感知业务信封；三元组取自 login_token 状态
		// （§10.1），与 start() 写入的 ch 同源。captcha 由场景守卫在进入
		// 因子前判定（§9.3），不再注入校验器到因子上下文。
		BizPurpose:  flowPurpose(flow, d.Usage),
		Subject:     p.GetTid(),
		ChallengeID: p.GetCh().GetNonce(),
		Limiter:     e.repo.Limiter,
		Users:       e.repo.Users,
		Credentials: e.repo.Credentials,
	}

	if req.Step == "challenge" {
		return e.start(ctx, flow, req, p, d, fctx)
	}
	if req.Step == stepSetPassword {
		return e.setPassword(ctx, flow, req, p, d)
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

// flowPurpose 登录过程态内的业务用途（§1.4 / §10.1）：主因子取 flow，
// 二次因子阶段取 mfa；与 start() 写 ch.purpose 同源，供因子上下文三元组使用。
func flowPurpose(flow string, usage factor.Usage) string {
	if usage == factor.UsageSecondary {
		return "mfa"
	}
	return flow
}

// evaluateCaptcha 在 Start 之前完成拦截（§2.2 第 4 步）。
// WebAuthn 取 options（challenge 步）不需要人机校验（§2.5 行 526）。
// 三方免密建号（tp 非空 + flow=login 的 set_password）同样不经
// captcha：该分支由 LoginOauth 已验证的三方身份背书，请求只提交 username
// （§2.7.5 行 685「仅提交用户名」——此处默认口径，待复核）。
func (e *Engine) evaluateCaptcha(ctx context.Context, d *Dispatched, req Request, p *token.LoginTokenPayload) (captcha.Outcome, error) {
	if e.gate == nil {
		return captcha.Outcome{}, nil
	}
	if d.Kind == factor.FactorWebAuthn && req.Step == "challenge" {
		return captcha.Outcome{}, nil
	}
	// register 直通入口（method=password、step=set_password）captcha 必经
	// （§2.3 行 450-451「captcha 必填」）。到达这里的 password + set_password
	// 只可能是 register 流（login 流被 dispatch 拒、reset 流被方式开关拒；
	// tp 免密建号除外——见上），复用 gate 的 Challenge 必经通道——docs 未
	// 明说 set_password 的 gate Request 形态，默认口径，待复核。
	direct := d.Kind == factor.FactorPassword && req.Step == stepSetPassword &&
		!(p.GetTp() != nil && p.GetFlow() == "login")
	r := captcha.Request{
		Challenge: req.Step == "challenge" || direct,
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
	// 密码登录读当日失败计数：user_ref 经注入的解析器按因子写入侧
	// 同款口径推导（用户存在 → "{userID}"；不存在 → "{ip}|{sha256}"），禁止
	// 直接拿 username 原文当键（键口径漂移 → 计数恒 0，渐进式保护失效）。
	if r.Password && e.failures != nil && e.userRef != nil && req.Payload != nil {
		if identifier := strings.TrimSpace(req.Payload.Username); identifier != "" {
			ref, err := e.userRef.UserRef(ctx, identifier)
			if err != nil {
				return captcha.Outcome{}, err
			}
			n, err := e.failures.Count(ctx, ref)
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
	// 因子可直接以 status 终止（如 user_not_found / too_many_requests），
	// 此时不签发 login_token；重试建议回填信封 error.retryAfter（§1.6 行 242）。
	if step != nil && step.Status != "" {
		resp := &ssov1.LoginFlowResponse{Status: step.Status}
		if step.RetryAfter > 0 {
			v := step.RetryAfter
			resp.Error = &ssov1.SsoError{RetryAfter: &v}
		}
		return resp
	}
	nonce, err := security.RandomString(challengeNonce)
	if err != nil {
		return failed()
	}
	purpose := flowPurpose(flow, d.Usage)
	target := targetOf(req.Payload)
	if d.Usage == factor.UsageSecondary {
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
	// login 流清挑战（终点 / MFA 不再需要）；register / reset 保留 ch.target
	// 供 set_password 建号落库（§7.4），令牌重新加密防篡改。
	if flow == "login" {
		p.Ch = nil
	}

	if d.Usage == factor.UsagePrimary {
		// 注册 / 重置的 verify 通过后不进 MFA / 终点（§7.4 行 1025-1026）：
		// register 流用户尚未建号（uid=0 合法，现状 uid==0 → failed 的分支
		// 不适用于 register），重签 login_token 返回 next，next_step 指向
		// set_password（endpoint 按 flow）。
		if flow == "register" || flow == "reset" {
			tok, err := e.state.Issue(p)
			if err != nil {
				return failed()
			}
			return &ssov1.LoginFlowResponse{
				Status:     StatusNext,
				LoginToken: tok,
				NextStep:   nextStep(flow, d.Kind, setPasswordForm(flow)),
			}
		}
		if p.Uid == 0 {
			return failed()
		}
		// 该用户已启用 MFA → status=mfa_required（§1.6 / §2.7.4 行 785）：
		// 只依据系统开关与用户启用状态判定，不下发因子列表；因子视图由验证
		// 内核 StartVerification 提供（§3.8）。
		required, err := e.mfaRequired(ctx, p.Uid)
		if err != nil {
			// 依赖读取故障按 fail-closed 收敛：不得静默跳过二次验证。
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
			}
		}
	}

	if e.terminal == nil {
		return failed()
	}
	return e.completeSuccess(ctx, req, p)
}

// mfaRequired 判定主因子通过后是否进入二次验证（§1.6 mfa_required、
// §2.7.4 行 785）：只依据系统开关与用户启用状态，不下发因子列表；因子
// 视图由验证内核 StartVerification 提供（§3.8）。
//
// 返回 error 表示依赖读取故障（连接失败 / 超时 / 用户查不到等），调用方
// 必须拒绝登录：读取故障不得被解释为「无需二次验证」，否则启用 MFA 的用户
// 会在故障窗口被跳过二次验证。用户行的任何读取错误都不得放行（仓储对
// not-found 也按错误返回）；仅 mfa_setting 凭据行不存在属正常语义（该用户
// 未启用自选 MFA），返回 (false, nil)。
func (e *Engine) mfaRequired(ctx context.Context, uid int64) (bool, error) {
	// uid=0 / 依赖未接入（单测裁剪装配）：无判定输入，按无需 MFA 处理。
	if uid == 0 || e.repo.Users == nil {
		return false, nil
	}
	if !boolSetting(e.dispatcher.Settings, settings.KeyMfaEnabled, true) {
		return false, nil
	}
	user, err := e.repo.Users.FindByID(ctx, uid)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, nil
	}
	if user.MfaRequired == 1 {
		return true, nil
	}
	// 凭据仓储未接入与旧 builder 口径一致（hasCredential 返回 false, nil）：
	// 属装配裁剪而非运行期故障，不得据此拒绝登录。
	if e.repo.Credentials == nil {
		return false, nil
	}
	c, err := e.repo.Credentials.FindByUserAndKind(ctx, uid, "mfa_setting")
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

// completeSuccess 组装 status=success 信封（verify 与 set_password 共用，
// §2.2 行 430-437、§10.3 行 1527、§10.4 行 1532）。
func (e *Engine) completeSuccess(ctx context.Context, req Request, p *token.LoginTokenPayload) *ssov1.LoginFlowResponse {
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
	} else if sink, ok := SessionTokenSinkFromContext(ctx); ok {
		sink(success.SessionToken)
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
