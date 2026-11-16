// Package verification 验证内核（docs/后端架构.md §3.7、§6.1、§6.3、
// §11.6.7）：本文件与 submit.go 共同构成 step-up 的服务层——挑战签发、
// 断言签发与断言消费校验。策略判定仍以 verification.go 的 Policy 为唯一
// 入口，令牌编解码以 assertion.go 的 AssertionCodec 为唯一出口。
package verification

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"authloft/gen/go/token"
	"authloft/internal/captcha"
	"authloft/internal/security"
	"authloft/internal/settings"
)

const (
	// AssertionTTL 断言有效期（§11.6.7、§3.8.2：120s）。
	AssertionTTL = 120 * time.Second
	// onceKeyPrefix / onceTTL（§5.1 行 880：al:once:{nonce}，TTL 120s）。
	onceKeyPrefix = "al:once:"
	onceTTL       = 120 * time.Second
)

// Settings 验证码有效期 / 重发冷却读取窄接口（§1.10.2、§5.6 表三）：
// *settings.Store 天然满足；每次现读，热更新只对后续请求生效。
type Settings interface {
	GetInt64(key string) (int64, bool)
}

// intSetting 读 settings 键的当前值；未注入、键缺失或非正值时取该键的注册
// 默认值（§5.6 表三：键名与默认值的唯一定义处），不在此另立数值。
func intSetting(st Settings, key string) int64 {
	if st != nil {
		if v, ok := st.GetInt64(key); ok && v > 0 {
			return v
		}
	}
	if d, ok := settings.Lookup(key); ok {
		if v, ok := d.Default.(int64); ok && v > 0 {
			return v
		}
	}
	return 0
}

// otpTTL 挑战有效期（§11.6.7：step-up 与 al:code 一致，取 otp_ttl）。
func (s *Service) otpTTL() time.Duration {
	return time.Duration(intSetting(s.d.Settings, settings.KeyOtpTtl)) * time.Second
}

// resendAfter 同目标重发冷却（§1.10.2：取 otp_resend_interval）。
func (s *Service) resendAfter() int64 {
	return intSetting(s.d.Settings, settings.KeyOtpResendInterval)
}

// otpSnapshot 请求级 OTP 配置快照（§4.7、§7.3 步骤 6）：Start 入口把现行
// otp_ttl / otp_resend_interval 各读一次固化，随后 methodView / ExpiresIn /
// IssueChallenge 一律经该副本取值。settings 热更新只对后续请求生效，落在
// 请求中途也不会让响应 expiresIn 与挑战令牌 exp 取自不同档位。实现
// Settings 窄接口供只读注入，复用 intSetting 的回退口径。
type otpSnapshot struct {
	ttl    int64
	resend int64
}

func (o otpSnapshot) GetInt64(key string) (int64, bool) {
	switch key {
	case settings.KeyOtpTtl:
		return o.ttl, true
	case settings.KeyOtpResendInterval:
		return o.resend, true
	default:
		return 0, false
	}
}

// snapshotOtp 取一次现行 OTP 配置，返回绑定该快照的服务副本与快照本身；
// 副本的 d.Settings 已被替换为只读快照，本次请求不再触达真实 Store。
func (s *Service) snapshotOtp() (*Service, otpSnapshot) {
	snap := otpSnapshot{
		ttl:    intSetting(s.d.Settings, settings.KeyOtpTtl),
		resend: intSetting(s.d.Settings, settings.KeyOtpResendInterval),
	}
	d := s.d
	d.Settings = snap
	return &Service{d: d}, snap
}

// 方法组所在域（§3.8.1）：SsoService 只接受 login，AccountService 接受其余值。
const (
	DomainSSO     = "sso"
	DomainAccount = "account"
)

// Error 是 step-up 的业务失败：Code 只取接口文档 §1.6 封闭集合成员，由
// handler 构造 Connect 错误体 + ErrorInfo（§3.8.5、§1.5）；RetryAfter 仅在
// 限流类失败（too_many_requests）时非零，供 ErrorInfo.retry_after 使用；
// AttemptsLeft 仅在 invalid_code 错码且键保留时非零，供两组响应按
// 「零值或缺失即不展示」承载剩余次数（§3.8.5、§1.6）。
type Error struct {
	Code         string
	RetryAfter   int64
	AttemptsLeft int64
	cause        error
}

func (e *Error) Error() string { return "verification: " + e.Code }
func (e *Error) Unwrap() error { return e.cause }

func failure(code string, cause error) error {
	if cause == nil {
		cause = errors.New(code)
	}
	return &Error{Code: code, cause: cause}
}

// failureWithAttempts 构造携带剩余尝试次数的业务失败（§3.8.5、§1.6）：
// 两组 invalid_code 失败态经此路径把 AttemptsLeft 透传到 handler，零值
// 时不携带，由响应侧「零值或缺失即不展示」收敛。
func failureWithAttempts(code string, attemptsLeft int64) error {
	return &Error{Code: code, AttemptsLeft: attemptsLeft, cause: errors.New(code)}
}

func failureRetry(code string, retryAfter int64) error {
	return &Error{Code: code, RetryAfter: retryAfter, cause: errors.New(code)}
}

// CaptchaGate 人机校验唯一拦截点（§9.3、§3.8.5）。生产注入 *captcha.Gate。
type CaptchaGate interface {
	Evaluate(ctx context.Context, req captcha.Request) (captcha.Outcome, error)
}

// OnceStore 高风险断言消费的一次性去重（§5.1 al:once:{nonce}）。
type OnceStore interface {
	SetNX(ctx context.Context, key string, value interface{}, ttl time.Duration) (bool, error)
}

// BoundFactorReader 读取主体已绑定 / 已启用因子，供策略表取交集
// （§1.10.2 约束 1）。主体为 tid 时无绑定资料，返回候选全量。
type BoundFactorReader interface {
	Bound(ctx context.Context, subject Subject, candidates []string) ([]string, error)
}

// FactorVerifier 提交阶段的因子凭据校验（§7.3 步骤 7）。未注入时 Submit
// fail-closed，不签发断言。
type FactorVerifier interface {
	Verify(ctx context.Context, in FactorVerifyInput) (FactorVerifyResult, error)
}

// FactorStarter 下发阶段执行所选因子的 challenge 步（§7.3 步骤 6、
// §10.2 步骤 6）：OTP 生成并投递验证码、WebAuthn 生成 options。返回的
// Nonce 必须写入挑战令牌，保证 WebAuthn options.challenge 与断言校验
// 同源。未注入时只签发令牌、不触发因子下发（测试 / 半装配口径）。
type FactorStarter interface {
	Start(ctx context.Context, in FactorStartInput) (FactorStartResult, error)
}

// FactorStartInput 因子下发入参：主体与操作取自与挑战令牌同源的上下文。
type FactorStartInput struct {
	Method     string
	BizPurpose BizPurpose
	Subject    Subject
	Nonce      string
}

// FactorStartResult 因子下发结论：Code 非空表示因子以该 §1.6 取值失败
// （如 too_many_requests / provider_disabled），不签发挑战令牌。
type FactorStartResult struct {
	Nonce         string
	Kind          string
	ChallengeData *structpb.Struct
	Code          string
	RetryAfter    int64
}

// LoginTokenReader 登录过程态主体推导（§3.8.1：uid != 0 且 passed 非空）。
type LoginTokenReader interface {
	Read(ctx context.Context, tok string) (uid int64, passed bool, err error)
}

// FactorVerifyInput 因子校验入参：三元组取自挑战令牌（§10.1、§11.6.7）。
type FactorVerifyInput struct {
	Method      string
	BizPurpose  BizPurpose
	Subject     Subject
	ChallengeID string
	Payload     *structpb.Struct
}

// FactorVerifyResult 因子校验结论；Code 为失败时的 §1.6 细分码，
// AttemptsLeft 为错码且键保留时的剩余尝试次数（§3.8.5、§1.6）。
type FactorVerifyResult struct {
	Passed       bool
	Code         string
	AttemptsLeft int64
}

// Deps 服务依赖（§20 依赖注入）；装配方逐项注入，未注入的判定项走 fail-closed。
type Deps struct {
	Codec       *AssertionCodec
	Policy      *Policy
	Settings    Settings
	Gate        CaptchaGate
	Once        OnceStore
	Bound       BoundFactorReader
	Verifier    FactorVerifier
	Starter     FactorStarter
	LoginTokens LoginTokenReader
	// LoginSso 读 login_token.sso 应用快照（§11.6.2）：与 LoginTokens 读同
	// 一令牌、独立透出快照，供候选按应用开关过滤（接口文档 §2.1 交集口径 MFA 行）。
	// login_token 编解码归装配层适配器所有，本包不感知其实现；未注入或读出
	// nil = 无应用上下文（直登 / OIDC / 未装配），候选不按应用过滤。
	LoginSso func(ctx context.Context, loginToken string) (*token.Sso, error)
	Login    LoginCompleter
	Now      func() time.Time
	NewNonce func() (string, error)
}

// Service step-up 服务层：不感知 Connect / Gin，只做令牌编排与契约校验。
type Service struct {
	d Deps
}

// NewService 构造；缺省策略表 / 时钟 / nonce 生成器由调用方按需覆盖（测试）。
func NewService(d Deps) *Service {
	if d.Policy == nil {
		d.Policy = DefaultPolicy()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.NewNonce == nil {
		d.NewNonce = randomNonce
	}
	return &Service{d: d}
}

func randomNonce() (string, error) {
	b, err := security.RandomBytes(24)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MethodView 是 StartVerificationResponse.methods[] 的领域视图：只含能力
// 字段（§3.8.2 同构 §2.1 注入快照的 method 条目），不表达业务策略。
type MethodView struct {
	Method          string
	Usage           []string
	Steps           []string
	ChallengeFields []*structpb.Struct
	CodeLength      int64
	ResendAfter     int64
	ExpiresIn       int64
	Capability      string
	Providers       []*structpb.Struct
}

// StartInput StartVerification 入参；主体由 handler 按域推导后注入
// （SsoService 组用 loginToken，AccountService 组用会话 uid）。
type StartInput struct {
	Domain     string
	BizPurpose BizPurpose
	Method     string
	Operation  string
	LoginToken string
	SessionUID string
	Captcha    *captcha.Submission
}

// StartResult StartVerification 结论。
type StartResult struct {
	ChallengeToken string
	Methods        []MethodView
	ExpiresIn      int64
	NextStepKind   string
	ChallengeData  *structpb.Struct
}

// Start 校验请求意图与主体、下发挑战令牌（§3.8.1、§3.8.2、§7.3 步骤 6）。
// captcha 失败以 *captcha.Failure 返回，由 handler 并列错误码与当前生效配置
// （§3.8.5、§2.5）；不新增 Redis 状态键（§3.8.5）。
func (s *Service) Start(ctx context.Context, in StartInput) (*StartResult, *captcha.Failure, error) {
	if s.d.Codec == nil {
		return nil, nil, fmt.Errorf("verification: codec not injected")
	}
	// 请求内只取一次 settings 快照：本次响应的 ExpiresIn、各因子视图与
	// 挑战令牌有效期共用同一份 otp_ttl，热更新只对后续请求生效（§4.7）。
	s, snap := s.snapshotOtp()
	ttl := time.Duration(snap.ttl) * time.Second
	expiresIn := snap.ttl
	if !in.BizPurpose.Valid() || in.Operation == "" {
		return nil, nil, failure("invalid_request", nil)
	}
	subject, ssoSnap, err := s.resolveSubject(ctx, in)
	if err != nil {
		return nil, nil, err
	}

	candidates := s.d.Policy.Factors(in.BizPurpose)
	if len(candidates) == 0 {
		return nil, nil, failure("method_disabled", nil)
	}
	if s.d.Bound != nil {
		bound, err := s.d.Bound.Bound(ctx, subject, candidates)
		if err != nil {
			return nil, nil, fmt.Errorf("verification: bound factors: %w", err)
		}
		candidates = intersect(candidates, bound)
	}
	// 应用开关过滤在绑定交集之后执行（接口文档 §2.1 交集口径 MFA 行的合取顺序）；
	// 过滤后为空复用既有 method_disabled 出口，该用户无法登录该应用。
	candidates = ssoAllowlist(candidates, ssoSnap)
	if len(candidates) == 0 {
		return nil, nil, failure("method_disabled", nil)
	}
	if in.Method != "" && !contains(candidates, in.Method) {
		return nil, nil, failure("invalid_request", nil)
	}

	// 场景守卫：本次下发所选因子决定场景，是否需要 captcha 由 Gate 按 §2.5
	// 触发表判定（§9.3）——OTP 类下发须过守卫，WebAuthn 只取 options、TOTP
	// 绑定与恢复码不下发，场景查表即「不需要」。守卫缺失时 fail-closed。
	if s.d.Gate == nil {
		return nil, nil, fmt.Errorf("verification: captcha gate not injected")
	}
	outcome, err := s.d.Gate.Evaluate(ctx, captcha.Request{
		Scene:      captchaScene(in.Method),
		Submission: in.Captcha,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("verification: captcha gate: %w", err)
	}
	if f := captcha.FailureFrom(outcome); f != nil {
		return nil, f, nil
	}

	views := make([]MethodView, 0, len(candidates))
	for _, m := range candidates {
		views = append(views, s.methodView(m))
	}

	// method 为空 = 只返回可用因子由前端选择，不签发挑战令牌
	//（接口文档 §10.2 步骤 5）。
	if in.Method == "" {
		return &StartResult{
			Methods:   views,
			ExpiresIn: expiresIn,
		}, nil, nil
	}

	nonce, err := s.d.NewNonce()
	if err != nil {
		return nil, nil, fmt.Errorf("verification: nonce: %w", err)
	}
	kind := s.lastStep(in.Method)
	var data *structpb.Struct
	// 下发阶段执行所选因子的 challenge 步（§7.3 步骤 6、§10.2 步骤 6）：
	// OTP 发码、WebAuthn 生成 options；返回的 nonce 与 options.challenge
	// 同源，必须写入挑战令牌，供 Submit 阶段逐项校验。
	if s.d.Starter != nil {
		sr, err := s.d.Starter.Start(ctx, FactorStartInput{
			Method:     in.Method,
			BizPurpose: in.BizPurpose,
			Subject:    subject,
			Nonce:      nonce,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("verification: start factor: %w", err)
		}
		if sr.Code != "" {
			return nil, nil, failureRetry(sr.Code, sr.RetryAfter)
		}
		if sr.Nonce != "" {
			nonce = sr.Nonce
		}
		if sr.Kind != "" {
			kind = sr.Kind
		}
		data = sr.ChallengeData
	}

	tok, err := s.d.Codec.IssueChallenge(Challenge{
		BizPurpose: in.BizPurpose,
		Subject:    subject,
		Nonce:      nonce,
		Operation:  in.Operation,
		Methods:    append([]string(nil), candidates...),
	}, ttl)
	if err != nil {
		return nil, nil, fmt.Errorf("verification: issue challenge: %w", err)
	}
	return &StartResult{
		ChallengeToken: tok,
		Methods:        views,
		ExpiresIn:      expiresIn,
		NextStepKind:   kind,
		ChallengeData:  data,
	}, nil, nil
}

// captchaScene 把本次下发所选因子翻译成 captcha 场景（§2.5 触发表）：OTP 类
// 产生一次性验证码下发（第 1 行）；WebAuthn 只取 options（第 2 行）；TOTP 取
// 挑战与恢复码本环节均无下发，同归无下发场景（TOTP 绑定在 account 域，不经本
// 入口）。
func captchaScene(method string) string {
	switch method {
	case "otp_sms", "otp_email":
		return captcha.SceneOtpDispatch
	case "webauthn":
		return captcha.SceneWebAuthnOptions
	default:
		return captcha.SceneNoDispatch
	}
}

// lastStep 返回该因子步骤序列的下一步渲染形态（§1.4）：step-up 选定因子
// 后直接进入 form（OTP / WebAuthn 的 challenge 已在 Start 内完成下发）。
func (s *Service) lastStep(method string) string {
	v := s.methodView(method)
	if len(v.Steps) == 0 {
		return ""
	}
	return v.Steps[len(v.Steps)-1]
}

// resolveSubject 按域推导确定主体，杜绝匿名裸调（§3.8.1）；SSO 域顺带透出
// login_token.sso 应用快照（§11.6.2），account 域读会话、无应用上下文。
func (s *Service) resolveSubject(ctx context.Context, in StartInput) (Subject, *token.Sso, error) {
	switch in.Domain {
	case DomainSSO:
		if in.BizPurpose != BizPurposeLogin {
			return Subject{}, nil, failure("invalid_request", nil)
		}
		if in.LoginToken != "" {
			if s.d.LoginTokens == nil {
				return Subject{}, nil, failure("token_invalid", nil)
			}
			uid, passed, err := s.d.LoginTokens.Read(ctx, in.LoginToken)
			if err != nil || uid == 0 || !passed {
				return Subject{}, nil, failure("token_invalid", err)
			}
			// 主体解析已验证同一令牌，快照读出口独立再解一次（令牌小、
			// 低频入口，不值得为此拓宽跨包契约）；再失败按 token_invalid
			// 收敛，不静默降级成无应用上下文。
			snap, err := s.loginSso(ctx, in.LoginToken)
			if err != nil {
				return Subject{}, nil, failure("token_invalid", err)
			}
			return Subject{Kind: SubjectKindUID, ID: fmt.Sprintf("%d", uid)}, snap, nil
		}
		return Subject{}, nil, failure("invalid_request", nil)
	case DomainAccount:
		// login 只走 SsoService 组；webauthn_enroll 的挑战由 RegisterWebauthn
		// 直接签发，不经 StartVerification（§3.8.1、§3.8.3）。会话 step-up
		// 不读应用配置（接口文档 §2.1：只有 flow=login 读应用级开关）。
		if in.BizPurpose == BizPurposeLogin || in.BizPurpose == BizPurposeWebAuthnEnroll {
			return Subject{}, nil, failure("invalid_request", nil)
		}
		if in.SessionUID == "" {
			return Subject{}, nil, failure("invalid_request", nil)
		}
		return Subject{Kind: SubjectKindUID, ID: in.SessionUID}, nil, nil
	default:
		return Subject{}, nil, failure("invalid_request", nil)
	}
}

// loginSso 经 Deps.LoginSso 读应用快照；读出口未注入 = 无应用上下文，
// 返回 nil 快照走全局口径。
func (s *Service) loginSso(ctx context.Context, loginToken string) (*token.Sso, error) {
	if s.d.LoginSso == nil {
		return nil, nil
	}
	return s.d.LoginSso(ctx, loginToken)
}

// methodView 因子能力视图，取值来自 §1.10.1 因子能力表与 §2.1 注入快照；
// 只表达能力，业务用途与策略数值不进视图。OTP 类的 resendAfter /
// expiresIn 取现行 otp_resend_interval / otp_ttl（§3.8.2、§1.10.2）。
func (s *Service) methodView(method string) MethodView {
	switch method {
	case "otp_sms", "otp_email":
		return MethodView{
			Method: method, Usage: []string{"primary", "secondary"},
			Steps: []string{"challenge", "form"}, CodeLength: 6,
			ResendAfter: s.resendAfter(), ExpiresIn: int64(s.otpTTL() / time.Second),
		}
	case "webauthn":
		return MethodView{
			Method: method, Usage: []string{"primary", "secondary"},
			Steps: []string{"challenge", "form"}, Capability: "window.PublicKeyCredential",
		}
	case "totp":
		return MethodView{
			Method: method, Usage: []string{"secondary"},
			Steps: []string{"form"}, CodeLength: 6,
		}
	case "recovery_code":
		return MethodView{
			Method: method, Usage: []string{"secondary"}, Steps: []string{"form"},
		}
	default:
		return MethodView{Method: method}
	}
}

// ParseCaptchaSubmission 把请求级 captcha 凭据（§2.5 提交格式，用 Struct
// 承载）还原为领域结构；字段语义与约束仍由 §2.5 定义，不接收任意 map。
func ParseCaptchaSubmission(s *structpb.Struct) *captcha.Submission {
	if s == nil {
		return nil
	}
	get := func(k string) string {
		v, ok := s.Fields[k]
		if !ok || v == nil {
			return ""
		}
		return v.GetStringValue()
	}
	return &captcha.Submission{
		ProviderKey: get("providerKey"),
		Token:       get("token"),
		ID:          get("id"),
		Answer:      get("answer"),
	}
}

func intersect(candidates, bound []string) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if contains(bound, c) {
			out = append(out, c)
		}
	}
	return out
}

// appSwitchedFactors 应用开关域内的 MFA 因子（接口文档 §2.1 交集口径 MFA 行）：三者
// 可主可次，随应用 login_methods 开关；totp / recovery_code 不在应用开关域，
// 只随全局 MFA 配置，应用快照对它们不构成约束。
var appSwitchedFactors = map[string]bool{"otp_sms": true, "otp_email": true, "webauthn": true}

// ssoAllowlist 按应用快照过滤 MFA 候选（接口文档 §2.1 交集口径 MFA 行）：nil 快照 =
// 无应用上下文，原样返回；快照在场时应用开关域内的因子须被快照 methods
// 放行（快照为首签时已与全局取过交集的生效集合），域外因子不受影响。
func ssoAllowlist(candidates []string, snap *token.Sso) []string {
	if snap == nil {
		return candidates
	}
	methods := snap.GetMethods()
	out := make([]string, 0, len(candidates))
	for _, m := range candidates {
		if appSwitchedFactors[m] && !contains(methods, m) {
			continue
		}
		out = append(out, m)
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
