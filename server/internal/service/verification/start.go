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
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"authloft/internal/captcha"
	"authloft/internal/security"
)

const (
	// ChallengeTTL step-up 挑战有效期（§11.6.7、§1.10.2：与 otp_ttl 一致 300s）。
	ChallengeTTL = 300 * time.Second
	// AssertionTTL 断言有效期（§11.6.7、§3.8.2：120s）。
	AssertionTTL = 120 * time.Second
	// onceKeyPrefix / onceTTL（§5.1 行 880：al:once:{nonce}，TTL 120s）。
	onceKeyPrefix = "al:once:"
	onceTTL       = 120 * time.Second
)

// 方法组所在域（§3.8.1）：SsoService 只接受 login，AccountService 接受其余值。
const (
	DomainSSO     = "sso"
	DomainAccount = "account"
)

// 扫码 step-up 的票据快照取值（§2.8 行 884、§11.6.5 行 1400）。验证内核只
// 做契约校验、不读 Redis：场景与状态由持票域按快照填充。
const (
	scanSceneLogin       = "login"
	scanStatusMFAPending = "mfa_pending"
	scanNonceSep         = "|"
)

// MFAPendingClaim 扫码 step-up 的票据快照视图（§2.8 行 884、§3.8.1 行 1233）：
// 由持票域（扫码 service）校验票据存在 / scene 后注入；验证内核据此拒绝
// 不存在或 scene 不符的 mfaPendingId，并以其中的 uid 作为目标主体。
type MFAPendingClaim struct {
	TicketID string
	Scene    string
	Status   string
	UID      int64
}

// Error 是 step-up 的业务失败：Code 只取接口文档 §1.6 封闭集合成员，由
// handler 构造 Connect 错误体 + ErrorInfo（§3.8.5、§1.5）；RetryAfter 仅在
// 限流类失败（too_many_requests）时非零，供 ErrorInfo.retry_after 使用。
type Error struct {
	Code       string
	RetryAfter int64
	cause      error
}

func (e *Error) Error() string { return "verification: " + e.Code }
func (e *Error) Unwrap() error { return e.cause }

func failure(code string, cause error) error {
	if cause == nil {
		cause = errors.New(code)
	}
	return &Error{Code: code, cause: cause}
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

// FactorVerifyResult 因子校验结论；Code 为失败时的 §1.6 细分码。
type FactorVerifyResult struct {
	Passed bool
	Code   string
}

// Deps 服务依赖（§20 依赖注入）；装配方逐项注入，未注入的判定项走 fail-closed。
type Deps struct {
	Codec       *AssertionCodec
	Policy      *Policy
	Gate        CaptchaGate
	Once        OnceStore
	Bound       BoundFactorReader
	Verifier    FactorVerifier
	Starter     FactorStarter
	LoginTokens LoginTokenReader
	Login       LoginCompleter
	Now         func() time.Time
	NewNonce    func() (string, error)
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
// （SsoService 组用 loginToken / mfaPendingId，AccountService 组用会话 uid）。
type StartInput struct {
	Domain       string
	BizPurpose   BizPurpose
	Method       string
	Operation    string
	LoginToken   string
	MFAPendingID string
	// MFAPending 扫码场景的票据快照（持票域注入）；MFAPendingID 非空时必填。
	MFAPending *MFAPendingClaim
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
	if !in.BizPurpose.Valid() || in.Operation == "" {
		return nil, nil, failure("invalid_request", nil)
	}
	subject, err := s.resolveSubject(ctx, in)
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
	if len(candidates) == 0 {
		return nil, nil, failure("method_disabled", nil)
	}
	if in.Method != "" && !contains(candidates, in.Method) {
		return nil, nil, failure("invalid_request", nil)
	}

	// 选定因子即本次要下发挑战凭据，按 §2.5 触发表「两步验证阶段下发 必须」
	// 过守卫；失败以领域错误透出，不套登录流程信封、不静默回落（§3.8.5）。
	if in.Method != "" && s.d.Gate != nil {
		outcome, err := s.d.Gate.Evaluate(ctx, captcha.Request{
			Challenge:  true,
			Submission: in.Captcha,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("verification: captcha gate: %w", err)
		}
		if f := captcha.FailureFrom(outcome); f != nil {
			return nil, f, nil
		}
	}

	views := make([]MethodView, 0, len(candidates))
	for _, m := range candidates {
		views = append(views, methodView(m))
	}

	// method 为空 = 只返回可用因子由前端选择，不签发挑战令牌
	//（接口文档 §10.2 步骤 5）。
	if in.Method == "" {
		return &StartResult{
			Methods:   views,
			ExpiresIn: int64(ChallengeTTL / time.Second),
		}, nil, nil
	}

	nonce, err := s.d.NewNonce()
	if err != nil {
		return nil, nil, fmt.Errorf("verification: nonce: %w", err)
	}
	kind := lastStep(in.Method)
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

	// 扫码场景把 ticket_id 绑定进 nonce：终态票据的收尾需要 ticket_id，
	// 而挑战令牌只携带 subject / nonce（§11.6.7）。前缀不改因子语义——
	// 因子下发使用原始 nonce，Submit 侧剥离前缀后再交给因子校验。
	if in.MFAPending != nil {
		nonce = scanNonce(in.MFAPending.TicketID, nonce)
	}

	tok, err := s.d.Codec.IssueChallenge(Challenge{
		BizPurpose: in.BizPurpose,
		Subject:    subject,
		Nonce:      nonce,
		Operation:  in.Operation,
		Methods:    append([]string(nil), candidates...),
	}, ChallengeTTL)
	if err != nil {
		return nil, nil, fmt.Errorf("verification: issue challenge: %w", err)
	}
	return &StartResult{
		ChallengeToken: tok,
		Methods:        views,
		ExpiresIn:      int64(ChallengeTTL / time.Second),
		NextStepKind:   kind,
		ChallengeData:  data,
	}, nil, nil
}

// lastStep 返回该因子步骤序列的下一步渲染形态（§1.4）：step-up 选定因子
// 后直接进入 form（OTP / WebAuthn 的 challenge 已在 Start 内完成下发）。
func lastStep(method string) string {
	v := methodView(method)
	if len(v.Steps) == 0 {
		return ""
	}
	return v.Steps[len(v.Steps)-1]
}

// resolveSubject 按域推导确定主体，杜绝匿名裸调（§3.8.1）。
func (s *Service) resolveSubject(ctx context.Context, in StartInput) (Subject, error) {
	switch in.Domain {
	case DomainSSO:
		if in.BizPurpose != BizPurposeLogin {
			return Subject{}, failure("invalid_request", nil)
		}
		if in.LoginToken != "" {
			if s.d.LoginTokens == nil {
				return Subject{}, failure("token_invalid", nil)
			}
			uid, passed, err := s.d.LoginTokens.Read(ctx, in.LoginToken)
			if err != nil || uid == 0 || !passed {
				return Subject{}, failure("token_invalid", err)
			}
			return Subject{Kind: SubjectKindUID, ID: fmt.Sprintf("%d", uid)}, nil
		}
		if in.MFAPendingID != "" {
			if in.MFAPending == nil || in.MFAPending.TicketID != in.MFAPendingID {
				return Subject{}, failure("invalid_request", nil)
			}
			if in.MFAPending.Scene != scanSceneLogin {
				return Subject{}, failure("invalid_request", nil)
			}
			if in.MFAPending.Status != scanStatusMFAPending || in.MFAPending.UID <= 0 {
				return Subject{}, failure("token_invalid", nil)
			}
			// 目标主体取票据快照的 uid：因子下发 / 校验都要求 uid != 0（§7.3
			// 校验点），扫码链路的第一因子已由小程序端完成。
			return Subject{Kind: SubjectKindUID, ID: fmt.Sprintf("%d", in.MFAPending.UID)}, nil
		}
		return Subject{}, failure("invalid_request", nil)
	case DomainAccount:
		// login 只走 SsoService 组；webauthn_enroll 的挑战由 RegisterWebauthn
		// 直接签发，不经 StartVerification（§3.8.1、§3.8.3）。
		if in.BizPurpose == BizPurposeLogin || in.BizPurpose == BizPurposeWebAuthnEnroll {
			return Subject{}, failure("invalid_request", nil)
		}
		if in.SessionUID == "" {
			return Subject{}, failure("invalid_request", nil)
		}
		return Subject{Kind: SubjectKindUID, ID: in.SessionUID}, nil
	default:
		return Subject{}, failure("invalid_request", nil)
	}
}

// methodView 因子能力视图，取值来自 §1.10.1 因子能力表与 §2.1 注入快照；
// 只表达能力，业务用途与策略数值不进视图。
func methodView(method string) MethodView {
	switch method {
	case "otp_sms", "otp_email":
		return MethodView{
			Method: method, Usage: []string{"primary", "secondary"},
			Steps: []string{"challenge", "form"}, CodeLength: 6,
			ResendAfter: 60, ExpiresIn: 300,
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

// scanNonce 把扫码票据标识绑定进挑战 nonce（内部编码，挑战令牌对前端不透明）。
func scanNonce(ticketID, nonce string) string {
	return ticketID + scanNonceSep + nonce
}

// splitScanNonce 拆出扫码票据标识与原始 nonce；非扫码挑战返回 ok=false。
// 原始 nonce 是 base64url 随机串，不含分隔符。
func splitScanNonce(nonce string) (ticketID, raw string, ok bool) {
	i := strings.Index(nonce, scanNonceSep)
	if i <= 0 {
		return "", nonce, false
	}
	return nonce[:i], nonce[i+1:], true
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

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
