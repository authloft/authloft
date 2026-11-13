package verification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

// ErrReplay 高风险断言被二次消费（§11.6.7:1485 重放）。
var ErrReplay = errors.New("verification: assertion replayed")

// ErrLoginContext 登录流程上下文与挑战令牌不一致或无法解析（§3.8.5：
// uid 必须与挑战令牌 subject 一致，解析失败同样按 verification_invalid）。
// 适配器以 errors.Is 包装返回，服务层映射为 verification_invalid。
var ErrLoginContext = errors.New("verification: login token context mismatch")

// 主体凭证（login_token）失效的可判别哨兵（§1.6 行 271、§3.8.5）：
// 由终点收尾适配器以 errors.Is 包装透出，服务层分别映射
// token_expired / token_invalid，不再一律落 internal。
var (
	ErrLoginTokenExpired = errors.New("verification: login token expired")
	ErrLoginTokenInvalid = errors.New("verification: login token invalid")
)

// LoginCompleter 登录终点收尾（§7.3 步骤 7）：建会话、投递登录日志、拼多域名
// 同步链与 OIDC 跳转。生产注入基于 orchestrator.Terminal 的适配器；登录链路
// 另附 loginToken 时用它恢复 oidc / tid / passed 等流程上下文。未注入时
// SsoService 组 Submit 返回失败，不越过终点收尾。
type LoginCompleter interface {
	Complete(ctx context.Context, subject Subject, loginToken, method string) (LoginSession, error)
}

// LoginSession 终点产物中 SsoService 组响应需要的字段（§3.8.2）。
type LoginSession struct {
	RedirectTo    string
	SyncCookieURL string
}

// SubmitInput SubmitVerification 入参（§3.8.2 请求字段 + 方法组所在域）。
type SubmitInput struct {
	Domain         string
	ChallengeToken string
	Method         string
	Payload        *structpb.Struct
	// LoginToken 仅 SsoService 组可用：恢复登录流程上下文（§3.8.1、§3.8.5）。
	LoginToken string
}

// SubmitResult SubmitVerification 结论（§3.8.2）：SsoService 组读 Status /
// RedirectTo / SyncCookieURL，AccountService 组读 VerificationToken /
// ExpiresIn，两组共用 AMR。
type SubmitResult struct {
	Status            string
	RedirectTo        string
	SyncCookieURL     string
	VerificationToken string
	ExpiresIn         int64
	AMR               []string
	// TicketID 扫码链路的票据标识（非空表示本次 step-up 属扫码场景，由调用方
	// 票据链路收尾写终态 TicketResult，不在此建会话，§2.8 行 884）。
	TicketID string
}

// Want 是消费方对断言的期望（§11.6.7:1482「biz_purpose + operation 双重
// 校验」、§16:1842 追加 subject），三者任一不符即 verification_invalid。
type Want struct {
	BizPurpose BizPurpose
	Operation  string
	Subject    Subject
}

// Submit 校验挑战令牌与因子凭据，原样带入挑战的 biz_purpose / subject /
// operation / nonce 签发断言（§3.8.4、§7.3 步骤 7）。
func (s *Service) Submit(ctx context.Context, in SubmitInput) (*SubmitResult, error) {
	if s.d.Codec == nil {
		return nil, fmt.Errorf("verification: codec not injected")
	}
	if in.ChallengeToken == "" || in.Method == "" {
		return nil, failure("verification_invalid", nil)
	}
	// loginToken 仅 SsoService 组可携带（§3.8.2、§3.8.5）。
	if in.Domain != DomainSSO && in.LoginToken != "" {
		return nil, failure("invalid_request", nil)
	}
	ch, err := s.d.Codec.ParseChallenge(in.ChallengeToken)
	if err != nil {
		return nil, failure("verification_invalid", err)
	}
	// 挑战主体严格比对会话 uid（§3.8.1、§3.8.4）：非 uid 主体（含历史
	// tid 兼容载荷）一律 verification_invalid，且不进入因子校验，避免
	// 主因子未过时消费验证码。
	if ch.Subject.Kind != SubjectKindUID || ch.Subject.ID == "" {
		return nil, failure("verification_invalid", nil)
	}
	if !contains(ch.Methods, in.Method) {
		return nil, failure("verification_invalid", nil)
	}
	if in.Domain == DomainSSO && ch.BizPurpose != BizPurposeLogin {
		return nil, failure("verification_invalid", nil)
	}
	if in.Domain == DomainAccount && ch.BizPurpose == BizPurposeLogin {
		return nil, failure("verification_invalid", nil)
	}
	// 扫码挑战把 ticket_id 绑定在 nonce 前缀（Start 侧编码）：剥离后再交给
	// 因子校验，保证 OTP owner / WebAuthn challenge 与下发阶段同源。
	// ticket_id 与 login_token.tid 是两个概念（接口文档 §2.8 行 857），
	// 不再从主体推导票据标识。
	verifyNonce := ch.Nonce
	scanTicket, rawNonce, isScan := splitScanNonce(ch.Nonce)
	if isScan {
		verifyNonce = rawNonce
	}
	// 未注入验证器时 fail-closed：任何情况都不得在未校验凭据的情况下签发断言。
	if s.d.Verifier == nil {
		return nil, failure("method_disabled", nil)
	}
	res, err := s.d.Verifier.Verify(ctx, FactorVerifyInput{
		Method:      in.Method,
		BizPurpose:  ch.BizPurpose,
		Subject:     ch.Subject,
		ChallengeID: verifyNonce,
		Payload:     in.Payload,
	})
	if err != nil {
		return nil, fmt.Errorf("verification: factor verify: %w", err)
	}
	if !res.Passed {
		code := res.Code
		if code == "" {
			code = "invalid_code"
		}
		return nil, failure(code, nil)
	}

	tok, err := s.d.Codec.IssueAssertion(Assertion{
		BizPurpose: ch.BizPurpose,
		Subject:    ch.Subject,
		Nonce:      verifyNonce,
		Operation:  ch.Operation,
		AMR:        []string{in.Method},
	}, AssertionTTL)
	if err != nil {
		// 断言签发失败按无效断言收敛为可判别业务失败，不静默吞错、
		// 也不一律落 internal（§3.8.5 无效 / 过期 / 重放口径）。
		return nil, failure("verification_invalid", err)
	}
	out := &SubmitResult{
		VerificationToken: tok,
		ExpiresIn:         int64(AssertionTTL / time.Second),
		AMR:               []string{in.Method},
	}
	if in.Domain == DomainSSO {
		out.Status = "success"
		if scanTicket != "" {
			// 扫码链路（§2.8 行 884）：主体必须是票据快照解析出的 uid，收尾
			// 由票据链路写终态 TicketResult，PC 端下一次轮询进入 success；
			// 这里不建会话（PC 是轮询方，会话在轮询命中终态时创建）。
			if ch.Subject.Kind != SubjectKindUID || ch.Subject.ID == "" {
				return nil, failure("verification_invalid", nil)
			}
			out.TicketID = scanTicket
			return out, nil
		}
		// 登录链路的二次验证通过后走既有终点收尾：建会话（一次写）、投递登录
		// 日志、拼多域名同步链与 OIDC 跳转（§7.3 步骤 7、§3.8.2）。
		if ch.Subject.Kind == SubjectKindUID {
			if s.d.Login == nil {
				return nil, failure("invalid_request", nil)
			}
			sess, err := s.d.Login.Complete(ctx, ch.Subject, in.LoginToken, in.Method)
			if err != nil {
				// 主体凭证（login_token）失效按 §1.6 行 271 分别映射
				// token_expired / token_invalid，不再与其它收尾错误一并
				// 落 internal；uid 与挑战主体不符仍判无效断言（§3.8.5）。
				if errors.Is(err, ErrLoginTokenExpired) {
					return nil, failure("token_expired", err)
				}
				if errors.Is(err, ErrLoginTokenInvalid) {
					return nil, failure("token_invalid", err)
				}
				if errors.Is(err, ErrLoginContext) {
					return nil, failure("verification_invalid", err)
				}
				return nil, fmt.Errorf("verification: complete login: %w", err)
			}
			out.RedirectTo = sess.RedirectTo
			out.SyncCookieURL = sess.SyncCookieURL
		}
	}
	return out, nil
}

// ConsumeAssertion 是敏感操作消费断言的唯一入口（§11.6.7:1482 / :1485、
// §16:1842、§3.8.4）：挑战 / 断言两类令牌由 AAD purpose 与独立密钥双重
// 隔离（ParseAssertion 内部已拒绝跨类型解析）；解出后按请求意图逐项校验
// biz_purpose / operation / subject；高风险 biz_purpose 消费时做一次
// SET NX al:once:{nonce} 去重，低风险（如 unbind_totp）按 nonce + exp
// 放行、不读 Redis。
func (s *Service) ConsumeAssertion(ctx context.Context, token string, want Want) (Assertion, error) {
	if token == "" {
		return Assertion{}, failure("verification_required", nil)
	}
	if s.d.Codec == nil {
		return Assertion{}, fmt.Errorf("verification: codec not injected")
	}
	a, err := s.d.Codec.ParseAssertion(token)
	if err != nil {
		return Assertion{}, failure("verification_invalid", err)
	}
	if a.BizPurpose != want.BizPurpose || a.Operation != want.Operation || a.Subject != want.Subject {
		return Assertion{}, failure("verification_invalid", nil)
	}
	if s.d.Policy.HighRisk(a.BizPurpose) {
		if s.d.Once == nil {
			return Assertion{}, failure("verification_invalid", nil)
		}
		ok, err := s.d.Once.SetNX(ctx, onceKeyPrefix+a.Nonce, "1", onceTTL)
		if err != nil {
			return Assertion{}, fmt.Errorf("verification: once: %w", err)
		}
		if !ok {
			return Assertion{}, failure("verification_invalid", ErrReplay)
		}
	}
	return a, nil
}
