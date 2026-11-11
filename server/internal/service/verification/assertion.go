package verification

import (
	"errors"
	"fmt"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/security"
)

var (
	// ErrInvalidChallenge 挑战令牌无效：跨 purpose / 篡改 / 未知 kid / 载荷字段
	// 不合法（biz_purpose、subject_kind、subject、nonce 逐项断言）。
	ErrInvalidChallenge = errors.New("verification: invalid challenge token")
	// ErrInvalidAssertion 断言令牌无效，口径同 ErrInvalidChallenge。
	ErrInvalidAssertion = errors.New("verification: invalid assertion token")
	// ErrTokenExpired 令牌已过期（§11.6.7 按 exp 判定）。
	ErrTokenExpired = errors.New("verification: token expired")
	// ErrCodecMissing 未注入 challenge / verification 密钥对应的 codec。
	ErrCodecMissing = errors.New("verification: codec not injected")
)

// Challenge 一次性挑战的业务视图（§11.6.7 ChallengeTokenPayload）。
type Challenge struct {
	BizPurpose BizPurpose
	Subject    Subject
	Nonce      string
	Operation  string
	// Methods step-up 允许的因子快照（§11.6.7）；本包原样透传、不做策略判定。
	Methods []string
}

// Assertion 二次验证通过后的断言业务视图（§11.6.7 VerificationTokenPayload）。
// AMR 由服务端写入，禁止客户端传入。
type Assertion struct {
	BizPurpose BizPurpose
	Subject    Subject
	Nonce      string
	AMR        []string
	Operation  string
}

// AssertionCodec 挑战与断言令牌的签发 / 解析（§11.6.7）。挑战令牌统一走
// security.PurposeChallenge + sign_key.challenge，断言令牌走
// security.PurposeVerification + sign_key.verification；两类令牌由 AAD
// purpose 与独立密钥双重隔离，Open 跨 purpose 天然拒解，无需额外的载荷
// 消息类型校验。now 可注入，便于断言跨过期时间点。
type AssertionCodec struct {
	challengeCodec    *security.Codec
	verificationCodec *security.Codec
	now               func() time.Time
}

// NewAssertionCodec 注入 challenge / verification 两把独立密钥对应的 codec
// （装配侧由 sign_key.challenge / sign_key.verification 构造，§1.4、§3.2）。
func NewAssertionCodec(challenge, verification *security.Codec) *AssertionCodec {
	return &AssertionCodec{
		challengeCodec:    challenge,
		verificationCodec: verification,
		now:               time.Now,
	}
}

func (a *AssertionCodec) nowTime() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

// IssueChallenge 签发挑战令牌。ttl 由调用方按 §11.6.7 注入（step-up 与
// otp_ttl 一致取 300s、webauthn_enroll 120s），本包不写字面量默认值
// （§3.2 第 16 条）。
func (a *AssertionCodec) IssueChallenge(c Challenge, ttl time.Duration) (string, error) {
	if a.challengeCodec == nil {
		return "", ErrCodecMissing
	}
	if err := validateTarget(c.BizPurpose, c.Subject, c.Nonce, ttl); err != nil {
		return "", err
	}
	now := a.nowTime()
	payload := &token.ChallengeTokenPayload{
		BizPurpose:  string(c.BizPurpose),
		SubjectKind: string(c.Subject.Kind),
		Subject:     c.Subject.ID,
		Nonce:       c.Nonce,
		Operation:   c.Operation,
		Methods:     append([]string(nil), c.Methods...),
		Iat:         now.Unix(),
		Exp:         now.Add(ttl).Unix(),
	}
	return a.challengeCodec.Seal(security.PurposeChallenge, payload)
}

// ParseChallenge 解析并校验挑战令牌：跨 purpose / 篡改 / 未知 kid 在 GCM
// 认证处失败；解出后逐项断言 biz_purpose 封闭集合、subject_kind、主体与
// nonce，并校验 exp（§11.6.7）。
func (a *AssertionCodec) ParseChallenge(tok string) (Challenge, error) {
	if a.challengeCodec == nil {
		return Challenge{}, ErrCodecMissing
	}
	payload, err := security.Open[token.ChallengeTokenPayload](a.challengeCodec, security.PurposeChallenge, tok)
	if err != nil {
		return Challenge{}, ErrInvalidChallenge
	}
	bp := BizPurpose(payload.GetBizPurpose())
	sub := Subject{Kind: SubjectKind(payload.GetSubjectKind()), ID: payload.GetSubject()}
	if !bp.Valid() || !sub.Valid() || payload.GetNonce() == "" {
		return Challenge{}, ErrInvalidChallenge
	}
	if payload.GetExp() <= a.nowTime().Unix() {
		return Challenge{}, ErrTokenExpired
	}
	return Challenge{
		BizPurpose: bp,
		Subject:    sub,
		Nonce:      payload.GetNonce(),
		Operation:  payload.GetOperation(),
		Methods:    append([]string(nil), payload.GetMethods()...),
	}, nil
}

// IssueAssertion 签发二次验证通过后的断言令牌（§11.6.7，有效期 120s）。
func (a *AssertionCodec) IssueAssertion(s Assertion, ttl time.Duration) (string, error) {
	if a.verificationCodec == nil {
		return "", ErrCodecMissing
	}
	if err := validateTarget(s.BizPurpose, s.Subject, s.Nonce, ttl); err != nil {
		return "", err
	}
	now := a.nowTime()
	payload := &token.VerificationTokenPayload{
		BizPurpose:  string(s.BizPurpose),
		SubjectKind: string(s.Subject.Kind),
		Subject:     s.Subject.ID,
		Nonce:       s.Nonce,
		Amr:         append([]string(nil), s.AMR...),
		Operation:   s.Operation,
		Iat:         now.Unix(),
		Exp:         now.Add(ttl).Unix(),
	}
	return a.verificationCodec.Seal(security.PurposeVerification, payload)
}

// ParseAssertion 解析并校验断言令牌。消费方仍须按 §11.6.7 做
// 「biz_purpose + operation 双重校验」与 nonce / 高风险 al:once 去重；
// 本包只提供解析，去重落点由消费方实现（Policy.HighRisk 供判定）。
func (a *AssertionCodec) ParseAssertion(tok string) (Assertion, error) {
	if a.verificationCodec == nil {
		return Assertion{}, ErrCodecMissing
	}
	payload, err := security.Open[token.VerificationTokenPayload](a.verificationCodec, security.PurposeVerification, tok)
	if err != nil {
		return Assertion{}, ErrInvalidAssertion
	}
	bp := BizPurpose(payload.GetBizPurpose())
	sub := Subject{Kind: SubjectKind(payload.GetSubjectKind()), ID: payload.GetSubject()}
	if !bp.Valid() || !sub.Valid() || payload.GetNonce() == "" {
		return Assertion{}, ErrInvalidAssertion
	}
	if payload.GetExp() <= a.nowTime().Unix() {
		return Assertion{}, ErrTokenExpired
	}
	return Assertion{
		BizPurpose: bp,
		Subject:    sub,
		Nonce:      payload.GetNonce(),
		AMR:        append([]string(nil), payload.GetAmr()...),
		Operation:  payload.GetOperation(),
	}, nil
}

// validateTarget 签发前的封闭集合 / 三元组前置校验（§11.6.7、§10.1）。
func validateTarget(bp BizPurpose, sub Subject, nonce string, ttl time.Duration) error {
	if !bp.Valid() || !sub.Valid() || nonce == "" || ttl <= 0 {
		return fmt.Errorf("verification: biz_purpose/subject/nonce/ttl invalid")
	}
	return nil
}
