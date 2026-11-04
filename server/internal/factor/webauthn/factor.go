// Package webauthn 通行密钥因子（docs/后端架构.md §8.3 行 1043-1052）。
// 主因子与二次因子共用一份代码（靠 usage 配置区分）；账号域注册场景复用
// LoginTokenPayload 签独立原子 token。challenge_data 以
// google.protobuf.Struct 承载完整 WebAuthn options 对象，前端不解析、整体透传
// （接口文档 §12.9 行 1779-1780）。
package webauthn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"gorm.io/gorm"
	"google.golang.org/protobuf/types/known/structpb"

	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/repo/model"
	"authloft/internal/security"
)

// 挑战长度（§8.3 行 1046：32 字节随机）。
const challengeLen = 32

// 默认挑战有效期 / options.timeout（§3.6 行 927、§8.3 行 1046）。
const defaultChallengeTTL = 120 * time.Second

// 登录流程域 status（接口文档 §1.6 行 228-273 封闭集合子集）。
const (
	StatusInvalidRequest     = "invalid_request"
	StatusInvalidCredentials = "invalid_credentials"
	StatusCodeExpired        = "code_expired"
)

// WebauthnStore 凭据读取窄接口（repo.WebauthnRepo 天然满足；测试用 Fake）。
// usernameless 断言提交后按 credential_id 反查用户与公钥（§8.3 行 1048）。
type WebauthnStore interface {
	FindByCredentialID(ctx context.Context, credentialID string) (*model.UserCredentialWebauthn, error)
}

// Options 服务端配置（装配方注入，本包不读配置）。
type Options struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
	ChallengeTTL  time.Duration
	Timeout       time.Duration
	Clock         func() time.Time
}

func (o Options) effective() Options {
	if o.ChallengeTTL <= 0 {
		o.ChallengeTTL = defaultChallengeTTL
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultChallengeTTL
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return o
}

// Factor 通行密钥因子（kind=webauthn，主 / 二次因子共用一份实现）。
type Factor struct {
	ceremony *ceremony
	codec    *security.Codec
	store    WebauthnStore
	queue    SignCountPusher
	clock    func() time.Time
	ttl      time.Duration
}

// New 构造因子；codec / store 必须注入，queue 可留空（投递降级）。
func New(codec *security.Codec, store WebauthnStore, queue SignCountPusher, opts Options) (*Factor, error) {
	opts = opts.effective()
	if opts.RPID == "" || len(opts.RPOrigins) == 0 {
		return nil, fmt.Errorf("webauthn: RPID and RPOrigins are required")
	}
	c, err := newCeremony(RPConfig{
		RPID:          opts.RPID,
		RPDisplayName: opts.RPDisplayName,
		RPOrigins:     opts.RPOrigins,
		Timeout:       opts.Timeout,
	})
	if err != nil {
		return nil, err
	}
	return &Factor{
		ceremony: c,
		codec:    codec,
		store:    store,
		queue:    queue,
		clock:    opts.Clock,
		ttl:      opts.ChallengeTTL,
	}, nil
}

// Kind 固定 webauthn。
func (f *Factor) Kind() factor.FactorKind { return factor.FactorWebAuthn }

// Usages 主因子与二次因子均可用（§8.3 行 1051、§1.10 行 308）。
func (f *Factor) Usages() []factor.Usage {
	return []factor.Usage{factor.UsagePrimary, factor.UsageSecondary}
}

// Steps challenge → form（§1.10 行 308）。
func (f *Factor) Steps() []factor.StepKind {
	return []factor.StepKind{factor.StepChallenge, factor.StepForm}
}

// Start 处理 challenge 步：生成 32 字节随机 challenge，绑定 login_token 的
// ch.nonce，经 challenge_data 下发完整 PublicKeyCredentialRequestOptions
// （固定 usernameless、allowCredentials 恒空，§8.3 行 1045-1048）。
func (f *Factor) Start(ctx *factor.FactorContext) (*factor.StepResult, error) {
	if ctx == nil || ctx.Login == nil {
		return nil, fmt.Errorf("webauthn: login state not configured")
	}
	challenge, err := security.RandomBytes(challengeLen)
	if err != nil {
		return nil, fmt.Errorf("webauthn: generate challenge: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(challenge)

	// 绑定 login_token 的 ch.nonce（§8.3 行 1046）；保留 ch 已有的
	// purpose / target，不覆盖登录流程态。
	ch := ctx.Login.GetCh()
	if ch == nil {
		ch = &token.Challenge{}
		ctx.Login.Ch = ch
	}
	ch.Nonce = nonce

	data, err := f.ceremony.requestOptions(challenge)
	if err != nil {
		return nil, err
	}
	return &factor.StepResult{
		Kind:          factor.StepForm,
		Method:        factor.FactorWebAuthn,
		ChallengeData: data,
		ExpiresIn:     int64(f.ttl.Seconds()),
	}, nil
}

// Verify 校验断言（§8.3 行 1049）：challenge 匹配、origin、rpId hash、
// 断言签名与 signCount 递增，通过后把 sign_count 投递延迟队列（不阻塞响应）。
func (f *Factor) Verify(ctx *factor.FactorContext) (*factor.VerifyResult, error) {
	if ctx == nil || ctx.Login == nil || ctx.Payload == nil || ctx.Payload.Credential == nil {
		return &factor.VerifyResult{Status: StatusInvalidRequest}, nil
	}
	storedChallenge := ctx.Login.GetCh().GetNonce()
	if storedChallenge == "" {
		return &factor.VerifyResult{Status: StatusInvalidRequest}, nil
	}
	if f.store == nil {
		return nil, fmt.Errorf("webauthn: store not configured")
	}

	credID, err := credentialIDOf(ctx.Payload.Credential)
	if err != nil {
		return &factor.VerifyResult{Status: StatusInvalidRequest}, nil
	}
	stored, err := f.store.FindByCredentialID(ctx.Context, credID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return failure(), nil
		}
		return nil, err
	}
	if stored == nil {
		return failure(), nil
	}

	res, err := f.ceremony.verifyAssertion(ctx.Payload.Credential, storedChallenge, stored.PublicKey)
	if err != nil {
		// 四项固定校验任一不过，统一按认证失败，不暴露内部细节。
		return failure(), nil
	}
	if !counterIncreases(stored.SignCount, res.SignCount) {
		return failure(), nil
	}
	// 二次因子阶段反查到的用户必须与 login_token 的 uid 一致，杜绝绕过主因子
	// （§7.3 行 1002）。主因子阶段 uid=0，不做该约束。
	if uid := ctx.Login.GetUid(); uid != 0 && len(ctx.Login.GetPassed()) > 0 && stored.UserID != uid {
		return failure(), nil
	}

	// 不阻塞响应：投递 UPDATE ... SET sign_count=?（§8.3 行 1049）。
	enqueueSignCount(f.queue, stored.ID, res.SignCount)
	return &factor.VerifyResult{Passed: true, UID: stored.UserID}, nil
}

// RegistrationChallenge 账号域注册 challenge 产出（§3.6 行 921-928）。
type RegistrationChallenge struct {
	Token         string
	ChallengeData *structpb.Struct
	ExpiresIn     int64
}

// RegistrationVerify 账号域注册 verify 产出；Status 非空即失败结论
// （invalid_request / code_expired）。
type RegistrationVerify struct {
	UID          int64
	CredentialID string
	PublicKey    []byte
	SignCount    int64
	Status       string
}

// BeginRegistration 账号域注册 challenge 步：无 login_token，改签独立原子
// token（§3.6 行 931、§8.3 行 1052），并下发完整
// PublicKeyCredentialCreationOptions（要求 resident key）。
func (f *Factor) BeginRegistration(uid int64) (*RegistrationChallenge, error) {
	if uid == 0 {
		return nil, fmt.Errorf("webauthn: registration requires a session uid")
	}
	if f.codec == nil {
		return nil, fmt.Errorf("webauthn: codec not configured")
	}
	challenge, err := security.RandomBytes(challengeLen)
	if err != nil {
		return nil, fmt.Errorf("webauthn: generate challenge: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(challenge)
	data, err := f.ceremony.creationOptions([]byte(strconv.FormatInt(uid, 10)), challenge)
	if err != nil {
		return nil, err
	}
	tok, err := issueRegistrationToken(f.codec, uid, nonce, f.clock(), f.ttl)
	if err != nil {
		return nil, fmt.Errorf("webauthn: issue registration token: %w", err)
	}
	return &RegistrationChallenge{
		Token:         tok,
		ChallengeData: data,
		ExpiresIn:     int64(f.ttl.Seconds()),
	}, nil
}

// FinishRegistration 账号域注册 verify 步：解析校验独立原子 token（篡改 /
// 无效 → invalid_request，过期 → code_expired），再校验 attestation 的
// challenge / origin / rpId / 签名四项固定。建库归账号域卡（NON-GOALS）。
func (f *Factor) FinishRegistration(tok string, credential *structpb.Struct) *RegistrationVerify {
	uid, challenge, status := parseRegistrationToken(f.codec, tok, f.clock())
	if status != "" {
		return &RegistrationVerify{Status: status}
	}
	if credential == nil {
		return &RegistrationVerify{Status: StatusInvalidRequest}
	}
	res, err := f.ceremony.verifyAttestation(credential, challenge)
	if err != nil {
		return &RegistrationVerify{Status: StatusInvalidRequest}
	}
	return &RegistrationVerify{
		UID:          uid,
		CredentialID: res.CredentialID,
		PublicKey:    res.PublicKey,
		SignCount:    res.SignCount,
	}
}

// credentialIDOf 从前端原样透传的断言对象取 rawId（base64url），供
// FindByCredentialID 反查；不解析其余字段（§2.6 行 548）。
func credentialIDOf(s *structpb.Struct) (string, error) {
	fields := s.GetFields()
	raw, ok := fields["rawId"]
	if !ok {
		raw, ok = fields["id"]
	}
	if !ok {
		return "", fmt.Errorf("webauthn: credential rawId missing")
	}
	v, ok := raw.GetKind().(*structpb.Value_StringValue)
	if !ok || v.StringValue == "" {
		return "", fmt.Errorf("webauthn: credential rawId must be a string")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(v.StringValue)
	if err != nil || len(decoded) == 0 {
		return "", fmt.Errorf("webauthn: credential rawId not base64url")
	}
	return v.StringValue, nil
}

// counterIncreases signCount 递增判定（防克隆，§8.3 行 1049）：认证器不支持
// 计数器时两侧均为 0，按 W3C 规范与库 Authenticator.UpdateCounter 口径跳过；
// 其余情形断言计数必须严格大于存储值。
func counterIncreases(stored, next int64) bool {
	if stored == 0 && next == 0 {
		return true
	}
	return next > stored
}

func failure() *factor.VerifyResult {
	return &factor.VerifyResult{Status: StatusInvalidCredentials}
}
