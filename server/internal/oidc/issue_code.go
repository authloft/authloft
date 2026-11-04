// issue_code.go 实现 OIDC 授权码核心（docs/后端架构.md §11.6.6、§14.2/§14.3、
// docs/接口文档.md §4.2/§4.7）：按 11 字段构造 token.OidcCodePayload，
// 经 security.Codec（AAD purpose=oidc_code）封装为对客户端不透明串，
// 落 cache.OIDCCodeStore（键 al:oidc:code:{code}、TTL 120s、GETDEL 一次性），
// 消费侧解封并校验 exp / 篡改 / 跨 purpose，返回结构化载荷供 §4.3 token 端点使用。
//
// 依赖（Store / Codec / Now）一律注入，本包不连 Redis、不读配置、不注册路由。
package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/cache"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
)

// codeTTL 授权码有效期（秒）：§11.6.6 exp = iat + 120，与 Redis TTL 一致（§4.7）。
const codeTTL int64 = 120

var (
	// ErrCodeNotFound 授权码未签发 / 已消费 / 已过期（GETDEL 未命中）。
	ErrCodeNotFound = errors.New("oidc: authorization code not found or already consumed")
	// ErrCodeExpired 载荷 exp 已过期（解封成功后按 iat+120 判定）。
	ErrCodeExpired = errors.New("oidc: authorization code expired")
	// errNotConfigured 依赖未注入。
	errNotConfigured = errors.New("oidc: issuer not configured (store/codec nil)")
)

// Store 授权码存储窄接口；*cache.OIDCCodeStore 天然满足（见编译期断言），
// 测试用内存 fake 实现，不新造 Redis 访问层（§14.2 步骤 3/6）。
type Store interface {
	Set(ctx context.Context, code, value string) error
	Consume(ctx context.Context, code string) (value string, ok bool, err error)
}

// CodeIssuer 实现 orchestrator.OIDCCodeIssuer（Issue 方法），供装配层注入
// Terminal.OIDC。Codec 用 *security.Codec（内存 KeyStore 构造即可纯本地计算）。
type CodeIssuer struct {
	Store Store
	Codec *security.Codec
	Now   func() time.Time
}

// 编译期断言：既有 store 与窄接口兼容；本类型满足编排层窄接口。
var _ Store = (*cache.OIDCCodeStore)(nil)
var _ orchestrator.OIDCCodeIssuer = (*CodeIssuer)(nil)

// NewCodeIssuer 构造；Now 缺省 time.Now。
func NewCodeIssuer(store Store, codec *security.Codec) *CodeIssuer {
	return &CodeIssuer{Store: store, Codec: codec, Now: time.Now}
}

func (i *CodeIssuer) now() time.Time {
	if i != nil && i.Now != nil {
		return i.Now()
	}
	return time.Now()
}

// Issue 满足 orchestrator.OIDCCodeIssuer：生成一次性授权码并返回不透明串。
func (i *CodeIssuer) Issue(ctx context.Context, in orchestrator.OIDCIssue) (string, error) {
	return issueCode(ctx, i, in)
}

// IssueCode 与 Issue 同义（文档 §14.2 所称 "oidc.IssueCode" 的方法入口）。
func (i *CodeIssuer) IssueCode(ctx context.Context, in orchestrator.OIDCIssue) (string, error) {
	return issueCode(ctx, i, in)
}

// issueCode 核心逻辑：构造 11 字段 → Seal(purpose=oidc_code) → Set → 返回 code。
// in.State 按 §11.6.6「state / prompt 不入载荷」显式忽略。
func issueCode(ctx context.Context, i *CodeIssuer, in orchestrator.OIDCIssue) (string, error) {
	if i == nil || i.Store == nil || i.Codec == nil {
		return "", errNotConfigured
	}
	iat := i.now().Unix()
	payload := &token.OidcCodePayload{
		ClientId:            in.ClientID,
		RedirectUri:         in.RedirectURI,
		Uid:                 in.UID,
		Scope:               in.Scope,
		Nonce:               in.Nonce,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		Amr:                 in.AMR,
		AuthTime:            in.AuthTime,
		Iat:                 iat,
		Exp:                 iat + codeTTL,
	}
	sealed, err := i.Codec.Seal(security.PurposeOidcCode, payload)
	if err != nil {
		return "", fmt.Errorf("oidc: seal code: %w", err)
	}
	// code 即封装串本身（§11.6.6 对客户端不透明）；键 al:oidc:code:{code}、
	// 值同串，cache.OIDCCodeStore 原样存取、不做加解密（§4.2 / §14.3）。
	if err := i.Store.Set(ctx, sealed, sealed); err != nil {
		return "", fmt.Errorf("oidc: store code: %w", err)
	}
	return sealed, nil
}

// Consume 一次性取走授权码并解封：security.Open 用 AAD purpose=oidc_code，
// 天然拒绝篡改 / 跨 purpose；随后校验 exp，返回结构化载荷供 §4.3 使用。
func (i *CodeIssuer) Consume(ctx context.Context, code string) (*token.OidcCodePayload, error) {
	if i == nil || i.Store == nil || i.Codec == nil {
		return nil, errNotConfigured
	}
	value, ok, err := i.Store.Consume(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oidc: consume code: %w", err)
	}
	if !ok {
		return nil, ErrCodeNotFound
	}
	payload, err := security.Open[token.OidcCodePayload](i.Codec, security.PurposeOidcCode, value)
	if err != nil {
		return nil, fmt.Errorf("oidc: open code: %w", err)
	}
	if payload.GetExp() <= i.now().Unix() {
		return nil, ErrCodeExpired
	}
	return payload, nil
}
