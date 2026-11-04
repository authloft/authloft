// Package orchestrator 登录流程编排（docs/后端架构.md §3.6、§7）。
// 本文件只落地 login_token 的签发 / 解析 / 重签：载荷见 §11.6.2 行 1257-1287，
// 固定 purpose=login、exp 10 分钟（§7.1 行 969）；加解密复用 security.Codec
// （§11.6.1 唯一封装），不另行实现加密。
package orchestrator

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"authloft/gen/go/token"
	"authloft/internal/security"
)

// loginTokenTTL login_token 固定有效期（§7.1 行 969：exp 固定 10 分钟）。
const loginTokenTTL = 10 * time.Minute

// loginFlows login_token 允许的 flow 取值（§11.6.2 行 1264：login|register|reset）。
var loginFlows = map[string]bool{
	"login":    true,
	"register": true,
	"reset":    true,
}

// challengePurposes login_token 内 ch.purpose 的合法取值（§11.6.2 行 1286-1287）：
// bind / webauthn 保留在枚举命名空间，但不属于 login_token，见到即拒绝。
var challengePurposes = map[string]bool{
	"login":    true,
	"register": true,
	"reset":    true,
	"mfa":      true,
}

// 可判别错误：调用方用 errors.Is 区分过期与其它非法令牌。
var (
	// ErrTokenInvalid 篡改、跨 purpose、载荷字段非法等。
	ErrTokenInvalid = errors.New("orchestrator: invalid login token")
	// ErrTokenExpired 令牌已过期（exp <= now）。
	ErrTokenExpired = errors.New("orchestrator: login token expired")
)

// State login_token 签发 / 解析 / 重签入口（§3.6 行 351）。
// now 由构造方注入，测试可替换；生产使用 time.Now。
type State struct {
	codec *security.Codec
	now   func() time.Time
}

// NewState 构造（codec 由装配方按 sign_key.login 构造注入，§7.1 行 969）。
func NewState(codec *security.Codec) *State {
	return &State{codec: codec, now: time.Now}
}

// Issue 签发 login_token：以当前时间刷新 iat / exp 后按 purpose=login 加密。
// 调用方传入的 payload 会被就地打上时间戳。
func (s *State) Issue(p *token.LoginTokenPayload) (string, error) {
	if p == nil {
		return "", fmt.Errorf("%w: nil payload", ErrTokenInvalid)
	}
	s.stamp(p)
	if err := s.validate(p); err != nil {
		return "", err
	}
	return s.codec.Seal(security.PurposeLogin, p)
}

// Parse 解析并校验 login_token。篡改 / 跨 purpose / 未知 kid / 载荷字段非法
// 返回 ErrTokenInvalid；过期返回 ErrTokenExpired（§7.1 行 969-972）。
func (s *State) Parse(tok string) (*token.LoginTokenPayload, error) {
	p, err := security.Open[token.LoginTokenPayload](s.codec, security.PurposeLogin, tok)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if err := s.validate(p); err != nil {
		return nil, err
	}
	return p, nil
}

// Renew 重签 login_token：先解析旧令牌（过期 / 篡改一律拒绝），在副本上
// 执行 mutate（可为 nil），保留原载荷全部字段，再刷新 iat / exp 后重新加密。
// 返回新令牌与本次使用的载荷。
func (s *State) Renew(tok string, mutate func(*token.LoginTokenPayload)) (string, *token.LoginTokenPayload, error) {
	p, err := s.Parse(tok)
	if err != nil {
		return "", nil, err
	}
	next, ok := proto.Clone(p).(*token.LoginTokenPayload)
	if !ok {
		return "", nil, fmt.Errorf("%w: clone payload", ErrTokenInvalid)
	}
	if mutate != nil {
		mutate(next)
	}
	s.stamp(next)
	if err := s.validate(next); err != nil {
		return "", nil, err
	}
	signed, err := s.codec.Seal(security.PurposeLogin, next)
	if err != nil {
		return "", nil, fmt.Errorf("orchestrator: seal login token: %w", err)
	}
	return signed, next, nil
}

// stamp 打上签发 / 过期时间（exp 固定 10 分钟）。
func (s *State) stamp(p *token.LoginTokenPayload) {
	now := s.now()
	p.Iat = now.Unix()
	p.Exp = now.Add(loginTokenTTL).Unix()
}

// validate 校验载荷与当前时间：exp 必须存在且未过期；flow 与 ch.purpose
// 必须落在 §11.6.2 的合法集合内。
func (s *State) validate(p *token.LoginTokenPayload) error {
	if p.GetExp() <= 0 {
		return fmt.Errorf("%w: missing exp", ErrTokenInvalid)
	}
	if s.now().Unix() >= p.GetExp() {
		return fmt.Errorf("%w: exp=%d", ErrTokenExpired, p.GetExp())
	}
	if !loginFlows[p.GetFlow()] {
		return fmt.Errorf("%w: flow %q", ErrTokenInvalid, p.GetFlow())
	}
	if ch := p.GetCh(); ch != nil && !challengePurposes[ch.GetPurpose()] {
		return fmt.Errorf("%w: challenge purpose %q", ErrTokenInvalid, ch.GetPurpose())
	}
	return nil
}
