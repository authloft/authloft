// 会话续期重签（docs/后端架构.md §11.5 / 接口文档 §1.9 行 289-291）：
// 每次校验通过后均重签 session_token——iat / exp 按当前时刻刷新、
// epoch / sid（及 id / amr）不变，纯计算、无任何存储写入（§18 行 1735）。
// 下发渠道（Cookie 来源 → Set-Cookie；Header 来源 → X-Authloft-Token
// 响应头）归 middleware，本文件不碰响应。
package session

import (
	"time"

	"authloft/gen/go/token"
)

// Renewer 会话令牌重签器。TTL 由构造注入（settings 键 session_ttl，
// 默认 7 天；快照热更由装配方注入新值）。结构上无任何存储依赖——
// 重签只做字段重算与重新 Seal（内存操作）。
type Renewer struct {
	tokens *Tokens
	ttl    time.Duration
	now    func() time.Time
}

// NewRenewer 构造。ttl 为新令牌有效期（exp = iat + ttl）。
func NewRenewer(tokens *Tokens, ttl time.Duration) *Renewer {
	return &Renewer{tokens: tokens, ttl: ttl, now: time.Now}
}

// Renew 重签载荷：新 iat = now、exp = now + ttl，id / epoch / amr / sid
// 原样保留；返回（新载荷, 新令牌串）。不触碰 epoch 存储与任何队列
// （§21.2 D：断言零存储写入——Renewer 无存储依赖，测试以 fake redis
// 调用计数佐证）。
func (r *Renewer) Renew(p *token.SessionTokenPayload) (*token.SessionTokenPayload, string, error) {
	now := r.now()
	fresh := &token.SessionTokenPayload{
		Id:    p.GetId(),
		Epoch: p.GetEpoch(),
		Amr:   p.GetAmr(),
		Sid:   p.GetSid(),
		Iat:   now.Unix(),
		Exp:   now.Add(r.ttl).Unix(),
	}
	tok, err := r.tokens.Sign(fresh)
	if err != nil {
		return nil, "", err
	}
	return fresh, tok, nil
}
