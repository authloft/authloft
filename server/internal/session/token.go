// Package session 会话域核心（docs/后端架构.md §11）：令牌签发 / 解析、
// 校验四步（§11.1）、续期重签（§11.5）与 Cookie 属性构造（接口文档 §1.9）。
// 会话令牌自包含、不落盘：校验只依赖令牌自身与 epoch（§11.1 行 1173），
// 绝不查会话记录类键。叶子件风格：Codec / epoch 读取链 / Cookie 名与
// TTL 均由构造注入，不读 settings / config。
//
// 本文件是签发 / 解析入口与 ctx 存取助手：固定 purpose=session 消费
// token.SessionTokenPayload（§11.6.3），加解密实现复用 security.Codec
// （§11.6.1 唯一封装）。
package session

import (
	"context"

	"authloft/gen/go/token"
	"authloft/internal/security"
)

// ctxKey ctx 注入键的私有类型：包外无法伪造同型键，防碰撞与越权写入。
type ctxKey int

const (
	ctxKeyUID ctxKey = iota
	ctxKeyAMR
	ctxKeySID
)

// WithSessionContext 把会话身份（uid/amr/sid）注入 ctx（§11.1 步骤 4：
// 校验通过后直接可用，RPC / OIDC 无需再查存储）。middleware 在校验
// 通过后调用；注入的是载荷值本身，不携带令牌串。
func WithSessionContext(ctx context.Context, p *token.SessionTokenPayload) context.Context {
	ctx = context.WithValue(ctx, ctxKeyUID, p.GetId())
	ctx = context.WithValue(ctx, ctxKeyAMR, p.GetAmr())
	ctx = context.WithValue(ctx, ctxKeySID, p.GetSid())
	return ctx
}

// UIDFromContext 读取注入的 uid；未注入（未登录请求）返回 false。
func UIDFromContext(ctx context.Context) (int64, bool) {
	v, ok := ctx.Value(ctxKeyUID).(int64)
	return v, ok
}

// AMRFromContext 读取注入的认证方法列表（如 ["pwd","otp"]）。
func AMRFromContext(ctx context.Context) ([]string, bool) {
	v, ok := ctx.Value(ctxKeyAMR).([]string)
	return v, ok
}

// SIDFromContext 读取注入的会话 ID。
func SIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKeySID).(string)
	return v, ok
}

// Tokens 会话令牌签发 / 解析入口（security.Codec 的会话域薄封装）：
// 固定 purpose=session，载荷用 token.SessionTokenPayload。
type Tokens struct {
	codec *security.Codec
}

// NewTokens 构造（codec 由装配方构造注入，本包不建 KeyStore）。
func NewTokens(codec *security.Codec) *Tokens {
	return &Tokens{codec: codec}
}

// Sign 签发会话令牌（§11.6.1 封装；nonce 每次 Seal 重随机）。
func (t *Tokens) Sign(p *token.SessionTokenPayload) (string, error) {
	return t.codec.Seal(security.PurposeSession, p)
}

// Parse 解析会话令牌。kid 未知 / 密文篡改 / 跨 purpose 串用一律失败
// （§11.1 步骤 1：失败即未登录；AAD 隔离见 §11.6.1）。
func (t *Tokens) Parse(tok string) (*token.SessionTokenPayload, error) {
	return security.Open[token.SessionTokenPayload](t.codec, security.PurposeSession, tok)
}
