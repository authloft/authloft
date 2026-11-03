// 会话校验四步（docs/后端架构.md §11.1 行 1178-1188，每请求）：
//  1. 解 session_token（验 kid → 取密钥 → 解密），失败即未登录；
//  2. exp 校验，过期即未登录；
//  3. epoch 比对：epochs.Current 三级链（进程内 localCache TTL 60s →
//     Redis GET al:pwdep:{uid} → 缺失回源注入函数并 SET 新值 TTL 24h），
//     token.epoch != cur 即会话失效；
//  4. 通过 → 返回载荷（uid/amr/sid 可直接注入 ctx，见 token.go）。
//
// 自包含不落盘：全程不查任何会话记录类键（§11.1 行 1173）。
package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"authloft/gen/go/token"
)

// EpochReader 当前 epoch 读取接口（cache.EpochStore 实现）：返回 uid
// 当前 user.epoch。接口化便于测试注入与装配解耦。
type EpochReader interface {
	Current(ctx context.Context, uid int64) (int64, error)
}

// 校验失败错误（§11.1）。middleware 按错误语义决定响应：
// 未登录类不携带会话身份；epoch 读取链故障属基础设施错误，不得与
// 未登录混同——避免把 Redis/DB 故障误判为登出态。
var (
	// ErrNotAuthenticated 未登录：解 token 失败（kid 未知 / 密文篡改 /
	// 跨 purpose 串用）或 exp 已过期。
	ErrNotAuthenticated = errors.New("session: not authenticated")
	// ErrSessionStale 会话失效：epoch 与 al:pwdep:{uid} 不一致（改密 /
	// 重置 / 管理员禁用后旧令牌仍在有效期内——§1.9 行 292）。
	ErrSessionStale = errors.New("session: stale (epoch mismatch)")
)

// Verifier 会话校验器。
type Verifier struct {
	tokens *Tokens
	epochs EpochReader
	now    func() time.Time
}

// NewVerifier 构造（tokens 与 epoch 读取链由装配方注入）。
func NewVerifier(tokens *Tokens, epochs EpochReader) *Verifier {
	return &Verifier{tokens: tokens, epochs: epochs, now: time.Now}
}

// Verify 执行 §11.1 四步校验，通过返回载荷。epoch 读取链故障（Redis
// 与回源均失败）返回包装错误（内部错误语义，非未登录）。
func (v *Verifier) Verify(ctx context.Context, sessionToken string) (*token.SessionTokenPayload, error) {
	// 步骤 1：解 token，失败即未登录（kid / 解密 / base64 / purpose 任一）。
	p, err := v.tokens.Parse(sessionToken)
	if err != nil {
		return nil, ErrNotAuthenticated
	}
	// 步骤 2：exp 校验（exp 为 Unix 秒；到点即过期）。
	if v.now().Unix() >= p.GetExp() {
		return nil, ErrNotAuthenticated
	}
	// 步骤 3：epoch 比对（三级链在 EpochReader 内）。
	cur, err := v.epochs.Current(ctx, p.GetId())
	if err != nil {
		return nil, fmt.Errorf("session: read epoch (uid=%d): %w", p.GetId(), err)
	}
	if p.GetEpoch() != cur {
		return nil, ErrSessionStale
	}
	// 步骤 4：通过，载荷直接可用。
	return p, nil
}
