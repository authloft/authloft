// 会话校验四步（docs/后端架构.md §11.1，每请求）：
//  1. 解 session_token（验 kid → 取密钥 → 解密），失败即未登录；
//  2. exp 校验，过期即未登录；
//  3. 失效检查（一条 MGET 双键在 EpochReader 内完成：epoch 比对 + sid
//     逐出判定合并为一次 Redis 访问；Redis 命令级故障的 fail-open 回源
//     降级封装在实现内，本层只消费 (epoch, revoked, err) 三元组）——
//     已逐出 → ErrSessionRevoked；epoch 不一致 → ErrSessionStale；
//  4. 通过 → 返回载荷（uid/amr/sid 可直接注入 ctx，见 token.go）。
//
// 自包含不落盘：全程不查任何会话记录类键（§11.1）。
package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"authloft/gen/go/token"
)

// EpochReader 会话失效检查接口（cache.EpochStore 实现）：一次读返回 uid
// 当前 epoch 与 sid 逐出标记。接口化便于测试注入与装配解耦。
type EpochReader interface {
	Check(ctx context.Context, uid int64, sid string) (epoch int64, revoked bool, err error)
}

// 校验失败错误（§11.1）。middleware 按错误语义决定响应：
// 未登录类不携带会话身份；失效检查读取链故障属基础设施错误，不得与
// 未登录混同——避免把 Redis/DB 故障误判为登出态。
var (
	// ErrNotAuthenticated 未登录：解 token 失败（kid 未知 / 密文篡改 /
	// 跨 purpose 串用）或 exp 已过期。
	ErrNotAuthenticated = errors.New("session: not authenticated")
	// ErrSessionStale 会话失效：epoch 与 al:pwdep:{uid} 不一致（改密 /
	// 重置 / 管理员禁用后旧令牌仍在有效期内——§1.9）。
	ErrSessionStale = errors.New("session: stale (epoch mismatch)")
	// ErrSessionRevoked 会话已逐出：al:sess:ev:{sid} 存在（服务端主动逐出
	// 标记，§11.1 / §5.1；逐出写入口为扩展点、本期不实现，读分支先行）。
	ErrSessionRevoked = errors.New("session: revoked (sid evicted)")
)

// Verifier 会话校验器。
type Verifier struct {
	tokens *Tokens
	epochs EpochReader
	now    func() time.Time
}

// NewVerifier 构造（tokens 与失效检查链由装配方注入）。
func NewVerifier(tokens *Tokens, epochs EpochReader) *Verifier {
	return &Verifier{tokens: tokens, epochs: epochs, now: time.Now}
}

// Verify 执行 §11.1 四步校验，通过返回载荷。失效检查读取链故障（Redis
// 命令级故障且回源也失败）返回包装错误（内部错误语义，非未登录）。
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
	// 步骤 3：失效检查（一条 MGET 双键在 EpochReader 内，fail-open 降级
	// 已封装在实现内）。
	cur, revoked, err := v.epochs.Check(ctx, p.GetId(), p.GetSid())
	if err != nil {
		return nil, fmt.Errorf("session: check session state (uid=%d): %w", p.GetId(), err)
	}
	// 逐出优先于 epoch 比对：标记存在即失效，无需再看 epoch。
	if revoked {
		return nil, ErrSessionRevoked
	}
	if p.GetEpoch() != cur {
		return nil, ErrSessionStale
	}
	// 步骤 4：通过，载荷直接可用。
	return p, nil
}
