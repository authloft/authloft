// session.go 建会话适配器（docs/后端架构.md §3.7 行 364、§11.1 行 1160、
// §11.5 行 1228-1230）：实现 orchestrator.SessionWriter，一次 Write 完成
// sid 生成、epoch 读取与 session_token 签发。会话令牌自包含、不落盘，
// 本文件不写 DB / Redis；epoch 只经注入的 EpochReader 读取。
package service

import (
	"context"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/security"
	"authloft/internal/session"
	"authloft/internal/settings"
)

// defaultSessionTTL session_ttl 键缺失 / 非法时的回落值（接口文档 §1.9：
// 默认有效期 7 天；§5.6 默认 604800 秒）。
const defaultSessionTTL int64 = 604800

// sidLength session ID 字符数（§11.6.3 只约束 sid 为非空串，长度由实现定）。
const sidLength = 32

// EpochReader 读取用户当前安全版本号（§11.1 步骤 3）；装配层适配
// cache.EpochStore，本层不感知 Redis / DB。
type EpochReader interface {
	Current(ctx context.Context, uid int64) (int64, error)
}

// SessionSettings 本适配器用到的配置窄接口（装配层传 *settings.Store）。
type SessionSettings interface {
	GetInt64(key string) (int64, bool)
}

// SessionWriter 会话写入适配器：生成 sid、读 epoch、签发 session_token。
// 满足 orchestrator.SessionWriter 签名（terminal.go 行 18-21）。
type SessionWriter struct {
	Tokens   *session.Tokens
	Epochs   EpochReader
	Settings SessionSettings
	// Now 可注入时钟；为空时使用 time.Now。
	Now func() time.Time
}

// NewSessionWriter 注入依赖；Now 为空时使用 time.Now。
func NewSessionWriter(tokens *session.Tokens, epochs EpochReader, cfg SessionSettings) *SessionWriter {
	return &SessionWriter{Tokens: tokens, Epochs: epochs, Settings: cfg}
}

// Write 建会话（§7.3 行 995）：生成 sid → 读 epoch → 组装载荷 → 签发令牌，
// 返回 (sid, sessionToken)。零存储写入（§11.1 行 1160、§11.5 行 1230）。
func (w *SessionWriter) Write(ctx context.Context, uid int64, amr []string) (string, string, error) {
	sid, err := security.RandomString(sidLength)
	if err != nil {
		return "", "", err
	}
	epoch, err := w.Epochs.Current(ctx, uid)
	if err != nil {
		return "", "", err
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	t := now()
	p := &token.SessionTokenPayload{
		Id:    uid,
		Epoch: epoch,
		Amr:   append([]string(nil), amr...),
		Sid:   sid,
		Iat:   t.Unix(),
		Exp:   t.Add(time.Duration(w.sessionTTL()) * time.Second).Unix(),
	}
	tok, err := w.Tokens.Sign(p)
	if err != nil {
		return "", "", err
	}
	return sid, tok, nil
}

// sessionTTL 读取 session_ttl（§1.9 / §5.6）；键缺失或非法（<=0）回落默认值。
func (w *SessionWriter) sessionTTL() int64 {
	if w.Settings != nil {
		if v, ok := w.Settings.GetInt64(settings.KeySessionTtl); ok && v > 0 {
			return v
		}
	}
	return defaultSessionTTL
}
