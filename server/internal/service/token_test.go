// token_test.go 覆盖 TokenService/DecodeSession 的续期重签与失败语义
// （docs/接口文档.md §7.1、docs/后端架构.md §17 行 1737）：Fake EpochReader +
// 真实 security.Codec（复用 session_test.go 的 testTokens）。Renewer 无存储
// 依赖，Fake EpochReader 只有只读 Current 接口（无写方法），故"零存储写入"
// 由结构天然成立；额外断言 epoch 读取次数佐证。
package service

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	rpcv1 "authloft/gen/go/api/rpc/v1"
	"authloft/gen/go/token"
	"authloft/internal/session"
)

// countingEpochReader 只读 Fake EpochReader：记录调用次数，无任何写接口。
type countingEpochReader struct {
	epoch int64
	calls int
}

func (f *countingEpochReader) Current(context.Context, int64) (int64, error) {
	f.calls++
	return f.epoch, nil
}

// newTokenService 构造被测 service（真实 Codec 签发的令牌 + 注入 TTL）。
func newTokenService(t *testing.T, epoch int64, ttl time.Duration) (*TokenService, *session.Tokens, *countingEpochReader) {
	t.Helper()
	tokens := testTokens(t)
	epochs := &countingEpochReader{epoch: epoch}
	return NewTokenService(session.NewVerifier(tokens, epochs), session.NewRenewer(tokens, ttl)), tokens, epochs
}

// signPayload 用真实 Codec 签发指定载荷并返回令牌串。
func signPayload(t *testing.T, tokens *session.Tokens, p *token.SessionTokenPayload) string {
	t.Helper()
	tok, err := tokens.Sign(p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return tok
}

// tamper 翻转令牌中部一个 base64url 字符，模拟密文 / tag 被篡改。
func tamper(tok string) string {
	b := []byte(tok)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// TestDecodeSessionRenewsToken 有效会话：返回非空 renewed_token，id / epoch /
// amr / sid 与旧令牌一致，iat / exp 刷新（新载荷 iat=now、exp=iat+ttl）。
func TestDecodeSessionRenewsToken(t *testing.T) {
	const ttl = 7 * 24 * time.Hour
	svc, tokens, epochs := newTokenService(t, 7, ttl)

	now := time.Now().Unix()
	old := &token.SessionTokenPayload{
		Id:    42,
		Epoch: 7,
		Amr:   []string{"pwd", "otp"},
		Sid:   "sid-0001",
		Iat:   now - 3600,
		Exp:   now + 6*24*3600,
	}
	oldTok := signPayload(t, tokens, old)

	resp, err := svc.DecodeSession(context.Background(), &rpcv1.DecodeSessionRequest{SessionToken: oldTok})
	if err != nil {
		t.Fatalf("DecodeSession: %v", err)
	}
	if resp.GetRenewedToken() == "" {
		t.Fatal("renewed_token must be non-empty on success")
	}
	if resp.GetRenewedToken() == oldTok {
		t.Fatal("renewed_token must be a newly sealed token")
	}
	if resp.GetId() != old.GetId() || resp.GetEpoch() != old.GetEpoch() || resp.GetSid() != old.GetSid() {
		t.Fatalf("identity changed: got id=%d epoch=%d sid=%q", resp.GetId(), resp.GetEpoch(), resp.GetSid())
	}
	if !reflect.DeepEqual(resp.GetAmr(), old.GetAmr()) {
		t.Fatalf("amr = %v, want %v", resp.GetAmr(), old.GetAmr())
	}
	if resp.GetIat() <= old.GetIat() {
		t.Fatalf("iat not refreshed: got %d, want > %d", resp.GetIat(), old.GetIat())
	}
	if want := resp.GetIat() + int64(ttl/time.Second); resp.GetExp() != want {
		t.Fatalf("exp = %d, want iat+ttl = %d", resp.GetExp(), want)
	}

	p, err := tokens.Parse(resp.GetRenewedToken())
	if err != nil {
		t.Fatalf("Parse renewed_token: %v", err)
	}
	if p.GetId() != resp.GetId() || p.GetEpoch() != resp.GetEpoch() ||
		p.GetSid() != resp.GetSid() || p.GetIat() != resp.GetIat() || p.GetExp() != resp.GetExp() {
		t.Fatalf("renewed payload mismatch: %+v vs response %+v", p, resp)
	}
	if !reflect.DeepEqual(p.GetAmr(), resp.GetAmr()) {
		t.Fatalf("renewed amr = %v, want %v", p.GetAmr(), resp.GetAmr())
	}
	// 校验只读 epoch 一次；Renew 不触碰任何存储（Fake 无写接口）。
	if epochs.calls != 1 {
		t.Fatalf("epoch calls = %d, want 1（仅校验读取，重签零存储）", epochs.calls)
	}
}

// TestDecodeSessionBadToken 篡改 / 垃圾令牌 → ErrNotAuthenticated，且不查 epoch。
func TestDecodeSessionBadToken(t *testing.T) {
	svc, tokens, epochs := newTokenService(t, 7, 7*24*time.Hour)
	now := time.Now().Unix()
	valid := signPayload(t, tokens, &token.SessionTokenPayload{
		Id: 42, Epoch: 7, Amr: []string{"pwd"}, Sid: "sid-0001",
		Iat: now, Exp: now + 3600,
	})

	for _, tc := range []struct{ name, tok string }{
		{"empty", ""},
		{"garbage", "not-a-token"},
		{"tampered", tamper(valid)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.DecodeSession(context.Background(), &rpcv1.DecodeSessionRequest{SessionToken: tc.tok})
			if !errors.Is(err, session.ErrNotAuthenticated) {
				t.Fatalf("err = %v, want ErrNotAuthenticated", err)
			}
		})
	}
	// 步骤①失败即止，全程不查 epoch（更无存储写入）。
	if epochs.calls != 0 {
		t.Fatalf("epoch calls = %d, want 0（坏令牌不查 epoch）", epochs.calls)
	}
}

// TestDecodeSessionExpired 过期 → ErrNotAuthenticated，不重签、不查 epoch。
func TestDecodeSessionExpired(t *testing.T) {
	svc, tokens, epochs := newTokenService(t, 7, 7*24*time.Hour)
	now := time.Now().Unix()
	tok := signPayload(t, tokens, &token.SessionTokenPayload{
		Id: 42, Epoch: 7, Amr: []string{"pwd"}, Sid: "sid-0001",
		Iat: now - 7200, Exp: now - 60,
	})

	if _, err := svc.DecodeSession(context.Background(), &rpcv1.DecodeSessionRequest{SessionToken: tok}); !errors.Is(err, session.ErrNotAuthenticated) {
		t.Fatalf("err = %v, want ErrNotAuthenticated", err)
	}
	if epochs.calls != 0 {
		t.Fatalf("epoch calls = %d, want 0（过期即止）", epochs.calls)
	}
}

// TestDecodeSessionEpochMismatch epoch 不一致 → ErrSessionStale，不重签。
func TestDecodeSessionEpochMismatch(t *testing.T) {
	svc, tokens, epochs := newTokenService(t, 8, 7*24*time.Hour) // 已改密 → 当前 8
	now := time.Now().Unix()
	tok := signPayload(t, tokens, &token.SessionTokenPayload{
		Id: 42, Epoch: 7, Amr: []string{"pwd"}, Sid: "sid-0001",
		Iat: now, Exp: now + 3600,
	})

	resp, err := svc.DecodeSession(context.Background(), &rpcv1.DecodeSessionRequest{SessionToken: tok})
	if !errors.Is(err, session.ErrSessionStale) {
		t.Fatalf("err = %v, want ErrSessionStale", err)
	}
	if resp != nil {
		t.Fatalf("response must be nil on failure, got %+v", resp)
	}
	if epochs.calls != 1 {
		t.Fatalf("epoch calls = %d, want 1", epochs.calls)
	}
}
