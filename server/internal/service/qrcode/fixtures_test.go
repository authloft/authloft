// fixtures_test.go 本包自持的测试 fake（拆包后不可跨包复用）：
// tpLoader / tpSessions / tpTicketPayloads / tpSettings / tpAdapter 从
// thirdparty_test.go 原样复制，与三方域测试保持同口径。
package qrcode

import (
	"context"

	"database/sql"

	"testing"

	"authloft/gen/go/token"
	"authloft/internal/provider"
	"authloft/internal/security"
)

// tpLoader ThirdpartyLoader 的 fake：按 key 返回预置 Provider。
type tpLoader struct {
	byKey map[string]*provider.Provider
}

func (l *tpLoader) Get(_ context.Context, key string) (*provider.Provider, error) {
	if p, ok := l.byKey[key]; ok {
		return p, nil
	}
	return nil, sql.ErrNoRows
}

type tpSessions struct {
	gotUID int64
	gotAMR []string
}

func (s *tpSessions) Write(_ context.Context, uid int64, amr []string) (string, string, error) {
	s.gotUID, s.gotAMR = uid, amr
	return "sid-1", "stok-1", nil
}

// tpTicketPayloads TicketPayloadStore 的 fake：内存快照 + 读取
// 记录 + 可注入 infra 错误（Read / Write 分开）；Read 缺失返回 (nil, nil)。
type tpTicketPayloads struct {
	snapshots map[string]*token.TicketPayload
	reads     []string
	err       error
	writeErr  error
	writes    int
}

func (f *tpTicketPayloads) Write(_ context.Context, p *token.TicketPayload) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writes++
	f.snapshots[p.GetTicketId()] = p
	return nil
}

func (f *tpTicketPayloads) Read(_ context.Context, ticketID string) (*token.TicketPayload, error) {
	f.reads = append(f.reads, ticketID)
	if f.err != nil {
		return nil, f.err
	}
	if p, ok := f.snapshots[ticketID]; ok {
		return p, nil
	}
	return nil, nil
}

// tpSettings SettingsReader 的 fake（mfa_methods 显式给值）。
type tpSettings struct {
	bools  map[string]bool
	slices map[string][]string
}

func (s *tpSettings) GetString(string) (string, bool) { return "", false }
func (s *tpSettings) GetInt64(string) (int64, bool)   { return 0, false }
func (s *tpSettings) GetBool(k string) (bool, bool)   { v, ok := s.bools[k]; return v, ok }
func (s *tpSettings) GetStringSlice(k string) ([]string, bool) {
	v, ok := s.slices[k]
	return v, ok
}

// tpAdapter 渠道适配器 fake：channel / 授权 URL / 三方身份可控。
type tpAdapter struct {
	channel     provider.ThirdPartyChannel
	authURL     string
	identity    *provider.ExternalIdentity
	exchangeErr error
	lastCtx     *provider.AuthContext
}

func (a *tpAdapter) Channel() provider.ThirdPartyChannel { return a.channel }

func (a *tpAdapter) BuildAuthURL(ctx *provider.AuthContext) (string, error) {
	a.lastCtx = ctx
	return a.authURL, nil
}

func (a *tpAdapter) Exchange(context.Context, provider.ExchangeInput) (*provider.Token, error) {
	if a.exchangeErr != nil {
		return nil, a.exchangeErr
	}
	return &provider.Token{Raw: map[string]any{"openid": a.identity.OpenID}}, nil
}

func (a *tpAdapter) FetchUser(context.Context, *provider.Token) (*provider.ExternalIdentity, error) {
	return a.identity, nil
}

// tpCodec 构造 32B 单密钥 Codec（seed 区分场景，避免跨 purpose 误开）。
func tpCodec(t *testing.T, seed byte) *security.Codec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return security.NewCodec(ks)
}
