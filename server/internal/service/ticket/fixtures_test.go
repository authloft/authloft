// fixtures_test.go 本包自持的测试 fake（拆包后不可跨包复用）：
// tpUsers / tpTicketPayloads / tpSettings / tpCodec 从 thirdparty_test.go、
// qrSessions 从 qrcode_test.go 原样复制，保持同口径。
package ticket

import (
	"context"
	"testing"

	"database/sql"

	"authloft/gen/go/token"
	"authloft/internal/repo/model"
	"authloft/internal/security"
)

// tpUsers factor.UserRepo + ThirdpartyUserLookup 的 fake。
type tpUsers struct {
	byID    map[int64]*model.User
	byEmail map[string]*model.User
	byPhone map[string]*model.User
	// failsAt > 0 时，FindByID 从第 failsAt 次调用起返回 err（模拟依赖在
	// 流程中途不可用）；finds 为累计调用次数。
	failsAt int
	finds   int
	err     error
}

func (u *tpUsers) FindByID(_ context.Context, id int64) (*model.User, error) {
	u.finds++
	if u.err != nil && u.failsAt > 0 && u.finds >= u.failsAt {
		return nil, u.err
	}
	if m, ok := u.byID[id]; ok {
		return m, nil
	}
	return nil, sql.ErrNoRows
}

func (u *tpUsers) FindByEmail(_ context.Context, email string) (*model.User, error) {
	if m, ok := u.byEmail[email]; ok {
		return m, nil
	}
	return nil, sql.ErrNoRows
}

func (u *tpUsers) FindByPhone(_ context.Context, phone string) (*model.User, error) {
	if m, ok := u.byPhone[phone]; ok {
		return m, nil
	}
	return nil, sql.ErrNoRows
}

// tpTicketPayloads TicketPayloadStore 的 fake：内存快照 + 读取
// 记录 + 可注入 infra 错误（Read / Write 分开）；Read 缺失返回 (nil, nil)。
type tpTicketPayloads struct {
	snapshots map[string]*token.TicketPayload
	reads     []string
	err       error
	writeErr  error
}

func (f *tpTicketPayloads) Write(_ context.Context, p *token.TicketPayload) error {
	if f.writeErr != nil {
		return f.writeErr
	}
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

// qrSessions SessionVerifier fake。
type qrSessions struct {
	uid int64
	err error
}

func (s *qrSessions) Verify(context.Context, string) (*token.SessionTokenPayload, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &token.SessionTokenPayload{Id: s.uid}, nil
}

// amrThirdParty 与 service.AMRThirdParty 同值（拆包后测试自持，避免
// ticket → service 反向依赖成环）。
const amrThirdParty = "thirdparty"
