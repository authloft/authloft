// login_ticket_test.go 统一写票 service 的可证伪用例：service 自行按目标
// 用户的二次验证启用状态写 success / mfa_pending 双分支（§2.8、§11.6.5）、
// ConfirmLoginTicket 链两种 MFA 状态、两类主体凭证推导（会话 / loginToken）、
// 主体校验、票据快照校验、写票失败与 MFA 判定依赖故障 fail-closed。
// 全部走 fake，不连 DB / Redis；loginToken 的签发 / 解析与生产同源，共用
// 同一 State；MFA 判定复用与三方登录同口径的用户 / 凭据 / 开关 fake。
package ticket

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/gen/go/token"
	"authloft/internal/cache"
	"authloft/internal/repo/model"
	"authloft/internal/service/orchestrator"
	"authloft/internal/settings"
)

// ltTickets TicketStore fake：记录写入、可注入写入失败。
type ltTickets struct {
	res      map[string]*token.TicketResult
	writes   []string
	writeErr error
}

func (f *ltTickets) WriteScanned(_ context.Context, _ string, _ *token.TicketResult) (cache.TicketWriteResult, error) {
	return cache.TicketWriteOK, nil
}
func (f *ltTickets) WriteComplete(_ context.Context, id string, res *token.TicketResult) (cache.TicketWriteResult, error) {
	f.writes = append(f.writes, id)
	if f.writeErr != nil {
		return cache.TicketWriteSkipped, f.writeErr
	}
	f.res[id] = res
	return cache.TicketWriteOK, nil
}
func (f *ltTickets) Peek(_ context.Context, id string) (*token.TicketResult, error) {
	return f.res[id], nil
}
func (f *ltTickets) Take(_ context.Context, id string) (*token.TicketResult, error) {
	return f.res[id], nil
}
func (f *ltTickets) Wait(_ context.Context, _ string, _ time.Duration) error {
	return cache.ErrTicketWaitTimeout
}

// ltCreds 自选二次验证凭据行读取 fake：按 kind 命中预置行；未命中按
// repo 口径返回 gorm.ErrRecordNotFound（正常未启用）；err 注入读取故障，
// 供 fail-closed 用例使用。
type ltCreds struct {
	byKind map[string]*model.UserCredential
	err    error
}

func (c *ltCreds) FindByUserAndKind(_ context.Context, _ int64, kind string) (*model.UserCredential, error) {
	if c.err != nil {
		return nil, c.err
	}
	if m, ok := c.byKind[kind]; ok {
		return m, nil
	}
	return nil, gorm.ErrRecordNotFound
}

// ltEnv 汇总一套全 fake 的统一写票 service 依赖。
type ltEnv struct {
	tickets     *ltTickets
	payloads    *tpTicketPayloads
	sessions    *qrSessions
	state       *orchestrator.State
	users       *tpUsers
	creds       *ltCreds
	mfaSettings *tpSettings
	svc         *LoginTicket
}

// enableMFA 把指定 uid 置为已启用二次验证（策略强制列）。
func (e *ltEnv) enableMFA(uid int64) {
	e.users.byID[uid] = &model.User{ID: uid, UserStatus: 1, MfaRequired: 1}
}

func newLTEnv(t *testing.T) *ltEnv {
	t.Helper()
	st := orchestrator.NewState(tpCodec(t, 0x70))
	tickets := &ltTickets{res: map[string]*token.TicketResult{}}
	payloads := &tpTicketPayloads{snapshots: map[string]*token.TicketPayload{}}
	// 一份合法 login-scene 快照（CreateQrcode 写入的形态，§11.6.4）。
	payloads.snapshots["tid123"] = &token.TicketPayload{
		TicketId: "tid123", ProviderKey: "scan", Scene: SceneLogin,
		Iat: 1_700_000_000, Exp: 1_700_000_600,
	}
	sessions := &qrSessions{uid: 9}
	// 默认用户存在但未启用二次验证：写票应落 success；系统开关缺省 true。
	// 各用例按需把用户置为启用 MFA / 加自选凭据行 / 关系统开关 / 注入故障。
	users := &tpUsers{byID: map[int64]*model.User{
		9:  {ID: 9, UserStatus: 1, MfaRequired: 0},
		42: {ID: 42, UserStatus: 1, MfaRequired: 0},
	}}
	creds := &ltCreds{byKind: map[string]*model.UserCredential{}}
	mfaSettings := &tpSettings{bools: map[string]bool{settings.KeyMfaEnabled: true}}
	return &ltEnv{
		tickets: tickets, payloads: payloads, sessions: sessions, state: st,
		users: users, creds: creds, mfaSettings: mfaSettings,
		svc: NewLoginTicket(LoginTicketDeps{
			Tickets:        tickets,
			TicketPayloads: payloads,
			Sessions:       sessions,
			State:          st,
			Users:          users,
			Settings:       mfaSettings,
			Credentials:    creds,
			Now:            func() time.Time { return time.Unix(1_700_000_100, 0) },
		}),
	}
}

// issueLoginToken 用环境内同一 State 签发一枚 loginToken（与生产同源）。
func (e *ltEnv) issueLoginToken(t *testing.T, p *token.LoginTokenPayload) string {
	t.Helper()
	tok, err := e.state.Issue(p)
	if err != nil {
		t.Fatalf("Issue loginToken: %v", err)
	}
	return tok
}

// TestWriteTicketStatusBranches 可证伪（§2.8、§11.6.5）：service 自行按
// 目标用户的二次验证启用状态写 success / mfa_pending 两态，回显一致；
// 写入的 TicketResult 逐字段核对（scene / channel / provider_key / exp /
// uid / v / created_at）。判定不随入参传入——把 mfaRequired 判定改坏
// （恒返回 false）会让 mfa_pending 子用例立即转红。
func TestWriteTicketStatusBranches(t *testing.T) {
	cases := []struct {
		name   string
		enable bool
		want   string
	}{
		{"未启用 MFA → success", false, TicketStatusSuccess},
		{"启用 MFA → mfa_pending", true, TicketStatusMFAPending},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newLTEnv(t)
			if tc.enable {
				e.enableMFA(9)
			}
			st, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{
				TicketID: "tid123", Session: "body-session", SessionUID: 9,
			})
			if err != nil {
				t.Fatalf("WriteTicket: %v", err)
			}
			if st.GetStatus() != tc.want || st.GetTicketId() != "tid123" {
				t.Fatalf("回显 = %+v, want {%s tid123}", st, tc.want)
			}
			got := e.tickets.res["tid123"]
			if got == nil {
				t.Fatal("未写入 al:ticket 结果")
			}
			if got.GetStatus() != tc.want {
				t.Fatalf("TicketResult.status = %q, want %q", got.GetStatus(), tc.want)
			}
			if got.GetV() != TicketResultV || got.GetScene() != SceneLogin ||
				got.GetChannel() != ChannelQRCode || got.GetProviderKey() != "scan" {
				t.Fatalf("TicketResult 头字段 = %+v", got)
			}
			if got.GetExpiresAt() != 1_700_000_600 || got.GetCreatedAt() != 1_700_000_100 {
				t.Fatalf("时间字段 = created %d exp %d, want 1_700_000_100 / 1_700_000_600",
					got.GetCreatedAt(), got.GetExpiresAt())
			}
			if got.GetLoginResult().GetUid() != 9 {
				t.Fatalf("login_result.uid = %d, want 9", got.GetLoginResult().GetUid())
			}
			if len(e.tickets.writes) != 1 || e.tickets.writes[0] != "tid123" {
				t.Fatalf("WriteComplete 记录 = %v, want [tid123]", e.tickets.writes)
			}
			// OIDC 不落 TicketResult：结构本身不携带该字段（§11.6.5）。
		})
	}
}

// TestWriteTicketConfirmChainMFAEnabledWritesPending 可证伪（§2.8、
// §11.6.5）：ConfirmLoginTicket 链（会话主体）用户启用二次验证（策略
// 强制列 mfa_required=1）时必须写 mfa_pending，PC 端经 needs_step_up
// 走 step-up，不得恒写 success 绕过。改坏 service 判定（恒 false）即转红。
func TestWriteTicketConfirmChainMFAEnabledWritesPending(t *testing.T) {
	e := newLTEnv(t)
	e.enableMFA(9)
	st, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{
		TicketID: "tid123", Session: "body-session", SessionUID: 9,
	})
	if err != nil {
		t.Fatalf("WriteTicket: %v", err)
	}
	if st.GetStatus() != TicketStatusMFAPending {
		t.Fatalf("回显 status = %q, want mfa_pending（启用 MFA 不得恒写 success）", st.GetStatus())
	}
	got := e.tickets.res["tid123"]
	if got == nil || got.GetStatus() != TicketStatusMFAPending {
		t.Fatalf("TicketResult.status = %+v, want mfa_pending", got.GetStatus())
	}
	if got.GetLoginResult().GetUid() != 9 {
		t.Fatalf("login_result.uid = %d, want 9（会话主体）", got.GetLoginResult().GetUid())
	}
}

// TestWriteTicketConfirmChainMFADisabledWritesSuccess 可证伪（§2.8、
// §11.6.5）：ConfirmLoginTicket 链用户未启用二次验证时写 success 终态。
// 改坏 service 判定（恒 true）会让本用例转红——与上一条互为反向证伪，
// 杜绝「把 success 写死」或「把 mfa_pending 写死」两种永真实现。
func TestWriteTicketConfirmChainMFADisabledWritesSuccess(t *testing.T) {
	e := newLTEnv(t)
	// 默认用户 mfa_required=0、无自选凭据行、系统开关 true → 未启用 MFA。
	st, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{
		TicketID: "tid123", Session: "body-session", SessionUID: 9,
	})
	if err != nil {
		t.Fatalf("WriteTicket: %v", err)
	}
	if st.GetStatus() != TicketStatusSuccess {
		t.Fatalf("回显 status = %q, want success（未启用 MFA 不应写 mfa_pending）", st.GetStatus())
	}
	if got := e.tickets.res["tid123"]; got == nil || got.GetStatus() != TicketStatusSuccess {
		t.Fatalf("TicketResult.status = %+v, want success", got.GetStatus())
	}
}

// TestWriteTicketConfirmChainMFAEnabledBySettingRow 可证伪：用户策略强制列
// 未启用，但自选 mfa_setting 凭据行 is_enabled=1 时仍需 step-up（复用
// 三方登录同口径）。改坏凭据行分支即转红。
func TestWriteTicketConfirmChainMFAEnabledBySettingRow(t *testing.T) {
	e := newLTEnv(t)
	e.creds.byKind["mfa_setting"] = &model.UserCredential{UserID: 9, Kind: "mfa_setting", IsEnabled: 1}
	st, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{
		TicketID: "tid123", Session: "body-session", SessionUID: 9,
	})
	if err != nil {
		t.Fatalf("WriteTicket: %v", err)
	}
	if st.GetStatus() != TicketStatusMFAPending {
		t.Fatalf("status = %q, want mfa_pending（自选凭据行启用）", st.GetStatus())
	}
}

// TestWriteTicketConfirmChainGlobalSwitchOff 可证伪：系统开关
// mfa_enabled=false 时不判二次验证，写 success。改坏开关读取即转红。
func TestWriteTicketConfirmChainGlobalSwitchOff(t *testing.T) {
	e := newLTEnv(t)
	e.enableMFA(9)
	e.mfaSettings.bools[settings.KeyMfaEnabled] = false
	st, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{
		TicketID: "tid123", Session: "body-session", SessionUID: 9,
	})
	if err != nil {
		t.Fatalf("WriteTicket: %v", err)
	}
	if st.GetStatus() != TicketStatusSuccess {
		t.Fatalf("status = %q, want success（开关关闭）", st.GetStatus())
	}
}

// TestWriteTicketConfirmChainMFALookupFailClosed 可证伪（§2.7.4、
// §7.3）：MFA 判定的用户行 / 凭据行读取故障必须 fail-closed——返回
// 错误、不写票，绝不把查询故障解释为「无需二次验证」而写 success。
func TestWriteTicketConfirmChainMFALookupFailClosed(t *testing.T) {
	t.Run("用户行读取故障", func(t *testing.T) {
		e := newLTEnv(t)
		infra := errors.New("user repo: connection refused")
		e.users.err, e.users.failsAt = infra, 1
		_, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{
			TicketID: "tid123", Session: "body-session", SessionUID: 9,
		})
		if !errors.Is(err, infra) {
			t.Fatalf("err = %v, want 透出用户行故障", err)
		}
		if len(e.tickets.writes) != 0 {
			t.Fatalf("fail-closed 不得写票, writes = %v", e.tickets.writes)
		}
	})
	t.Run("凭据行读取故障", func(t *testing.T) {
		e := newLTEnv(t)
		e.creds.err = errors.New("credential repo: connection refused")
		// 命中凭据行查询：策略强制列 0，需走到 FindByUserAndKind。
		_, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{
			TicketID: "tid123", Session: "body-session", SessionUID: 9,
		})
		if err == nil {
			t.Fatal("凭据行读取故障应 fail-closed 返回错误")
		}
		if len(e.tickets.writes) != 0 {
			t.Fatalf("fail-closed 不得写票, writes = %v", e.tickets.writes)
		}
	})
	t.Run("凭据行不存在属正常未启用", func(t *testing.T) {
		e := newLTEnv(t)
		// tpCreds 未命中返回 gorm.ErrRecordNotFound：应视为未启用而非故障。
		st, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{
			TicketID: "tid123", Session: "body-session", SessionUID: 9,
		})
		if err != nil || st.GetStatus() != TicketStatusSuccess {
			t.Fatalf("(status, err) = (%q, %v), want (success, nil)", st.GetStatus(), err)
		}
	})
}

// TestWriteTicketScanBranchRestoresUID 扫码分支（LoginOauth 内联调用，
// §2.7.4）以 loginToken 为主体凭证：目标 uid 经 State.Parse 恢复，service
// 按该 uid 的启用状态写 mfa_pending。若绕过 State.Parse 直接用 0 值 uid，
// 或 MFA 判定恒 false，本用例立即转红。
func TestWriteTicketScanBranchRestoresUID(t *testing.T) {
	e := newLTEnv(t)
	e.enableMFA(42) // 扫码上游已判定 MFA 才会走到写票；service 自行判定同源
	lt := e.issueLoginToken(t, &token.LoginTokenPayload{
		Tid: "tid-scan", Flow: "login", Uid: 42,
		Passed: []string{amrThirdParty}, Amr: []string{amrThirdParty},
		Oidc: &token.Oidc{ClientId: "client-1", RedirectUri: "https://rp.example/cb"},
	})
	st, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{
		TicketID: "tid123", LoginToken: lt,
	})
	if err != nil {
		t.Fatalf("WriteTicket: %v", err)
	}
	if st.GetStatus() != TicketStatusMFAPending {
		t.Fatalf("status = %q, want mfa_pending", st.GetStatus())
	}
	got := e.tickets.res["tid123"]
	if got == nil || got.GetLoginResult().GetUid() != 42 {
		t.Fatalf("写入 uid = %+v, want 42（从 loginToken 恢复）", got.GetLoginResult())
	}
}

// TestWriteTicketRejectsWeakLoginToken 可证伪（§3.8.5 防绕过主因子）：
// 篡改 / uid=0 / passed 空的 loginToken 一律拒绝推进到 mfa_pending，且
// 不落任何票据写入。若移除 uid / passed 校验，本用例立即转红。
func TestWriteTicketRejectsWeakLoginToken(t *testing.T) {
	cases := []struct {
		name  string
		token func(*testing.T, *ltEnv) string
	}{
		{"篡改令牌", func(*testing.T, *ltEnv) string { return "garbage" }},
		{"uid 缺失", func(t *testing.T, e *ltEnv) string {
			return e.issueLoginToken(t, &token.LoginTokenPayload{
				Tid: "tid-0", Flow: "login", Uid: 0, Passed: []string{amrThirdParty},
			})
		}},
		{"缺已过主因子", func(t *testing.T, e *ltEnv) string {
			return e.issueLoginToken(t, &token.LoginTokenPayload{
				Tid: "tid-nopass", Flow: "login", Uid: 42,
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newLTEnv(t)
			_, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{
				TicketID: "tid123", LoginToken: tc.token(t, e),
			})
			if !errors.Is(err, ErrQrcodeTicketInvalid) {
				t.Fatalf("err = %v, want ErrQrcodeTicketInvalid", err)
			}
			if len(e.tickets.writes) != 0 {
				t.Fatalf("非法 loginToken 不得写票, writes = %v", e.tickets.writes)
			}
		})
	}
}

// TestWriteTicketSessionSubject 会话主体校验（§2.8）：body session 为准，
// 与 Cookie 侧 uid 同 uid 校验；缺主体 / 校验失败按 401。可证伪：改坏
// 同 uid 校验或回落 Cookie 侧即转红。
func TestWriteTicketSessionSubject(t *testing.T) {
	cases := []struct {
		name    string
		in      WriteTicketInput
		sessErr error
		wantUID int64
		wantErr error
	}{
		{"body 为准（Cookie 侧空）", WriteTicketInput{TicketID: "tid123", Session: "body", SessionUID: 0}, nil, 9, nil},
		{"body 与 Cookie 同 uid", WriteTicketInput{TicketID: "tid123", Session: "body", SessionUID: 9}, nil, 9, nil},
		{"Cookie 侧直登", WriteTicketInput{TicketID: "tid123", SessionUID: 9}, nil, 9, nil},
		{"uid 不一致", WriteTicketInput{TicketID: "tid123", Session: "body", SessionUID: 8}, nil, 0, ErrQrcodeInvalidRequest},
		{"无主体", WriteTicketInput{TicketID: "tid123"}, nil, 0, ErrQrcodeUnauthenticated},
		{"会话校验失败", WriteTicketInput{TicketID: "tid123", Session: "body"}, errors.New("bad session"), 0, ErrQrcodeUnauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newLTEnv(t)
			e.sessions.err = tc.sessErr
			st, err := e.svc.WriteTicket(context.Background(), tc.in)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if len(e.tickets.writes) != 0 {
					t.Fatalf("拒绝路径不得写票, writes = %v", e.tickets.writes)
				}
				return
			}
			if err != nil {
				t.Fatalf("WriteTicket: %v", err)
			}
			if st.GetStatus() != TicketStatusSuccess {
				t.Fatalf("status = %q, want success", st.GetStatus())
			}
			if got := e.tickets.res["tid123"].GetLoginResult().GetUid(); got != tc.wantUID {
				t.Fatalf("uid = %d, want %d", got, tc.wantUID)
			}
		})
	}
}

// TestWriteTicketPayloadAndWriteGuards 票据快照校验与写票失败（§11.6.4 /
// §11.6.5）：空 ticket_id / 快照缺失 / scene 非 login / ticket_id 不自洽
// / 读取故障 / 写入故障均不得谎报成功。可证伪：移除任一校验即转红。
func TestWriteTicketPayloadAndWriteGuards(t *testing.T) {
	t.Run("空 ticket_id", func(t *testing.T) {
		e := newLTEnv(t)
		_, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{TicketID: "  ", SessionUID: 9})
		if !errors.Is(err, ErrQrcodeInvalidRequest) {
			t.Fatalf("err = %v, want ErrQrcodeInvalidRequest", err)
		}
	})
	t.Run("快照缺失", func(t *testing.T) {
		e := newLTEnv(t)
		delete(e.payloads.snapshots, "tid123")
		_, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{TicketID: "tid123", SessionUID: 9})
		if !errors.Is(err, ErrQrcodeTicketInvalid) {
			t.Fatalf("err = %v, want ErrQrcodeTicketInvalid", err)
		}
	})
	t.Run("scene 非 login", func(t *testing.T) {
		e := newLTEnv(t)
		e.payloads.snapshots["tid123"].Scene = SceneBind
		_, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{TicketID: "tid123", SessionUID: 9})
		if !errors.Is(err, ErrQrcodeTicketInvalid) {
			t.Fatalf("err = %v, want ErrQrcodeTicketInvalid", err)
		}
	})
	t.Run("ticket_id 不自洽", func(t *testing.T) {
		e := newLTEnv(t)
		e.payloads.snapshots["tid123"].TicketId = "other"
		_, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{TicketID: "tid123", SessionUID: 9})
		if !errors.Is(err, ErrQrcodeTicketInvalid) {
			t.Fatalf("err = %v, want ErrQrcodeTicketInvalid", err)
		}
	})
	t.Run("读取故障透出", func(t *testing.T) {
		e := newLTEnv(t)
		infra := errors.New("redis read down")
		e.payloads.err = infra
		_, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{TicketID: "tid123", SessionUID: 9})
		if !errors.Is(err, infra) {
			t.Fatalf("err = %v, want 透出读取故障", err)
		}
		if len(e.tickets.writes) != 0 {
			t.Fatalf("读取故障不得进入写票, writes = %v", e.tickets.writes)
		}
	})
	t.Run("写入故障透出", func(t *testing.T) {
		e := newLTEnv(t)
		infra := errors.New("redis write down")
		e.tickets.writeErr = infra
		_, err := e.svc.WriteTicket(context.Background(), WriteTicketInput{TicketID: "tid123", SessionUID: 9})
		if !errors.Is(err, infra) {
			t.Fatalf("err = %v, want 透出写入故障", err)
		}
	})
}
