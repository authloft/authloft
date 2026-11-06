// thirdparty_test.go account 域三方绑定族四方法 + BindToCurrentUser 内核的
// 单测。全部走 fake，不连 DB / Redis：双列表投影与过滤排序 / 解绑
// 判定口径与 Union 连带审计 / redirect 通道载体校验链（b 前缀、state 一致、
// 过期、uid 串号、通道限 redirect、上游故障）/ 内核三分支（幂等、target_
// taken、写入 + Union 联动 + extra 落 Raw + 审计只在写入分支）/ 轮询五态
// （expired 双态、pending、scanned 回写、success 带 bind、失败类原样上抛、
// scene 双重校验、poll 钳制、target_taken 固定文案）。
package account

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"

	"authloft/gen/go/token"
	"authloft/internal/cache"
	"authloft/internal/eventlog"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
)

// —— fake 全家 ——

// fakeLoader ProviderLoader 的 fake：按 key / type 返回预置实例。
type fakeLoader struct {
	byKey  map[string]*provider.Provider
	byType map[string][]*provider.Provider
}

func (l *fakeLoader) Get(_ context.Context, key string) (*provider.Provider, error) {
	if p, ok := l.byKey[key]; ok {
		return p, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (l *fakeLoader) ListByType(_ context.Context, typ string) ([]*provider.Provider, error) {
	return l.byType[typ], nil
}

// fakeProviders ProviderFinder 的 fake。
type fakeProviders struct {
	byKey map[string]*model.Provider
}

func (f *fakeProviders) FindByKey(_ context.Context, key string) (*model.Provider, error) {
	if p, ok := f.byKey[key]; ok {
		return p, nil
	}
	return nil, gorm.ErrRecordNotFound
}

// unbindCall UnbindWithUnionCascade 入参记录。
type unbindCall struct {
	id, uid          int64
	unionProviderKey string
}

// fakeBinds BindStore 的 fake：判重 / 写入 / 级联删除全内存；listRows 非空时
// ListByUserID 返回预置（绑定列表用例独立数据），否则按 rows 派生。
type fakeBinds struct {
	rows       map[string]model.UserThirdpartyBind // key = pk + "|" + openid
	listRows   []model.UserThirdpartyBind
	listByUser int64
	created    []model.UserThirdpartyBind
	unions     [][2]string // CreateWithUnion 的 (unionProviderKey, unionID)
	cascades   []unbindCall
	createErr  error
	findErr    error
	dupOnUnion string // 非空时该 (unionKey) 触发 ErrBindDuplicate 语义
}

func bindKey(pk, openid string) string { return pk + "|" + openid }

func (b *fakeBinds) FindByProviderOpenID(_ context.Context, pk, openid string) (*model.UserThirdpartyBind, error) {
	if b.findErr != nil {
		return nil, b.findErr
	}
	if r, ok := b.rows[bindKey(pk, openid)]; ok {
		r := r
		return &r, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (b *fakeBinds) ListByUserID(_ context.Context, uid int64) ([]model.UserThirdpartyBind, error) {
	if b.listRows != nil {
		return b.listRows, nil
	}
	var out []model.UserThirdpartyBind
	for _, r := range b.rows {
		if r.UserID == uid {
			out = append(out, r)
		}
	}
	return out, nil
}

func (b *fakeBinds) CreateWithUnion(_ context.Context, m *model.UserThirdpartyBind, unionProviderKey, unionID string) error {
	if b.createErr != nil {
		return b.createErr
	}
	if _, exists := b.rows[bindKey(m.ProviderKey, m.OpenID)]; exists ||
		(unionProviderKey != "" && unionID != "" && b.dupOnUnion == bindKey(unionProviderKey, unionID)) {
		// 同 repo.CreateWithUnion 的判别链（fmt.Errorf("%w: %w", repo.ErrBindDuplicate, …)）。
		return fmt.Errorf("bind repo: create with union: %w: %w", repo.ErrBindDuplicate, gorm.ErrDuplicatedKey)
	}
	b.created = append(b.created, *m)
	b.unions = append(b.unions, [2]string{unionProviderKey, unionID})
	b.rows[bindKey(m.ProviderKey, m.OpenID)] = *m
	if unionProviderKey != "" && unionID != "" {
		b.rows[bindKey(unionProviderKey, unionID)] = model.UserThirdpartyBind{
			UserID: m.UserID, ProviderKey: unionProviderKey, OpenID: unionID,
		}
	}
	return nil
}

func (b *fakeBinds) UnbindWithUnionCascade(_ context.Context, id, uid int64, unionProviderKey string) error {
	b.cascades = append(b.cascades, unbindCall{id: id, uid: uid, unionProviderKey: unionProviderKey})
	if k := byID(b, id); k != "" {
		delete(b.rows, k)
	}
	return nil
}

// byID 测试辅助：按行 id 找 rows 键（级联删除模拟）。
func byID(b *fakeBinds, id int64) string {
	for k, r := range b.rows {
		if r.ID == id {
			return k
		}
	}
	return ""
}

// fakeCreds CredentialReader 的 fake：password 行可控。
type fakeCreds struct {
	password *model.UserCredential
	err      error
}

func (c *fakeCreds) FindByUserAndKind(_ context.Context, _ int64, kind string) (*model.UserCredential, error) {
	if c.err != nil {
		return nil, c.err
	}
	if kind == "password" && c.password != nil {
		return c.password, nil
	}
	return nil, gorm.ErrRecordNotFound
}

// fakeTickets TicketStore 的 fake：预置结果 + Take 取走即删 + Wait 记录
// （waitNil=true 时模拟等待后键出现：仅第一次 Take 落空）。
type fakeTickets struct {
	results map[string]*token.TicketResult
	waited  []time.Duration
	scanIDs []string
	waitNil bool
}

func (f *fakeTickets) WriteScanned(_ context.Context, id string, res *token.TicketResult) (cache.TicketWriteResult, error) {
	f.scanIDs = append(f.scanIDs, id)
	if _, ok := f.results[id]; ok {
		return cache.TicketWriteSkipped, nil
	}
	f.results[id] = res
	return cache.TicketWriteOK, nil
}

func (f *fakeTickets) Take(_ context.Context, id string) (*token.TicketResult, error) {
	res, ok := f.results[id]
	if !ok {
		return nil, nil
	}
	delete(f.results, id)
	return res, nil
}

func (f *fakeTickets) Wait(_ context.Context, _ string, timeout time.Duration) error {
	f.waited = append(f.waited, timeout)
	if f.waitNil {
		return nil // 模拟等待后出现（下一次 Take 命中需调用方另行预置）
	}
	return cache.ErrTicketWaitTimeout
}

// fakeAudit AuditSink 的 fake：收集事件。
type fakeAudit struct{ events []model.EventLog }

func (f *fakeAudit) PushEvent(ev model.EventLog) { f.events = append(f.events, ev) }

// fakeAdapter 渠道适配器 fake：channel / 身份 / Exchange 故障可控。
type fakeAdapter struct {
	channel     provider.ThirdPartyChannel
	identity    *provider.ExternalIdentity
	exchangeErr error
}

func (a *fakeAdapter) Channel() provider.ThirdPartyChannel { return a.channel }

func (a *fakeAdapter) BuildAuthURL(*provider.AuthContext) (string, error) {
	return "", errors.New("not supported")
}

func (a *fakeAdapter) Exchange(context.Context, provider.ExchangeInput) (*provider.Token, error) {
	if a.exchangeErr != nil {
		return nil, a.exchangeErr
	}
	if a.identity == nil {
		return nil, errors.New("no identity")
	}
	return &provider.Token{Raw: map[string]any{"openid": a.identity.OpenID}}, nil
}

func (a *fakeAdapter) FetchUser(context.Context, *provider.Token) (*provider.ExternalIdentity, error) {
	return a.identity, nil
}

// testCodec 构造 32B 单密钥 Codec（seed 区分场景，避免跨 purpose 误开）。
func testCodec(t *testing.T, seed byte) *security.Codec {
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

// providerRow 构造 oauth provider 实例（IsEnabled / EnableSignin 默认 1）。
func providerRow(key, typ, union string, enabled, signin int8) *provider.Provider {
	return &provider.Provider{
		Key:  key,
		Type: typ,
		Row: &model.Provider{
			ProviderKey:   key,
			UnionProvider: union,
			DisplayName:   key + "-display",
			Category:      providerCategoryOAuth,
			Type:          typ,
			EnableSignin:  signin,
			IsEnabled:     enabled,
			UiGroup:       "social",
			SortOrder:     10,
			IconURL:       "https://icons.example.com/" + key + ".png",
		},
	}
}

// env 汇总一套全 fake 的依赖与被测 service。
type env struct {
	loader   *fakeLoader
	finders  *fakeProviders
	binds    *fakeBinds
	creds    *fakeCreds
	tickets  *fakeTickets
	audit    *fakeAudit
	adapter  *fakeAdapter
	metas    func() []provider.Meta
	svc      *ThirdpartyService
	now      time.Time
	cookieCK *security.Codec
	ticketCK *security.Codec
}

// newEnv 构造：默认可绑 provider qq（redirect，type=qq）+ wechat_mp_scan
// （qrcode，type=wechat_mp_scan）+ 排序干扰项；b 前缀 state 签发助手见
// sealLoginState。
func newEnv(t *testing.T) *env {
	t.Helper()
	at := time.Unix(1_700_000_000, 0).UTC()
	e := &env{
		loader:  &fakeLoader{byKey: map[string]*provider.Provider{}, byType: map[string][]*provider.Provider{}},
		finders: &fakeProviders{byKey: map[string]*model.Provider{}},
		binds:   &fakeBinds{rows: map[string]model.UserThirdpartyBind{}},
		creds:   &fakeCreds{},
		tickets: &fakeTickets{results: map[string]*token.TicketResult{}},
		audit:   &fakeAudit{},
		adapter: &fakeAdapter{
			channel: provider.ChannelRedirect,
			identity: &provider.ExternalIdentity{
				ProviderKey: "qq", ProviderType: "qq",
				OpenID: "openid-1", UnionID: "union-1",
				Nickname: "QQ 用户", AvatarURL: "https://q.cn/a.png",
				Raw: map[string]any{"openid": "openid-1"},
			},
		},
		now: at,
	}
	// 注册表 fake：两个 oauth type（各含一个实例）——available 用例数据源。
	qq := providerRow("qq", "qq", "", 1, 1)
	scan := providerRow("wechat_mp_scan", "wechat_mp_scan", "wechat_union", 1, 1)
	scan.Row.SortOrder = 20
	e.loader.byKey["qq"] = qq
	e.loader.byKey["wechat_mp_scan"] = scan
	e.loader.byType["qq"] = []*provider.Provider{qq}
	e.loader.byType["wechat_mp_scan"] = []*provider.Provider{scan}
	e.finders.byKey["qq"] = qq.Row
	e.finders.byKey["wechat_mp_scan"] = scan.Row
	e.metas = func() []provider.Meta {
		return []provider.Meta{
			{Type: "qq", Category: providerCategoryOAuth, Channel: provider.ChannelRedirect},
			{Type: "wechat_mp_scan", Category: providerCategoryOAuth, Channel: provider.ChannelQRCode},
		}
	}
	e.cookieCK = testCodec(t, 0x20)
	e.ticketCK = testCodec(t, 0x30)
	e.svc = NewThirdpartyService(Deps{
		Loader:      e.loader,
		Providers:   e.finders,
		Binds:       e.binds,
		Creds:       e.creds,
		NewAdapter:  func(*provider.Provider) (provider.AuthAdapter, error) { return e.adapter, nil },
		Tickets:     e.tickets,
		TicketCodec: e.ticketCK,
		CookieCodec: e.cookieCK,
		Audit:       e.audit,
		Metas:       e.metas,
		Now:         func() time.Time { return e.now },
	})
	return e
}

// sealLoginState 签发 al_login_state 载荷（b 场景 uid + 10 分钟 exp）。
func (e *env) sealLoginState(t *testing.T, state string, uid int64) string {
	t.Helper()
	value, err := e.cookieCK.Seal(security.PurposeCookie, &token.LoginStatePayload{
		State: state,
		Uid:   uid,
		Iat:   e.now.Unix(),
		Exp:   e.now.Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("seal login state: %v", err)
	}
	return value
}

// sealTicket 签发轮询 ticket（scene=bind 默认）。
func (e *env) sealTicket(t *testing.T, id, pk, scene string, ttl time.Duration) string {
	t.Helper()
	value, err := e.ticketCK.Seal(security.PurposeTicket, &token.TicketPayload{
		TicketId:    id,
		ProviderKey: pk,
		Scene:       scene,
		Iat:         e.now.Unix(),
		Exp:         e.now.Add(ttl).Unix(),
	})
	if err != nil {
		t.Fatalf("seal ticket: %v", err)
	}
	return value
}

// bindResult 组装扫码提交方写入的 bind 结果（thirdparty_identity 含 raw）。
func bindResult(pk, openid, unionID string, scene string) *token.TicketResult {
	raw, _ := structpb.NewStruct(map[string]any{"openid": openid})
	return &token.TicketResult{
		V:           1,
		Scene:       scene,
		Status:      ticketStatusSuccess,
		ProviderKey: pk,
		Channel:     "qrcode",
		ThirdpartyIdentity: &token.ThirdpartyIdentity{
			OpenId:  openid,
			UnionId: unionID,
			Raw:     raw,
		},
	}
}

// —— GetThirdpartyBindings ——

// TestGetThirdpartyBindings 双列表（§3.7 行 953-959）：items 含 Union 行
// （type 投影 provider 行）与脏数据行（provider 缺失仅投影绑定行字段）；
// available 过滤未启用 / 未开放登录 / 已绑定 / Union，排序 sort_order ASC。
func TestGetThirdpartyBindings(t *testing.T) {
	e := newEnv(t)
	// 已绑定：qq（普通）+ wechat_union（Union 归并行，type=union）+ 脏数据行。
	e.binds.listRows = []model.UserThirdpartyBind{
		{ID: 11, UserID: 10086, ProviderKey: "qq", OpenID: "openid-1", CreatedAt: e.now.Add(-time.Hour)},
		{ID: 12, UserID: 10086, ProviderKey: "wechat_union", OpenID: "union-9", CreatedAt: e.now.Add(-2 * time.Hour)},
		{ID: 13, UserID: 10086, ProviderKey: "ghost", OpenID: "openid-x", CreatedAt: e.now.Add(-3 * time.Hour)},
	}
	union := providerRow("wechat_union", "union", "", 1, 0)
	union.Row.Category = providerCategoryUnion
	union.Row.Type = "union"
	e.loader.byKey["wechat_union"] = union
	// available 候选：wechat_mp_scan（可绑）+ 被禁用 + 关闭登录 + api 通道
	//（照常出现，行 953 channel 取值含 api）。
	disabled := providerRow("ding", "ding", "", 0, 1)
	noSignin := providerRow("feishu", "feishu", "", 1, 0)
	apiCh := providerRow("wechat_mp", "wechat_mp", "", 1, 1)
	apiCh.Row.SortOrder = 5
	e.loader.byType["ding"] = []*provider.Provider{disabled}
	e.loader.byType["feishu"] = []*provider.Provider{noSignin}
	e.loader.byType["wechat_mp"] = []*provider.Provider{apiCh}
	e.loader.byKey["ding"] = disabled
	e.loader.byKey["feishu"] = noSignin
	e.loader.byKey["wechat_mp"] = apiCh
	e.metas = func() []provider.Meta {
		return []provider.Meta{
			{Type: "qq", Category: providerCategoryOAuth, Channel: provider.ChannelRedirect},
			{Type: "wechat_mp_scan", Category: providerCategoryOAuth, Channel: provider.ChannelQRCode},
			{Type: "ding", Category: providerCategoryOAuth, Channel: provider.ChannelRedirect},
			{Type: "feishu", Category: providerCategoryOAuth, Channel: provider.ChannelRedirect},
			{Type: "wechat_mp", Category: providerCategoryOAuth, Channel: provider.ChannelAPI},
			{Type: "smtp", Category: "email"}, // 非 oauth category 不参与
		}
	}
	e.svc = NewThirdpartyService(Deps{
		Loader: e.loader, Providers: e.finders, Binds: e.binds, Creds: e.creds,
		NewAdapter: func(*provider.Provider) (provider.AuthAdapter, error) { return e.adapter, nil },
		Tickets:    e.tickets, TicketCodec: e.ticketCK, CookieCodec: e.cookieCK,
		Audit: e.audit, Metas: e.metas, Now: func() time.Time { return e.now },
	})

	res, err := e.svc.GetThirdpartyBindings(context.Background(), 10086)
	if err != nil {
		t.Fatalf("GetThirdpartyBindings: %v", err)
	}
	if len(res.Items) != 3 {
		t.Fatalf("items len = %d, want 3（含 Union 行与脏数据行）: %+v", len(res.Items), res.Items)
	}
	qqRow := res.Items[0]
	if qqRow.ProviderKey != "qq" || qqRow.DisplayName != "qq-display" ||
		qqRow.Type != "qq" || qqRow.Channel != "redirect" ||
		qqRow.Icon != "https://icons.example.com/qq.png" ||
		qqRow.CreatedAt != e.now.Add(-time.Hour).Unix() {
		t.Errorf("items[qq] = %+v", qqRow)
	}
	unionRow := res.Items[1]
	if unionRow.ProviderKey != "wechat_union" || unionRow.Type != "union" || unionRow.Channel != "" {
		t.Errorf("items[union] = %+v, want type 投影 provider 行、channel 空串（无注册适配器）", unionRow)
	}
	ghost := res.Items[2]
	if ghost.ProviderKey != "ghost" || ghost.DisplayName != "" || ghost.CreatedAt != e.now.Add(-3*time.Hour).Unix() {
		t.Errorf("items[ghost] = %+v, want 脏数据行仅绑定行自带字段", ghost)
	}
	// available：wechat_mp(sort 5) → wechat_mp_scan(sort 20)；qq 已绑定、
	// ding / feishu 被过滤、smtp 非 oauth、union 不出现。
	wantAvail := []string{"wechat_mp", "wechat_mp_scan"}
	if len(res.Available) != len(wantAvail) {
		t.Fatalf("available = %+v, want %v", res.Available, wantAvail)
	}
	for i, w := range wantAvail {
		if res.Available[i].ProviderKey != w {
			t.Errorf("available[%d] = %q, want %q（sort_order ASC 排序）", i, res.Available[i].ProviderKey, w)
		}
	}
	if res.Available[0].Channel != "api" || res.Available[1].Channel != "qrcode" {
		t.Errorf("available channel = (%q, %q), want (api, qrcode)——§2.7.1 同款取值", res.Available[0].Channel, res.Available[1].Channel)
	}
	if res.Available[1].UiGroup != "social" || res.Available[1].SortOrder != 20 {
		t.Errorf("available[1] uiGroup/sortOrder = (%q, %d)", res.Available[1].UiGroup, res.Available[1].SortOrder)
	}
}

// —— UnbindThirdparty ——

// TestUnbindThirdparty 解绑族（§3.7 行 954 / 行 961 判定口径 + §12.7 Union）。
func TestUnbindThirdparty(t *testing.T) {
	const uid = 10086
	newCase := func(t *testing.T) *env {
		t.Helper()
		e := newEnv(t)
		e.binds.rows[bindKey("qq", "openid-1")] = model.UserThirdpartyBind{ID: 11, UserID: uid, ProviderKey: "qq", OpenID: "openid-1"}
		return e
	}

	t.Run("空 providerKey → invalid_request", func(t *testing.T) {
		e := newCase(t)
		if err := e.svc.UnbindThirdparty(context.Background(), uid, ""); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("err = %v, want ErrInvalidRequest", err)
		}
	})
	t.Run("provider 不存在 → not_found", func(t *testing.T) {
		e := newCase(t)
		err := e.svc.UnbindThirdparty(context.Background(), uid, "nope")
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("err = %v, want gorm.ErrRecordNotFound", err)
		}
	})
	t.Run("Union Provider 不可单独解绑", func(t *testing.T) {
		e := newCase(t)
		union := &model.Provider{ProviderKey: "wechat_union", Category: providerCategoryUnion, UnionProvider: ""}
		e.finders.byKey["wechat_union"] = union
		if err := e.svc.UnbindThirdparty(context.Background(), uid, "wechat_union"); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("err = %v, want ErrInvalidRequest（§12.7 行 1547）", err)
		}
		if len(e.binds.cascades) != 0 {
			t.Errorf("cascades = %+v, want 空", e.binds.cascades)
		}
	})
	t.Run("无该绑定 → not_found", func(t *testing.T) {
		e := newCase(t)
		err := e.svc.UnbindThirdparty(context.Background(), uid, "wechat_mp_scan")
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Errorf("err = %v, want gorm.ErrRecordNotFound", err)
		}
	})
	t.Run("最后登录方式 → invalid_request（无 password 无其余绑定）", func(t *testing.T) {
		e := newCase(t)
		if err := e.svc.UnbindThirdparty(context.Background(), uid, "qq"); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("err = %v, want ErrInvalidRequest（行 954 解绑后须仍有登录方式）", err)
		}
		if len(e.binds.cascades) != 0 || len(e.audit.events) != 0 {
			t.Errorf("cascades = %+v, audit = %+v, want 均不发生", e.binds.cascades, e.audit.events)
		}
	})
	t.Run("其余仅 Union 绑定 → invalid_request（Union 不计入）", func(t *testing.T) {
		e := newCase(t)
		e.binds.rows[bindKey("wechat_union", "union-9")] = model.UserThirdpartyBind{ID: 12, UserID: uid, ProviderKey: "wechat_union", OpenID: "union-9"}
		e.finders.byKey["wechat_union"] = &model.Provider{ProviderKey: "wechat_union", Category: providerCategoryUnion}
		if err := e.svc.UnbindThirdparty(context.Background(), uid, "qq"); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("err = %v, want ErrInvalidRequest（Union 行不计入，行 961）", err)
		}
	})
	t.Run("有 password → 允许 + 级联 + 审计", func(t *testing.T) {
		e := newCase(t)
		e.creds.password = &model.UserCredential{Kind: "password", IsEnabled: 1}
		if err := e.svc.UnbindThirdparty(context.Background(), uid, "qq"); err != nil {
			t.Fatalf("UnbindThirdparty: %v", err)
		}
		if len(e.binds.cascades) != 1 || e.binds.cascades[0].id != 11 || e.binds.cascades[0].uid != uid {
			t.Errorf("cascades = %+v, want 按 id=11 归属删除", e.binds.cascades)
		}
		if len(e.audit.events) != 1 {
			t.Fatalf("audit events = %d, want 1", len(e.audit.events))
		}
		ev := e.audit.events[0]
		if ev.Event != eventlog.EventThirdpartyUnbind || ev.ActorType != eventlog.ActorTypeUser ||
			ev.ActorID != uid || ev.UserID != uid || ev.Target != "qq" {
			t.Errorf("audit event = %+v", ev)
		}
	})
	t.Run("password 行停用 → 不算数，其余非 Union 绑定兜底", func(t *testing.T) {
		e := newCase(t)
		e.creds.password = &model.UserCredential{Kind: "password", IsEnabled: 0}
		e.binds.rows[bindKey("wechat_mp_scan", "openid-2")] = model.UserThirdpartyBind{ID: 14, UserID: uid, ProviderKey: "wechat_mp_scan", OpenID: "openid-2"}
		if err := e.svc.UnbindThirdparty(context.Background(), uid, "qq"); err != nil {
			t.Fatalf("UnbindThirdparty: %v（仍绑定 wechat_mp_scan 应允许）", err)
		}
		// Union 连带参数 = provider 行的 union_provider（既有级联机制）。
		if len(e.binds.cascades) != 1 || e.binds.cascades[0].unionProviderKey != "" {
			t.Errorf("cascades = %+v, want qq 无 union_provider", e.binds.cascades)
		}
	})
	t.Run("Union provider 关联的级联参数透传", func(t *testing.T) {
		e := newCase(t)
		e.creds.password = &model.UserCredential{Kind: "password", IsEnabled: 1}
		e.binds.rows[bindKey("wechat_mp_scan", "openid-2")] = model.UserThirdpartyBind{ID: 15, UserID: uid, ProviderKey: "wechat_mp_scan", OpenID: "openid-2"}
		if err := e.svc.UnbindThirdparty(context.Background(), uid, "wechat_mp_scan"); err != nil {
			t.Fatalf("UnbindThirdparty: %v", err)
		}
		if e.binds.cascades[0].unionProviderKey != "wechat_union" || e.binds.cascades[0].id != 15 {
			t.Errorf("cascades = %+v, want union_provider=wechat_union", e.binds.cascades)
		}
	})
}

// —— ThirdpartyOauth（redirect 绑定通道 A）——

// TestThirdpartyOauth redirect 绑定链（§3.7.1 A 行 969-1003）。
func TestThirdpartyOauth(t *testing.T) {
	const uid = 10086
	state := "b" + "0123456789abcdef0123456789abcdef"

	newInput := func(e *env) OauthInput {
		return OauthInput{
			ProviderKey: "qq",
			Code:        "code-1",
			State:       state,
			StateCookie: e.sealLoginState(t, state, uid),
			UID:         uid,
		}
	}

	t.Run("成功绑定：写入 + Union 联动 + extra 落 Raw + 审计", func(t *testing.T) {
		e := newEnv(t)
		out, err := e.svc.ThirdpartyOauth(context.Background(), newInput(e))
		if err != nil {
			t.Fatalf("ThirdpartyOauth: %v", err)
		}
		if out.ProviderKey != "qq" || out.DisplayName != "qq-display" {
			t.Errorf("outcome = %+v", out)
		}
		if len(e.binds.created) != 1 {
			t.Fatalf("created = %d, want 1", len(e.binds.created))
		}
		b := e.binds.created[0]
		if b.UserID != uid || b.ProviderKey != "qq" || b.OpenID != "openid-1" ||
			b.Nickname != "QQ 用户" || b.AvatarURL != "https://q.cn/a.png" {
			t.Errorf("created row = %+v", b)
		}
		var extra map[string]any
		if err := msgpack.Unmarshal(b.Extra, &extra); err != nil || extra["openid"] != "openid-1" {
			t.Errorf("extra = %v (err %v), want msgpack Raw 透传", extra, err)
		}
		// Union 联动（§12.7 行 1560）：qq 无关联 Union Provider → unionProviderKey
		// 传空、repo 侧只写普通行（unionID 原样透传，空 key 即无联动）。
		if len(e.binds.unions) != 1 || e.binds.unions[0] != [2]string{"", "union-1"} {
			t.Errorf("unions = %+v, want 单次普通行写入", e.binds.unions)
		}
		if len(e.audit.events) != 1 || e.audit.events[0].Event != eventlog.EventThirdpartyBind ||
			e.audit.events[0].ActorType != eventlog.ActorTypeUser || e.audit.events[0].Target != "qq" {
			t.Errorf("audit = %+v", e.audit.events)
		}
	})
	t.Run("Union 联动参数透传（provider 关联 Union）", func(t *testing.T) {
		e := newEnv(t)
		qq := providerRow("qq", "qq", "wechat_union", 1, 1)
		e.loader.byKey["qq"] = qq
		e.finders.byKey["qq"] = qq.Row
		if _, err := e.svc.ThirdpartyOauth(context.Background(), newInput(e)); err != nil {
			t.Fatalf("ThirdpartyOauth: %v", err)
		}
		if e.binds.unions[0] != [2]string{"wechat_union", "union-1"} {
			t.Errorf("unions = %+v, want (wechat_union, union-1)", e.binds.unions)
		}
	})
	t.Run("幂等：已绑当前 uid → success 且不写不审计", func(t *testing.T) {
		e := newEnv(t)
		e.binds.rows[bindKey("qq", "openid-1")] = model.UserThirdpartyBind{ID: 11, UserID: uid, ProviderKey: "qq", OpenID: "openid-1"}
		out, err := e.svc.ThirdpartyOauth(context.Background(), newInput(e))
		if err != nil {
			t.Fatalf("ThirdpartyOauth: %v（已绑本人应幂等 success）", err)
		}
		if out.ProviderKey != "qq" {
			t.Errorf("outcome = %+v", out)
		}
		if len(e.binds.created) != 0 || len(e.audit.events) != 0 {
			t.Errorf("created = %d, audit = %d, want 均零", len(e.binds.created), len(e.audit.events))
		}
	})
	t.Run("已绑他人 → target_taken", func(t *testing.T) {
		e := newEnv(t)
		e.binds.rows[bindKey("qq", "openid-1")] = model.UserThirdpartyBind{ID: 9, UserID: 999, ProviderKey: "qq", OpenID: "openid-1"}
		if _, err := e.svc.ThirdpartyOauth(context.Background(), newInput(e)); !errors.Is(err, ErrTargetTaken) {
			t.Errorf("err = %v, want ErrTargetTaken", err)
		}
	})
	t.Run("并发被抢唯一键 → target_taken", func(t *testing.T) {
		e := newEnv(t)
		e.binds.createErr = fmt.Errorf("bind repo: create with union: %w: %w", repo.ErrBindDuplicate, gorm.ErrDuplicatedKey)
		if _, err := e.svc.ThirdpartyOauth(context.Background(), newInput(e)); !errors.Is(err, ErrTargetTaken) {
			t.Errorf("err = %v, want ErrTargetTaken（uk 冲突收敛，§12.5 行 256）", err)
		}
	})
	t.Run("l 前缀 / 缺 state → invalid_request（b 前缀校验）", func(t *testing.T) {
		e := newEnv(t)
		in := newInput(e)
		in.State = "l" + "0123456789abcdef0123456789abcde"
		if _, err := e.svc.ThirdpartyOauth(context.Background(), in); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("err = %v, want ErrInvalidRequest（前缀不符，§12.6 行 1534）", err)
		}
		in.State = ""
		if _, err := e.svc.ThirdpartyOauth(context.Background(), in); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("err = %v, want ErrInvalidRequest（空 state）", err)
		}
	})
	t.Run("state 与 Cookie 不一致 / Cookie 缺失 → state_mismatch", func(t *testing.T) {
		e := newEnv(t)
		in := newInput(e)
		in.State = "b" + "ffffffffffffffffffffffffffffffff"
		if _, err := e.svc.ThirdpartyOauth(context.Background(), in); !errors.Is(err, ErrStateMismatch) {
			t.Errorf("err = %v, want ErrStateMismatch", err)
		}
		in = newInput(e)
		in.StateCookie = ""
		if _, err := e.svc.ThirdpartyOauth(context.Background(), in); !errors.Is(err, ErrStateMismatch) {
			t.Errorf("err = %v, want ErrStateMismatch（无 Cookie 可比对）", err)
		}
	})
	t.Run("Cookie 过期 → state_mismatch", func(t *testing.T) {
		e := newEnv(t)
		stale, err := e.cookieCK.Seal(security.PurposeCookie, &token.LoginStatePayload{
			State: state, Uid: uid,
			Iat: e.now.Add(-11 * time.Minute).Unix(),
			Exp: e.now.Add(-time.Minute).Unix(),
		})
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		in := newInput(e)
		in.StateCookie = stale
		if _, err := e.svc.ThirdpartyOauth(context.Background(), in); !errors.Is(err, ErrStateMismatch) {
			t.Errorf("err = %v, want ErrStateMismatch（10 分钟 exp 兜底）", err)
		}
	})
	t.Run("Cookie uid 与会话不一致 → invalid_request（防串号）", func(t *testing.T) {
		e := newEnv(t)
		in := OauthInput{
			ProviderKey: "qq", Code: "code-1", State: state,
			StateCookie: e.sealLoginState(t, state, 99999), // 发起方 A
			UID:         10086,                             // 回调时会话已换成 B
		}
		if _, err := e.svc.ThirdpartyOauth(context.Background(), in); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("err = %v, want ErrInvalidRequest（行 1002 uid 串号）", err)
		}
	})
	t.Run("provider 不存在 / 停用 / 关闭登录 → provider_disabled", func(t *testing.T) {
		e := newEnv(t)
		in := newInput(e)
		in.ProviderKey = "nope"
		if _, err := e.svc.ThirdpartyOauth(context.Background(), in); !errors.Is(err, ErrProviderDisabled) {
			t.Errorf("err = %v, want ErrProviderDisabled", err)
		}
		e.loader.byKey["qq"] = providerRow("qq", "qq", "", 0, 1)
		if _, err := e.svc.ThirdpartyOauth(context.Background(), newInput(e)); !errors.Is(err, ErrProviderDisabled) {
			t.Errorf("err = %v, want ErrProviderDisabled（is_enabled=0）", err)
		}
		e.loader.byKey["qq"] = providerRow("qq", "qq", "", 1, 0)
		if _, err := e.svc.ThirdpartyOauth(context.Background(), newInput(e)); !errors.Is(err, ErrProviderDisabled) {
			t.Errorf("err = %v, want ErrProviderDisabled（enable_signin=0，不检查 enable_signup）", err)
		}
	})
	t.Run("非 redirect 通道 → invalid_request", func(t *testing.T) {
		e := newEnv(t)
		e.adapter.channel = provider.ChannelQRCode
		if _, err := e.svc.ThirdpartyOauth(context.Background(), newInput(e)); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("err = %v, want ErrInvalidRequest（行 1001 仅支持 redirect）", err)
		}
	})
	t.Run("Exchange / FetchUser 故障 → ErrFailed", func(t *testing.T) {
		e := newEnv(t)
		e.adapter.exchangeErr = errors.New("upstream down")
		if _, err := e.svc.ThirdpartyOauth(context.Background(), newInput(e)); !errors.Is(err, ErrFailed) {
			t.Errorf("err = %v, want ErrFailed", err)
		}
		e.adapter.exchangeErr = nil
		e.adapter.identity = nil
		if _, err := e.svc.ThirdpartyOauth(context.Background(), newInput(e)); !errors.Is(err, ErrFailed) {
			t.Errorf("err = %v, want ErrFailed（空身份）", err)
		}
	})
	t.Run("无会话 → unauthenticated", func(t *testing.T) {
		e := newEnv(t)
		in := newInput(e)
		in.UID = 0
		if _, err := e.svc.ThirdpartyOauth(context.Background(), in); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("err = %v, want ErrUnauthenticated", err)
		}
	})
}

// —— GetThirdpartyTicket（扫码绑定长轮询）——

// TestGetThirdpartyTicket 五态与差异点（§3.7.1 B 行 1012-1026）。
func TestGetThirdpartyTicket(t *testing.T) {
	const uid = 10086
	const ticketID = "ticket-0001"
	newTicket := func(e *env) string { return e.sealTicket(t, ticketID, "wechat_mp_scan", sceneBind, 10*time.Minute) }

	t.Run("非法 ticket → invalid_request（无 ticket 回显）", func(t *testing.T) {
		e := newEnv(t)
		resp := e.svc.GetThirdpartyTicket(context.Background(), TicketInput{Ticket: "garbage", UID: uid})
		if resp.GetStatus() != orchestrator.StatusInvalidRequest || resp.GetTicket() != nil {
			t.Errorf("resp = %+v, want status-only invalid_request", resp)
		}
	})
	t.Run("过期 → 双 expired 终态", func(t *testing.T) {
		e := newEnv(t)
		tk := e.sealTicket(t, ticketID, "wechat_mp_scan", sceneBind, -time.Minute)
		resp := e.svc.GetThirdpartyTicket(context.Background(), TicketInput{Ticket: tk, UID: uid})
		if resp.GetStatus() != statusExpired || resp.GetTicket().GetStatus() != statusExpired {
			t.Errorf("resp = %+v, want 双 expired", resp)
		}
		if len(e.tickets.results) != 0 {
			t.Error("expired 终态不应消费已写入结果")
		}
	})
	t.Run("login 票据 → invalid_request（反之亦然，行 1052）", func(t *testing.T) {
		e := newEnv(t)
		tk := e.sealTicket(t, ticketID, "wechat_mp_scan", "login", 10*time.Minute)
		resp := e.svc.GetThirdpartyTicket(context.Background(), TicketInput{Ticket: tk, UID: uid})
		if resp.GetStatus() != orchestrator.StatusInvalidRequest || resp.GetTicket() != nil {
			t.Errorf("resp = %+v, want status-only invalid_request", resp)
		}
	})
	t.Run("未就绪 → pending；poll 钳制 ≤15s 与剩余寿命", func(t *testing.T) {
		e := newEnv(t)
		tk := e.sealTicket(t, ticketID, "wechat_mp_scan", sceneBind, 10*time.Second)
		resp := e.svc.GetThirdpartyTicket(context.Background(), TicketInput{Ticket: tk, Poll: 99, UID: uid})
		if resp.GetStatus() != statusPending || resp.GetTicket().GetStatus() != statusPending ||
			resp.GetTicket().GetTicketId() != ticketID {
			t.Errorf("resp = %+v, want pending + ticketId 回显", resp)
		}
		// 99s 请求 → 钳到 15s；15s 请求且剩余寿命 10s → 钳到 10s（§2.8 行 729）。
		e2 := newEnv(t)
		tk2 := e2.sealTicket(t, "ticket-0002", "wechat_mp_scan", sceneBind, 10*time.Second)
		e2.svc.GetThirdpartyTicket(context.Background(), TicketInput{Ticket: tk2, Poll: 99, UID: uid})
		if len(e2.tickets.waited) != 1 || e2.tickets.waited[0] != 10*time.Second {
			t.Errorf("waited = %v, want [10s]（≤15s 且 ≤剩余寿命）", e2.tickets.waited)
		}
	})
	t.Run("已扫码 → scanned 回写 SETNX 幂等", func(t *testing.T) {
		e := newEnv(t)
		e.tickets.results[ticketID] = &token.TicketResult{V: 1, Scene: sceneBind, Status: ticketStatusScanned}
		resp := e.svc.GetThirdpartyTicket(context.Background(), TicketInput{Ticket: newTicket(e), UID: uid})
		if resp.GetStatus() != ticketStatusScanned || resp.GetTicket().GetStatus() != ticketStatusScanned {
			t.Errorf("resp = %+v, want 双 scanned", resp)
		}
		if len(e.tickets.scanIDs) != 1 || e.tickets.scanIDs[0] != ticketID {
			t.Errorf("scanIDs = %v, want 回写一次", e.tickets.scanIDs)
		}
		if _, ok := e.tickets.results[ticketID]; !ok {
			t.Error("scanned 标记应回写（后续轮询仍见）")
		}
	})
	t.Run("命中成功 → 当前会话 uid 完成绑定 + bind 字段", func(t *testing.T) {
		e := newEnv(t)
		e.tickets.results[ticketID] = bindResult("wechat_mp_scan", "openid-9", "union-9", sceneBind)
		resp := e.svc.GetThirdpartyTicket(context.Background(), TicketInput{Ticket: newTicket(e), UID: uid})
		if resp.GetStatus() != ticketStatusSuccess || resp.GetTicket().GetStatus() != ticketStatusSuccess {
			t.Fatalf("resp = %+v, want 双 success", resp)
		}
		bind := resp.GetBind()
		if bind == nil || bind.GetProviderKey() != "wechat_mp_scan" || bind.GetDisplayName() != "wechat_mp_scan-display" {
			t.Errorf("bind = %+v, want {providerKey, displayName}（行 1040）", bind)
		}
		if len(e.binds.created) != 1 {
			t.Fatalf("created = %d, want 1（绑定判定在 PC 端轮询时进行）", len(e.binds.created))
		}
		b := e.binds.created[0]
		if b.UserID != uid || b.ProviderKey != "wechat_mp_scan" || b.OpenID != "openid-9" {
			t.Errorf("created row = %+v, want 当前会话 uid + ticket 身份", b)
		}
		// Union 联动：wechat_mp_scan.union_provider=wechat_union + union-9（§12.7）。
		if e.binds.unions[0] != [2]string{"wechat_union", "union-9"} {
			t.Errorf("unions = %+v", e.binds.unions)
		}
		if len(e.audit.events) != 1 || e.audit.events[0].Event != eventlog.EventThirdpartyBind {
			t.Errorf("audit = %+v", e.audit.events)
		}
	})
	t.Run("provider_key 回显缺失回落 ticket 载荷", func(t *testing.T) {
		e := newEnv(t)
		res := bindResult("", "openid-9", "", sceneBind)
		res.ThirdpartyIdentity.Raw = nil
		e.tickets.results[ticketID] = res
		resp := e.svc.GetThirdpartyTicket(context.Background(), TicketInput{Ticket: newTicket(e), UID: uid})
		if resp.GetStatus() != ticketStatusSuccess {
			t.Fatalf("resp = %+v, want success（回显缺失回落 payload.provider_key）", resp)
		}
		if resp.GetBind().GetProviderKey() != "wechat_mp_scan" {
			t.Errorf("bind.providerKey = %q, want wechat_mp_scan", resp.GetBind().GetProviderKey())
		}
	})
	t.Run("结果 scene 非 bind → invalid_request + ticket failed（confirm 误写防护）", func(t *testing.T) {
		e := newEnv(t)
		e.tickets.results[ticketID] = bindResult("wechat_mp_scan", "openid-9", "", "login")
		resp := e.svc.GetThirdpartyTicket(context.Background(), TicketInput{Ticket: newTicket(e), UID: uid})
		if resp.GetStatus() != orchestrator.StatusInvalidRequest || resp.GetTicket().GetStatus() != ticketStatusFailed {
			t.Errorf("resp = %+v, want invalid_request + ticket failed", resp)
		}
		if len(e.binds.created) != 0 {
			t.Error("scene 不符不得写绑定关系")
		}
	})
	t.Run("命中但 target_taken → 信封 target_taken + 固定文案", func(t *testing.T) {
		e := newEnv(t)
		e.binds.rows[bindKey("wechat_mp_scan", "openid-9")] = model.UserThirdpartyBind{ID: 9, UserID: 999, ProviderKey: "wechat_mp_scan", OpenID: "openid-9"}
		e.tickets.results[ticketID] = bindResult("wechat_mp_scan", "openid-9", "union-9", sceneBind)
		resp := e.svc.GetThirdpartyTicket(context.Background(), TicketInput{Ticket: newTicket(e), UID: uid})
		if resp.GetStatus() != orchestrator.StatusTargetTaken || resp.GetTicket().GetStatus() != ticketStatusFailed {
			t.Errorf("resp = %+v, want target_taken + ticket failed（行 1044）", resp)
		}
		if got := resp.GetError().GetMessage(); got != "该账号已被其他账号绑定" {
			t.Errorf("error.message = %q, want 固定文案（行 987）", got)
		}
	})
	t.Run("失败类结果原样上抛信封", func(t *testing.T) {
		e := newEnv(t)
		e.tickets.results[ticketID] = &token.TicketResult{V: 1, Scene: sceneBind, Status: orchestrator.StatusFailed}
		resp := e.svc.GetThirdpartyTicket(context.Background(), TicketInput{Ticket: newTicket(e), UID: uid})
		if resp.GetStatus() != orchestrator.StatusFailed || resp.GetTicket().GetStatus() != ticketStatusFailed {
			t.Errorf("resp = %+v, want failed + ticket failed", resp)
		}
	})
	t.Run("绑定内核 provider_disabled → 信封 provider_disabled", func(t *testing.T) {
		e := newEnv(t)
		e.loader.byKey["wechat_mp_scan"] = providerRow("wechat_mp_scan", "wechat_mp_scan", "", 1, 0)
		e.tickets.results[ticketID] = bindResult("wechat_mp_scan", "openid-9", "", sceneBind)
		resp := e.svc.GetThirdpartyTicket(context.Background(), TicketInput{Ticket: newTicket(e), UID: uid})
		if resp.GetStatus() != statusProviderDisabled || resp.GetTicket().GetStatus() != ticketStatusFailed {
			t.Errorf("resp = %+v, want provider_disabled + ticket failed", resp)
		}
	})
}

// TestBindToCurrentUser 内核直测（§12.6 六步；uid / providerKey 入口防御 +
// FindByProviderOpenID 基础设施故障 → failed）。
func TestBindToCurrentUser(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	identity := BindIdentity{OpenID: "openid-1", UnionID: "union-1", Raw: map[string]any{"k": "v"}}

	if out, fail := e.svc.BindToCurrentUser(ctx, 0, "qq", identity); out != nil || fail != orchestrator.StatusInvalidRequest {
		t.Errorf("uid=0 → (%+v, %q), want invalid_request", out, fail)
	}
	if out, fail := e.svc.BindToCurrentUser(ctx, 10086, "", identity); out != nil || fail != orchestrator.StatusInvalidRequest {
		t.Errorf("空 providerKey → (%+v, %q), want invalid_request", out, fail)
	}
	if out, fail := e.svc.BindToCurrentUser(ctx, 10086, "nope", identity); out != nil || fail != statusProviderDisabled {
		t.Errorf("provider 缺失 → (%+v, %q), want provider_disabled", out, fail)
	}
	e.binds.findErr = errors.New("db down")
	if out, fail := e.svc.BindToCurrentUser(ctx, 10086, "qq", identity); out != nil || fail != orchestrator.StatusFailed {
		t.Errorf("查询故障 → (%+v, %q), want failed", out, fail)
	}
}
