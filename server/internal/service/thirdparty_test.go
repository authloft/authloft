// thirdparty_test.go 覆盖三方登录通道的 service 层用例：Authorize
// 两 scene / 未启用 / 非 redirect 通道 / state 前缀与 Cookie 属性断言；
// LoginOauth redirect 全链（fake adapter）/ state_mismatch 清 Cookie /
// api 通道信封 session_token / binding_required（allowSignup 两态 + tp 载荷
// 形态 §12.5 行 1499）/ auto_bind 命中与关闭 / Union 归并 / MFA 信封与
// amr=thirdparty / 扫码两阶段写入（scanned 快照校验链与幂等 /
// complete 按 scene 分派写 login_result / thirdparty_identity / MFA 不写
// ticket）；追加：user_disabled（普通行 / Union / auto_bind）/ auto_bind
// extra 落 Raw / 非成功终态删 al_login_state。全部走 fake，不连 DB / Redis；
// wechat_mp 渠道 code2session 的 httptest 拦截已由 provider/oauth/wechat_mp
// 包内测试覆盖，此处 api 通道以 fake adapter 验证 service 编排语义。
package service

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"gorm.io/gorm"

	"authloft/gen/go/token"
	"authloft/internal/cache"
	"authloft/internal/factor"
	"authloft/internal/provider"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
	"authloft/internal/session"
	"authloft/internal/settings"
)

// —— fake 全家 ——

// tpLoader ThirdpartyLoader 的 fake：按 key 返回预置 Provider。
type tpLoader struct {
	byKey map[string]*provider.Provider
}

func (l *tpLoader) Get(_ context.Context, key string) (*provider.Provider, error) {
	if p, ok := l.byKey[key]; ok {
		return p, nil
	}
	return nil, gorm.ErrRecordNotFound
}

// tpBinds ThirdpartyBindStore 的 fake。
type tpBinds struct {
	rows          map[string]model.UserThirdpartyBind // key = pk + "|" + openid
	created       []model.UserThirdpartyBind
	unionCreated  []string // 每次 CreateWithUnion 的 (unionProviderKey, unionID)
	createErr     error
	dupOnUnionKey string // 非空时该 (unionKey) 触发 ErrBindDuplicate
}

func key(pk, openid string) string { return pk + "|" + openid }

func (b *tpBinds) FindByProviderOpenID(_ context.Context, pk, openid string) (*model.UserThirdpartyBind, error) {
	if r, ok := b.rows[key(pk, openid)]; ok {
		r := r
		return &r, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (b *tpBinds) CreateWithUnion(_ context.Context, m *model.UserThirdpartyBind, unionProviderKey, unionID string) error {
	if b.createErr != nil {
		return b.createErr
	}
	if _, exists := b.rows[key(m.ProviderKey, m.OpenID)]; exists ||
		(unionProviderKey != "" && unionID != "" && b.dupOnUnionKey == key(unionProviderKey, unionID)) {
		return errors.Join(repoErrBindDuplicate, gorm.ErrDuplicatedKey)
	}
	b.created = append(b.created, *m)
	b.unionCreated = append(b.unionCreated, unionProviderKey+"|"+unionID)
	b.rows[key(m.ProviderKey, m.OpenID)] = *m
	if unionProviderKey != "" && unionID != "" {
		b.rows[key(unionProviderKey, unionID)] = model.UserThirdpartyBind{
			UserID: m.UserID, ProviderKey: unionProviderKey, OpenID: unionID,
		}
	}
	return nil
}

// repoErrBindDuplicate 与 repo.ErrBindDuplicate 同语义的本地哨兵（service
// 测试不 import repo，判别链经 errors.Is 满足即可——生产实现返回
// fmt.Errorf("%w: %w", repo.ErrBindDuplicate, ...)，本 fake 等价）。
var repoErrBindDuplicate = errors.New("bind repo: duplicate unique key")

// tpUsers factor.UserRepo + ThirdpartyUserLookup 的 fake。
type tpUsers struct {
	byID    map[int64]*model.User
	byEmail map[string]*model.User
	byPhone map[string]*model.User
}

func (u *tpUsers) FindByID(_ context.Context, id int64) (*model.User, error) {
	if m, ok := u.byID[id]; ok {
		return m, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (u *tpUsers) FindByEmail(_ context.Context, email string) (*model.User, error) {
	if m, ok := u.byEmail[email]; ok {
		return m, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (u *tpUsers) FindByPhone(_ context.Context, phone string) (*model.User, error) {
	if m, ok := u.byPhone[phone]; ok {
		return m, nil
	}
	return nil, gorm.ErrRecordNotFound
}

// tpCreds orchestrator.MFACredentialReader 的 fake：按 kind 返回 totp 行。
type tpCreds struct {
	totp     bool
	webauthn bool
}

func (c *tpCreds) FindByUserAndKind(_ context.Context, _ int64, kind string) (*model.UserCredential, error) {
	if kind == "totp" && c.totp {
		return &model.UserCredential{Kind: "totp", IsEnabled: 1}, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func (c *tpCreds) ListWebauthn(_ context.Context, _ int64) ([]model.UserCredentialWebauthn, error) {
	if c.webauthn {
		return []model.UserCredentialWebauthn{{UserID: 9}}, nil
	}
	return nil, nil
}

// tpSessions orchestrator.SessionWriter 的 fake。
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

// tpTickets TicketStore 的 fake（thirdparty 侧）：内存结果 +
// WriteScanned SET NX / WriteComplete 不覆盖 success 的简化语义 + 写入记录。
type tpTickets struct {
	results    map[string]*token.TicketResult
	scanWrites []string
	compWrites []string
}

func (f *tpTickets) WriteScanned(_ context.Context, id string, res *token.TicketResult) (cache.TicketWriteResult, error) {
	f.scanWrites = append(f.scanWrites, id)
	if _, ok := f.results[id]; ok {
		return cache.TicketWriteSkipped, nil
	}
	f.results[id] = res
	return cache.TicketWriteOK, nil
}

func (f *tpTickets) WriteComplete(_ context.Context, id string, res *token.TicketResult) (cache.TicketWriteResult, error) {
	f.compWrites = append(f.compWrites, id)
	if prev, ok := f.results[id]; ok && prev.GetStatus() == ticketStatusSuccess {
		return cache.TicketWriteSkipped, nil
	}
	f.results[id] = res
	return cache.TicketWriteOK, nil
}

func (f *tpTickets) Take(_ context.Context, id string) (*token.TicketResult, error) {
	return f.results[id], nil
}

func (f *tpTickets) Wait(_ context.Context, _ string, _ time.Duration) error {
	return cache.ErrTicketWaitTimeout
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

// tpEnv 汇总一套全 fake 的三方 service 依赖。
type tpEnv struct {
	loader   *tpLoader
	binds    *tpBinds
	users    *tpUsers
	adapter  *tpAdapter
	state    *orchestrator.State
	sessions *tpSessions
	settings *tpSettings
	tickets  *tpTickets
	payloads *tpTicketPayloads
	svc      *Thirdparty
	now      time.Time
	// httpsMode https_deployment 三态源（默认 nil = 未接入 → Secure 沿旧
	// 默认恒 true；三态用例覆写）。
	httpsMode func() string
}

// newTPEnv 构造：redirect 渠道 provider_key=qq（默认行形态见各用例覆写）。
func newTPEnv(t *testing.T) *tpEnv {
	t.Helper()
	at := time.Unix(1_700_000_000, 0)
	env := &tpEnv{
		loader: &tpLoader{byKey: map[string]*provider.Provider{}},
		binds:  &tpBinds{rows: map[string]model.UserThirdpartyBind{}},
		users: &tpUsers{
			byID:    map[int64]*model.User{},
			byEmail: map[string]*model.User{},
			byPhone: map[string]*model.User{},
		},
		adapter: &tpAdapter{
			channel: provider.ChannelRedirect,
			authURL: "https://graph.qq.com/oauth2.0/authorize?state={state}",
			identity: &provider.ExternalIdentity{
				ProviderKey: "qq", ProviderType: "qq",
				OpenID: "openid_1", Nickname: "QQ 用户", AvatarURL: "https://q.cn/a.png",
			},
		},
		sessions: &tpSessions{},
		tickets:  &tpTickets{results: map[string]*token.TicketResult{}},
		payloads: &tpTicketPayloads{snapshots: map[string]*token.TicketPayload{}},
		now:      at,
	}
	loginCodec := tpCodec(t, 0x10)
	cookieCodec := tpCodec(t, 0x20)
	env.state = orchestrator.NewState(loginCodec)

	st := &tpSettings{
		bools:  map[string]bool{settings.KeyMfaEnabled: true},
		slices: map[string][]string{settings.KeyMfaMethods: {"totp", "otp_sms", "otp_email", "webauthn"}},
	}
	env.settings = st
	terminal := orchestrator.NewTerminal(env.sessions, nil, nil, nil, nil)
	env.svc = NewThirdparty(ThirdpartyDeps{
		Loader:         env.loader,
		Binds:          env.binds,
		Users:          env.users,
		NewAdapter:     func(*provider.Provider) (provider.AuthAdapter, error) { return env.adapter, nil },
		State:          env.state,
		MFA:            orchestrator.NewMFABuilder(env.users, &tpCreds{}, st),
		Terminal:       terminal,
		Tickets:        env.tickets,
		TicketPayloads: env.payloads,
		CookieCodec:    cookieCodec,
		HTTPSMode:      env.httpsMode,
	})
	// cookie codec 的时钟跟随 env.now（过期用例推进）。
	env.svc.now = func() time.Time { return env.now }
	return env
}

// addProvider 注册一个 provider 行（默认启用 + 可登录）。
func (e *tpEnv) addProvider(pk string, mutate func(*model.Provider)) *provider.Provider {
	row := &model.Provider{
		ProviderKey: pk, Category: "oauth", Type: "qq",
		EnableSignin: 1, EnableSignup: 1, IsEnabled: 1,
		DisplayName: "QQ", AutoBindFields: "email,phone",
	}
	if mutate != nil {
		mutate(row)
	}
	p := &provider.Provider{Key: row.ProviderKey, Type: row.Type, Row: row}
	e.loader.byKey[pk] = p
	return p
}

// stateCookie 用 env 的 cookie codec 签一枚 al_login_state 值。
func (e *tpEnv) stateCookie(t *testing.T, state string, uid int64, age time.Duration) string {
	t.Helper()
	codec := e.svc.deps.CookieCodec
	payload := &token.LoginStatePayload{
		State: state, Uid: uid,
		Iat: e.now.Add(-age).Unix(),
		Exp: e.now.Add(-age).Add(loginStateTTL).Unix(),
	}
	v, err := codec.Seal(security.PurposeCookie, payload)
	if err != nil {
		t.Fatalf("Seal cookie: %v", err)
	}
	return v
}

// —— Authorize ——

// TestAuthorizeScenes 两 scene + 未启用 + 非 redirect + Cookie 属性与
// state 前缀断言（§2.7.2 行 593-613、§12.4 行 1485-1486）。
func TestAuthorizeScenes(t *testing.T) {
	ctx := context.Background()

	t.Run("login scene", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		out, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "qq"})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if out.AuthorizeURL == "" {
			t.Fatal("authorize_url 应非空")
		}
		ck := out.Cookie
		if ck == nil {
			t.Fatal("应下发 al_login_state Cookie")
		}
		// Cookie 属性断言（§12.4 行 1486 / §1.9 行 303：HttpOnly; SameSite=Lax
		// 恒定、会话级不设 Max-Age；Secure 在未注入三态源（deps.HTTPSMode nil）
		// 时沿旧默认恒 true——三态驱动见
		// TestAuthorizeLoginStateCookieHTTPSDeployment）。
		if ck.Name != LoginStateCookieName || ck.Path != "/" || !ck.HttpOnly ||
			!ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.MaxAge != 0 || ck.Domain != "" {
			t.Fatalf("Cookie 属性 = %+v", ck)
		}
		// 载荷：state 一致且 l 前缀、uid=0（login 场景，§12.4 行 1485）。
		payload, err := security.Open[token.LoginStatePayload](e.svc.deps.CookieCodec, security.PurposeCookie, ck.Value)
		if err != nil {
			t.Fatalf("Open cookie: %v", err)
		}
		if payload.GetUid() != 0 {
			t.Errorf("login 场景 uid = %d, want 0", payload.GetUid())
		}
		state := payload.GetState()
		if len(state) != 1+stateRandomLen || state[:1] != StatePrefixLogin {
			t.Fatalf("state 前缀/长度 = %q", state)
		}
		if got := e.adapter.lastCtx.State; got != state {
			t.Errorf("BuildAuthURL state = %q, want %q", got, state)
		}
		if e.adapter.lastCtx.ProviderKey != "qq" {
			t.Errorf("AuthContext.ProviderKey = %q", e.adapter.lastCtx.ProviderKey)
		}
	})

	t.Run("bind scene 带会话", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		out, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "qq", Scene: "bind", UID: 42})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		payload, err := security.Open[token.LoginStatePayload](e.svc.deps.CookieCodec, security.PurposeCookie, out.Cookie.Value)
		if err != nil {
			t.Fatalf("Open cookie: %v", err)
		}
		if payload.GetUid() != 42 {
			t.Errorf("bind 场景 uid = %d, want 42", payload.GetUid())
		}
		if s := payload.GetState(); s[:1] != StatePrefixBind {
			t.Errorf("state 前缀 = %q, want %q", s[:1], StatePrefixBind)
		}
	})

	t.Run("bind scene 无会话 401", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		if _, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "qq", Scene: "bind"}); !errors.Is(err, ErrThirdpartyUnauthenticated) {
			t.Fatalf("err = %v, want ErrThirdpartyUnauthenticated", err)
		}
	})

	t.Run("scene 非法", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		if _, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "qq", Scene: "other"}); !errors.Is(err, ErrThirdpartyInvalidRequest) {
			t.Fatalf("err = %v, want ErrThirdpartyInvalidRequest", err)
		}
	})

	t.Run("provider 空", func(t *testing.T) {
		e := newTPEnv(t)
		if _, err := e.svc.Authorize(ctx, AuthorizeInput{}); !errors.Is(err, ErrThirdpartyInvalidRequest) {
			t.Fatalf("err = %v, want ErrThirdpartyInvalidRequest", err)
		}
	})

	t.Run("未启用 / 不允许登录 / 不存在", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("off", func(r *model.Provider) { r.IsEnabled = 0 })
		e.addProvider("nosignin", func(r *model.Provider) { r.EnableSignin = 0 })
		for _, pk := range []string{"off", "nosignin", "missing"} {
			if _, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: pk}); !errors.Is(err, ErrThirdpartyProviderDisabled) {
				t.Errorf("%s: err = %v, want ErrThirdpartyProviderDisabled", pk, err)
			}
		}
	})

	t.Run("非 redirect 通道", func(t *testing.T) {
		for _, ch := range []provider.ThirdPartyChannel{provider.ChannelAPI, provider.ChannelQRCode} {
			e := newTPEnv(t)
			e.addProvider("qq", nil)
			e.adapter.channel = ch
			if _, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "qq"}); !errors.Is(err, ErrThirdpartyInvalidRequest) {
				t.Errorf("channel %q: err = %v, want ErrThirdpartyInvalidRequest", ch, err)
			}
		}
	})
}

// TestAuthorizeLoginStateCookieHTTPSDeployment al_login_state 的
// Secure 属性受 https_deployment 三态驱动（§1.9 行 303：HttpOnly /
// SameSite=Lax / 会话级恒定不变；判定为真 → HttpOnly; Secure; SameSite=Lax，
// 判定为假 → 省略 Secure）。auto 信号经 ctx（connect 装配层注入的
// RequestSignal）；SameSite 不随 Secure 联动（它本就是 Lax）——与
// al_session 的 None↔Lax 联动相区分。
func TestAuthorizeLoginStateCookieHTTPSDeployment(t *testing.T) {
	base := context.Background()
	httpsHeader := http.Header{"X-Forwarded-Proto": []string{"https"}}

	cases := []struct {
		name   string
		mode   func() string
		ctx    context.Context
		secure bool
	}{
		{"false 恒明文（无视 https 头）", func() string { return settings.HTTPSDeploymentFalse },
			session.WithRequestSignal(base, session.RequestSignal{Header: httpsHeader}), false},
		{"true 恒 HTTPS（无信号）", func() string { return settings.HTTPSDeploymentTrue }, base, true},
		{"auto + 头 https", func() string { return settings.HTTPSDeploymentAuto },
			session.WithRequestSignal(base, session.RequestSignal{Header: httpsHeader}), true},
		{"auto + 无信号兜底明文", func() string { return settings.HTTPSDeploymentAuto }, base, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTPEnv(t)
			e.httpsMode = tc.mode
			// 重新装配 svc（newTPEnv 内构造时 httpsMode 尚未覆写）。
			e.svc = NewThirdparty(ThirdpartyDeps{
				Loader:      e.loader,
				Binds:       e.binds,
				Users:       e.users,
				NewAdapter:  func(*provider.Provider) (provider.AuthAdapter, error) { return e.adapter, nil },
				State:       e.state,
				MFA:         orchestrator.NewMFABuilder(e.users, &tpCreds{}, e.settings),
				Terminal:    orchestrator.NewTerminal(e.sessions, nil, nil, nil, nil),
				CookieCodec: e.svc.deps.CookieCodec,
				HTTPSMode:   e.httpsMode,
			})
			e.svc.now = func() time.Time { return e.now }
			e.addProvider("qq", nil)
			out, err := e.svc.Authorize(tc.ctx, AuthorizeInput{Provider: "qq"})
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			ck := out.Cookie
			if ck == nil {
				t.Fatal("应下发 al_login_state Cookie")
			}
			if ck.Secure != tc.secure {
				t.Errorf("Secure = %v, want %v", ck.Secure, tc.secure)
			}
			// SameSite 恒 Lax（§1.9 行 303：不随 Secure 联动降级）。
			if ck.SameSite != http.SameSiteLaxMode {
				t.Errorf("SameSite = %v, want Lax（al_login_state 恒定）", ck.SameSite)
			}
			if !ck.HttpOnly || ck.Path != "/" || ck.MaxAge != 0 {
				t.Errorf("HttpOnly/Path/Max-Age 应恒定: %+v", ck)
			}
		})
	}
}

// —— LoginOauth ——

// oauthRequest 组装 redirect 通道请求（state + cookie 配对）。
func (e *tpEnv) oauthRequest(t *testing.T, state string, age time.Duration) OauthInput {
	return OauthInput{
		ProviderKey: "qq",
		Code:        "authcode",
		State:       state,
		StateCookie: e.stateCookie(t, state, 0, age),
	}
}

// TestLoginOauthRedirectFullChain redirect 全链：已绑定无 MFA → success、
// state Cookie 删除、会话写入 amr=thirdparty（§12.4 行 1494）。
func TestLoginOauthRedirectFullChain(t *testing.T) {
	ctx := context.Background()
	e := newTPEnv(t)
	e.addProvider("qq", nil)
	e.binds.rows[key("qq", "openid_1")] = model.UserThirdpartyBind{UserID: 7, ProviderKey: "qq", OpenID: "openid_1"}
	e.users.byID[7] = &model.User{ID: 7, UserStatus: 1, MfaRequired: 0}

	// 先经 Authorize 拿一枚合法 state（端到端形态）。
	auth, err := e.svc.Authorize(ctx, AuthorizeInput{Provider: "qq"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	payload, _ := security.Open[token.LoginStatePayload](e.svc.deps.CookieCodec, security.PurposeCookie, auth.Cookie.Value)
	in := OauthInput{ProviderKey: "qq", Code: "authcode", State: payload.GetState(), StateCookie: auth.Cookie.Value}

	out := e.svc.LoginOauth(ctx, in)
	if out.Envelope.GetStatus() != "success" {
		t.Fatalf("status = %q, want success (resp %+v)", out.Envelope.GetStatus(), out.Envelope)
	}
	if out.Envelope.GetUserId() != 7 || out.Envelope.GetSessionId() != "sid-1" {
		t.Errorf("信封 = %+v", out.Envelope)
	}
	// state 校验通过即删（§2.7.2 行 611）。
	if out.Cookie == nil || out.Cookie.MaxAge != -1 || out.Cookie.Name != LoginStateCookieName {
		t.Errorf("Cookie = %+v, want MaxAge=-1 删除", out.Cookie)
	}
	// 浏览器场景 session_token 出参（handler 经 Cookie 下发）；信封不带。
	if out.SessionToken != "stok-1" || out.Envelope.GetSessionToken() != "" || out.SessionInBody {
		t.Errorf("session_token 出参 = %q / 信封 = %q / inBody=%v", out.SessionToken, out.Envelope.GetSessionToken(), out.SessionInBody)
	}
	if e.sessions.gotUID != 7 {
		t.Errorf("会话 uid = %d, want 7", e.sessions.gotUID)
	}
	if len(e.sessions.gotAMR) != 1 || e.sessions.gotAMR[0] != amrThirdParty {
		t.Errorf("会话 amr = %v, want [thirdparty]", e.sessions.gotAMR)
	}
}

// TestLoginOauthStateMismatch 四态：不一致 / b 前缀 / Cookie 缺失 / 过期
// → state_mismatch 且清 Cookie（§12.4 行 1493、§2.7.2 行 611）。
func TestLoginOauthStateMismatch(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		in   func(e *tpEnv, t *testing.T) OauthInput
	}{
		{"state 与 Cookie 不一致", func(e *tpEnv, t *testing.T) OauthInput {
			in := e.oauthRequest(t, "l"+"a", 0)
			in.State = "l" + "b"
			return in
		}},
		{"b 前缀不由本接口处理", func(e *tpEnv, t *testing.T) OauthInput {
			return e.oauthRequest(t, StatePrefixBind+"abc", 0)
		}},
		{"Cookie 缺失", func(e *tpEnv, t *testing.T) OauthInput {
			return OauthInput{ProviderKey: "qq", Code: "authcode", State: "l" + "abc"}
		}},
		{"Cookie 过期", func(e *tpEnv, t *testing.T) OauthInput {
			return e.oauthRequest(t, "l"+"abc", loginStateTTL+time.Minute)
		}},
		{"state 空", func(e *tpEnv, t *testing.T) OauthInput {
			in := e.oauthRequest(t, "l"+"abc", 0)
			in.State = ""
			return in
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTPEnv(t)
			e.addProvider("qq", nil)
			out := e.svc.LoginOauth(ctx, tc.in(e, t))
			if out.Envelope.GetStatus() != statusStateMismatch {
				t.Fatalf("status = %q, want state_mismatch", out.Envelope.GetStatus())
			}
			if out.Cookie == nil || out.Cookie.MaxAge != -1 {
				t.Errorf("应清 Cookie, got %+v", out.Cookie)
			}
			if e.sessions.gotUID != 0 {
				t.Errorf("不应建会话, got uid=%d", e.sessions.gotUID)
			}
		})
	}
}

// TestLoginOauthRejects 入口拒绝：scanned 缺 ticketId / complete 带
// ticketId 但非 qrcode 通道 / provider_key 空、code 空、qrcode 通道无
// ticketId、未启用 provider。
func TestLoginOauthRejects(t *testing.T) {
	ctx := context.Background()

	t.Run("scanned 缺 ticketId / ticketId 通道不符", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		for _, in := range []OauthInput{
			// stage=scanned 必带 ticketId（§2.7.4 行 641）。
			{ProviderKey: "qq", Code: "c", Stage: stageScanned},
			// 扫码提交必为 qrcode 通道（§13.2）；redirect 通道携带 ticketId
			// 不合规范。
			{ProviderKey: "qq", Code: "c", TicketID: "t-1"},
		} {
			if out := e.svc.LoginOauth(ctx, in); out.Envelope.GetStatus() != orchestrator.StatusInvalidRequest {
				t.Errorf("in=%+v: status = %q, want invalid_request", in, out.Envelope.GetStatus())
			}
		}
	})

	t.Run("参数缺失", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		for _, in := range []OauthInput{
			{Code: "c"},
			{ProviderKey: "qq"},
		} {
			if out := e.svc.LoginOauth(ctx, in); out.Envelope.GetStatus() != orchestrator.StatusInvalidRequest {
				t.Errorf("in=%+v: status = %q, want invalid_request", in, out.Envelope.GetStatus())
			}
		}
	})

	t.Run("qrcode 通道", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("wxscan", nil)
		e.adapter.channel = provider.ChannelQRCode
		out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Code: "c"})
		if out.Envelope.GetStatus() != orchestrator.StatusInvalidRequest {
			t.Fatalf("status = %q, want invalid_request", out.Envelope.GetStatus())
		}
	})

	t.Run("未启用 provider", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", func(r *model.Provider) { r.EnableSignin = 0 })
		out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "qq", Code: "c"})
		if out.Envelope.GetStatus() != statusProviderDisabled {
			t.Fatalf("status = %q, want provider_disabled", out.Envelope.GetStatus())
		}
	})
}

// —— 扫码两阶段写入（§2.7.4 行 656-659、§13.2b）——

// seedSnapshot 预置一张快照（默认与 env.now 对齐、exp=600s）。
func (e *tpEnv) seedSnapshot(id, pk, scene string) *token.TicketPayload {
	p := &token.TicketPayload{
		TicketId:    id,
		ProviderKey: pk,
		Scene:       scene,
		Iat:         e.now.Unix(),
		Exp:         e.now.Add(qrcodeTicketTTL).Unix(),
	}
	e.payloads.snapshots[id] = p
	return p
}

// newScanEnv 构造扫码提交环境：qrcode 通道 provider + 快照。
func newScanEnv(t *testing.T, scene string) *tpEnv {
	t.Helper()
	e := newTPEnv(t)
	e.addProvider("wxscan", nil)
	e.adapter.channel = provider.ChannelQRCode
	e.adapter.identity.ProviderKey = "wxscan"
	e.seedSnapshot("tid-1", "wxscan", scene)
	return e
}

// TestLoginOauthScanned stage=scanned：快照校验通过 → WriteScanned 空结果
// （TicketResult{status:"scanned", scene, channel=qrcode, expires_at 与
// ticket.exp 一致}，不含 login_result / thirdparty_identity）→ 票据状态应答
// {status:"scanned"}；重复上报幂等（SET NX 不覆盖）。
func TestLoginOauthScanned(t *testing.T) {
	ctx := context.Background()

	t.Run("正向写入", func(t *testing.T) {
		e := newScanEnv(t, sceneLogin)
		out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Stage: stageScanned, TicketID: "tid-1"})
		if out.Envelope.GetStatus() != ticketStatusScanned {
			t.Fatalf("status = %q, want scanned", out.Envelope.GetStatus())
		}
		if out.Envelope.GetTicket() != nil {
			t.Errorf("scanned 应答只含 status, got ticket %+v", out.Envelope.GetTicket())
		}
		if len(e.tickets.scanWrites) != 1 || e.tickets.scanWrites[0] != "tid-1" {
			t.Fatalf("WriteScanned = %v, want [tid-1]", e.tickets.scanWrites)
		}
		res := e.tickets.results["tid-1"]
		if res.GetStatus() != ticketStatusScanned || res.GetScene() != sceneLogin ||
			res.GetProviderKey() != "wxscan" || res.GetChannel() != channelQRCode ||
			res.GetV() != ticketResultV {
			t.Fatalf("TicketResult = %+v", res)
		}
		if res.GetExpiresAt() != e.payloads.snapshots["tid-1"].GetExp() {
			t.Errorf("expires_at = %d, want 与 ticket.exp 一致", res.GetExpiresAt())
		}
		if res.GetLoginResult() != nil || res.GetThirdpartyIdentity() != nil {
			t.Errorf("scanned 空结果不含 login_result / thirdparty_identity, got %+v", res)
		}
		// scanned 不建会话、不签 token。
		if e.sessions.gotUID != 0 {
			t.Errorf("不应建会话, uid=%d", e.sessions.gotUID)
		}
	})

	t.Run("幂等：重复上报不覆盖", func(t *testing.T) {
		e := newScanEnv(t, sceneLogin)
		for i := 0; i < 2; i++ {
			out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Stage: stageScanned, TicketID: "tid-1"})
			if out.Envelope.GetStatus() != ticketStatusScanned {
				t.Fatalf("第 %d 次上报 status = %q, want scanned", i+1, out.Envelope.GetStatus())
			}
		}
		if len(e.tickets.scanWrites) != 2 {
			t.Fatalf("两次上报应各调一次 WriteScanned, got %v", e.tickets.scanWrites)
		}
		if res := e.tickets.results["tid-1"]; res.GetStatus() != ticketStatusScanned {
			t.Fatalf("结果应为 scanned, got %q", res.GetStatus())
		}
	})

	t.Run("已存在 success 不覆盖", func(t *testing.T) {
		e := newScanEnv(t, sceneLogin)
		e.tickets.results["tid-1"] = &token.TicketResult{V: ticketResultV, Status: ticketStatusSuccess}
		out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Stage: stageScanned, TicketID: "tid-1"})
		if out.Envelope.GetStatus() != ticketStatusScanned {
			t.Fatalf("status = %q, want scanned（上报幂等成功）", out.Envelope.GetStatus())
		}
		if res := e.tickets.results["tid-1"]; res.GetStatus() != ticketStatusSuccess {
			t.Fatalf("success 被覆盖为 %q", res.GetStatus())
		}
	})

	t.Run("快照校验链拒绝", func(t *testing.T) {
		// 缺失（不存在 / 已过期）。
		e := newScanEnv(t, sceneLogin)
		out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Stage: stageScanned, TicketID: "tid-none"})
		if out.Envelope.GetStatus() != orchestrator.StatusInvalidRequest {
			t.Fatalf("快照缺失: status = %q, want invalid_request", out.Envelope.GetStatus())
		}
		// scene 非法（与本次扫码用途不一致）。
		e2 := newScanEnv(t, sceneLogin)
		e2.seedSnapshot("tid-2", "wxscan", "other")
		out2 := e2.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Stage: stageScanned, TicketID: "tid-2"})
		if out2.Envelope.GetStatus() != orchestrator.StatusInvalidRequest {
			t.Fatalf("scene 不匹配: status = %q, want invalid_request", out2.Envelope.GetStatus())
		}
		// providerKey 不匹配。
		e3 := newScanEnv(t, sceneLogin)
		out3 := e3.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxother", Stage: stageScanned, TicketID: "tid-1"})
		if out3.Envelope.GetStatus() != orchestrator.StatusInvalidRequest {
			t.Fatalf("providerKey 不匹配: status = %q, want invalid_request", out3.Envelope.GetStatus())
		}
		// 快照过期（键 TTL 与 ticket 同寿命的防御性复判）。
		e4 := newScanEnv(t, sceneLogin)
		e4.seedSnapshot("tid-3", "wxscan", sceneLogin).Exp = e4.now.Unix()
		out4 := e4.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Stage: stageScanned, TicketID: "tid-3"})
		if out4.Envelope.GetStatus() != orchestrator.StatusInvalidRequest {
			t.Fatalf("快照过期: status = %q, want invalid_request", out4.Envelope.GetStatus())
		}
		// 校验不通过一律不写 ticket。
		for _, env := range []*tpEnv{e, e2, e3, e4} {
			if len(env.tickets.scanWrites) != 0 {
				t.Errorf("校验失败不应写 ticket, got %v", env.tickets.scanWrites)
			}
		}
	})

	t.Run("bind 场景同样支持 scanned 中间态", func(t *testing.T) {
		e := newScanEnv(t, sceneBind)
		out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Stage: stageScanned, TicketID: "tid-1"})
		if out.Envelope.GetStatus() != ticketStatusScanned {
			t.Fatalf("status = %q, want scanned", out.Envelope.GetStatus())
		}
		if res := e.tickets.results["tid-1"]; res.GetScene() != sceneBind {
			t.Fatalf("scene = %q, want bind", res.GetScene())
		}
	})

	t.Run("快照读取 infra 故障 → failed", func(t *testing.T) {
		e := newScanEnv(t, sceneLogin)
		e.payloads.err = errors.New("redis down")
		out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Stage: stageScanned, TicketID: "tid-1"})
		if out.Envelope.GetStatus() != orchestrator.StatusFailed {
			t.Fatalf("status = %q, want failed", out.Envelope.GetStatus())
		}
	})
}

// TestLoginOauthTicketComplete stage=complete 带 ticketId：按 scene 分派写
// TicketResult（§2.7.4 行 649、§13.2b 行 1616、§11.6.5）。
func TestLoginOauthTicketComplete(t *testing.T) {
	ctx := context.Background()

	submit := func(e *tpEnv) *OauthOutput {
		return e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Code: "c", TicketID: "tid-1"})
	}

	t.Run("login 已绑定 → login_result", func(t *testing.T) {
		e := newScanEnv(t, sceneLogin)
		e.binds.rows[key("wxscan", "openid_1")] = model.UserThirdpartyBind{UserID: 7, ProviderKey: "wxscan", OpenID: "openid_1"}
		e.users.byID[7] = &model.User{ID: 7, UserStatus: 1, MfaRequired: 0}
		out := submit(e)
		if out.Envelope.GetStatus() != orchestrator.StatusSuccess {
			t.Fatalf("status = %q, want success", out.Envelope.GetStatus())
		}
		if tk := out.Envelope.GetTicket(); tk == nil || tk.GetStatus() != ticketStatusSuccess || tk.GetTicketId() != "tid-1" {
			t.Fatalf("ticket = %+v, want {success, tid-1}", tk)
		}
		res := e.tickets.results["tid-1"]
		lr := res.GetLoginResult()
		if lr == nil || lr.GetUid() != 7 || lr.GetBindingRequired() {
			t.Fatalf("login_result = %+v, want {uid:7, binding_required:false}", lr)
		}
		if res.GetThirdpartyIdentity() != nil {
			t.Errorf("已绑定登录不填 thirdparty_identity, got %+v", res.GetThirdpartyIdentity())
		}
		// 建会话推迟到 PC 端轮询（§2.8 行 746），本侧不建。
		if e.sessions.gotUID != 0 {
			t.Errorf("不应建会话, uid=%d", e.sessions.gotUID)
		}
		if out.SessionToken != "" || out.Cookie != nil {
			t.Errorf("ticket 分支无会话 / Cookie 出参, got %+v", out)
		}
	})

	t.Run("login 未绑定 → binding_required + thirdparty_identity", func(t *testing.T) {
		e := newScanEnv(t, sceneLogin)
		out := submit(e)
		if out.Envelope.GetStatus() != orchestrator.StatusSuccess {
			t.Fatalf("status = %q, want success", out.Envelope.GetStatus())
		}
		res := e.tickets.results["tid-1"]
		lr := res.GetLoginResult()
		if lr == nil || lr.GetUid() != 0 || !lr.GetBindingRequired() {
			t.Fatalf("login_result = %+v, want {uid:0, binding_required:true}", lr)
		}
		// 轮询方用 thirdparty_identity 签发 login_token（§11.6.5 行 1370）。
		idn := res.GetThirdpartyIdentity()
		if idn == nil || idn.GetOpenId() != "openid_1" || idn.GetNickname() != "QQ 用户" {
			t.Fatalf("thirdparty_identity = %+v", idn)
		}
		// 不签 token、不建会话（信封由轮询方组装）。
		if out.Envelope.GetLoginToken() != "" || e.sessions.gotUID != 0 {
			t.Errorf("本侧不签 token / 不建会话, out=%+v uid=%d", out.Envelope, e.sessions.gotUID)
		}
	})

	t.Run("bind → thirdparty_identity，不建会话不查绑定不写绑定关系", func(t *testing.T) {
		e := newScanEnv(t, sceneBind)
		e.adapter.identity.UnionID = "union_1"
		e.adapter.identity.Raw = map[string]any{"session_key": "sk-1"}
		out := submit(e)
		if out.Envelope.GetStatus() != orchestrator.StatusSuccess {
			t.Fatalf("status = %q, want success", out.Envelope.GetStatus())
		}
		res := e.tickets.results["tid-1"]
		if res.GetScene() != sceneBind || res.GetLoginResult() != nil {
			t.Fatalf("bind 结果 = %+v（无 login_result）", res)
		}
		idn := res.GetThirdpartyIdentity()
		if idn == nil || idn.GetOpenId() != "openid_1" || idn.GetUnionId() != "union_1" ||
			idn.GetNickname() != "QQ 用户" || idn.GetAvatarUrl() != "https://q.cn/a.png" {
			t.Fatalf("thirdparty_identity = %+v", idn)
		}
		if idn.GetRaw().GetFields()["session_key"].GetStringValue() != "sk-1" {
			t.Errorf("raw = %+v, want 含 session_key（绑定要落 extra）", idn.GetRaw())
		}
		// 不查绑定（预置普通行也不归并）、不写绑定、不建会话（§13.2b）。
		e2 := newScanEnv(t, sceneBind)
		e2.binds.rows[key("wxscan", "openid_1")] = model.UserThirdpartyBind{UserID: 7, ProviderKey: "wxscan", OpenID: "openid_1"}
		e2.users.byID[7] = &model.User{ID: 7, UserStatus: 1}
		out2 := submit(e2)
		if out2.Envelope.GetStatus() != orchestrator.StatusSuccess {
			t.Fatalf("status = %q, want success", out2.Envelope.GetStatus())
		}
		if len(e2.binds.created) != 0 {
			t.Errorf("bind 场景不应写绑定关系, got %d 行", len(e2.binds.created))
		}
		if e2.sessions.gotUID != 0 {
			t.Errorf("bind 场景不建会话, uid=%d", e2.sessions.gotUID)
		}
	})

	t.Run("失败类 → ticket failed + 信封 status", func(t *testing.T) {
		// Exchange 失败。
		e := newScanEnv(t, sceneLogin)
		e.adapter.exchangeErr = errors.New("upstream 500")
		out := submit(e)
		if out.Envelope.GetStatus() != orchestrator.StatusFailed {
			t.Fatalf("Exchange 失败: status = %q, want failed", out.Envelope.GetStatus())
		}
		if tk := out.Envelope.GetTicket(); tk == nil || tk.GetStatus() != ticketStatusFailed || tk.GetTicketId() != "tid-1" {
			t.Fatalf("ticket = %+v, want {failed, tid-1}", tk)
		}
		if res := e.tickets.results["tid-1"]; res.GetStatus() != orchestrator.StatusFailed {
			t.Fatalf("TicketResult.status = %q, want failed（结论落结果）", res.GetStatus())
		}
		// 用户禁用（§1.6 行 253）。
		e2 := newScanEnv(t, sceneLogin)
		e2.binds.rows[key("wxscan", "openid_1")] = model.UserThirdpartyBind{UserID: 8, ProviderKey: "wxscan", OpenID: "openid_1"}
		e2.users.byID[8] = &model.User{ID: 8, UserStatus: 2}
		out2 := submit(e2)
		if out2.Envelope.GetStatus() != statusUserDisabled {
			t.Fatalf("user_disabled: status = %q", out2.Envelope.GetStatus())
		}
		if res := e2.tickets.results["tid-1"]; res.GetStatus() != statusUserDisabled {
			t.Fatalf("TicketResult.status = %q, want user_disabled", res.GetStatus())
		}
		if tk := out2.Envelope.GetTicket(); tk.GetStatus() != ticketStatusFailed {
			t.Fatalf("ticket = %+v, want failed", tk)
		}
	})

	t.Run("快照校验拒绝 → 不写 ticket", func(t *testing.T) {
		e := newScanEnv(t, sceneLogin)
		out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Code: "c", TicketID: "tid-none"})
		if out.Envelope.GetStatus() != orchestrator.StatusInvalidRequest {
			t.Fatalf("status = %q, want invalid_request", out.Envelope.GetStatus())
		}
		if len(e.tickets.compWrites) != 0 {
			t.Errorf("校验失败不应写 ticket, got %v", e.tickets.compWrites)
		}
	})
}

// TestLoginOauthTicketMFA MFA×扫码（§2.8 行 750、§13.2 行 1607）：已绑定
// 用户启用 MFA → mfa_required 信封（login_token + mfa，语义与非扫码路径
// 一致）、**不写 ticket**（PC 端轮询至 expired）。
func TestLoginOauthTicketMFA(t *testing.T) {
	ctx := context.Background()
	e := newScanEnv(t, sceneLogin)
	e.binds.rows[key("wxscan", "openid_1")] = model.UserThirdpartyBind{UserID: 3, ProviderKey: "wxscan", OpenID: "openid_1"}
	e.users.byID[3] = &model.User{ID: 3, UserStatus: 1, MfaRequired: 1}
	// totp 凭证存在 → MFA required（凭证 fake 重建 builder）。
	e.svc.deps.MFA = orchestrator.NewMFABuilder(e.users, &tpCreds{totp: true}, e.settings)

	out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wxscan", Code: "c", TicketID: "tid-1"})
	if out.Envelope.GetStatus() != orchestrator.StatusMFARequired {
		t.Fatalf("status = %q, want mfa_required", out.Envelope.GetStatus())
	}
	if m := out.Envelope.GetMfa(); m == nil || len(m.GetMethods()) == 0 {
		t.Errorf("mfa = %+v", m)
	}
	if out.Envelope.GetLoginToken() == "" {
		t.Error("mfa_required 信封应含 login_token（既有分支语义）")
	}
	// 不写 ticket：无 scanned / complete 写入、无结果键。
	if len(e.tickets.scanWrites) != 0 || len(e.tickets.compWrites) != 0 || len(e.tickets.results) != 0 {
		t.Fatalf("MFA 不写 ticket, scan=%v comp=%v results=%v",
			e.tickets.scanWrites, e.tickets.compWrites, e.tickets.results)
	}
	if e.sessions.gotUID != 0 {
		t.Errorf("MFA 前不应建会话, uid=%d", e.sessions.gotUID)
	}
}

// TestLoginOauthBindingRequired 未绑定：binding_required 信封 + 重签
// login_token 精简 tp 载荷（§12.5 行 1499-1501：pk/openid/unionid/nickname/
// avatar，Raw 不进载荷）+ allowSignup 两态（enable_signup 映射，§2.7.5 行 678）。
func TestLoginOauthBindingRequired(t *testing.T) {
	ctx := context.Background()

	newCase := func(t *testing.T, enableSignup int8) (*tpEnv, *OauthOutput) {
		e := newTPEnv(t)
		e.addProvider("qq", func(r *model.Provider) {
			r.EnableSignup = enableSignup
			r.UnionProvider = "qq_union"
		})
		e.adapter.identity.UnionID = "union_9"
		e.adapter.identity.Email = "new@example.com"
		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		return e, out
	}

	t.Run("allowSignup=true", func(t *testing.T) {
		e, out := newCase(t, 1)
		if out.Envelope.GetStatus() != orchestrator.StatusBindingRequired {
			t.Fatalf("status = %q, want binding_required", out.Envelope.GetStatus())
		}
		b := out.Envelope.GetBinding()
		if b.GetProviderKey() != "qq" || b.GetDisplayName() != "QQ" || !b.GetAllowSignup() ||
			b.GetNickname() != "QQ 用户" || b.GetAvatarUrl() != "https://q.cn/a.png" {
			t.Errorf("binding = %+v", b)
		}
		// tp 载荷形态（§12.5 行 1499）：五字段齐、无 Raw（proto 无该字段）。
		p, err := e.state.Parse(out.Envelope.GetLoginToken())
		if err != nil {
			t.Fatalf("Parse login_token: %v", err)
		}
		tp := p.GetTp()
		if tp == nil || tp.GetProviderKey() != "qq" || tp.GetOpenId() != "openid_1" ||
			tp.GetUnionId() != "union_9" || tp.GetNickname() != "QQ 用户" || tp.GetAvatarUrl() != "https://q.cn/a.png" {
			t.Errorf("tp 载荷 = %+v", tp)
		}
		if p.GetFlow() != "login" || p.GetUid() != 0 {
			t.Errorf("payload flow/uid = %q/%d, want login/0", p.GetFlow(), p.GetUid())
		}
	})

	t.Run("allowSignup=false", func(t *testing.T) {
		_, out := newCase(t, 0)
		if out.Envelope.GetStatus() != orchestrator.StatusBindingRequired {
			t.Fatalf("status = %q, want binding_required", out.Envelope.GetStatus())
		}
		if out.Envelope.GetBinding().GetAllowSignup() {
			t.Error("enable_signup=0 → allowSignup 应为 false")
		}
	})
}

// TestLoginOauthAutoBind auto_bind=1 按 email 匹配直接绑定（§12.5 行 1508）；
// auto_bind=0 / 无命中 → binding_required；命中用户已启用 MFA → 先绑定
// 再 mfa_required（§2.7.5 行 691）。
func TestLoginOauthAutoBind(t *testing.T) {
	ctx := context.Background()

	newCase := func(t *testing.T, autoBind int8, mfa bool) (*tpEnv, *OauthOutput) {
		e := newTPEnv(t)
		e.addProvider("qq", func(r *model.Provider) { r.AutoBind = autoBind })
		e.adapter.identity.Email = "exist@example.com"
		e.users.byEmail["exist@example.com"] = &model.User{ID: 9, UserStatus: 1, MfaRequired: 0}
		e.users.byID[9] = &model.User{ID: 9, UserStatus: 1, MfaRequired: 0}
		if mfa {
			e.users.byEmail["exist@example.com"] = &model.User{ID: 9, UserStatus: 1, MfaRequired: 1}
			e.users.byID[9] = &model.User{ID: 9, UserStatus: 1, MfaRequired: 1}
			// totp 凭证存在 → MFA required（凭证 fake 重建 builder）。
			e.svc.deps.MFA = orchestrator.NewMFABuilder(e.users, &tpCreds{totp: true}, e.settings)
		}
		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		return e, out
	}

	t.Run("命中并绑定", func(t *testing.T) {
		e, out := newCase(t, 1, false)
		if out.Envelope.GetStatus() != "success" || out.Envelope.GetUserId() != 9 {
			t.Fatalf("status/uid = %q/%d, want success/9", out.Envelope.GetStatus(), out.Envelope.GetUserId())
		}
		if len(e.binds.created) != 1 {
			t.Fatalf("绑定写入 %d 行, want 1", len(e.binds.created))
		}
		if c := e.binds.created[0]; c.UserID != 9 || c.ProviderKey != "qq" || c.OpenID != "openid_1" {
			t.Errorf("绑定行 = %+v", c)
		}
	})

	t.Run("关闭", func(t *testing.T) {
		_, out := newCase(t, 0, false)
		if out.Envelope.GetStatus() != orchestrator.StatusBindingRequired {
			t.Fatalf("status = %q, want binding_required", out.Envelope.GetStatus())
		}
	})

	t.Run("无命中", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", func(r *model.Provider) { r.AutoBind = 1 })
		e.adapter.identity.Email = "nobody@example.com"
		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		if out.Envelope.GetStatus() != orchestrator.StatusBindingRequired {
			t.Fatalf("status = %q, want binding_required", out.Envelope.GetStatus())
		}
	})

	t.Run("命中且 MFA", func(t *testing.T) {
		e, out := newCase(t, 1, true)
		// totp 凭证存在 → MFA required（builder 需带凭证 fake 重建）。
		if out.Envelope.GetStatus() != orchestrator.StatusMFARequired {
			t.Fatalf("status = %q, want mfa_required", out.Envelope.GetStatus())
		}
		// 先绑定再 MFA（§2.7.5 行 691）。
		if len(e.binds.created) != 1 {
			t.Errorf("MFA 前应已写绑定, got %d 行", len(e.binds.created))
		}
		if m := out.Envelope.GetMfa(); m == nil || len(m.GetMethods()) == 0 {
			t.Errorf("mfa = %+v", m)
		}
	})
}

// tpDegradedRegistry 最小因子注册表 fake（orchestrator.FactorLookup）：
// webauthn 恒未注册（启动降级窗口形态），其余 kind 一并未注册（Build 只
// 查 webauthn，语义不受影响）。
type tpDegradedRegistry struct{}

func (tpDegradedRegistry) Get(factor.FactorKind) (factor.Factor, error) {
	return nil, factor.ErrKindNotRegistered
}

// TestLoginOauthWebauthnDegradedFailClosed 三方登录路径的窗口期
// fail-closed（§8.3 行 1069）：auto_bind 命中的
// mfa_required 用户唯一可用因子为 webauthn、注册表因启动降级未注册 →
// 不进终点（绝不 required=false 静默放行直通 success），信封
// status=method_disabled + error.message 明示"通行密钥暂不可用"（与引擎
// 路径同一 status / 文案）。
func TestLoginOauthWebauthnDegradedFailClosed(t *testing.T) {
	ctx := context.Background()
	e := newTPEnv(t)
	e.addProvider("qq", func(r *model.Provider) { r.AutoBind = 1 })
	e.adapter.identity.Email = "exist@example.com"
	e.users.byEmail["exist@example.com"] = &model.User{ID: 9, UserStatus: 1, MfaRequired: 1}
	e.users.byID[9] = &model.User{ID: 9, UserStatus: 1, MfaRequired: 1}
	// 已绑 webauthn（唯一可用因子）+ 降级注册表（webauthn 未注册）。
	mfa := orchestrator.NewMFABuilder(e.users, &tpCreds{webauthn: true}, e.settings)
	mfa.Factors = tpDegradedRegistry{}
	e.svc.deps.MFA = mfa

	out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
	if out.Envelope.GetStatus() != orchestrator.StatusMethodDisabled {
		t.Fatalf("status = %q, want method_disabled (fail-closed), envelope %+v", out.Envelope.GetStatus(), out.Envelope)
	}
	if em := out.Envelope.GetError(); em == nil || em.GetMessage() != orchestrator.WebauthnDegradedMessage {
		t.Fatalf("error = %+v, want message %q", em, orchestrator.WebauthnDegradedMessage)
	}
	// 不进终点：无会话写入、无绑定放行痕迹（auto_bind 绑定发生在 MFA 判定
	// 之前，允许存在；但绝不得签发会话）。
	if out.Envelope.GetSessionId() != "" || out.Envelope.GetUserId() != 0 {
		t.Fatalf("fail-closed must not reach terminal: %+v", out.Envelope)
	}
}

// TestLoginOauthUnionMerge Union 归并（§12.7 行 1549）：普通行未命中、
// Union 行 (union_provider, unionid) 命中 → 归并到同一账号。
func TestLoginOauthUnionMerge(t *testing.T) {
	ctx := context.Background()
	e := newTPEnv(t)
	e.addProvider("qq", func(r *model.Provider) { r.UnionProvider = "qq_union" })
	e.adapter.identity.UnionID = "union_7"
	e.binds.rows[key("qq_union", "union_7")] = model.UserThirdpartyBind{UserID: 5, ProviderKey: "qq_union", OpenID: "union_7"}
	e.users.byID[5] = &model.User{ID: 5, UserStatus: 1, MfaRequired: 0}

	out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
	if out.Envelope.GetStatus() != "success" || out.Envelope.GetUserId() != 5 {
		t.Fatalf("status/uid = %q/%d, want success/5（Union 归并）", out.Envelope.GetStatus(), out.Envelope.GetUserId())
	}

	// Union 行不命中 → binding_required（不写库）。
	e2 := newTPEnv(t)
	e2.addProvider("qq", func(r *model.Provider) { r.UnionProvider = "qq_union" })
	e2.adapter.identity.UnionID = "union_none"
	out2 := e2.svc.LoginOauth(ctx, e2.oauthRequest(t, "l"+"x", 0))
	if out2.Envelope.GetStatus() != orchestrator.StatusBindingRequired {
		t.Fatalf("status = %q, want binding_required", out2.Envelope.GetStatus())
	}
}

// TestLoginOauthMFAEnvelope 已绑定用户启用 MFA → mfa_required 信封 +
// login_token（uid / passed / amr=thirdparty / oidc 写入，§2.7.4 行 652）。
func TestLoginOauthMFAEnvelope(t *testing.T) {
	ctx := context.Background()
	e := newTPEnv(t)
	e.addProvider("qq", nil)
	e.binds.rows[key("qq", "openid_1")] = model.UserThirdpartyBind{UserID: 3, ProviderKey: "qq", OpenID: "openid_1"}
	e.users.byID[3] = &model.User{ID: 3, UserStatus: 1, MfaRequired: 1}
	// totp 凭证存在 → MFA required（凭证 fake 重建 builder）。
	e.svc.deps.MFA = orchestrator.NewMFABuilder(e.users, &tpCreds{totp: true}, e.settings)

	oidcCtx := &token.Oidc{ClientId: "cid-1", RedirectUri: "https://rp/cb", State: "s-1"}
	in := e.oauthRequest(t, "l"+"x", 0)
	in.OIDC = oidcCtx
	out := e.svc.LoginOauth(ctx, in)
	if out.Envelope.GetStatus() != orchestrator.StatusMFARequired {
		t.Fatalf("status = %q, want mfa_required", out.Envelope.GetStatus())
	}
	if e.sessions.gotUID != 0 {
		t.Errorf("MFA 前不应建会话, uid=%d", e.sessions.gotUID)
	}
	p, err := e.state.Parse(out.Envelope.GetLoginToken())
	if err != nil {
		t.Fatalf("Parse login_token: %v", err)
	}
	if p.GetUid() != 3 {
		t.Errorf("uid = %d, want 3", p.GetUid())
	}
	if len(p.GetPassed()) != 1 || p.GetPassed()[0] != amrThirdParty {
		t.Errorf("passed = %v, want [thirdparty]", p.GetPassed())
	}
	if len(p.GetAmr()) != 1 || p.GetAmr()[0] != amrThirdParty {
		t.Errorf("amr = %v, want [thirdparty]", p.GetAmr())
	}
	if p.GetOidc().GetClientId() != "cid-1" || p.GetOidc().GetState() != "s-1" {
		t.Errorf("oidc 写入 = %+v", p.GetOidc())
	}
}

// TestLoginOauthAPIChannel api 通道（小程序，§13.1 行 1583）：无 state
// 校验（Referer 归 origin 中间件）、session_token 直接作为信封字段返回、
// 不写 Cookie。
func TestLoginOauthAPIChannel(t *testing.T) {
	ctx := context.Background()
	e := newTPEnv(t)
	e.addProvider("wechat_mp", nil)
	e.adapter.channel = provider.ChannelAPI
	e.adapter.identity.ProviderKey = "wechat_mp"
	e.binds.rows[key("wechat_mp", "openid_1")] = model.UserThirdpartyBind{UserID: 11, ProviderKey: "wechat_mp", OpenID: "openid_1"}
	e.users.byID[11] = &model.User{ID: 11, UserStatus: 1, MfaRequired: 0}

	out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wechat_mp", Code: "wxcode"})
	if out.Envelope.GetStatus() != "success" {
		t.Fatalf("status = %q, want success", out.Envelope.GetStatus())
	}
	if out.Envelope.GetSessionToken() != "stok-1" {
		t.Errorf("信封 session_token = %q, want stok-1（§13.1 行 1583）", out.Envelope.GetSessionToken())
	}
	if !out.SessionInBody {
		t.Error("SessionInBody 应为 true")
	}
	if out.SessionToken != "" {
		t.Errorf("api 通道不应走 Cookie 下发出参, got %q", out.SessionToken)
	}
	if out.Cookie != nil {
		t.Errorf("api 通道不应有 Cookie 动作, got %+v", out.Cookie)
	}
}

// TestLoginOauthExchangeFails 渠道 Exchange / FetchUser 失败 → failed
// （§1.6 行 261 兜底，不暴露内部信息）。
func TestLoginOauthExchangeFails(t *testing.T) {
	ctx := context.Background()
	e := newTPEnv(t)
	e.addProvider("qq", nil)
	e.adapter.exchangeErr = errors.New("upstream 500")
	out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
	if out.Envelope.GetStatus() != orchestrator.StatusFailed {
		t.Fatalf("status = %q, want failed", out.Envelope.GetStatus())
	}
}

// TestSignupStateAndCreateBind service 对 orchestrator.ThirdpartySignup
// 窄接口的实现（免密建号消费，§12.5 行 1504）：enable_signup 两态 + Union
// key 透传；provider 失效返回 ErrRecordNotFound。
func TestSignupStateAndCreateBind(t *testing.T) {
	ctx := context.Background()
	e := newTPEnv(t)
	e.addProvider("qq", func(r *model.Provider) { r.UnionProvider = "qq_union" })

	st, err := e.svc.SignupState(ctx, "qq")
	if err != nil || !st.Enabled || st.UnionKey != "qq_union" {
		t.Fatalf("SignupState = %+v err=%v", st, err)
	}
	e.addProvider("qq_nosignup", func(r *model.Provider) { r.EnableSignup = 0 })
	if st, _ := e.svc.SignupState(ctx, "qq_nosignup"); st.Enabled {
		t.Error("enable_signup=0 → Enabled 应为 false")
	}
	if _, err := e.svc.SignupState(ctx, "missing"); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("缺失 provider err = %v, want ErrRecordNotFound", err)
	}

	row := &model.UserThirdpartyBind{UserID: 1, ProviderKey: "qq", OpenID: "o1"}
	if err := e.svc.CreateBind(ctx, row, "qq_union", "u1"); err != nil {
		t.Fatalf("CreateBind: %v", err)
	}
	if len(e.binds.created) != 1 || e.binds.unionCreated[0] != "qq_union|u1" {
		t.Errorf("CreateBind 透传 = %+v / %v", e.binds.created, e.binds.unionCreated)
	}
}

// —— user_disabled 等追加用例 ——

// TestLoginOauthUserDisabled 已绑定（普通行 / Union 归并 / auto_bind
// 命中）路径的用户状态校验——禁用账号（user_status≠1）→ user_disabled 信封
// 且不建会话；auto_bind 命中禁用用户时不写绑定（校验先于写入）。
func TestLoginOauthUserDisabled(t *testing.T) {
	ctx := context.Background()

	t.Run("普通行绑定禁用用户", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		e.binds.rows[key("qq", "openid_1")] = model.UserThirdpartyBind{UserID: 7, ProviderKey: "qq", OpenID: "openid_1"}
		e.users.byID[7] = &model.User{ID: 7, UserStatus: 0}

		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		if out.Envelope.GetStatus() != statusUserDisabled {
			t.Fatalf("status = %q, want user_disabled", out.Envelope.GetStatus())
		}
		if e.sessions.gotUID != 0 {
			t.Errorf("禁用用户不应建会话, uid=%d", e.sessions.gotUID)
		}
	})

	t.Run("Union 归并禁用用户", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", func(r *model.Provider) { r.UnionProvider = "qq_union" })
		e.adapter.identity.UnionID = "union_7"
		e.binds.rows[key("qq_union", "union_7")] = model.UserThirdpartyBind{UserID: 5, ProviderKey: "qq_union", OpenID: "union_7"}
		e.users.byID[5] = &model.User{ID: 5, UserStatus: 0}

		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		if out.Envelope.GetStatus() != statusUserDisabled {
			t.Fatalf("status = %q, want user_disabled", out.Envelope.GetStatus())
		}
	})

	t.Run("auto_bind 命中禁用用户不写绑定", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", func(r *model.Provider) { r.AutoBind = 1 })
		e.adapter.identity.Email = "banned@example.com"
		e.users.byEmail["banned@example.com"] = &model.User{ID: 9, UserStatus: 0}
		e.users.byID[9] = &model.User{ID: 9, UserStatus: 0}

		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		if out.Envelope.GetStatus() != statusUserDisabled {
			t.Fatalf("status = %q, want user_disabled", out.Envelope.GetStatus())
		}
		if len(e.binds.created) != 0 {
			t.Errorf("禁用用户不应产生绑定副作用, got %d 行", len(e.binds.created))
		}
	})

	t.Run("状态查询失败按 failed 收敛", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		e.binds.rows[key("qq", "openid_1")] = model.UserThirdpartyBind{UserID: 7, ProviderKey: "qq", OpenID: "openid_1"}
		// byID 无该行 → fake FindByID 返回 ErrRecordNotFound（非禁用语义）。
		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		if out.Envelope.GetStatus() != orchestrator.StatusFailed {
			t.Fatalf("status = %q, want failed", out.Envelope.GetStatus())
		}
	})
}

// TestLoginOauthAutoBindExtraRaw auto_bind 直接绑定时 extra 落本次
// 请求原始资料 Raw（§12.5 行 1502；msgpack 编码，§4.3 行 708 透传语义）；
// Raw 为空 → Extra nil；setpass 中间态路径 extra 空可接受（不经此处）。
func TestLoginOauthAutoBindExtraRaw(t *testing.T) {
	ctx := context.Background()

	t.Run("Raw 落 Extra", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", func(r *model.Provider) { r.AutoBind = 1 })
		e.adapter.identity.Email = "exist@example.com"
		e.adapter.identity.Raw = map[string]any{
			"openid": "openid_1", "city": "深圳", "vip": true,
		}
		e.users.byEmail["exist@example.com"] = &model.User{ID: 9, UserStatus: 1}
		e.users.byID[9] = &model.User{ID: 9, UserStatus: 1}

		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		if out.Envelope.GetStatus() != "success" {
			t.Fatalf("status = %q, want success", out.Envelope.GetStatus())
		}
		if len(e.binds.created) != 1 {
			t.Fatalf("绑定写入 %d 行", len(e.binds.created))
		}
		extra := e.binds.created[0].Extra
		if len(extra) == 0 {
			t.Fatal("auto_bind 绑定行 Extra 应落 Raw")
		}
		var got map[string]any
		if err := msgpack.Unmarshal(extra, &got); err != nil {
			t.Fatalf("Extra 应为 msgpack(map): %v", err)
		}
		if got["openid"] != "openid_1" || got["city"] != "深圳" || got["vip"] != true {
			t.Errorf("Extra 解码 = %v", got)
		}
	})

	t.Run("Raw 空则 Extra nil", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", func(r *model.Provider) { r.AutoBind = 1 })
		e.adapter.identity.Email = "exist@example.com"
		e.users.byEmail["exist@example.com"] = &model.User{ID: 9, UserStatus: 1}
		e.users.byID[9] = &model.User{ID: 9, UserStatus: 1}

		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		if out.Envelope.GetStatus() != "success" {
			t.Fatalf("status = %q, want success", out.Envelope.GetStatus())
		}
		if ex := e.binds.created[0].Extra; ex != nil {
			t.Errorf("Raw 空时 Extra 应 nil, got %v", ex)
		}
	})
}

// TestLoginOauthNonSuccessClearsStateCookie redirect 通道各非成功
// 终态（binding_required / mfa_required / failed / user_disabled）一律删
// al_login_state（§12.4 行 1486「校验通过或失败后立即删除」，防 state
// 复用重放）；api 通道无 Cookie 场景不动作。
func TestLoginOauthNonSuccessClearsStateCookie(t *testing.T) {
	ctx := context.Background()

	assertCleared := func(t *testing.T, out *OauthOutput) {
		t.Helper()
		if out.Cookie == nil || out.Cookie.Name != LoginStateCookieName || out.Cookie.MaxAge != -1 {
			t.Errorf("终态应删 al_login_state, got %+v", out.Cookie)
		}
	}

	t.Run("binding_required", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		if out.Envelope.GetStatus() != orchestrator.StatusBindingRequired {
			t.Fatalf("status = %q", out.Envelope.GetStatus())
		}
		assertCleared(t, out)
	})

	t.Run("mfa_required", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		e.binds.rows[key("qq", "openid_1")] = model.UserThirdpartyBind{UserID: 3, ProviderKey: "qq", OpenID: "openid_1"}
		e.users.byID[3] = &model.User{ID: 3, UserStatus: 1, MfaRequired: 1}
		e.svc.deps.MFA = orchestrator.NewMFABuilder(e.users, &tpCreds{totp: true}, e.settings)
		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		if out.Envelope.GetStatus() != orchestrator.StatusMFARequired {
			t.Fatalf("status = %q", out.Envelope.GetStatus())
		}
		assertCleared(t, out)
	})

	t.Run("failed（Exchange 失败）", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		e.adapter.exchangeErr = errors.New("upstream 500")
		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		if out.Envelope.GetStatus() != orchestrator.StatusFailed {
			t.Fatalf("status = %q", out.Envelope.GetStatus())
		}
		assertCleared(t, out)
	})

	t.Run("user_disabled", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("qq", nil)
		e.binds.rows[key("qq", "openid_1")] = model.UserThirdpartyBind{UserID: 7, ProviderKey: "qq", OpenID: "openid_1"}
		e.users.byID[7] = &model.User{ID: 7, UserStatus: 0}
		out := e.svc.LoginOauth(ctx, e.oauthRequest(t, "l"+"x", 0))
		if out.Envelope.GetStatus() != statusUserDisabled {
			t.Fatalf("status = %q", out.Envelope.GetStatus())
		}
		assertCleared(t, out)
	})

	t.Run("api 通道终态无 Cookie 动作", func(t *testing.T) {
		e := newTPEnv(t)
		e.addProvider("wechat_mp", nil)
		e.adapter.channel = provider.ChannelAPI
		e.adapter.identity.ProviderKey = "wechat_mp"
		e.adapter.exchangeErr = errors.New("upstream 500")
		out := e.svc.LoginOauth(ctx, OauthInput{ProviderKey: "wechat_mp", Code: "wx"})
		if out.Envelope.GetStatus() != orchestrator.StatusFailed {
			t.Fatalf("status = %q", out.Envelope.GetStatus())
		}
		if out.Cookie != nil {
			t.Errorf("api 通道不应有 Cookie 动作, got %+v", out.Cookie)
		}
	})
}
