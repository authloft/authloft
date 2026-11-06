// qrcode_test.go 覆盖扫码三桩 service 层用例：CreateQrcode（captcha
// 必检 / scene 分派与 bind 401 / ticket 形态与加密 / 码图链与 storage 渲染
// / 未配置拒绝）；GetLoginTicket 五态轮询（pending / scanned 补写 / expired
// 终态不消费 / success 建会话 / binding_required 信封 / 失败类映射）+
// poll 钳制 + 码图自动删除投递；ConfirmLoginTicket（body 与 Cookie 优先级、
// 同 uid 校验、写入形态、幂等）；TicketResultSealer protojson 整值加密往返。
// 全部走 fake（TicketStore / Storage / Gate verifier / SessionVerifier），
// 不连 DB / Redis；GETDEL 原子性由 cache 包 ticket_test.go 覆盖。
package service

import (
	"context"
	"errors"
	"testing"
	"time"

	providerpb "authloft/gen/go/provider"
	"authloft/gen/go/token"
	"authloft/internal/asyncqueue"
	"authloft/internal/cache"
	"authloft/internal/captcha"
	"authloft/internal/provider"
	"authloft/internal/qrcode"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
	"authloft/internal/storage"
)

// —— fake 全家（qrcode 专用）——

// qrAdapter qrcode 渠道适配器 fake：实现 AuthAdapter + QRCodeSupporter。
type qrAdapter struct {
	identity   *provider.ExternalIdentity
	fetchBody  []byte
	fetchErr   error
	fetchCalls []string
}

func (a *qrAdapter) Channel() provider.ThirdPartyChannel { return provider.ChannelQRCode }
func (a *qrAdapter) BuildAuthURL(*provider.AuthContext) (string, error) {
	return "", errors.New("not supported")
}
func (a *qrAdapter) Exchange(context.Context, provider.ExchangeInput) (*provider.Token, error) {
	return &provider.Token{Raw: map[string]any{"openid": a.identity.OpenID}}, nil
}
func (a *qrAdapter) FetchUser(context.Context, *provider.Token) (*provider.ExternalIdentity, error) {
	return a.identity, nil
}
func (a *qrAdapter) FetchQrcode(_ context.Context, scene string) ([]byte, error) {
	a.fetchCalls = append(a.fetchCalls, scene)
	if a.fetchErr != nil {
		return nil, a.fetchErr
	}
	return a.fetchBody, nil
}

// qrTickets TicketStore fake：内存键值 + Take/Wait 调用记录。
type qrTickets struct {
	res        map[string]*token.TicketResult // Take 返回（模拟 GETDEL 后的下一读）
	takes      []string
	waits      []time.Duration
	scanWrites []string // WriteScanned 补写记录
	compWrites []string // WriteComplete 记录
}

func (f *qrTickets) WriteScanned(_ context.Context, id string, _ *token.TicketResult) (cache.TicketWriteResult, error) {
	f.scanWrites = append(f.scanWrites, id)
	return cache.TicketWriteOK, nil
}
func (f *qrTickets) WriteComplete(_ context.Context, id string, _ *token.TicketResult) (cache.TicketWriteResult, error) {
	f.compWrites = append(f.compWrites, id)
	return cache.TicketWriteOK, nil
}
func (f *qrTickets) Take(_ context.Context, id string) (*token.TicketResult, error) {
	f.takes = append(f.takes, id)
	return f.res[id], nil
}
func (f *qrTickets) Wait(_ context.Context, id string, timeout time.Duration) error {
	f.waits = append(f.waits, timeout)
	if _, ok := f.res[id]; ok {
		return nil
	}
	return cache.ErrTicketWaitTimeout
}

// qrStorage Storage fake：记录 Put。
type qrStorage struct {
	putKey   string
	putBody  []byte
	putCT    string
	putURL   string
	putCalls int
}

func (f *qrStorage) Put(_ context.Context, key string, body []byte, ct string) (string, error) {
	f.putCalls++
	f.putKey, f.putBody, f.putCT = key, body, ct
	return f.putURL, nil
}
func (f *qrStorage) Get(context.Context, string) ([]byte, error) { return nil, nil }
func (f *qrStorage) Delete(context.Context, string) error        { return nil }
func (f *qrStorage) URL(string) string                           { return "" }
func (f *qrStorage) PresignPut(context.Context, string, string, int64) (string, map[string]string, error) {
	return "", nil, nil
}

// qrResolver QRCodeStorageResolver fake。
type qrResolver struct {
	st  storage.Storage
	err error
}

func (f *qrResolver) Resolve(context.Context, string) (storage.Storage, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.st, nil
}

// qrVerifier captcha.Verifier fake。
type qrVerifier struct{ err error }

func (v *qrVerifier) Verify(context.Context, string, captcha.Submission) error { return v.err }

// qrCatalog captcha.ProviderCatalog fake：nil = 降级内置图形码。
type qrCatalog struct{ p *captcha.Provider }

func (c *qrCatalog) Current(context.Context) (*captcha.Provider, error) { return c.p, nil }

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

// qrQueue QueuePusher fake。
type qrQueue struct{ tasks []asyncqueue.Task }

func (q *qrQueue) Push(task asyncqueue.Task) bool {
	q.tasks = append(q.tasks, task)
	return true
}

// qrEnv 汇总一套全 fake 的扫码 service 依赖。
type qrEnv struct {
	loader   *tpLoader
	adapter  *qrAdapter
	gate     *captcha.Gate
	verifier *qrVerifier
	tickets  *qrTickets
	payloads *tpTicketPayloads
	store    *qrStorage
	resolver *qrResolver
	sessions *qrSessions
	queue    *qrQueue
	writer   *tpSessions
	state    *orchestrator.State
	svc      *QRCode
	now      time.Time
	ticketC  *security.Codec
	loginC   *security.Codec
}

func newQrEnv(t *testing.T) *qrEnv {
	t.Helper()
	env := &qrEnv{
		loader: &tpLoader{byKey: map[string]*provider.Provider{}},
		adapter: &qrAdapter{
			identity:  &provider.ExternalIdentity{ProviderKey: "scan", ProviderType: "wechat_mp_scan", OpenID: "o-1"},
			fetchBody: []byte("fake-wxacode-bytes"),
		},
		verifier: &qrVerifier{},
		tickets:  &qrTickets{res: map[string]*token.TicketResult{}},
		payloads: &tpTicketPayloads{snapshots: map[string]*token.TicketPayload{}},
		store:    &qrStorage{putURL: "https://cdn.example.com/qr/x.jpg"},
		sessions: &qrSessions{uid: 9},
		queue:    &qrQueue{},
		writer:   &tpSessions{},
		now:      time.Unix(1_700_000_000, 0),
		ticketC:  tpCodec(t, 0x30),
		loginC:   tpCodec(t, 0x40),
	}
	env.resolver = &qrResolver{st: env.store}
	env.gate = captcha.NewGate(&tpSettings{}, &qrCatalog{}, env.verifier)
	env.state = orchestrator.NewState(env.loginC)
	env.svc = NewQRCode(QRCodeDeps{
		Loader:         env.loader,
		NewAdapter:     func(*provider.Provider) (provider.AuthAdapter, error) { return env.adapter, nil },
		Gate:           env.gate,
		TicketCodec:    env.ticketC,
		Tickets:        env.tickets,
		TicketPayloads: env.payloads,
		Storage:        env.resolver,
		Queue:          env.queue,
		Sessions:       env.sessions,
		State:          env.state,
		Terminal:       orchestrator.NewTerminal(env.writer, nil, nil, nil, nil),
		NewTID:         func() (string, error) { return "tid-qr-1", nil },
		Now:            func() time.Time { return env.now },
	})
	return env
}

// addScanProvider 注册一个扫码 provider 行（Ext 含 storage_provider /
// storage_path 模板，§15.1 示例逐字）。
func (e *qrEnv) addScanProvider(pk string, mutate func(*model.Provider)) *provider.Provider {
	row := &model.Provider{
		ProviderKey: pk, Category: "oauth", Type: "wechat_mp_scan",
		EnableSignin: 1, EnableSignup: 1, IsEnabled: 1,
		DisplayName: "微信小程序扫码",
	}
	if mutate != nil {
		mutate(row)
	}
	p := &provider.Provider{
		Key: pk, Type: row.Type, Row: row,
		Ext: &providerpb.Ext{
			StorageProvider: "files",
			StoragePath:     `'qrcodes_' & $.ticket_id & '.jpg'`,
		},
	}
	e.loader.byKey[pk] = p
	return p
}

// validCaptcha 经内置图形码通道的合法提交（catalog 降级 builtin_image）。
func validCaptcha() *captcha.Submission {
	return &captcha.Submission{ProviderKey: captcha.BuiltinProviderKey, ID: "cap-1", Answer: "123456"}
}

// sealTicket 用 env 的 ticket codec 签一枚轮询入参 ticket。
func (e *qrEnv) sealTicket(t *testing.T, p *token.TicketPayload) string {
	t.Helper()
	v, err := e.ticketC.Seal(security.PurposeTicket, p)
	if err != nil {
		t.Fatalf("Seal ticket: %v", err)
	}
	return v
}

// —— CreateQrcode ——

// TestCreateQrcodeCaptcha 必检：缺 captcha → captcha_required；校验失败 →
// captcha_invalid；合法 → 放行（§2.8 行 703、§9.3 Challenge 恒触发）。
func TestCreateQrcodeCaptcha(t *testing.T) {
	ctx := context.Background()

	t.Run("缺 captcha", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan"})
		if !errors.Is(err, ErrQrcodeCaptchaRequired) {
			t.Fatalf("err = %v, want ErrQrcodeCaptchaRequired", err)
		}
	})
	t.Run("captcha 无效", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		e.verifier.err = captcha.ErrInvalid
		_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
		if !errors.Is(err, ErrQrcodeCaptchaInvalid) {
			t.Fatalf("err = %v, want ErrQrcodeCaptchaInvalid", err)
		}
	})
	t.Run("合法 captcha 放行", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		out, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
		if err != nil {
			t.Fatalf("CreateQrcode: %v", err)
		}
		if out.QrcodeURL == "" || out.Ticket == "" {
			t.Fatalf("out = %+v", out)
		}
	})
}

// TestCreateQrcodeScenes scene 分派：login 默认；bind 无会话 401；bind 带
// uid 写入 ticket；非法 scene invalid_request（§2.8 行 716）。
func TestCreateQrcodeScenes(t *testing.T) {
	ctx := context.Background()

	t.Run("bind 无会话", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Scene: "bind", Captcha: validCaptcha()})
		if !errors.Is(err, ErrQrcodeUnauthenticated) {
			t.Fatalf("err = %v, want ErrQrcodeUnauthenticated", err)
		}
	})
	t.Run("非法 scene", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Scene: "other", Captcha: validCaptcha()})
		if !errors.Is(err, ErrQrcodeInvalidRequest) {
			t.Fatalf("err = %v, want ErrQrcodeInvalidRequest", err)
		}
	})
	t.Run("bind 带会话 scene 落 ticket", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		out, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Scene: "bind", UID: 9, Captcha: validCaptcha()})
		if err != nil {
			t.Fatalf("CreateQrcode: %v", err)
		}
		got, err := security.Open[token.TicketPayload](e.ticketC, security.PurposeTicket, out.Ticket)
		if err != nil {
			t.Fatalf("Open ticket: %v", err)
		}
		if got.GetScene() != "bind" || got.GetTicketId() != out.TicketID {
			t.Fatalf("payload = %+v, out = %+v", got, out)
		}
	})
}

// TestCreateQrcodeTicketForm ticket 形态（§11.6.4）：ticket_id ≤24、
// provider_key/scene/iat/exp 齐备、exp-iat=600、sign_key.ticket 可解而
// 跨密钥不可解、expiresIn=600。
func TestCreateQrcodeTicketForm(t *testing.T) {
	ctx := context.Background()
	e := newQrEnv(t)
	e.addScanProvider("scan", nil)
	out, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
	if err != nil {
		t.Fatalf("CreateQrcode: %v", err)
	}
	if len(out.TicketID) > 24 || out.TicketID == "" {
		t.Fatalf("ticket_id = %q（长度 %d），应 ≤24 且非空", out.TicketID, len(out.TicketID))
	}
	if out.ExpiresIn != 600 {
		t.Fatalf("expiresIn = %d, want 600", out.ExpiresIn)
	}
	got, err := security.Open[token.TicketPayload](e.ticketC, security.PurposeTicket, out.Ticket)
	if err != nil {
		t.Fatalf("Open ticket: %v", err)
	}
	if got.GetProviderKey() != "scan" || got.GetScene() != "login" {
		t.Fatalf("payload = %+v", got)
	}
	if got.GetExp()-got.GetIat() != 600 {
		t.Fatalf("exp-iat = %d, want 600", got.GetExp()-got.GetIat())
	}
	// 跨密钥不可解（AAD 含密钥版本，§11.6.1）。
	other := tpCodec(t, 0x99)
	if _, err := security.Open[token.TicketPayload](other, security.PurposeTicket, out.Ticket); err == nil {
		t.Fatalf("跨密钥不应解 开")
	}
}

// TestCreateQrcodeSnapshotWrite 拉码同步写快照键（§2.8 行 719、
// §11.6.4 行 1350）：快照与 ticket 串同源（ticket_id / provider_key /
// scene / iat / exp 逐字段一致），供小程序端提交侧校验；写入失败拉码失败。
func TestCreateQrcodeSnapshotWrite(t *testing.T) {
	ctx := context.Background()

	t.Run("快照与 ticket 同源", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		out, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
		if err != nil {
			t.Fatalf("CreateQrcode: %v", err)
		}
		snap, err := e.payloads.Read(ctx, out.TicketID)
		if err != nil {
			t.Fatalf("Read 快照: %v", err)
		}
		got, err := security.Open[token.TicketPayload](e.ticketC, security.PurposeTicket, out.Ticket)
		if err != nil {
			t.Fatalf("Open ticket: %v", err)
		}
		if snap == nil {
			t.Fatal("快照缺失（CreateQrcode 应 1 次写入）")
		}
		if snap.GetTicketId() != got.GetTicketId() || snap.GetProviderKey() != got.GetProviderKey() ||
			snap.GetScene() != got.GetScene() || snap.GetIat() != got.GetIat() || snap.GetExp() != got.GetExp() {
			t.Fatalf("快照与 ticket 不同源: snap=%+v ticket=%+v", snap, got)
		}
		if snap.GetScene() != sceneLogin || snap.GetTicketId() != out.TicketID {
			t.Fatalf("快照形态 = %+v", snap)
		}
	})

	t.Run("bind scene 快照带 scene", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		out, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Scene: "bind", UID: 9, Captcha: validCaptcha()})
		if err != nil {
			t.Fatalf("CreateQrcode: %v", err)
		}
		snap, err := e.payloads.Read(ctx, out.TicketID)
		if err != nil || snap == nil {
			t.Fatalf("快照: (%+v, %v)", snap, err)
		}
		if snap.GetScene() != sceneBind {
			t.Fatalf("scene = %q, want bind", snap.GetScene())
		}
	})

	t.Run("快照写入失败 → 拉码失败", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		e.payloads.writeErr = errors.New("redis down")
		if _, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()}); err == nil {
			t.Fatal("快照写入失败应导致拉码失败")
		}
	})
}

// TestCreateQrcodeWxacodeAndStorage 拉码链：FetchQrcode 的 scene=ticket_id、
// JPEG 压缩后 Put、key 按模板渲染、qrcodeUrl 透传。
func TestCreateQrcodeWxacodeAndStorage(t *testing.T) {
	ctx := context.Background()
	e := newQrEnv(t)
	e.addScanProvider("scan", nil)
	out, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
	if err != nil {
		t.Fatalf("CreateQrcode: %v", err)
	}
	if len(e.adapter.fetchCalls) != 1 || e.adapter.fetchCalls[0] != out.TicketID {
		t.Fatalf("FetchQrcode 入参 = %v, want [ticket_id]", e.adapter.fetchCalls)
	}
	if e.store.putCalls != 1 {
		t.Fatalf("Put 次数 = %d, want 1", e.store.putCalls)
	}
	if e.store.putKey != "qrcodes_"+out.TicketID+".jpg" {
		t.Fatalf("object key = %q, want 模板渲染 'qrcodes_' & $.ticket_id & '.jpg'", e.store.putKey)
	}
	if e.store.putCT != "image/jpeg" {
		t.Fatalf("contentType = %q, want image/jpeg", e.store.putCT)
	}
	if out.QrcodeURL != e.store.putURL {
		t.Fatalf("qrcodeUrl = %q, want %q", out.QrcodeURL, e.store.putURL)
	}
}

// TestCreateQrcodeProviderFailures provider 侧拒绝路径：查无行 / 禁用 /
// 非 qrcode 通道 / storage 未配置 / 拉码故障（§13.0 行 1576「按失败处理」）。
func TestCreateQrcodeProviderFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("查无行", func(t *testing.T) {
		e := newQrEnv(t)
		_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "ghost", Captcha: validCaptcha()})
		if !errors.Is(err, ErrQrcodeProviderDisabled) {
			t.Fatalf("err = %v, want ErrQrcodeProviderDisabled", err)
		}
	})
	t.Run("未启用", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", func(r *model.Provider) { r.IsEnabled = 0 })
		_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
		if !errors.Is(err, ErrQrcodeProviderDisabled) {
			t.Fatalf("err = %v, want ErrQrcodeProviderDisabled", err)
		}
	})
	t.Run("storage 未配置", func(t *testing.T) {
		e := newQrEnv(t)
		p := e.addScanProvider("scan", nil)
		p.Ext = &providerpb.Ext{} // Ext.storage_provider / storage_path 为空
		_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
		if !errors.Is(err, ErrQrcodeProviderDisabled) {
			t.Fatalf("err = %v, want ErrQrcodeProviderDisabled", err)
		}
	})
	t.Run("storage 解析失败", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		e.resolver.err = storage.ErrNotConfigured
		_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
		if !errors.Is(err, ErrQrcodeProviderDisabled) {
			t.Fatalf("err = %v, want ErrQrcodeProviderDisabled", err)
		}
	})
	t.Run("拉码故障", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		e.adapter.fetchErr = errors.New("wx quota exceeded")
		_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
		if !errors.Is(err, ErrQrcodeProviderDisabled) {
			t.Fatalf("err = %v, want ErrQrcodeProviderDisabled", err)
		}
	})
	t.Run("非 qrcode 通道", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		// 直接构造 channel=api 的 fake。
		api := &tpAdapter{channel: provider.ChannelAPI, identity: e.adapter.identity}
		e.svc = NewQRCode(QRCodeDeps{
			Loader: e.loader, NewAdapter: func(*provider.Provider) (provider.AuthAdapter, error) { return api, nil },
			Gate: e.gate, TicketCodec: e.ticketC, Tickets: e.tickets, Storage: e.resolver,
			Queue: e.queue, Sessions: e.sessions, State: e.state,
			Terminal: orchestrator.NewTerminal(e.writer, nil, nil, nil, nil),
			Now:      func() time.Time { return e.now },
		})
		_, err := e.svc.CreateQrcode(ctx, CreateQrcodeInput{ProviderKey: "scan", Captcha: validCaptcha()})
		if !errors.Is(err, ErrQrcodeInvalidRequest) {
			t.Fatalf("err = %v, want ErrQrcodeInvalidRequest", err)
		}
	})
}

// —— GetLoginTicket ——

// pollInput 构造一枚有效 login-scene ticket 的轮询入参。
func pollInput(t *testing.T, e *qrEnv, age time.Duration, poll int64) GetLoginTicketInput {
	t.Helper()
	ticket := e.sealTicket(t, &token.TicketPayload{
		TicketId:    "tid123",
		ProviderKey: "scan",
		Scene:       "login",
		Iat:         e.now.Add(-age).Unix(),
		Exp:         e.now.Add(-age).Add(600 * time.Second).Unix(),
	})
	return GetLoginTicketInput{Ticket: ticket, Poll: poll}
}

// TestGetLoginTicketFiveStates 五态轮询（§2.8 行 731-748）。
func TestGetLoginTicketFiveStates(t *testing.T) {
	ctx := context.Background()

	t.Run("pending", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		out := e.svc.GetLoginTicket(ctx, pollInput(t, e, 0, 0))
		if out.Envelope.GetStatus() != "pending" || out.Envelope.GetTicket().GetStatus() != "pending" {
			t.Fatalf("envelope = %+v", out.Envelope)
		}
		if out.Envelope.GetTicket().GetTicketId() != "tid123" {
			t.Fatalf("ticket echo = %+v", out.Envelope.GetTicket())
		}
	})
	t.Run("scanned 补写", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		e.tickets.res["tid123"] = &token.TicketResult{V: 1, Status: "scanned", Scene: "login"}
		out := e.svc.GetLoginTicket(ctx, pollInput(t, e, 0, 0))
		if out.Envelope.GetStatus() != "scanned" || out.Envelope.GetTicket().GetStatus() != "scanned" {
			t.Fatalf("envelope = %+v", out.Envelope)
		}
		// Take 消费后原样补写回（幂等标记保持，§2.7.4 两阶段写入）。
		if len(e.tickets.scanWrites) != 1 || e.tickets.scanWrites[0] != "tid123" {
			t.Fatalf("scanWrites = %v, want [tid123]", e.tickets.scanWrites)
		}
	})
	t.Run("expired 终态不消费", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		// 键上已有结果，但票据已过期：expired 即终态（§2.8 行 748），不消费。
		e.tickets.res["tid123"] = &token.TicketResult{V: 1, Status: "success", Scene: "login"}
		out := e.svc.GetLoginTicket(ctx, pollInput(t, e, 601*time.Second, 0))
		if out.Envelope.GetStatus() != "expired" || out.Envelope.GetTicket().GetStatus() != "expired" {
			t.Fatalf("envelope = %+v", out.Envelope)
		}
		if len(e.tickets.takes) != 0 {
			t.Fatalf("过期票据不应 Take, takes = %v", e.tickets.takes)
		}
	})
	t.Run("failed 失败类映射", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		e.tickets.res["tid123"] = &token.TicketResult{V: 1, Status: "target_taken", Scene: "login"}
		out := e.svc.GetLoginTicket(ctx, pollInput(t, e, 0, 0))
		// 结论在信封 status（§1.6 行 264），ticket 只报 failed。
		if out.Envelope.GetStatus() != "target_taken" || out.Envelope.GetTicket().GetStatus() != "failed" {
			t.Fatalf("envelope = %+v", out.Envelope)
		}
	})
	t.Run("invalid ticket", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		out := e.svc.GetLoginTicket(ctx, GetLoginTicketInput{Ticket: "garbage"})
		if out.Envelope.GetStatus() != orchestrator.StatusInvalidRequest {
			t.Fatalf("status = %q, want invalid_request", out.Envelope.GetStatus())
		}
	})
	t.Run("bind 票据拒绝", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		ticket := e.sealTicket(t, &token.TicketPayload{
			TicketId: "tid123", ProviderKey: "scan", Scene: "bind",
			Iat: e.now.Unix(), Exp: e.now.Add(600 * time.Second).Unix(),
		})
		out := e.svc.GetLoginTicket(ctx, GetLoginTicketInput{Ticket: ticket})
		if out.Envelope.GetStatus() != orchestrator.StatusInvalidRequest {
			t.Fatalf("status = %q, want invalid_request（bind 轮询走 account 域）", out.Envelope.GetStatus())
		}
	})
}

// TestGetLoginTicketSuccessBound 命中 success + 已绑定：建会话断言
// （1 次写、uid/amr 正确）+ 外层 success + login 内层信封 + SessionToken
// 由 handler 下发 + 码图自动删除投递（§2.8 行 746、§13.3）。
func TestGetLoginTicketSuccessBound(t *testing.T) {
	ctx := context.Background()
	e := newQrEnv(t)
	e.addScanProvider("scan", nil)
	e.tickets.res["tid123"] = &token.TicketResult{
		V: 1, Status: "success", Scene: "login", ProviderKey: "scan",
		LoginResult: &token.LoginResult{Uid: 9, BindingRequired: false},
	}
	out := e.svc.GetLoginTicket(ctx, pollInput(t, e, 0, 0))
	if out.Envelope.GetStatus() != "success" || out.Envelope.GetTicket().GetStatus() != "success" {
		t.Fatalf("envelope = %+v", out.Envelope)
	}
	inner := out.Envelope.GetLogin()
	if inner == nil || inner.GetStatus() != orchestrator.StatusSuccess {
		t.Fatalf("login = %+v, want success 信封", inner)
	}
	if inner.GetUserId() != 9 || inner.GetSessionId() != "sid-1" {
		t.Fatalf("login = %+v", inner)
	}
	// 建会话断言（Terminal 1 次写）。
	if e.writer.gotUID != 9 {
		t.Fatalf("建会话 uid = %d, want 9", e.writer.gotUID)
	}
	if len(e.writer.gotAMR) != 1 || e.writer.gotAMR[0] != "thirdparty" {
		t.Fatalf("amr = %v, want [thirdparty]", e.writer.gotAMR)
	}
	if out.SessionToken != "stok-1" {
		t.Fatalf("SessionToken = %q, want stok-1（handler 经 Cookie 构造器下发）", out.SessionToken)
	}
	if len(e.tickets.takes) != 1 {
		t.Fatalf("Take 次数 = %d, want 1（GETDEL 一次性消费）", len(e.tickets.takes))
	}
	// qrcode_auto_delete 未开启：不投递。
	if len(e.queue.tasks) != 0 {
		t.Fatalf("queue = %v, want 空", e.queue.tasks)
	}
}

// TestGetLoginTicketBindingRequired 命中 success + 未绑定：外层 success +
// login 内层 binding_required 信封（login_token tp 精简载荷 + binding
// allowSignup 映射），不建会话（§11.6.5 行 1361、§12.5 行 1501）。
func TestGetLoginTicketBindingRequired(t *testing.T) {
	ctx := context.Background()
	e := newQrEnv(t)
	e.addScanProvider("scan", func(r *model.Provider) { r.DisplayName = "微信扫码" })
	e.tickets.res["tid123"] = &token.TicketResult{
		V: 1, Status: "success", Scene: "login", ProviderKey: "scan",
		LoginResult: &token.LoginResult{Uid: 0, BindingRequired: true},
		ThirdpartyIdentity: &token.ThirdpartyIdentity{
			OpenId: "o-1", UnionId: "u-1", Nickname: "微信用户", AvatarUrl: "https://wx.cn/a.png",
		},
	}
	out := e.svc.GetLoginTicket(ctx, pollInput(t, e, 0, 0))
	if out.Envelope.GetStatus() != "success" {
		t.Fatalf("outer = %q, want success（结果就绪）", out.Envelope.GetStatus())
	}
	inner := out.Envelope.GetLogin()
	if inner == nil || inner.GetStatus() != orchestrator.StatusBindingRequired {
		t.Fatalf("login = %+v, want binding_required", inner)
	}
	// login_token 用 ticket codec 解：tp 精简载荷（pk/openid/unionid/
	// nickname/avatar；LoginTokenPayload 无 raw 字段——结构上即不可携带）。
	lt, err := security.Open[token.LoginTokenPayload](e.loginC, security.PurposeLogin, inner.GetLoginToken())
	if err != nil {
		t.Fatalf("Open login_token: %v", err)
	}
	tp := lt.GetTp()
	if tp.GetProviderKey() != "scan" || tp.GetOpenId() != "o-1" || tp.GetUnionId() != "u-1" ||
		tp.GetNickname() != "微信用户" || tp.GetAvatarUrl() != "https://wx.cn/a.png" {
		t.Fatalf("tp = %+v", tp)
	}
	// binding 信封：display_name / allow_signup 映射（§2.7.5 行 678）。
	b := inner.GetBinding()
	if b.GetProviderKey() != "scan" || b.GetDisplayName() != "微信扫码" || !b.GetAllowSignup() {
		t.Fatalf("binding = %+v", b)
	}
	// 不建会话。
	if e.writer.gotUID != 0 {
		t.Fatalf("binding_required 不应建会话, got uid %d", e.writer.gotUID)
	}
}

// TestGetLoginTicketPollClamp 长轮询钳制：poll=0 不等待；poll=99 钳到
// 15s 且不超过票据剩余寿命（§2.8 行 729）。
func TestGetLoginTicketPollClamp(t *testing.T) {
	ctx := context.Background()

	t.Run("poll=0 不等待", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		e.svc.GetLoginTicket(ctx, pollInput(t, e, 0, 0))
		if len(e.tickets.waits) != 0 {
			t.Fatalf("不应 Wait, got %v", e.tickets.waits)
		}
	})
	t.Run("poll=99 钳到 15s", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		e.svc.GetLoginTicket(ctx, pollInput(t, e, 0, 99))
		if len(e.tickets.waits) != 1 || e.tickets.waits[0] != 15*time.Second {
			t.Fatalf("waits = %v, want [15s]", e.tickets.waits)
		}
	})
	t.Run("不超过剩余寿命", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		// 票据已消耗 590s：剩余 10s < poll 15s。
		e.svc.GetLoginTicket(ctx, pollInput(t, e, 590*time.Second, 15))
		if len(e.tickets.waits) != 1 || e.tickets.waits[0] != 10*time.Second {
			t.Fatalf("waits = %v, want [10s]", e.tickets.waits)
		}
	})
}

// TestGetLoginTicketAutoDelete qrcode_auto_delete 开关（§13.3）：开启时
// 完成 SSO 后按同一模板 + ticket_id + iat 重算 key 投延迟队列（DeleteTask
// 携带 storage provider 与重算 key）；关闭则不投递。
func TestGetLoginTicketAutoDelete(t *testing.T) {
	ctx := context.Background()

	t.Run("关闭不投递", func(t *testing.T) {
		e := newQrEnv(t)
		e.addScanProvider("scan", nil)
		e.svc.deps.Queue = e.queue
		e.tickets.res["tid123"] = &token.TicketResult{
			V: 1, Status: "success", Scene: "login", ProviderKey: "scan",
			LoginResult: &token.LoginResult{Uid: 9},
		}
		out := e.svc.GetLoginTicket(ctx, pollInput(t, e, 0, 0))
		if out.Envelope.GetStatus() != "success" {
			t.Fatalf("status = %q", out.Envelope.GetStatus())
		}
		if len(e.queue.tasks) != 0 {
			t.Fatalf("queue = %v, want 空", e.queue.tasks)
		}
	})
	t.Run("开启投递 DeleteTask", func(t *testing.T) {
		e := newQrEnv(t)
		p := e.addScanProvider("scan", nil)
		p.Ext.QrcodeAutoDelete = true
		e.tickets.res["tid123"] = &token.TicketResult{
			V: 1, Status: "success", Scene: "login", ProviderKey: "scan",
			LoginResult: &token.LoginResult{Uid: 9},
		}
		out := e.svc.GetLoginTicket(ctx, pollInput(t, e, 0, 0))
		if out.Envelope.GetStatus() != "success" {
			t.Fatalf("status = %q", out.Envelope.GetStatus())
		}
		if len(e.queue.tasks) != 1 {
			t.Fatalf("queue = %v, want 1 个任务", e.queue.tasks)
		}
		del, ok := e.queue.tasks[0].Value.(qrcode.DeleteTask)
		if !ok {
			t.Fatalf("task value = %T, want qrcode.DeleteTask", e.queue.tasks[0].Value)
		}
		if del.StorageKey != "files" || del.ObjectKey != "qrcodes_tid123.jpg" {
			t.Fatalf("task = %+v, want {files qrcodes_tid123.jpg}", del)
		}
	})
}

// —— ConfirmLoginTicket ——

// TestConfirmLoginTicketSessionPriority body 与 Cookie 并存以 body 为准、
// 同 uid 校验否则 invalid_request；缺省取 Cookie（§2.8 行 757）。
func TestConfirmLoginTicketSessionPriority(t *testing.T) {
	ctx := context.Background()

	t.Run("body 优先 + 同 uid 成功", func(t *testing.T) {
		e := newQrEnv(t)
		st, err := e.svc.ConfirmLoginTicket(ctx, ConfirmLoginTicketInput{
			TicketID: "tid123", Session: "body-token", SessionUID: 9,
		})
		if err != nil {
			t.Fatalf("Confirm: %v", err)
		}
		if st.GetStatus() != "success" || st.GetTicketId() != "tid123" {
			t.Fatalf("status = %+v, want {success tid123}", st)
		}
		// 写入形态：scene=login、status=success、uid=9、v=1、channel=qrcode。
		if len(e.tickets.compWrites) != 1 || e.tickets.compWrites[0] != "tid123" {
			t.Fatalf("compWrites = %v", e.tickets.compWrites)
		}
	})
	t.Run("body 与 Cookie uid 不一致", func(t *testing.T) {
		e := newQrEnv(t)
		_, err := e.svc.ConfirmLoginTicket(ctx, ConfirmLoginTicketInput{
			TicketID: "tid123", Session: "body-token", SessionUID: 8,
		})
		if !errors.Is(err, ErrQrcodeInvalidRequest) {
			t.Fatalf("err = %v, want ErrQrcodeInvalidRequest", err)
		}
	})
	t.Run("仅 Cookie 会话", func(t *testing.T) {
		e := newQrEnv(t)
		st, err := e.svc.ConfirmLoginTicket(ctx, ConfirmLoginTicketInput{TicketID: "tid123", SessionUID: 9})
		if err != nil || st.GetStatus() != "success" {
			t.Fatalf("err = %v, st = %+v", err, st)
		}
	})
	t.Run("无任何会话 401", func(t *testing.T) {
		e := newQrEnv(t)
		_, err := e.svc.ConfirmLoginTicket(ctx, ConfirmLoginTicketInput{TicketID: "tid123"})
		if !errors.Is(err, ErrQrcodeUnauthenticated) {
			t.Fatalf("err = %v, want ErrQrcodeUnauthenticated", err)
		}
	})
	t.Run("body 会话失效 401", func(t *testing.T) {
		e := newQrEnv(t)
		e.sessions.err = errors.New("invalid session token")
		_, err := e.svc.ConfirmLoginTicket(ctx, ConfirmLoginTicketInput{TicketID: "tid123", Session: "bad"})
		if !errors.Is(err, ErrQrcodeUnauthenticated) {
			t.Fatalf("err = %v, want ErrQrcodeUnauthenticated", err)
		}
	})
	t.Run("空 ticketId", func(t *testing.T) {
		e := newQrEnv(t)
		_, err := e.svc.ConfirmLoginTicket(ctx, ConfirmLoginTicketInput{Session: "body-token"})
		if !errors.Is(err, ErrQrcodeInvalidRequest) {
			t.Fatalf("err = %v, want ErrQrcodeInvalidRequest", err)
		}
	})
}

// —— TicketResultSealer ——

// TestTicketResultSealerRoundtrip protojson 整值加密往返 + 跨密钥拒绝 +
// 未知版本按失败处理（§11.6.5 行 1347 / 1351）。
func TestTicketResultSealerRoundtrip(t *testing.T) {
	codec := tpCodec(t, 0x50)
	sealer := NewTicketResultSealer(codec)
	res := &token.TicketResult{
		V: 1, Scene: "login", Status: "success", ProviderKey: "scan", Channel: "qrcode",
		LoginResult: &token.LoginResult{Uid: 9},
	}
	sealed, err := sealer.Seal(res)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := sealer.Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.GetV() != 1 || got.GetScene() != "login" || got.GetStatus() != "success" ||
		got.GetLoginResult().GetUid() != 9 || got.GetChannel() != "qrcode" {
		t.Fatalf("roundtrip = %+v", got)
	}
	// 跨密钥不可解。
	if _, err := NewTicketResultSealer(tpCodec(t, 0x51)).Open(sealed); err == nil {
		t.Fatalf("跨密钥不应解 开")
	}
	// 未知版本按失败处理（§11.6.5 行 1351）。
	bad, err := sealer.Seal(&token.TicketResult{V: 99, Status: "success"})
	if err != nil {
		t.Fatalf("Seal v99: %v", err)
	}
	if _, err := sealer.Open(bad); err == nil {
		t.Fatalf("未知版本应按失败处理")
	}
}
