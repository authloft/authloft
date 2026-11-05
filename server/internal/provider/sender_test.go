// sender_test.go：消息 Sender 基建单测（注册表校验 / 生效实例解析 / 异步
// 桥 / 重试执行器）+ 登录链端到端回归（三场景：
// 发送成功→验证码校验通过；渠道未配置→封闭集合 provider_disabled；厂商
// 发送失败→验证码不回滚仍可提交，§8.2 行 1051 / §15.2 行 1726）。
// engine 层回归不连任何外部服务：code store / users / vendor 全为进程内
// Fake，队列为真实 asyncqueue + SendExecutor。
package provider_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/asyncqueue"
	"authloft/internal/cache"
	"authloft/internal/factor"
	factorotp "authloft/internal/factor/otp"
	coreotp "authloft/internal/otp"
	"authloft/internal/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
	"authloft/internal/settings"
)

// —— 测试用消息厂商（注册进 provider 消息域注册表，工厂返回固定 Fake）——

const (
	testEmailVendorType  = "e2e_test_email"        // 成功投递（email）
	testSMSVendorType    = "e2e_test_sms"          // 成功投递（sms，用于类型不符）
	testFailVendorType   = "e2e_test_email_fail"   // 永远失败的 email 厂商
	testBridgeVendorType = "e2e_test_email_bridge" // 桥单测专用（隔离调用计数）
	testClosedVendorType = "e2e_test_email_closed" // 队列关闭单测专用
)

var (
	testVendorsOnce sync.Once
	okEmailVendor   = &fakeVendor{}                   // engine 场景 A
	okSMSVendor     = &fakeVendor{}                   // 类型不符用，不实际投递
	failVendor      = &fakeVendor{err: errVendorBoom} // engine 场景 C
	bridgeVendor    = &fakeVendor{}                   // 桥单测
	closedVendor    = &fakeVendor{}                   // 队列关闭单测
)

var errVendorBoom = errors.New("vendor boom")

func ensureTestVendors() {
	testVendorsOnce.Do(func() {
		reg := func(t string, v *fakeVendor, category string) {
			provider.RegisterSender(t, provider.SenderMeta{
				Type: t, DisplayName: t, Category: category,
			}, func(*provider.Provider) (provider.Sender, error) { return v, nil })
		}
		reg(testEmailVendorType, okEmailVendor, provider.CategoryEmail)
		reg(testSMSVendorType, okSMSVendor, provider.CategorySMS)
		reg(testFailVendorType, failVendor, provider.CategoryEmail)
		reg(testBridgeVendorType, bridgeVendor, provider.CategoryEmail)
		reg(testClosedVendorType, closedVendor, provider.CategoryEmail)
	})
}

// fakeVendor provider.Sender Fake：记录调用 / 收件人 / 模板 / 参数，可注入错误。
type fakeVendor struct {
	mu      sync.Mutex
	calls   int
	lastTo  string
	lastTpl string
	last    map[string]string
	err     error
}

func (f *fakeVendor) Send(_ context.Context, to string, tpl string, params map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastTo = to
	f.lastTpl = tpl
	cp := make(map[string]string, len(params))
	for k, v := range params {
		cp[k] = v
	}
	f.last = cp
	return f.err
}

func (f *fakeVendor) snapshot() (calls int, to, tpl string, params map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.lastTo, f.lastTpl, f.last
}

// —— 注册表与解析单测 ——

// TestRegisterSenderValidation 注册表校验：空 type / 空 factory / 非法
// category / 重复注册一律 panic（init 无法返回错误）；LookupSenderMeta 可查回。
func TestRegisterSenderValidation(t *testing.T) {
	ensureTestVendors()

	factory := func(*provider.Provider) (provider.Sender, error) { return nil, nil }
	mustPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: RegisterSender must panic", name)
			}
		}()
		fn()
	}
	mustPanic("empty type", func() {
		provider.RegisterSender("", provider.SenderMeta{Category: provider.CategorySMS}, factory)
	})
	mustPanic("nil factory", func() {
		provider.RegisterSender("e2e_nil_factory", provider.SenderMeta{Category: provider.CategorySMS}, nil)
	})
	mustPanic("bad category", func() {
		provider.RegisterSender("e2e_bad_cat", provider.SenderMeta{Category: "oauth"}, factory)
	})
	mustPanic("duplicate", func() {
		provider.RegisterSender(testEmailVendorType, provider.SenderMeta{Category: provider.CategoryEmail}, factory)
	})

	meta, ok := provider.LookupSenderMeta(testEmailVendorType)
	if !ok || meta.Type != testEmailVendorType || meta.Category != provider.CategoryEmail {
		t.Fatalf("LookupSenderMeta = %+v ok=%v", meta, ok)
	}
	if _, ok := provider.LookupSenderMeta("no_such_type"); ok {
		t.Fatal("LookupSenderMeta must miss for unknown type")
	}
}

// TestNewSenderMatrix NewSender 判定矩阵：nil 实例 / 未注册为消息厂商的
// type / 渠道不符 → 结构化错误；命中注册表 → 构造成功。
func TestNewSenderMatrix(t *testing.T) {
	ensureTestVendors()
	ext, err := repo.MarshalProviderExt(&providerpb.Ext{})
	if err != nil {
		t.Fatalf("marshal ext: %v", err)
	}
	p := func(typ string) *provider.Provider {
		return &provider.Provider{
			Key:  "k-" + typ,
			Type: typ,
			Row:  &model.Provider{ProviderKey: "k-" + typ, Type: typ, IsEnabled: 1, Ext: ext},
		}
	}

	if _, err := provider.NewSender(nil, provider.CategorySMS); !errors.Is(err, provider.ErrNilProvider) {
		t.Fatalf("nil provider err = %v, want ErrNilProvider", err)
	}
	// oauth 渠道名不在消息域注册表（并列键空间互不串扰）。
	if _, err := provider.NewSender(p("wechat_mp"), provider.CategorySMS); !errors.Is(err, provider.ErrChannelNotConfigured) {
		t.Fatalf("oauth type err = %v, want ErrChannelNotConfigured", err)
	}
	// 渠道不符：sms 厂商不能当 email 用。
	if _, err := provider.NewSender(p(testSMSVendorType), provider.CategoryEmail); !errors.Is(err, provider.ErrChannelNotConfigured) {
		t.Fatalf("category mismatch err = %v, want ErrChannelNotConfigured", err)
	}
	s, err := provider.NewSender(p(testSMSVendorType), provider.CategorySMS)
	if err != nil || s == nil {
		t.Fatalf("NewSender(sms) = (%v, %v), want non-nil sender", s, err)
	}
}

// TestSenderTypes 消息域注册表枚举（GetProviderTypes 数据源之一）：
// 全部已注册厂商返回、按 Type 稳定升序、meta 逐字段与 LookupSenderMeta 同源。
func TestSenderTypes(t *testing.T) {
	ensureTestVendors()
	got := provider.SenderTypes()
	if len(got) == 0 {
		t.Fatal("SenderTypes = 空（ensureTestVendors 后必非空）")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Type >= got[i].Type {
			t.Errorf("Type 未稳定排序: %q >= %q", got[i-1].Type, got[i].Type)
		}
	}
	for _, meta := range got {
		want, ok := provider.LookupSenderMeta(meta.Type)
		if !ok {
			t.Fatalf("SenderTypes 含 %q 但 LookupSenderMeta 未命中", meta.Type)
		}
		if want.Type != meta.Type || want.Category != meta.Category || want.DisplayName != meta.DisplayName {
			t.Errorf("meta 与注册表不同源: %+v vs %+v", meta, want)
		}
	}
	// 抽查测试厂商在列。
	byType := map[string]bool{}
	for _, meta := range got {
		byType[meta.Type] = true
	}
	for _, want := range []string{testEmailVendorType, testSMSVendorType, testBridgeVendorType} {
		if !byType[want] {
			t.Errorf("SenderTypes 缺少已注册厂商 %q", want)
		}
	}
}

// TestNewCodeBridgeValidation 桥构造 fail-fast：依赖缺失 / 非法 category。
func TestNewCodeBridgeValidation(t *testing.T) {
	if _, err := provider.NewCodeBridge(nil, nil, nil, "k", provider.CategorySMS); err == nil {
		t.Fatal("nil deps must fail")
	}
	loader := provider.NewLoader(fakeRowSource{}, nil, provider.LoaderOptions{})
	q := asyncqueue.New(provider.SendExecutor{}, asyncqueue.Options{
		Capacity: 4, Workers: 1, BatchSize: 4, FlushInterval: time.Hour,
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = q.Close(ctx)
	})
	if _, err := provider.NewCodeBridge(newEngineSettings(""), loader, q, "k", "oauth"); err == nil {
		t.Fatal("bad category must fail")
	}
}

// —— 投递桥单测 ——

// TestCodeBridgeSendCodeEnqueuesToQueue 成功解析后入队：执行器经队列异步
// 调用厂商 Send，to / tpl（otp）/ params（code）按桥口径组装。
func TestCodeBridgeSendCodeEnqueuesToQueue(t *testing.T) {
	ensureTestVendors()
	st := newEngineSettings("eml_bridge")
	bridge := newEmailBridgeForTest(t, st, "eml_bridge", testBridgeVendorType, 1, 5*time.Millisecond)

	if err := bridge.SendCode(context.Background(), "alice@example.com", "654321"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	waitFor(t, func() bool {
		calls, to, tpl, params := bridgeVendor.snapshot()
		return calls >= 1 && to == "alice@example.com" && tpl == "otp" && params["code"] == "654321"
	})
}

// TestCodeBridgeSendCodeDroppedWhenQueueClosed 队列已关闭：Push 落空但
// SendCode 仍返回 nil（§5.2 行 893 丢弃不阻塞登录主链路），厂商零调用。
func TestCodeBridgeSendCodeDroppedWhenQueueClosed(t *testing.T) {
	ensureTestVendors()
	st := newEngineSettings("eml_closed")
	bridge := newEmailBridgeForTest(t, st, "eml_closed", testClosedVendorType, 1, time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := bridge.queueClose(ctx); err != nil { // 关闭前队列为空，flush 秒过
		t.Fatalf("close queue: %v", err)
	}
	if err := bridge.SendCode(context.Background(), "alice@example.com", "123456"); err != nil {
		t.Fatalf("SendCode on closed queue err = %v, want nil (dropped)", err)
	}
	if calls, _, _, _ := closedVendor.snapshot(); calls != 0 {
		t.Fatalf("vendor calls = %d, want 0", calls)
	}
}

// TestSendExecutorRetry 执行器只消费 SendJob：失败重试 sendAttempts 次；
// 成功只调一次；非 SendJob 任务原样忽略。
func TestSendExecutorRetry(t *testing.T) {
	exec := provider.SendExecutor{}
	boom := &fakeVendor{err: errVendorBoom}
	exec.Execute(context.Background(), []asyncqueue.Task{
		{Key: "s1", Value: provider.SendJob{Sender: boom, To: "x", Tpl: "otp", Params: map[string]string{"code": "1"}}},
		{Key: "s2", Value: "not-a-send-job"},
	})
	if calls, _, _, _ := boom.snapshot(); calls != 3 {
		t.Fatalf("failing vendor calls = %d, want 3", calls)
	}

	ok := &fakeVendor{}
	exec.Execute(context.Background(), []asyncqueue.Task{
		{Key: "s3", Value: provider.SendJob{Sender: ok, To: "x", Tpl: "otp", Params: map[string]string{"code": "1"}}},
	})
	if calls, _, _, _ := ok.snapshot(); calls != 1 {
		t.Fatalf("ok vendor calls = %d, want 1", calls)
	}
}

// —— engine 层登录链回归 ——

// loginHarness 端到端夹具：真实 otp 因子 + 真实投递桥 + 真实 asyncqueue，
// settings / users / code store / 厂商为进程内 Fake；不连 DB / Redis / 外网。
type loginHarness struct {
	engine   *orchestrator.Engine
	store    *fakeCodeStore
	sessions *fakeSessions
	events   *fakeEvents
}

// newLoginHarness settingsKey 为 email_provider_key 取值；rowKey 非空时
// 以该 key + rowType + enabled 构造 Provider 行（rowKey 为空 = 实例缺失）。
func newLoginHarness(t *testing.T, settingsKey, rowKey, rowType string, enabled int) *loginHarness {
	t.Helper()
	ensureTestVendors()

	st := newEngineSettings(settingsKey)
	var row *model.Provider
	if rowKey != "" {
		ext, err := repo.MarshalProviderExt(&providerpb.Ext{})
		if err != nil {
			t.Fatalf("marshal ext: %v", err)
		}
		row = &model.Provider{
			ProviderKey: rowKey, DisplayName: "Test Email", Category: provider.CategoryEmail,
			Type: rowType, IsEnabled: int8(enabled), Ext: ext,
		}
	}
	loader := provider.NewLoader(fakeRowSource{row: row}, nil, provider.LoaderOptions{})
	q := asyncqueue.New(provider.SendExecutor{}, asyncqueue.Options{
		Capacity: 16, Workers: 1, BatchSize: 8, FlushInterval: 5 * time.Millisecond,
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = q.Close(ctx)
	})
	bridge, err := provider.NewCodeBridge(st, loader, q, settings.KeyEmailProviderKey, provider.CategoryEmail)
	if err != nil {
		t.Fatalf("NewCodeBridge: %v", err)
	}

	store := &fakeCodeStore{}
	svc := coreotp.NewService(store, coreotp.DefaultConfig())
	otpf, err := factorotp.New(factor.FactorOTPEmail, svc, bridge, nil, coreotp.DefaultConfig())
	if err != nil {
		t.Fatalf("otp.New: %v", err)
	}
	registry := factor.NewRegistry()
	if err := registry.Register(factor.FactorOTPEmail, otpf); err != nil {
		t.Fatalf("Register: %v", err)
	}

	email := "alice@example.com"
	users := &fakeUsers{user: &model.User{ID: 42, Email: &email, EmailVerified: 1}}
	creds := fakeCreds{}

	ks, err := security.NewKeyStore(security.KeyEntry{
		ID:  security.KeyID{Version: 1, Kid: 1},
		Key: testCodecKey(),
	})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	state := orchestrator.NewState(security.NewCodec(ks))

	sessions := &fakeSessions{}
	events := &fakeEvents{}
	terminal := orchestrator.NewTerminal(sessions, fakeOIDCIssuer{}, events, fakeSync{}, st)
	engine := orchestrator.NewEngine(orchestrator.EngineDeps{
		State:      state,
		Dispatcher: &orchestrator.Dispatcher{Registry: registry, Settings: st},
		Gate:       nil, // §9 captcha gate 未接入；engine 对 nil 安全（跳过人机校验）
		MFA:        orchestrator.NewMFABuilder(users, creds, st),
		Terminal:   terminal,
		Factor:     orchestrator.FactorDeps{Users: users, Credentials: creds},
	})
	return &loginHarness{engine: engine, store: store, sessions: sessions, events: events}
}

// newEmailBridgeForTest 桥单测夹具：返回桥与队列关闭函数。
type bridgeFixture struct {
	*provider.CodeBridge
	queueClose func(ctx context.Context) error
}

func newEmailBridgeForTest(t *testing.T, st *fakeSettings, rowKey, rowType string, enabled int, flush time.Duration) *bridgeFixture {
	t.Helper()
	ext, err := repo.MarshalProviderExt(&providerpb.Ext{})
	if err != nil {
		t.Fatalf("marshal ext: %v", err)
	}
	loader := provider.NewLoader(fakeRowSource{row: &model.Provider{
		ProviderKey: rowKey, DisplayName: "Test Email", Category: provider.CategoryEmail,
		Type: rowType, IsEnabled: int8(enabled), Ext: ext,
	}}, nil, provider.LoaderOptions{})
	q := asyncqueue.New(provider.SendExecutor{}, asyncqueue.Options{
		Capacity: 16, Workers: 1, BatchSize: 8, FlushInterval: flush,
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = q.Close(ctx)
	})
	bridge, err := provider.NewCodeBridge(st, loader, q, settings.KeyEmailProviderKey, provider.CategoryEmail)
	if err != nil {
		t.Fatalf("NewCodeBridge: %v", err)
	}
	return &bridgeFixture{CodeBridge: bridge, queueClose: q.Close}
}

// TestLoginChainOTPSendSuccessThenVerify 场景一：challenge 发送成功 →
// 厂商收到验证码 → form 步提交 → 校验通过 → 完成登录（§2.2 / §8.2）。
func TestLoginChainOTPSendSuccessThenVerify(t *testing.T) {
	h := newLoginHarness(t, "eml_ok", "eml_ok", testEmailVendorType, 1)

	resp := h.engine.Submit(context.Background(), "login", orchestrator.Request{
		Method: "otp_email", Step: "challenge",
		Payload: &factor.Payload{Email: "alice@example.com"},
	})
	if resp.Status != orchestrator.StatusNext || resp.LoginToken == "" || resp.NextStep == nil {
		t.Fatalf("challenge resp = %+v, want next + login_token + next_step", resp)
	}
	if resp.NextStep.Kind != "form" {
		t.Fatalf("next_step.kind = %q, want form", resp.NextStep.Kind)
	}

	// 写码与投递内容一致：厂商最终收到与存储一致的 6 位码。
	target, code := h.store.lastCode()
	if target != "alice@example.com" {
		t.Fatalf("issued target = %q, want bound email", target)
	}
	waitFor(t, func() bool {
		calls, _, tpl, params := okEmailVendor.snapshot()
		return calls >= 1 && tpl == "otp" && params["code"] == code
	})

	// form 步提交验证码 → 校验通过 → success（建会话恰好一次）。
	resp = h.engine.Submit(context.Background(), "login", orchestrator.Request{
		LoginToken: resp.LoginToken, Step: "verify",
		Payload: &factor.Payload{Code: code},
	})
	if resp.Status != orchestrator.StatusSuccess {
		t.Fatalf("verify resp = %+v, want success", resp)
	}
	if resp.UserId != 42 || resp.SessionId != "sid-1" {
		t.Fatalf("success fields = %+v", resp)
	}
	if n := h.sessions.count(); n != 1 {
		t.Fatalf("session writes = %d, want exactly 1", n)
	}
}

// TestLoginChainChannelUnconfiguredProviderDisabled 场景二：渠道未配置
// （settings 键空 / 实例缺失 / 未启用 / 类型不符）→ challenge 以封闭集合
// provider_disabled 终止（§1.6 行 259），不签发 login_token。
func TestLoginChainChannelUnconfiguredProviderDisabled(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		rowKey  string
		rowType string
		enabled int
	}{
		{"settings 键空", "", "", testEmailVendorType, 1},
		{"实例缺失", "eml_missing", "", testEmailVendorType, 1},
		{"实例未启用", "eml_off", "eml_off", testEmailVendorType, 0},
		{"类型不符（sms 厂商挂在 email 键）", "eml_sms", "eml_sms", testSMSVendorType, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newLoginHarness(t, tc.key, tc.rowKey, tc.rowType, tc.enabled)
			resp := h.engine.Submit(context.Background(), "login", orchestrator.Request{
				Method: "otp_email", Step: "challenge",
				Payload: &factor.Payload{Email: "alice@example.com"},
			})
			if resp.Status != factorotp.StatusProviderDisabled {
				t.Fatalf("status = %q, want provider_disabled (§1.6 行 259)", resp.Status)
			}
			if resp.LoginToken != "" || resp.NextStep != nil {
				t.Fatalf("terminal status must not issue login_token / next_step: %+v", resp)
			}
		})
	}
}

// TestLoginChainSendFailureDoesNotRollbackCode 场景三：厂商发送失败（异步
// 重试 3 次后放弃）→ 验证码已生成的状态不回滚，用户仍可提交验证码完成登录
// （§8.2 行 1051 / §15.2 行 1726）。
func TestLoginChainSendFailureDoesNotRollbackCode(t *testing.T) {
	h := newLoginHarness(t, "eml_fail", "eml_fail", testFailVendorType, 1)

	resp := h.engine.Submit(context.Background(), "login", orchestrator.Request{
		Method: "otp_email", Step: "challenge",
		Payload: &factor.Payload{Email: "alice@example.com"},
	})
	if resp.Status != orchestrator.StatusNext || resp.LoginToken == "" {
		t.Fatalf("challenge resp = %+v, want next（发送异步化不阻塞主链路）", resp)
	}

	// 执行器重试 sendAttempts 次后放弃（进程内 200ms 退避，仅告警不回滚）。
	waitFor(t, func() bool {
		calls, _, _, _ := failVendor.snapshot()
		return calls >= 3
	})

	_, code := h.store.lastCode()
	resp = h.engine.Submit(context.Background(), "login", orchestrator.Request{
		LoginToken: resp.LoginToken, Step: "verify",
		Payload: &factor.Payload{Code: code},
	})
	if resp.Status != orchestrator.StatusSuccess {
		t.Fatalf("verify resp = %+v, want success（验证码未被回滚）", resp)
	}
	if n := h.sessions.count(); n != 1 {
		t.Fatalf("session writes = %d, want 1", n)
	}
}

// —— Fake ——

// fakeSettings 同时满足 orchestrator.SettingsReader 与 provider.SettingGetter。
type fakeSettings struct {
	strs   map[string]string
	ints   map[string]int64
	bools  map[string]bool
	slices map[string][]string
}

func (s *fakeSettings) GetString(key string) (string, bool) { v, ok := s.strs[key]; return v, ok }
func (s *fakeSettings) GetInt64(key string) (int64, bool)   { v, ok := s.ints[key]; return v, ok }
func (s *fakeSettings) GetBool(key string) (bool, bool)     { v, ok := s.bools[key]; return v, ok }
func (s *fakeSettings) GetStringSlice(key string) ([]string, bool) {
	v, ok := s.slices[key]
	return v, ok
}

// newEngineSettings 登录链夹具默认键（engine 层消费的最小集合）。
func newEngineSettings(emailProviderKey string) *fakeSettings {
	return &fakeSettings{
		strs: map[string]string{
			settings.KeyCookieName:       "al_session",
			settings.KeyEmailProviderKey: emailProviderKey,
		},
		ints:  map[string]int64{settings.KeySessionTtl: 604800},
		bools: map[string]bool{settings.KeyMfaEnabled: true},
		slices: map[string][]string{
			settings.KeyLoginMethods: {"password", "otp_sms", "otp_email", "webauthn", "thirdparty"},
			settings.KeyMfaMethods:   {"totp", "otp_sms", "otp_email", "webauthn"},
		},
	}
}

// fakeRowSource provider.RowSource：仅 row.ProviderKey 命中时返回该行，
// 未命中返回包装的 gorm.ErrRecordNotFound（与 repo 同口径）。
type fakeRowSource struct{ row *model.Provider }

func (s fakeRowSource) FindByKey(_ context.Context, key string) (*model.Provider, error) {
	if s.row != nil && s.row.ProviderKey == key {
		cp := *s.row
		return &cp, nil
	}
	return nil, fmt.Errorf("provider repo: find %q: %w", key, gorm.ErrRecordNotFound)
}

func (fakeRowSource) ListProviders(context.Context, repo.ProviderListQuery) ([]model.Provider, int64, error) {
	return nil, 0, nil
}

// fakeCodeStore coreotp.Store：记录最近一次写码；Verify 按记录值比对。
type fakeCodeStore struct {
	mu             sync.Mutex
	target, code   string
	purpose, owner string
}

func (s *fakeCodeStore) Send(_ context.Context, target, purpose, owner, _ string, code string) (cache.SendResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.target, s.purpose, s.owner, s.code = target, purpose, owner, code
	return cache.SendOK, nil
}

func (s *fakeCodeStore) Verify(_ context.Context, target, purpose, owner, code string) (cache.CodeVerifyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.target == target && s.purpose == purpose && s.owner == owner && s.code == code {
		return cache.CodeVerifyResult{Result: cache.VerifyOK}, nil
	}
	return cache.CodeVerifyResult{Result: cache.VerifyMismatch, AttemptsLeft: 4}, nil
}

func (s *fakeCodeStore) lastCode() (target, code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.target, s.code
}

// fakeUsers factor.UserRepo：恒返回同一用户（存在性检查放行）。
type fakeUsers struct{ user *model.User }

func (f *fakeUsers) FindByID(context.Context, int64) (*model.User, error) {
	return f.user, nil
}
func (f *fakeUsers) FindByPhone(context.Context, string) (*model.User, error) {
	return f.user, nil
}
func (f *fakeUsers) FindByEmail(context.Context, string) (*model.User, error) {
	return f.user, nil
}

// fakeCreds 同时满足 factor.CredentialRepo 与 orchestrator.MFACredentialReader。
type fakeCreds struct{}

func (fakeCreds) FindByUserAndKind(context.Context, int64, string) (*model.UserCredential, error) {
	return nil, gorm.ErrRecordNotFound
}
func (fakeCreds) ListWebauthn(context.Context, int64) ([]model.UserCredentialWebauthn, error) {
	return nil, nil
}

// fakeSessions orchestrator.SessionWriter：计数会话写入。
type fakeSessions struct {
	mu    sync.Mutex
	calls int
}

func (f *fakeSessions) Write(context.Context, int64, []string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return "sid-1", "stok-1", nil
}

func (f *fakeSessions) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeOIDCIssuer struct{}

func (fakeOIDCIssuer) Issue(context.Context, orchestrator.OIDCIssue) (string, error) {
	return "code-1", nil
}

type fakeEvents struct {
	mu    sync.Mutex
	count int
}

func (f *fakeEvents) Record(context.Context, orchestrator.LoginEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count++
	return nil
}

type fakeSync struct{}

func (fakeSync) Build(context.Context, string, string, string, []string, string) (string, error) {
	return "", nil
}

// testCodecKey login_token 加解密测试密钥（AES-256 恰 32 字节；仅测试用）。
func testCodecKey() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

// waitFor 轮询直至条件成立或超时（异步队列投递的确定性等待）。
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}
