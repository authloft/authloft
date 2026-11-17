// gate_test.go 覆盖 Gate 判定面（§9.1 / §9.3）：场景触发表、配置现算与降级、
// 工厂化后的两条校验路径——图形码内置路径（不入 factory，Store GETDEL）与
// 第三方 factory 运行期构造（配置变化即构造出新对象）。
package captcha

import (
	"context"
	"errors"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
)

type mapSettings map[string]int64

func (m mapSettings) GetInt64(key string) (int64, bool) {
	v, ok := m[key]
	return v, ok
}

// testProvider 造最小完整实例：Key/Type/Ext.client_id 供 normalize 与 factory
// 断言（Row 由 Catalog 实装侧校验，fake catalog 不需要）。
func testProvider(key, typ, siteKey string) *provider.Provider {
	return &provider.Provider{
		Key:  key,
		Type: typ,
		Ext:  &providerpb.Ext{ClientId: siteKey},
	}
}

type fakeCatalog struct {
	p   *provider.Provider
	err error
}

func (f *fakeCatalog) Current(context.Context) (*provider.Provider, error) { return f.p, f.err }

// fakeImageStore 内置图形码存储桩：ok/err 控制放行 / 无效 / 基础设施错误，
// 记录调用参数供断言。
type fakeImageStore struct {
	ok      bool
	err     error
	ids     []string
	answers []string
}

func (f *fakeImageStore) Set(context.Context, string, string) error { return nil }

func (f *fakeImageStore) Verify(_ context.Context, id, answer string) (bool, error) {
	f.ids = append(f.ids, id)
	f.answers = append(f.answers, answer)
	return f.ok, f.err
}

func newFakeImageStore() *fakeImageStore { return &fakeImageStore{ok: true} }

// fakeVerifier 第三方校验桩（经 fake factory 注入）：记录 providerKey 与
// submission，result 控制放行 / 无效 / 基础设施错误。
type fakeVerifier struct {
	calls  []string
	sub    *Submission
	result error
}

func (f *fakeVerifier) Verify(_ context.Context, providerKey string, sub Submission) error {
	f.calls = append(f.calls, providerKey)
	f.sub = &sub
	return f.result
}

// fakeFactory factory 桩：记录收到的当前生效 provider 实例，返回受控 verifier
// 或构造错误（verifier 为 nil 时仅考察构造路径）。
type fakeFactory struct {
	got      []*provider.Provider
	verifier *fakeVerifier
	buildErr error
}

func (f *fakeFactory) factory(p *provider.Provider) (provider.Verifier, error) {
	f.got = append(f.got, p)
	if f.buildErr != nil {
		return nil, f.buildErr
	}
	return f.verifier, nil
}

// TestGateConfigDegradesToBuiltin 降级各态：nil catalog / 无 provider / 直读
// error / 未登记 type / 缺 siteKey → 内置图形码（§2.5 降级语义）。
func TestGateConfigDegradesToBuiltin(t *testing.T) {
	cases := []struct {
		name    string
		catalog ProviderCatalog
	}{
		{"nil catalog", nil},
		{"no provider", &fakeCatalog{}},
		{"catalog error", &fakeCatalog{err: errors.New("health check failed")}},
		{"unknown type", &fakeCatalog{p: testProvider("x", "unknown", "")}},
		{"missing site key", &fakeCatalog{p: testProvider("x", TypeTurnstile, "")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGate(mapSettings{}, tc.catalog, newFakeImageStore(), func(*provider.Provider) (provider.Verifier, error) {
				return nil, nil
			})
			got := g.Config(context.Background())
			if got.ProviderKey != BuiltinProviderKey || got.Type != TypeImage || got.SiteKey != "" {
				t.Fatalf("degrade config = %+v, want builtin image", got)
			}
		})
	}
}

func TestGateConfigUsesCurrentProvider(t *testing.T) {
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider("turnstile-1", TypeTurnstile, "site-1")},
		newFakeImageStore(), func(*provider.Provider) (provider.Verifier, error) { return nil, nil })
	got := g.Config(context.Background())
	if got.ProviderKey != "turnstile-1" || got.Type != TypeTurnstile || got.SiteKey != "site-1" {
		t.Fatalf("config = %+v", got)
	}
}

func TestGateRequiredSceneNeedsCaptcha(t *testing.T) {
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider("turnstile-1", TypeTurnstile, "site-1")},
		newFakeImageStore(), func(*provider.Provider) (provider.Verifier, error) { return nil, nil })
	out, err := g.Evaluate(context.Background(), Request{Scene: SceneOtpDispatch})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !out.Required || out.Status != StatusRequired {
		t.Fatalf("outcome = %+v, want StatusRequired", out)
	}
	if out.Config.ProviderKey != "turnstile-1" || out.Config.SiteKey != "site-1" {
		t.Fatalf("config = %+v", out.Config)
	}
}

// TestSceneTable 按 §2.5 触发表核对场景结论：表内 7 个场景 + 无下发场景，
// 未知场景 fail-closed（按「必须」处理）。
func TestSceneTable(t *testing.T) {
	cases := []struct {
		scene string
		want  bool
	}{
		{SceneOtpDispatch, true},         // 第 1 行 任何一次性验证码下发
		{SceneWebAuthnOptions, false},    // 第 2 行 WebAuthn 取 options
		{ScenePasswordLogin, false},      // 第 3 行 密码登录：0 次失败不触发
		{SceneSignupResetDispatch, true}, // 第 4 行 注册 / 重置的下发
		{SceneMfaDispatch, true},         // 第 5 行 两步验证阶段下发
		{SceneContactBind, true},         // 第 6 行 绑定 / 换绑联系方式
		{SceneQrcodeFetch, true},         // 第 7 行 拉取小程序码
		{SceneNoDispatch, false},         // 无下发环节
		{"", true},                       // 未登记 → fail-closed
		{"no_such_scene", true},          // 未登记 → fail-closed
	}
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider(BuiltinProviderKey, TypeImage, "")},
		newFakeImageStore(), func(*provider.Provider) (provider.Verifier, error) { return nil, nil })
	for _, tc := range cases {
		t.Run(tc.scene, func(t *testing.T) {
			out, err := g.Evaluate(context.Background(), Request{Scene: tc.scene})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if out.Required != tc.want {
				t.Fatalf("scene=%q required=%v, want %v", tc.scene, out.Required, tc.want)
			}
			if tc.want && out.Status != StatusRequired {
				t.Fatalf("scene=%q status=%q, want %q", tc.scene, out.Status, StatusRequired)
			}
		})
	}
}

// TestNotRequiredScenesSkipVerify 不需要的场景既不校验凭据也不触发任何
// 校验路径（内置 Store 与 factory 都不调用）。
func TestNotRequiredScenesSkipVerify(t *testing.T) {
	store := &fakeImageStore{}
	ff := &fakeFactory{verifier: &fakeVerifier{}}
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider(BuiltinProviderKey, TypeImage, "")},
		store, ff.factory)
	for _, scene := range []string{SceneWebAuthnOptions, SceneNoDispatch} {
		out, err := g.Evaluate(context.Background(), Request{
			Scene:      scene,
			Submission: &Submission{ProviderKey: BuiltinProviderKey, ID: "id", Answer: "1234"},
		})
		if err != nil {
			t.Fatalf("scene=%q Evaluate: %v", scene, err)
		}
		if out.Required || out.Status != "" {
			t.Fatalf("scene=%q outcome = %+v, want 放行", scene, out)
		}
	}
	if len(store.ids) != 0 || len(ff.got) != 0 {
		t.Fatalf("不需要 captcha 的场景不应校验凭据，store=%v factory=%v", store.ids, ff.got)
	}
}

// TestGateImageBuiltinPass 图形码内置路径（不入 factory）：正确答案经 Store
// 一次性消费放行，factory 不被触达（§9.1 image 保留内置）。
func TestGateImageBuiltinPass(t *testing.T) {
	store := &fakeImageStore{ok: true}
	ff := &fakeFactory{verifier: &fakeVerifier{}}
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider(BuiltinProviderKey, TypeImage, "")},
		store, ff.factory)
	out, err := g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: BuiltinProviderKey, ID: "id", Answer: "1234"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Status != "" {
		t.Fatalf("status = %q, want pass", out.Status)
	}
	if len(store.ids) != 1 || store.ids[0] != "id" || store.answers[0] != "1234" {
		t.Fatalf("store calls = %v/%v", store.ids, store.answers)
	}
	if len(ff.got) != 0 {
		t.Fatalf("图形码不得入 factory，factory got %v", ff.got)
	}
}

// TestGateImageTypedProviderRow type=image 的表内行同走内置路径（§9.2，
// 不另写第二条校验路径）。
func TestGateImageTypedProviderRow(t *testing.T) {
	store := &fakeImageStore{ok: true}
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider("custom_img", TypeImage, "")},
		store, func(*provider.Provider) (provider.Verifier, error) { return nil, nil })
	out, err := g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: "custom_img", ID: "id2", Answer: "5678"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Status != "" || len(store.ids) != 1 || store.ids[0] != "id2" {
		t.Fatalf("outcome=%+v store=%v, want type=image 走内置路径", out, store.ids)
	}
}

// TestGateImageInvalid 与存储故障映射：未命中 → StatusInvalid（一次性语义
// 由 Store 保证）；存储故障为基础设施错误原样上抛（不误映射 invalid）。
func TestGateImageInvalid(t *testing.T) {
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider(BuiltinProviderKey, TypeImage, "")},
		&fakeImageStore{ok: false}, func(*provider.Provider) (provider.Verifier, error) { return nil, nil })
	out, err := g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: BuiltinProviderKey, ID: "id", Answer: "bad"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Status != StatusInvalid {
		t.Fatalf("status = %q, want StatusInvalid", out.Status)
	}

	g = NewGate(mapSettings{}, &fakeCatalog{p: testProvider(BuiltinProviderKey, TypeImage, "")},
		&fakeImageStore{err: errors.New("redis down")}, func(*provider.Provider) (provider.Verifier, error) { return nil, nil })
	_, err = g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: BuiltinProviderKey, ID: "id", Answer: "x"},
	})
	if err == nil {
		t.Fatal("expected infra error to propagate")
	}
}

// TestGateFactoryDispatch 第三方经 factory 运行期构造（§9.1）：factory 收到
// 当前生效完整实例；verifier 收到当前生效 providerKey；ErrInvalid → StatusInvalid，
// 构造失败为基础设施错误。
func TestGateFactoryDispatch(t *testing.T) {
	ff := &fakeFactory{verifier: &fakeVerifier{}}
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider("turnstile-1", TypeTurnstile, "site")},
		newFakeImageStore(), ff.factory)
	out, err := g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: "turnstile-1", Token: "tok"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Status != "" {
		t.Fatalf("status = %q, want pass", out.Status)
	}
	if len(ff.got) != 1 || ff.got[0].Key != "turnstile-1" || ff.got[0].Type != TypeTurnstile {
		t.Fatalf("factory got %+v, want 当前生效实例", ff.got)
	}
	if v := ff.verifier; len(v.calls) != 1 || v.calls[0] != "turnstile-1" || v.sub == nil || v.sub.Token != "tok" {
		t.Fatalf("verifier calls=%v sub=%+v", v.calls, v.sub)
	}

	// 校验不通过 → StatusInvalid（可判别哨兵）。
	ff2 := &fakeFactory{verifier: &fakeVerifier{result: ErrInvalid}}
	g = NewGate(mapSettings{}, &fakeCatalog{p: testProvider("turnstile-1", TypeTurnstile, "site")},
		newFakeImageStore(), ff2.factory)
	out, err = g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: "turnstile-1", Token: "bad"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Status != StatusInvalid {
		t.Fatalf("status = %q, want StatusInvalid", out.Status)
	}

	// factory 构造失败 → 基础设施错误。
	ff3 := &fakeFactory{buildErr: errors.New("registry miss")}
	g = NewGate(mapSettings{}, &fakeCatalog{p: testProvider("turnstile-1", TypeTurnstile, "site")},
		newFakeImageStore(), ff3.factory)
	if _, err = g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: "turnstile-1", Token: "t"},
	}); err == nil {
		t.Fatal("expected factory build error to propagate")
	}
}

// TestGateFactoryRebuiltPerEvaluate 运行期构造语义（§9.1）：不改 Gate，
// 仅更换当前生效 provider，下一次校验即按新配置构造——「配置变化即构造出
// 新高频正确对象」，不存在旧配置实例复用。
func TestGateFactoryRebuiltPerEvaluate(t *testing.T) {
	catalog := &fakeCatalog{p: testProvider("cf", TypeTurnstile, "site")}
	ff := &fakeFactory{verifier: &fakeVerifier{}}
	g := NewGate(mapSettings{}, catalog, newFakeImageStore(), ff.factory)
	if _, err := g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: "cf", Token: "t"},
	}); err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// 热更：换 provider 行（键与 type 都变），不重新构造 Gate。
	catalog.p = testProvider("goog", TypeRecaptcha, "gsite")
	if _, err := g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: "goog", Token: "t"},
	}); err != nil {
		t.Fatalf("Evaluate after change: %v", err)
	}
	if len(ff.got) != 2 || ff.got[1].Key != "goog" || ff.got[1].Type != TypeRecaptcha {
		t.Fatalf("factory got %v, want 第二次按新配置构造", ff.got)
	}
}

func TestGateProviderKeyMismatch(t *testing.T) {
	ff := &fakeFactory{verifier: &fakeVerifier{}}
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider("turnstile-1", TypeTurnstile, "site")},
		newFakeImageStore(), ff.factory)
	out, err := g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: "other", Token: "t"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Status != StatusInvalid {
		t.Fatalf("status = %q, want StatusInvalid", out.Status)
	}
	if len(ff.got) != 0 {
		t.Fatalf("factory should not be called, got=%v", ff.got)
	}
}

func TestGatePasswordThresholdIsRuntime(t *testing.T) {
	settings := mapSettings{"pwd_fail_capture": 3}
	g := NewGate(settings, &fakeCatalog{p: testProvider(BuiltinProviderKey, TypeImage, "")},
		newFakeImageStore(), func(*provider.Provider) (provider.Verifier, error) { return nil, nil })

	out, err := g.Evaluate(context.Background(), Request{Scene: ScenePasswordLogin, FailedAttempts: 2})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Required {
		t.Fatalf("failures=2 must not require captcha")
	}

	// 运行时改阈值，不重新构造 Gate，证明不缓存配置。
	settings["pwd_fail_capture"] = 2
	out, err = g.Evaluate(context.Background(), Request{Scene: ScenePasswordLogin, FailedAttempts: 2})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !out.Required || out.Status != StatusRequired {
		t.Fatalf("outcome = %+v, want required after hot settings change", out)
	}
}

func TestGatePasswordDefaultThreshold(t *testing.T) {
	g := NewGate(mapSettings{}, &fakeCatalog{p: testProvider(BuiltinProviderKey, TypeImage, "")},
		newFakeImageStore(), func(*provider.Provider) (provider.Verifier, error) { return nil, nil })
	if out, _ := g.Evaluate(context.Background(), Request{Scene: ScenePasswordLogin, FailedAttempts: 2}); out.Required {
		t.Fatal("default threshold 3 must not trigger at 2")
	}
	if out, _ := g.Evaluate(context.Background(), Request{Scene: ScenePasswordLogin, FailedAttempts: 3}); !out.Required {
		t.Fatal("default threshold 3 must trigger at 3")
	}
}

// TestFailureFrom 判定结果转领域失败：放行（Status 为空）返回 nil；失败码与
// 配置与判定同源，供错误体 details 并列下发（§1.5 / §9.1）。
func TestFailureFrom(t *testing.T) {
	if got := FailureFrom(Outcome{}); got != nil {
		t.Fatalf("放行应返回 nil, got %+v", got)
	}
	if got := FailureFrom(Outcome{Required: true}); got != nil {
		t.Fatalf("已提交合法凭据且判定放行应返回 nil, got %+v", got)
	}
	cfg := Config{ProviderKey: "cf_turnstile", Type: TypeTurnstile, SiteKey: "0xSITE"}
	for _, status := range []string{StatusRequired, StatusInvalid} {
		got := FailureFrom(Outcome{Required: true, Config: cfg, Status: status})
		if got == nil {
			t.Fatalf("status=%q 应返回领域失败", status)
		}
		if got.Code != status {
			t.Fatalf("failure.code = %q, want %q", got.Code, status)
		}
		if got.Config != cfg {
			t.Fatalf("failure.config = %+v, want 同源 %+v", got.Config, cfg)
		}
		if got.Error() == "" {
			t.Fatal("Failure 应实现 error 接口且消息非空")
		}
	}
}
