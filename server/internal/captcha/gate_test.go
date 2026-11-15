package captcha

import (
	"context"
	"errors"
	"testing"
)

type mapSettings map[string]int64

func (m mapSettings) GetInt64(key string) (int64, bool) {
	v, ok := m[key]
	return v, ok
}

type fakeCatalog struct {
	p   *Provider
	err error
}

func (f fakeCatalog) Current(context.Context) (*Provider, error) { return f.p, f.err }

type fakeVerifier struct {
	calls  []string
	result error
}

func (f *fakeVerifier) Verify(_ context.Context, providerKey string, _ Submission) error {
	f.calls = append(f.calls, providerKey)
	return f.result
}

func TestGateConfigDegradesToBuiltin(t *testing.T) {
	cases := []struct {
		name    string
		catalog ProviderCatalog
	}{
		{"nil catalog", nil},
		{"no provider", fakeCatalog{}},
		{"catalog error", fakeCatalog{err: errors.New("health check failed")}},
		{"unknown type", fakeCatalog{p: &Provider{ProviderKey: "x", Type: "unknown"}}},
		{"missing site key", fakeCatalog{p: &Provider{ProviderKey: "x", Type: "turnstile"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGate(mapSettings{}, tc.catalog, &fakeVerifier{})
			got := g.Config(context.Background())
			if got.ProviderKey != BuiltinProviderKey || got.Type != TypeImage || got.SiteKey != "" {
				t.Fatalf("degrade config = %+v, want builtin image", got)
			}
		})
	}
}

func TestGateConfigUsesCurrentProvider(t *testing.T) {
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{
		ProviderKey: "turnstile-1", Type: "turnstile", SiteKey: "site-1",
	}}, &fakeVerifier{})
	got := g.Config(context.Background())
	if got.ProviderKey != "turnstile-1" || got.Type != "turnstile" || got.SiteKey != "site-1" {
		t.Fatalf("config = %+v", got)
	}
}

func TestGateRequiredSceneNeedsCaptcha(t *testing.T) {
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{
		ProviderKey: "turnstile-1", Type: "turnstile", SiteKey: "site-1",
	}}, &fakeVerifier{})
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
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{ProviderKey: "builtin_image", Type: "image"}}, &fakeVerifier{})
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

// TestNotRequiredScenesSkipVerifier 不需要的场景既不校验凭据也不调用 Verifier。
func TestNotRequiredScenesSkipVerifier(t *testing.T) {
	v := &fakeVerifier{}
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{ProviderKey: "builtin_image", Type: "image"}}, v)
	for _, scene := range []string{SceneWebAuthnOptions, SceneNoDispatch} {
		out, err := g.Evaluate(context.Background(), Request{
			Scene:      scene,
			Submission: &Submission{ProviderKey: "builtin_image", ID: "id", Answer: "1234"},
		})
		if err != nil {
			t.Fatalf("scene=%q Evaluate: %v", scene, err)
		}
		if out.Required || out.Status != "" {
			t.Fatalf("scene=%q outcome = %+v, want 放行", scene, out)
		}
	}
	if len(v.calls) != 0 {
		t.Fatalf("不需要 captcha 的场景不应校验凭据，calls = %v", v.calls)
	}
}

func TestGateChallengeVerifyPass(t *testing.T) {
	v := &fakeVerifier{}
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{ProviderKey: "builtin_image", Type: "image"}}, v)
	out, err := g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: "builtin_image", ID: "id", Answer: "1234"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Status != "" {
		t.Fatalf("status = %q, want pass", out.Status)
	}
	if len(v.calls) != 1 || v.calls[0] != "builtin_image" {
		t.Fatalf("verifier calls = %v", v.calls)
	}
}

func TestGateVerifyInvalid(t *testing.T) {
	v := &fakeVerifier{result: ErrInvalid}
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{ProviderKey: "builtin_image", Type: "image"}}, v)
	out, err := g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: "builtin_image", ID: "id", Answer: "bad"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Status != StatusInvalid {
		t.Fatalf("status = %q, want StatusInvalid", out.Status)
	}
}

func TestGateVerifyInfraError(t *testing.T) {
	v := &fakeVerifier{result: errors.New("redis down")}
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{ProviderKey: "builtin_image", Type: "image"}}, v)
	_, err := g.Evaluate(context.Background(), Request{
		Scene:      SceneOtpDispatch,
		Submission: &Submission{ProviderKey: "builtin_image", ID: "id", Answer: "x"},
	})
	if err == nil {
		t.Fatal("expected infra error to propagate")
	}
}

func TestGateProviderKeyMismatch(t *testing.T) {
	v := &fakeVerifier{}
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{ProviderKey: "turnstile-1", Type: "turnstile", SiteKey: "site"}}, v)
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
	if len(v.calls) != 0 {
		t.Fatalf("verifier should not be called, calls=%v", v.calls)
	}
}

func TestGatePasswordThresholdIsRuntime(t *testing.T) {
	settings := mapSettings{"pwd_fail_capture": 3}
	g := NewGate(settings, fakeCatalog{p: &Provider{ProviderKey: "builtin_image", Type: "image"}}, &fakeVerifier{})

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
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{ProviderKey: "builtin_image", Type: "image"}}, &fakeVerifier{})
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
	cfg := Config{ProviderKey: "cf_turnstile", Type: "turnstile", SiteKey: "0xSITE"}
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
