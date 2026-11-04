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

func TestGateChallengeRequiresCaptcha(t *testing.T) {
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{
		ProviderKey: "turnstile-1", Type: "turnstile", SiteKey: "site-1",
	}}, &fakeVerifier{})
	out, err := g.Evaluate(context.Background(), Request{Challenge: true})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !out.Required || out.Status != StatusRequired {
		t.Fatalf("outcome = %+v, want captcha_required", out)
	}
	if out.Config.ProviderKey != "turnstile-1" || out.Config.SiteKey != "site-1" {
		t.Fatalf("config = %+v", out.Config)
	}
}

func TestGateChallengeVerifyPass(t *testing.T) {
	v := &fakeVerifier{}
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{ProviderKey: "builtin_image", Type: "image"}}, v)
	out, err := g.Evaluate(context.Background(), Request{
		Challenge:  true,
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
		Challenge:  true,
		Submission: &Submission{ProviderKey: "builtin_image", ID: "id", Answer: "bad"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Status != StatusInvalid {
		t.Fatalf("status = %q, want captcha_invalid", out.Status)
	}
}

func TestGateVerifyInfraError(t *testing.T) {
	v := &fakeVerifier{result: errors.New("redis down")}
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{ProviderKey: "builtin_image", Type: "image"}}, v)
	_, err := g.Evaluate(context.Background(), Request{
		Challenge:  true,
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
		Challenge:  true,
		Submission: &Submission{ProviderKey: "other", Token: "t"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Status != StatusInvalid {
		t.Fatalf("status = %q, want captcha_invalid", out.Status)
	}
	if len(v.calls) != 0 {
		t.Fatalf("verifier should not be called, calls=%v", v.calls)
	}
}

func TestGatePasswordThresholdIsRuntime(t *testing.T) {
	settings := mapSettings{"pwd_fail_capture": 3}
	g := NewGate(settings, fakeCatalog{p: &Provider{ProviderKey: "builtin_image", Type: "image"}}, &fakeVerifier{})

	out, err := g.Evaluate(context.Background(), Request{Password: true, FailedAttempts: 2})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if out.Required {
		t.Fatalf("failures=2 must not require captcha")
	}

	// 运行时改阈值，不重新构造 Gate，证明不缓存配置。
	settings["pwd_fail_capture"] = 2
	out, err = g.Evaluate(context.Background(), Request{Password: true, FailedAttempts: 2})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !out.Required || out.Status != StatusRequired {
		t.Fatalf("outcome = %+v, want required after hot settings change", out)
	}
}

func TestGatePasswordDefaultThreshold(t *testing.T) {
	g := NewGate(mapSettings{}, fakeCatalog{p: &Provider{ProviderKey: "builtin_image", Type: "image"}}, &fakeVerifier{})
	if out, _ := g.Evaluate(context.Background(), Request{Password: true, FailedAttempts: 2}); out.Required {
		t.Fatal("default threshold 3 must not trigger at 2")
	}
	if out, _ := g.Evaluate(context.Background(), Request{Password: true, FailedAttempts: 3}); !out.Required {
		t.Fatal("default threshold 3 must trigger at 3")
	}
}
