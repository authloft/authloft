// captcha_test.go 覆盖 verifier 槽语义（docs/后端架构.md §9.1 阶段三、§15.3）
// 与 Loader 直读通道（§9.1 captcha catalog「下发与拦截同源、不缓存」的落点）：
// register + WithVerifier 注册后 NewVerifier 按类型运行期分派；未注册 / 无
// verifier 槽 → ErrUnknownType；RegisterVerifier 薄封装的程序错误 panic；
// GetDirect 绕过本地 LRU 立即取到热更后的行（Get 仍在缓存窗口内）。
package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"authloft/internal/proxyclient"
)

// fakeVerifierProduct verifier 槽测试产物。
type fakeVerifierProduct struct{ key string }

func (f *fakeVerifierProduct) Verify(context.Context, string, Submission) error { return nil }

// TestVerifierSlotDispatch verifier 槽语义（§15.3）：register + WithVerifier
// 注册后 NewVerifier 按类型分派并收到实例；未注册 / 无 verifier 槽 / nil 入参
// / factory 返回 nil 的判别面；factory 自身错误原样上抛。
func TestVerifierSlotDispatch(t *testing.T) {
	const captchaTyp = "test_captcha_slot"
	if err := register(captchaTyp, Meta{Type: captchaTyp, DisplayName: "测试 captcha", Category: CategoryCaptcha},
		WithVerifier(func(p *Provider) (Verifier, error) { return &fakeVerifierProduct{key: p.Key}, nil })); err != nil {
		t.Fatalf("register verifier: %v", err)
	}
	v, err := NewVerifier(&Provider{Key: "cf", Type: captchaTyp})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	got, ok := v.(*fakeVerifierProduct)
	if !ok || got.key != "cf" {
		t.Errorf("NewVerifier 返回 %T(%+v), want fakeVerifierProduct{cf}", v, got)
	}
	if _, err := NewVerifier(nil); !errors.Is(err, ErrNilProvider) {
		t.Errorf("NewVerifier(nil) = %v, want ErrNilProvider", err)
	}
	for _, typ := range []string{"test_captcha_missing", "test_multi_slot_meta"} {
		if _, err := NewVerifier(&Provider{Type: typ}); !errors.Is(err, ErrUnknownType) {
			t.Errorf("NewVerifier(%q) = %v, want ErrUnknownType", typ, err)
		}
	}
	const brokenTyp = "test_captcha_nil_product"
	if err := register(brokenTyp, Meta{Type: brokenTyp, Category: CategoryCaptcha},
		WithVerifier(func(*Provider) (Verifier, error) { return nil, nil })); err != nil {
		t.Fatalf("register broken: %v", err)
	}
	if _, err := NewVerifier(&Provider{Type: brokenTyp}); !errors.Is(err, ErrNilAdapter) {
		t.Errorf("NewVerifier(nil product) = %v, want ErrNilAdapter", err)
	}
	const errTyp = "test_captcha_build_err"
	if err := register(errTyp, Meta{Type: errTyp, Category: CategoryCaptcha},
		WithVerifier(func(*Provider) (Verifier, error) { return nil, errors.New("bad ext") })); err != nil {
		t.Fatalf("register err: %v", err)
	}
	if _, err := NewVerifier(&Provider{Type: errTyp}); err == nil || errors.Is(err, ErrUnknownType) {
		t.Errorf("NewVerifier(build err) = %v, want factory 错误原样上抛", err)
	}
}

// TestRegisterVerifierPanics RegisterVerifier 薄封装的程序错误（空 type /
// nil factory / category 非 captcha / 重复注册）直接 panic（init 无法返回
// 错误，§15.3）。
func TestRegisterVerifierPanics(t *testing.T) {
	cases := []struct {
		name    string
		typ     string
		meta    Meta
		factory VerifierFactory
	}{
		{"空 type", "", Meta{Category: CategoryCaptcha}, func(*Provider) (Verifier, error) { return nil, nil }},
		{"nil factory", "test_captcha_nilf", Meta{Category: CategoryCaptcha}, nil},
		{"category 非 captcha", "test_captcha_cat", Meta{Category: CategoryProxy}, func(*Provider) (Verifier, error) { return nil, nil }},
		{"重复注册", CaptchaTypeTurnstile, Meta{Category: CategoryCaptcha}, func(*Provider) (Verifier, error) { return nil, nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("RegisterVerifier(%q) 应 panic", tc.typ)
				}
			}()
			RegisterVerifier(tc.typ, tc.meta, tc.factory)
		})
	}
}

// TestLoaderGetDirectBypassesCache 直读通道专项（§9.1）：Get 命中本地 LRU
// 不回源；底行热更后 GetDirect 立即回源取新值（Get 仍返回旧值证明改动落在
// 60s 缓存窗口内），且 GetDirect 每次都真实回源（不读 LRU、不合并 singleflight）。
func TestLoaderGetDirectBypassesCache(t *testing.T) {
	clock := newFakeClock()
	row := makeRow(t, "cf", CaptchaTypeTurnstile, "", "secret-v1", 1)
	src := newFakeSource(row)
	loader := NewLoader(src, nil, proxyclient.NewPoolSet(), providerOptions(clock, 60*time.Second, 5*time.Second))
	ctx := context.Background()

	if _, err := loader.Get(ctx, "cf"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if find, _ := src.counts(); find != 1 {
		t.Fatalf("find calls = %d, want 1", find)
	}
	if _, err := loader.Get(ctx, "cf"); err != nil {
		t.Fatalf("Get cached: %v", err)
	}
	if find, _ := src.counts(); find != 1 {
		t.Fatalf("find calls after cache hit = %d, want 1", find)
	}

	// 底行热更（secret v1 → v2）：普通读仍在缓存窗口内。
	row2 := makeRow(t, "cf", CaptchaTypeRecaptcha, "", "secret-v2", 1)
	src.set(row2)

	cached, err := loader.Get(ctx, "cf")
	if err != nil {
		t.Fatalf("Get after change: %v", err)
	}
	if cached.Ext.GetClientSecret() != "secret-v1" || cached.Type != CaptchaTypeTurnstile {
		t.Fatalf("Get = %s/%s, want 缓存旧值 secret-v1/turnstile", cached.Ext.GetClientSecret(), cached.Type)
	}

	// 直读立即取到新值，且每次真实回源。
	for i := 0; i < 2; i++ {
		direct, err := loader.GetDirect(ctx, "cf")
		if err != nil {
			t.Fatalf("GetDirect #%d: %v", i, err)
		}
		if direct.Ext.GetClientSecret() != "secret-v2" || direct.Type != CaptchaTypeRecaptcha {
			t.Fatalf("GetDirect = %s/%s, want 直读新值 secret-v2/recaptcha（无缓存窗口）", direct.Ext.GetClientSecret(), direct.Type)
		}
	}
	if find, _ := src.counts(); find != 3 {
		t.Fatalf("find calls after two GetDirect = %d, want 3（每次直读均回源）", find)
	}
	// 直读装配语义与 Get 同构：Outbound 引用解析后挂实例（nil = 直连）。
	if direct, _ := loader.GetDirect(ctx, "cf"); direct.Outbound != nil {
		t.Fatalf("无代理引用时 Outbound = %v, want nil", direct.Outbound)
	}
}
