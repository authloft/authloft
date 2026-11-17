// factory_chain_test.go 三家各走自身 factory 的 gate 级链路用例
// （docs/后端架构.md §9.1 阶段三）：真 Gate + 真注册表（blank import 触发
// 三家 init 自注册）+ catalog 直读真 Loader，第三方校验按当前生效 provider
// 经 provider.NewVerifier 现场构造并命中 ext.endpoint（httptest 假端点，
// 不打真实厂商）；type=image 恒走内置路径不入 factory（同文件 gate_test
// 已覆盖，此处锁「未注册 type 降级 + 注册 type 分派」的反向）。
package captcha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/proto"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/proxyclient"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/settings"

	_ "authloft/internal/provider/captcha/hcaptcha"
	_ "authloft/internal/provider/captcha/recaptcha"
	_ "authloft/internal/provider/captcha/turnstile"
)

// chainExt proto 编码 Ext 列字节（provider 表行回源形态）。
func chainExt(t *testing.T, ext *providerpb.Ext) []byte {
	t.Helper()
	raw, err := proto.Marshal(ext)
	if err != nil {
		t.Fatalf("Marshal ext: %v", err)
	}
	return raw
}

// chainRows repo 行源桩：单键 captcha 行（Ext 经 proto 编码，Loader 唯一
// 出口 repo.ParseProviderExt 解析）。
type chainRows struct {
	row *model.Provider
}

func (f chainRows) FindByKey(context.Context, string) (*model.Provider, error) {
	return f.row, nil
}

func (chainRows) ListProviders(context.Context, repo.ProviderListQuery) ([]model.Provider, int64, error) {
	return nil, 0, nil
}

// TestGateRegistryChain 三家逐 type 端到端：catalog（真 Loader 直读）→
// Gate.Evaluate → provider.NewVerifier 注册表分派 → 厂商校验命中 ext.endpoint，
// form 恰含 secret/response 两字段（§9.1）。
func TestGateRegistryChain(t *testing.T) {
	for _, tc := range []struct {
		typ    string
		secret string
	}{
		{TypeTurnstile, "sec-cf"},
		{TypeRecaptcha, "sec-goog"},
		{TypeHcaptcha, "sec-hc"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			var method string
			form := map[string]string{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				method = r.Method
				_ = r.ParseForm()
				for k, vs := range r.PostForm {
					form[k] = vs[0]
				}
				_, _ = w.Write([]byte(`{"success":true}`))
			}))
			defer srv.Close()

			row := &model.Provider{
				ProviderKey: "pk-" + tc.typ,
				Category:    CategoryCaptcha,
				Type:        tc.typ,
				IsEnabled:   1,
				Ext: chainExt(t, &providerpb.Ext{
					ClientId: "0xSITE", ClientSecret: tc.secret, Endpoint: srv.URL,
				}),
			}
			loader := provider.NewLoader(chainRows{row: row}, nil, proxyclient.NewPoolSet(), provider.LoaderOptions{})
			g := NewGate(mapSettings{},
				NewCatalog(mapKeys{settings.KeyCaptchaProviderKey: "pk-" + tc.typ}, loader),
				newFakeImageStore(), provider.NewVerifier)

			out, err := g.Evaluate(context.Background(), Request{
				Scene:      SceneOtpDispatch,
				Submission: &Submission{ProviderKey: "pk-" + tc.typ, Token: "tok-1"},
			})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if out.Status != "" {
				t.Fatalf("status = %q, want 放行（注册表分派成功）", out.Status)
			}
			if method != http.MethodPost || len(form) != 2 ||
				form["secret"] != tc.secret || form["response"] != "tok-1" {
				t.Fatalf("siteverify 请求形态 = (%q, %v), want POST {secret:%s, response:tok-1}", method, form, tc.secret)
			}
			if out.Config.SiteKey != "0xSITE" || out.Config.Type != tc.typ {
				t.Fatalf("config = %+v, want 与拦截同源的下发配置", out.Config)
			}
		})
	}
}

// TestGateRegistryUnregisteredTypeDegrades 行 type 未注册（阶段三口径下的
// 未知 captcha type）：normalize 按封闭集合降级内置图形码，factory 不被触达。
func TestGateRegistryUnregisteredTypeDegrades(t *testing.T) {
	row := &model.Provider{
		ProviderKey: "weird", Category: CategoryCaptcha, Type: "geetest", IsEnabled: 1,
		Ext: chainExt(t, &providerpb.Ext{ClientId: "site"}),
	}
	loader := provider.NewLoader(chainRows{row: row}, nil, proxyclient.NewPoolSet(), provider.LoaderOptions{})
	g := NewGate(mapSettings{},
		NewCatalog(mapKeys{settings.KeyCaptchaProviderKey: "weird"}, loader),
		newFakeImageStore(), provider.NewVerifier)
	cfg := g.Config(context.Background())
	if cfg.ProviderKey != BuiltinProviderKey || cfg.Type != TypeImage {
		t.Fatalf("config = %+v, want 降级内置图形码", cfg)
	}
}
