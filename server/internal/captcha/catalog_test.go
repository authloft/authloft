// catalog_test.go 覆盖 Catalog.Current 的降级三态（键空串 / 禁用 / 查不到）、
// 正常取生效项（接口文档 §2.5、§5.6）与直读通道专项（§9.1：配置改动立即
// 生效、不经 60s 缓存窗口——用真 Loader + 假 repo 行源实证）。
package captcha

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/proxyclient"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

// mapKeys 假 settings 字符串快照。
type mapKeys map[string]string

func (m mapKeys) GetString(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}

// fakeSource 直读源桩：rows 无该键 = 无此行；err 非空 = 基础设施错误。
type fakeSource struct {
	rows  map[string]*provider.Provider
	err   error
	calls int
}

func (f *fakeSource) GetDirect(_ context.Context, key string) (*provider.Provider, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.rows[key], nil
}

// captchaRow 造 provider 表行（Loader 回源形态）。
func captchaRow(key, typ string, enabled int8, siteKey string) *model.Provider {
	return &model.Provider{
		ProviderKey: key,
		Category:    CategoryCaptcha,
		Type:        typ,
		IsEnabled:   enabled,
		Ext:         mustExt(siteKey),
	}
}

func mustExt(siteKey string) []byte {
	raw, err := proto.Marshal(&providerpb.Ext{ClientId: siteKey})
	if err != nil {
		panic(err)
	}
	return raw
}

// TestCatalogCurrentDegradation 降级三态 + category 不符：一律 nil,nil
// （Gate 降级 builtin_image 的输入语义）。
func TestCatalogCurrentDegradation(t *testing.T) {
	cases := []struct {
		name string
		keys KeyReader
		rows map[string]*provider.Provider
	}{
		{"键空串 = 内置", mapKeys{settings.KeyCaptchaProviderKey: ""}, nil},
		{"键未设置", mapKeys{}, nil},
		{"查不到该 key 的行", mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}, nil},
		{"category 不是 captcha", mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}, map[string]*provider.Provider{
			"cf_turnstile": {Key: "cf_turnstile", Type: TypeTurnstile, Row: &model.Provider{
				ProviderKey: "cf_turnstile", Category: "oauth", Type: TypeTurnstile, IsEnabled: 1,
			}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCatalog(tc.keys, &fakeSource{rows: tc.rows})
			got, err := c.Current(context.Background())
			if err != nil {
				t.Fatalf("Current err = %v, want nil（无可用项不是错误）", err)
			}
			if got != nil {
				t.Fatalf("Current = %+v, want nil（降级语义归 Gate）", got)
			}
		})
	}
}

// TestCatalogCurrentEnabledRow 正常路径：返回生效行的完整 Provider 实例
// （type 取表列、siteKey 由 Gate 从 ext.client_id 折算，§9.1）。
func TestCatalogCurrentEnabledRow(t *testing.T) {
	c := NewCatalog(
		mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"},
		&fakeSource{rows: map[string]*provider.Provider{
			"cf_turnstile": {Key: "cf_turnstile", Type: TypeTurnstile,
				Row: captchaRow("cf_turnstile", TypeTurnstile, 1, "0x4AAA"),
				Ext: &providerpb.Ext{ClientId: "0x4AAA", ClientSecret: "s-1", Endpoint: "https://v.example"}},
		}},
	)
	got, err := c.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got == nil {
		t.Fatal("Current = nil, want provider row")
	}
	if got.Key != "cf_turnstile" || got.Type != TypeTurnstile ||
		got.Ext.GetClientId() != "0x4AAA" || got.Ext.GetClientSecret() != "s-1" {
		t.Fatalf("Current = %+v", got)
	}
}

// TestCatalogCurrentIgnoresIsEnabledRow captcha 行不消费 is_enabled：
// 行命中即生效（IsEnabled 列值不影响 Current 判定）。
func TestCatalogCurrentIgnoresIsEnabledRow(t *testing.T) {
	c := NewCatalog(
		mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"},
		&fakeSource{rows: map[string]*provider.Provider{
			"cf_turnstile": {Key: "cf_turnstile", Type: TypeTurnstile,
				Row: captchaRow("cf_turnstile", TypeTurnstile, 0, "0x4AAA"),
				Ext: &providerpb.Ext{ClientId: "0x4AAA"}},
		}},
	)
	got, err := c.Current(context.Background())
	if err != nil || got == nil {
		t.Fatalf("Current = (%+v, %v), want 行命中即生效", got, err)
	}
}

// TestCatalogCurrentInfraError 基础设施错误上抛（Gate 按健康检查失败降级，
// §9.1），不得吞成 nil。
func TestCatalogCurrentInfraError(t *testing.T) {
	c := NewCatalog(
		mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"},
		&fakeSource{err: errors.New("db down")},
	)
	if _, err := c.Current(context.Background()); err == nil {
		t.Fatal("Current err = nil, want infra error")
	}
}

// TestCatalogCurrentNotCached 每次现算：settings 键热更后不重新构造即生效
// （§9.1「每次生成时重新判定，不缓存」）。
func TestCatalogCurrentNotCached(t *testing.T) {
	keys := mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}
	rows := map[string]*provider.Provider{
		"cf_turnstile": {Key: "cf_turnstile", Type: TypeTurnstile, Row: captchaRow("cf_turnstile", TypeTurnstile, 1, "k")},
		"goog":         {Key: "goog", Type: TypeRecaptcha, Row: captchaRow("goog", TypeRecaptcha, 1, "g")},
	}
	c := NewCatalog(keys, &fakeSource{rows: rows})

	got, err := c.Current(context.Background())
	if err != nil || got == nil || got.Key != "cf_turnstile" {
		t.Fatalf("首次 Current = (%+v, %v)", got, err)
	}
	// 热更：换键 → 立即取到新行；清空 → 立即无可用项。
	keys[settings.KeyCaptchaProviderKey] = "goog"
	if got, _ = c.Current(context.Background()); got == nil || got.Key != "goog" || got.Type != TypeRecaptcha {
		t.Fatalf("换键后 Current = %+v, want goog/recaptcha", got)
	}
	keys[settings.KeyCaptchaProviderKey] = ""
	if got, _ = c.Current(context.Background()); got != nil {
		t.Fatalf("清空后 Current = %+v, want nil", got)
	}
}

// TestCatalogCurrentNoCacheWindow 直读通道专项（§9.1「下发、拦截与错误体
// 永远同源、配置改动立即生效」）：真 Loader + 假 repo 行源——先经普通读路径
// Get 灌满本地 LRU，再改底行内容；GetDirect 必须立即取到新值（Get 仍返回旧值
// 证明改动确在缓存窗口内），Catalog.Current 立即跟随新值，无 60s 窗口。
func TestCatalogCurrentNoCacheWindow(t *testing.T) {
	rows := map[string]*model.Provider{
		"cf": captchaRow("cf", TypeTurnstile, 1, "site-v1"),
	}
	src := &fakeRepo{rows: rows}
	loader := provider.NewLoader(src, nil, proxyclient.NewPoolSet(), provider.LoaderOptions{})
	ctx := context.Background()

	// 灌缓存：普通读路径（LRU 60s 窗口内）。
	if _, err := loader.Get(ctx, "cf"); err != nil {
		t.Fatalf("Loader.Get: %v", err)
	}
	// 底行内容热更（siteKey v1 → v2、type 换厂商）。
	rows["cf"] = captchaRow("cf", TypeRecaptcha, 1, "site-v2")

	// Get 命中缓存旧值，证明改动落在缓存窗口内。
	cached, err := loader.Get(ctx, "cf")
	if err != nil {
		t.Fatalf("Loader.Get: %v", err)
	}
	if cached.Ext.GetClientId() != "site-v1" || cached.Type != TypeTurnstile {
		t.Fatalf("Get = %s/%s, want 缓存旧值 site-v1/turnstile", cached.Ext.GetClientId(), cached.Type)
	}

	// 直读通道立即取到新值；Catalog.Current 同步跟随（不重新构造）。
	keys := mapKeys{settings.KeyCaptchaProviderKey: "cf"}
	c := NewCatalog(keys, loader)
	got, err := c.Current(ctx)
	if err != nil || got == nil {
		t.Fatalf("Current = (%v, %v)", got, err)
	}
	if got.Ext.GetClientId() != "site-v2" || got.Type != TypeRecaptcha {
		t.Fatalf("Current = %s/%s, want 直读新值 site-v2/recaptcha（无缓存窗口）", got.Ext.GetClientId(), got.Type)
	}
	// 换键同理：普通读路径未预热的新键立即可用。
	keys[settings.KeyCaptchaProviderKey] = "hc"
	rows["hc"] = captchaRow("hc", TypeHcaptcha, 1, "h-site")
	if got, _ = c.Current(ctx); got == nil || got.Key != "hc" || got.Type != TypeHcaptcha {
		t.Fatalf("换键后 Current = %+v, want hc/hcaptcha", got)
	}
}

// fakeRepo Loader 的 repo 行源桩（RowSource 窄集）。
type fakeRepo struct{ rows map[string]*model.Provider }

func (f *fakeRepo) FindByKey(_ context.Context, key string) (*model.Provider, error) {
	row, ok := f.rows[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return row, nil
}

func (f *fakeRepo) ListProviders(context.Context, repo.ProviderListQuery) ([]model.Provider, int64, error) {
	return nil, 0, nil
}
