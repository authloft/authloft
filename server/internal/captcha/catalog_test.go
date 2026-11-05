// catalog_test.go 覆盖 Catalog.Current 的降级三态（键空串 / 禁用 / 查不到）
// 与正常取生效项（接口文档 §2.5 行 513-517、§5.6 行 1334）。
package captcha

import (
	"context"
	"errors"
	"testing"

	"authloft/internal/settings"
)

// mapKeys 假 settings 字符串快照。
type mapKeys map[string]string

func (m mapKeys) GetString(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}

// mapSource 假 provider 行源：rows 无该键 = 无此行；err 非空 = 基础设施错误。
type mapSource struct {
	rows map[string]*ProviderRecord
	err  error
}

func (m mapSource) Find(_ context.Context, providerKey string) (*ProviderRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.rows[providerKey], nil
}

// TestCatalogCurrentDegradation 降级三态 + category 不符：一律 nil,nil
//（Gate 降级 builtin_image 的输入语义）。
func TestCatalogCurrentDegradation(t *testing.T) {
	cases := []struct {
		name string
		keys KeyReader
		rows map[string]*ProviderRecord
	}{
		{"键空串 = 内置", mapKeys{settings.KeyCaptchaProviderKey: ""}, nil},
		{"键未设置", mapKeys{}, nil},
		{"查不到该 key 的行", mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}, nil},
		{"禁用 is_enabled=0", mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}, map[string]*ProviderRecord{
			"cf_turnstile": {ProviderKey: "cf_turnstile", Category: CategoryCaptcha, Type: TypeTurnstile},
		}},
		{"category 不是 captcha", mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}, map[string]*ProviderRecord{
			"cf_turnstile": {ProviderKey: "cf_turnstile", Category: "oauth", Type: TypeTurnstile, Enabled: true},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCatalog(tc.keys, mapSource{rows: tc.rows})
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

// TestCatalogCurrentEnabledRow 正常路径：返回生效行的 Provider 投影
//（Type 取 provider 表列，SiteKey 取 ext.client_id 投影，§9.1 行 1083）。
func TestCatalogCurrentEnabledRow(t *testing.T) {
	c := NewCatalog(
		mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"},
		mapSource{rows: map[string]*ProviderRecord{
			"cf_turnstile": {
				ProviderKey: "cf_turnstile", Category: CategoryCaptcha, Type: TypeTurnstile,
				Enabled: true, SiteKey: "0x4AAA", Secret: "s-1", VerifyURL: "https://v.example",
			},
		}},
	)
	got, err := c.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got == nil {
		t.Fatal("Current = nil, want provider row")
	}
	if got.ProviderKey != "cf_turnstile" || got.Type != TypeTurnstile || got.SiteKey != "0x4AAA" {
		t.Fatalf("Current = %+v", got)
	}
}

// TestCatalogCurrentInfraError 基础设施错误上抛（Gate 按健康检查失败降级，
// §9.1 行 1095），不得吞成 nil。
func TestCatalogCurrentInfraError(t *testing.T) {
	c := NewCatalog(
		mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"},
		mapSource{err: errors.New("db down")},
	)
	if _, err := c.Current(context.Background()); err == nil {
		t.Fatal("Current err = nil, want infra error")
	}
}

// TestCatalogCurrentNotCached 每次现算：settings 键热更后不重新构造即生效
//（§9.1 行 1094「每次生成时重新判定，不缓存」）。
func TestCatalogCurrentNotCached(t *testing.T) {
	keys := mapKeys{settings.KeyCaptchaProviderKey: "cf_turnstile"}
	rows := map[string]*ProviderRecord{
		"cf_turnstile": {ProviderKey: "cf_turnstile", Category: CategoryCaptcha, Type: TypeTurnstile, Enabled: true, SiteKey: "k"},
		"goog":         {ProviderKey: "goog", Category: CategoryCaptcha, Type: TypeRecaptcha, Enabled: true, SiteKey: "g"},
	}
	c := NewCatalog(keys, mapSource{rows: rows})

	got, err := c.Current(context.Background())
	if err != nil || got == nil || got.ProviderKey != "cf_turnstile" {
		t.Fatalf("首次 Current = (%+v, %v)", got, err)
	}
	// 热更：换键 → 立即取到新行；清空 → 立即无可用项。
	keys[settings.KeyCaptchaProviderKey] = "goog"
	if got, _ = c.Current(context.Background()); got == nil || got.ProviderKey != "goog" || got.Type != TypeRecaptcha {
		t.Fatalf("换键后 Current = %+v, want goog/recaptcha", got)
	}
	keys[settings.KeyCaptchaProviderKey] = ""
	if got, _ = c.Current(context.Background()); got != nil {
		t.Fatalf("清空后 Current = %+v, want nil", got)
	}
}
