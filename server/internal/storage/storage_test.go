// storage_test.go 覆盖 Resolver 解析口径（§13.0「未配置按失败处理」）
// 与 RenderKey 渲染（§15.1 示例逐字 + 非法模板 fail-fast）。local 实现的
// 磁盘行为见 local_test.go。全部走 fake ProviderGetter，不连 DB。
package storage

import (
	"context"
	"errors"
	"testing"

	"gorm.io/gorm"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/repo/model"
)

// fakeGetter ProviderGetter fake：按 key 返回预置行。
type fakeGetter struct {
	byKey map[string]*provider.Provider
}

func (g fakeGetter) Get(_ context.Context, key string) (*provider.Provider, error) {
	if p, ok := g.byKey[key]; ok {
		return p, nil
	}
	return nil, gorm.ErrRecordNotFound
}

func storageRow(key, category, typ string, enabled bool) *provider.Provider {
	row := &model.Provider{ProviderKey: key, Category: category, Type: typ, IsEnabled: 1}
	if !enabled {
		row.IsEnabled = 0
	}
	return &provider.Provider{Key: key, Type: typ, Row: row, Ext: &providerpb.Ext{}}
}

// TestResolveNotConfigured 空键 / 查无行 / 禁用 / category≠storage /
// local 关键字段缺失 / 未支持 type 全部按 ErrNotConfigured 收敛。
func TestResolveNotConfigured(t *testing.T) {
	localEmpty := storageRow("local-empty", "storage", "local", true)
	s3 := storageRow("s3", "storage", "s3", true)
	getter := fakeGetter{byKey: map[string]*provider.Provider{
		"local-empty": localEmpty,
		"s3":          s3,
		"disabled":    storageRow("disabled", "storage", "local", false),
		"oauthish":    storageRow("oauthish", "oauth", "local", true),
	}}
	r := NewResolver(getter)
	cases := []struct {
		key string
	}{
		{""},
		{"local-empty"},
		{"s3"},
		{"disabled"},
		{"oauthish"},
		{"missing"},
	}
	for _, tc := range cases {
		_, err := r.Resolve(context.Background(), tc.key)
		if err == nil {
			t.Fatalf("Resolve(%q) 应失败", tc.key)
		}
		if !errors.Is(err, ErrNotConfigured) {
			t.Errorf("Resolve(%q) err = %v, want ErrNotConfigured", tc.key, err)
		}
	}
	// s3 属未支持 type：ErrNotConfigured 与 ErrUnsupportedType 双命中。
	if _, err := r.Resolve(context.Background(), "s3"); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("s3 应同时命中 ErrUnsupportedType, got %v", err)
	}
}

// TestResolveLocal 成功路径：local 行 + bucket/domain 齐备 → *Local。
func TestResolveLocal(t *testing.T) {
	row := storageRow("files", "storage", "local", true)
	row.Ext = &providerpb.Ext{Bucket: "/data/files", Domain: "https://cdn.example.com", PathPrefix: "qr"}
	r := NewResolver(fakeGetter{byKey: map[string]*provider.Provider{"files": row}})
	st, err := r.Resolve(context.Background(), "files")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	lc, ok := st.(*Local)
	if !ok {
		t.Fatalf("Resolve 返回 %T, want *Local", st)
	}
	if got := lc.URL("k1.jpg"); got != "https://cdn.example.com/qr/k1.jpg" {
		t.Errorf("URL = %q", got)
	}
}

// TestRenderKeyDocumentedExample §15.1 行 1718 示例 + timestamp 变量。
func TestRenderKeyDocumentedExample(t *testing.T) {
	key, err := RenderKey(`'qrcodes_' & $.ticket_id & '.jpg'`, "c7Kx9", 1761800000)
	if err != nil {
		t.Fatalf("RenderKey: %v", err)
	}
	if key != "qrcodes_c7Kx9.jpg" {
		t.Fatalf("key = %q, want qrcodes_c7Kx9.jpg", key)
	}
	key, err = RenderKey(`'q/' & $.timestamp & '/' & $.ticket_id & '.jpg'`, "t1", 42)
	if err != nil {
		t.Fatalf("RenderKey timestamp: %v", err)
	}
	if key != "q/42/t1.jpg" {
		t.Fatalf("key = %q, want q/42/t1.jpg", key)
	}
}

// TestRenderKeyFailFast 空模板 / 未知变量 / 渲染穿越段 / 空 key 全部报错
// （管理配置类错误不得静默求空串）。
func TestRenderKeyFailFast(t *testing.T) {
	cases := []struct {
		name string
		tpl  string
		id   string
	}{
		{"空模板", "", "t"},
		// 未知变量取纯路径形态：undefined → ErrNotString（注意 JSONata 2.x
		// 的 & 拼接会把 undefined cast 成空串——`'a' & $.oops` 得 "a" 属
		// 库标准语义，见 internal/jsonata TestEvaluateNormal 行为记录）。
		{"未知变量（纯路径）", `$.oops`, "t"},
		{"渲染出空 key", `''`, "t"},
		{"渲染出绝对 key", `'/' & $.ticket_id`, "t"},
		{"渲染出穿越段", `'../' & $.ticket_id & '.jpg'`, "t"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := RenderKey(tc.tpl, tc.id, 1)
			if err == nil {
				t.Fatalf("RenderKey(%q) = %q, want error", tc.tpl, key)
			}
		})
	}
}
