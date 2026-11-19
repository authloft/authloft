// template_test.go 覆盖 TemplateService 的关键口径（§5.7 / §8.1）：
// 写路径缓存失效可证伪（Create→Resolve→Update→Resolve 返回新内容而非 TTL 内
// 旧值、Delete→Resolve miss）、内置同名 key 被拒、Resolve 四级回落（缓存 /
// 内置不回填 / DB 回填失败不阻断 / 全 miss）、改 key 双失效、唯一键冲突转译。
// store 与 Redis 均用内存 fake，本地可跑、不连 DB / Redis。
package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"database/sql"

	"authloft/internal/cache"
	"authloft/internal/pages"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// fakeTemplateStore templateStore 的内存实现：模拟 UK 冲突、未命中
// sql.ErrNoRows、Create 回填 id（模拟真库自增主键回填语义）。
type fakeTemplateStore struct {
	mu             sync.Mutex
	rows           map[int64]*model.Template
	nextID         int64
	findByKeyCalls int
}

func newFakeTemplateStore() *fakeTemplateStore {
	return &fakeTemplateStore{rows: map[int64]*model.Template{}, nextID: 1}
}

func (f *fakeTemplateStore) FindByKey(_ context.Context, key string) (*model.Template, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.findByKeyCalls++
	for _, row := range f.rows {
		if row.TemplateKey == key {
			cp := *row
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("fake: find template by key: %w", sql.ErrNoRows)
}

func (f *fakeTemplateStore) List(_ context.Context) ([]model.Template, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]model.Template, 0, len(f.rows))
	for i := int64(1); i < f.nextID; i++ {
		if row, ok := f.rows[i]; ok {
			out = append(out, *row)
		}
	}
	return out, nil
}

func (f *fakeTemplateStore) Create(_ context.Context, t *model.Template) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, row := range f.rows {
		if row.TemplateKey == t.TemplateKey {
			return fmt.Errorf("fake: create template: %w: 1062", repo.ErrTemplateDuplicate)
		}
	}
	t.ID = f.nextID
	f.nextID++
	cp := *t
	f.rows[t.ID] = &cp
	return nil
}

func (f *fakeTemplateStore) Update(_ context.Context, t *model.Template) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, row := range f.rows {
		if id != t.ID && row.TemplateKey == t.TemplateKey {
			return fmt.Errorf("fake: update template: %w: 1062", repo.ErrTemplateDuplicate)
		}
	}
	if _, ok := f.rows[t.ID]; !ok {
		return fmt.Errorf("fake: update template: %w", sql.ErrNoRows)
	}
	cp := *t
	f.rows[t.ID] = &cp
	return nil
}

func (f *fakeTemplateStore) Delete(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.rows[id]; !ok {
		return fmt.Errorf("fake: delete template: %w", sql.ErrNoRows)
	}
	delete(f.rows, id)
	return nil
}

// fakeTemplateRedis 实现 cache 包所用 Redis 窄接口（结构满足，不依赖其类型）。
type fakeTemplateRedis struct {
	mu     sync.Mutex
	vals   map[string]string
	ops    []string
	setErr error
}

func newFakeTemplateRedis() *fakeTemplateRedis {
	return &fakeTemplateRedis{vals: map[string]string{}}
}

func (f *fakeTemplateRedis) Get(ctx context.Context, key string) cache.StringResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, "GET "+key)
	if v, ok := f.vals[key]; ok {
		return cache.NewStringResult(v, nil)
	}
	return cache.NewStringResult("", cache.Nil)
}

func (f *fakeTemplateRedis) Set(ctx context.Context, key string, value interface{}, _ time.Duration) cache.StatusResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, "SET "+key)
	if f.setErr != nil {
		return cache.NewStatusResult(f.setErr)
	}
	f.vals[key] = fmt.Sprint(value)
	return cache.NewStatusResult(nil)
}

func (f *fakeTemplateRedis) Del(ctx context.Context, keys ...string) cache.IntResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, key := range keys {
		f.ops = append(f.ops, "DEL "+key)
		delete(f.vals, key)
	}
	return cache.NewIntResult(int64(len(keys)), nil)
}

func (f *fakeTemplateRedis) has(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.vals[key]
	return ok
}

func (f *fakeTemplateRedis) countOp(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.ops {
		if v == op {
			n++
		}
	}
	return n
}

// newTestTemplateService 组装一套 store + cache + service。
func newTestTemplateService() (*TemplateService, *fakeTemplateStore, *fakeTemplateRedis) {
	store := newFakeTemplateStore()
	r := newFakeTemplateRedis()
	return NewTemplateService(store, cache.NewTemplateCache(r)), store, r
}

// TestTemplateServiceCacheInvalidation 缓存失效可证伪：Update 后 Resolve 必须
// 返回新内容（若未 DEL，600s TTL 内仍读旧值 → 断言命中 v1 而失败）；Delete
// 后 Resolve 返回 miss。
func TestTemplateServiceCacheInvalidation(t *testing.T) {
	ctx := context.Background()
	svc, _, r := newTestTemplateService()
	key := "tpl-invalidate"
	rowKey := cache.TemplateRowKey(key)

	if err := svc.Create(ctx, key, "name", "content-v1"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := svc.Resolve(ctx, key)
	if err != nil || got != "content-v1" {
		t.Fatalf("首次 Resolve = %q,%v, want content-v1,nil", got, err)
	}
	if !r.has(rowKey) {
		t.Fatal("DB 命中后应回填缓存")
	}

	v2 := "content-v2"
	if err := svc.Update(ctx, 1, nil, nil, &v2); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err = svc.Resolve(ctx, key)
	if err != nil || got != "content-v2" {
		t.Fatalf("Update 后 Resolve = %q,%v, want content-v2,nil（旧值属缓存未失效）", got, err)
	}
	if n := r.countOp("DEL " + rowKey); n < 1 {
		t.Fatalf("Update 后应 DEL %q，实际次数 %d", rowKey, n)
	}

	if err := svc.Delete(ctx, 1); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := svc.Resolve(ctx, key); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Delete 后 Resolve err = %v, want ErrInvalidRequest", err)
	}
}

// TestTemplateServiceBuiltinKeyRejected 内置同名 key（扫描全集，不止单个）被
// 拒绝；空 key / 超列宽 key 亦被拒；Update 改到内置 key 同样被拒。
func TestTemplateServiceBuiltinKeyRejected(t *testing.T) {
	if err := pages.InitBuiltinTemplates(); err != nil {
		t.Fatalf("InitBuiltinTemplates: %v", err)
	}
	builtins := []string{"login", "account", "admin", "setup"}
	for _, k := range builtins {
		if !pages.IsBuiltinTemplate(k) {
			t.Fatalf("内置模板 %q 未注册，测试前置失败", k)
		}
	}

	ctx := context.Background()
	svc, _, _ := newTestTemplateService()
	for _, k := range builtins {
		if err := svc.Create(ctx, k, "n", "c"); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("Create 内置 key %q err = %v, want ErrInvalidRequest", k, err)
		}
	}
	if err := svc.Create(ctx, "", "n", "c"); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("空 key err = %v, want ErrInvalidRequest", err)
	}
	if err := svc.Create(ctx, strings.Repeat("a", 65), "n", "c"); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("超列宽 key err = %v, want ErrInvalidRequest", err)
	}

	if err := svc.Create(ctx, "custom-key", "n", "c"); err != nil {
		t.Fatalf("Create custom: %v", err)
	}
	builtinKey := "admin"
	if err := svc.Update(ctx, 1, &builtinKey, nil, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Update 改到内置 key err = %v, want ErrInvalidRequest", err)
	}
}

// TestTemplateServiceResolveCacheHit 第一级回落：缓存命中直接返回，不回源 DB。
func TestTemplateServiceResolveCacheHit(t *testing.T) {
	ctx := context.Background()
	svc, store, r := newTestTemplateService()
	key := "lvl-cache"
	if err := cache.NewTemplateCache(r).SetRow(ctx, key, "from-cache"); err != nil {
		t.Fatalf("SetRow: %v", err)
	}
	before := store.findByKeyCalls
	got, err := svc.Resolve(ctx, key)
	if err != nil || got != "from-cache" {
		t.Fatalf("Resolve = %q,%v, want from-cache,nil", got, err)
	}
	if store.findByKeyCalls != before {
		t.Fatalf("缓存命中不应回源 DB，findByKey 调用 %d → %d", before, store.findByKeyCalls)
	}
}

// TestTemplateServiceResolveBuiltinNoBackfill 第二级回落：内置模板命中返回，
// 且不回填缓存、不回源 DB。
func TestTemplateServiceResolveBuiltinNoBackfill(t *testing.T) {
	if err := pages.InitBuiltinTemplates(); err != nil {
		t.Fatalf("InitBuiltinTemplates: %v", err)
	}
	builtin, ok := pages.GetBuiltinTemplate("login")
	if !ok {
		t.Fatal("login 内置模板缺失，测试前置失败")
	}
	ctx := context.Background()
	svc, store, r := newTestTemplateService()
	before := store.findByKeyCalls
	got, err := svc.Resolve(ctx, "login")
	if err != nil || got != builtin {
		t.Fatalf("Resolve = %q,%v, want builtin content", got, err)
	}
	if store.findByKeyCalls != before {
		t.Fatal("内置命中不应回源 DB")
	}
	if r.has(cache.TemplateRowKey("login")) {
		t.Fatal("内置命中不应回填缓存")
	}
}

// TestTemplateServiceResolveDBBackfill 第三级回落：DB 命中回填缓存并返回；
// 回填失败（SET 报错）不阻断本次返回。
func TestTemplateServiceResolveDBBackfill(t *testing.T) {
	ctx := context.Background()
	svc, _, r := newTestTemplateService()
	key := "lvl-db"
	if err := svc.Create(ctx, key, "n", "from-db"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := svc.Resolve(ctx, key)
	if err != nil || got != "from-db" {
		t.Fatalf("Resolve = %q,%v, want from-db,nil", got, err)
	}
	if !r.has(cache.TemplateRowKey(key)) {
		t.Fatal("DB 命中应回填缓存")
	}

	// 清缓存并使回填报错，验证回填失败不阻断。
	r.Del(ctx, cache.TemplateRowKey(key))
	r.setErr = errors.New("set failed")
	got, err = svc.Resolve(ctx, key)
	if err != nil || got != "from-db" {
		t.Fatalf("回填失败时 Resolve = %q,%v, want from-db,nil", got, err)
	}
}

// TestTemplateServiceResolveMiss 第四级：三处均 miss → ErrInvalidRequest。
func TestTemplateServiceResolveMiss(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newTestTemplateService()
	if _, err := svc.Resolve(ctx, "no-such-template"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Resolve miss err = %v, want ErrInvalidRequest", err)
	}
	if _, err := svc.Resolve(ctx, ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("空 key Resolve err = %v, want ErrInvalidRequest", err)
	}
}

// TestTemplateServiceUpdateKeyDoubleInvalidate 改 key 时旧、新两 key 均失效。
func TestTemplateServiceUpdateKeyDoubleInvalidate(t *testing.T) {
	ctx := context.Background()
	svc, _, r := newTestTemplateService()
	if err := svc.Create(ctx, "old-key", "n", "c"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Resolve(ctx, "old-key"); err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	newKey := "new-key"
	if err := svc.Update(ctx, 1, &newKey, nil, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
	for _, k := range []string{cache.TemplateRowKey("old-key"), cache.TemplateRowKey("new-key")} {
		if n := r.countOp("DEL " + k); n < 1 {
			t.Errorf("改 key 应 DEL %q，实际次数 %d", k, n)
		}
	}
	if _, err := svc.Resolve(ctx, "old-key"); !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("旧 key Resolve err = %v, want ErrInvalidRequest", err)
	}
	if got, err := svc.Resolve(ctx, "new-key"); err != nil || got != "c" {
		t.Errorf("新 key Resolve = %q,%v, want c,nil", got, err)
	}
}

// TestTemplateServiceDuplicateKey 唯一键冲突转译 ErrDuplicateKey。
func TestTemplateServiceDuplicateKey(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newTestTemplateService()
	if err := svc.Create(ctx, "dup", "n", "c"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := svc.Create(ctx, "dup", "n", "c"); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("重复 key err = %v, want ErrDuplicateKey", err)
	}
}

// TestTemplateServiceList 分页与 q 按 name 模糊筛选（§5.7 / §1.7），只返回 DB 行。
func TestTemplateServiceList(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newTestTemplateService()
	for _, spec := range []struct{ key, name string }{
		{"k1", "alpha"}, {"k2", "beta"}, {"k3", "alphabet"},
	} {
		if err := svc.Create(ctx, spec.key, spec.name, "c"); err != nil {
			t.Fatalf("Create %s: %v", spec.key, err)
		}
	}
	rows, total, err := svc.List(ctx, 1, 2, "")
	if err != nil || total != 3 || len(rows) != 2 {
		t.Fatalf("List page1 = %d rows / %d total, err=%v", len(rows), total, err)
	}
	rows, total, err = svc.List(ctx, 2, 2, "")
	if err != nil || total != 3 || len(rows) != 1 {
		t.Fatalf("List page2 = %d rows / %d total, err=%v", len(rows), total, err)
	}
	rows, total, err = svc.List(ctx, 1, 10, "alpha")
	if err != nil || total != 2 || len(rows) != 2 {
		t.Fatalf("List q=alpha = %d rows / %d total, err=%v", len(rows), total, err)
	}
}

// TestNewTemplateServiceNilStorePanic nil store fail-fast。
func TestNewTemplateServiceNilStorePanic(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("nil store 应 panic")
		}
	}()
	NewTemplateService(nil, nil)
}
