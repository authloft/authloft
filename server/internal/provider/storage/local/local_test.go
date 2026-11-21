// local_test.go local 实现磁盘行为：Put 写盘 + URL 拼接（含 path_prefix）、
// Get 回读、Delete 幂等、路径穿越防护、PresignPut 恒错误。目录用
// t.TempDir，不碰真实部署路径。经 factory / NewLocal 构造等价性由
// internal/storage 的 TestResolveLocal 覆盖（Resolver → 注册表 → 本包工厂）。
package local

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"authloft/internal/provider"

	providerpb "authloft/gen/go/provider"
)

// 接口满足编译期断言：*Local 实现 provider.Storage（§15.1 逐字接口）。
var _ provider.Storage = (*Local)(nil)

func newLocal(t *testing.T, dir, prefix, domain string) *Local {
	t.Helper()
	l, err := NewLocal(&providerpb.Ext{Bucket: dir, PathPrefix: prefix, Domain: domain})
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	return l
}

// TestLocalPutGetURL 写盘 + 公开 URL + 回读三件一致。
func TestLocalPutGetURL(t *testing.T) {
	dir := t.TempDir()
	l := newLocal(t, dir, "qr", "https://cdn.example.com")

	url, err := l.Put(context.Background(), "q1.jpg", []byte("jpeg-bytes"), "image/jpeg")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if url != "https://cdn.example.com/qr/q1.jpg" {
		t.Fatalf("url = %q", url)
	}
	body, err := l.Get(context.Background(), "q1.jpg")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(body) != "jpeg-bytes" {
		t.Fatalf("body = %q", body)
	}
	if _, err := os.Stat(filepath.Join(dir, "qr", "q1.jpg")); err != nil {
		t.Fatalf("磁盘文件缺失: %v", err)
	}
}

// TestLocalPutWithoutPrefix path_prefix 为空时 URL 不出现空段。
func TestLocalPutWithoutPrefix(t *testing.T) {
	l := newLocal(t, t.TempDir(), "", "https://s.example.com")
	url, err := l.Put(context.Background(), "a.jpg", []byte("x"), "image/jpeg")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if url != "https://s.example.com/a.jpg" || strings.Contains(url, "//a") {
		t.Fatalf("url = %q", url)
	}
}

// TestLocalDeleteIdempotent 删除成功后重复删除不报错（§13.3 幂等）。
func TestLocalDeleteIdempotent(t *testing.T) {
	l := newLocal(t, t.TempDir(), "", "https://s.example.com")
	if _, err := l.Put(context.Background(), "k.jpg", []byte("x"), "image/jpeg"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := l.Delete(context.Background(), "k.jpg"); err != nil {
			t.Fatalf("Delete #%d: %v", i, err)
		}
	}
}

// TestLocalKeyGuard 穿越防护：空 / 绝对 / .. 段 / 反斜杠 / 盘符。
func TestLocalKeyGuard(t *testing.T) {
	l := newLocal(t, t.TempDir(), "", "https://s.example.com")
	for _, key := range []string{"", "/abs.jpg", "../escape.jpg", "a/../../b.jpg", `a\b.jpg`, "C:ev.jpg"} {
		if _, err := l.Put(context.Background(), key, []byte("x"), "image/jpeg"); err == nil {
			t.Errorf("Put(%q) 应被拒绝", key)
		}
		if err := l.Delete(context.Background(), key); err == nil {
			t.Errorf("Delete(%q) 应被拒绝", key)
		}
	}
}

// TestLocalPresignNotSupported local 无预签名能力（§15.1）。
func TestLocalPresignNotSupported(t *testing.T) {
	l := newLocal(t, t.TempDir(), "", "https://s.example.com")
	_, _, err := l.PresignPut(context.Background(), "k", "image/jpeg", 10)
	if !errors.Is(err, ErrPresignNotSupported) {
		t.Fatalf("err = %v, want ErrPresignNotSupported", err)
	}
}

// TestNewLocalNotConfigured bucket / domain 为空即未配置。
func TestNewLocalNotConfigured(t *testing.T) {
	for _, ext := range []*providerpb.Ext{
		nil,
		{Bucket: "/data"},
		{Domain: "https://cdn.example.com"},
	} {
		if _, err := NewLocal(ext); !errors.Is(err, provider.ErrNotConfigured) {
			t.Errorf("NewLocal(%+v) err = %v, want ErrNotConfigured", ext, err)
		}
	}
}

// TestRegistryRegistration init 自注册形态：type 已挂 storage 槽、category
// 正确、不进登录快照（§15.3：storage 类型不得污染登录方式列表）。
func TestRegistryRegistration(t *testing.T) {
	meta, ok := provider.LookupTypeMeta(Type)
	if !ok {
		t.Fatal("local 未注册（本包 init 未生效）")
	}
	if meta.Category != provider.CategoryStorage {
		t.Errorf("category = %q, want %q", meta.Category, provider.CategoryStorage)
	}
	st, err := provider.NewStorage(&provider.Provider{Type: Type, Ext: &providerpb.Ext{Bucket: "/data/x", Domain: "https://cdn.example.com"}})
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	if _, ok := st.(*Local); !ok {
		t.Errorf("NewStorage 返回 %T, want *Local（factory 等价）", st)
	}
	for _, typ := range provider.AdapterTypes() {
		if typ == Type {
			t.Error("AdapterTypes 混入 storage 类型（登录快照被污染）")
		}
	}
}

// TestSchemaExtKinds Schema 声明形态（§5.3：键恒等于表列名或 Ext 字段名）：
// 表列基线落 column、Ext 字段落 ext；storage 恒可用（不消费 is_enabled），
// 该字段不在声明内——列表页 / 编辑表单对本类别不出现启停。
func TestSchemaExtKinds(t *testing.T) {
	fields := storageLocalSchema()
	extKeys := map[string]bool{"bucket": true, "domain": true, "path_prefix": true}
	columnKeys := map[string]bool{
		"provider_key": true, "display_name": true, "icon_url": true,
		"sort_order": true, "remark": true,
	}
	seen := map[string]int{}
	for _, f := range fields {
		seen[f.Key]++
		want := provider.StorageExt
		if columnKeys[f.Key] {
			want = provider.StorageColumn
		}
		if (extKeys[f.Key] || columnKeys[f.Key]) && f.Storage != want {
			t.Errorf("field %q storage = %q, want %q", f.Key, f.Storage, want)
		}
		if f.Label == "" || f.Type == "" || f.Section == "" {
			t.Errorf("field %q 声明残缺: %+v", f.Key, f)
		}
	}
	for k := range extKeys {
		if seen[k] != 1 {
			t.Errorf("ext 字段 %q 声明 %d 次, want 1", k, seen[k])
		}
	}
	for k := range columnKeys {
		if seen[k] != 1 {
			t.Errorf("表列 %q 声明 %d 次, want 1", k, seen[k])
		}
	}
	if len(seen) != len(fields) {
		t.Errorf("Schema 出现未声明键: %+v", fields)
	}
	if seen["is_enabled"] != 0 {
		t.Errorf("is_enabled 不应声明（storage 恒可用，不消费即不下发）")
	}
}
