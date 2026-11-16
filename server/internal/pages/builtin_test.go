// 内置模板扫描全集单测（§3.13）：InitBuiltinTemplates 扫描 templatesFS
// 下全部 .html 注册，四 entry key 均为内置、非内置 key 不命中，
// GetBuiltinTemplate 与 templatesFS.ReadFile 全文逐字一致。
package pages

import (
	"strings"
	"testing"
)

// TestInitBuiltinTemplates 四 entry 均注册且内容与嵌入文件逐字一致。
func TestInitBuiltinTemplates(t *testing.T) {
	if err := InitBuiltinTemplates(); err != nil {
		t.Fatalf("InitBuiltinTemplates: %v", err)
	}
	for _, key := range []string{"login", "account", "admin", "setup"} {
		if !IsBuiltinTemplate(key) {
			t.Errorf("IsBuiltinTemplate(%q) = false, want true", key)
		}
		got, ok := GetBuiltinTemplate(key)
		if !ok {
			t.Errorf("GetBuiltinTemplate(%q) ok = false, want true", key)
			continue
		}
		want, err := templatesFS.ReadFile("templates/" + key + ".html")
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", key, err)
		}
		if got != string(want) {
			t.Errorf("GetBuiltinTemplate(%q) 与嵌入文件不一致", key)
		}
	}
	if IsBuiltinTemplate("nonexistent") {
		t.Error("IsBuiltinTemplate(nonexistent) = true, want false")
	}
	if _, ok := GetBuiltinTemplate("nonexistent"); ok {
		t.Error("GetBuiltinTemplate(nonexistent) ok = true, want false")
	}
}

// TestInitBuiltinTemplatesScansAll 验证不按「仅 login」裁剪：扫描所得每个
// .html 文件都被注册，map 数量与文件数一致。
func TestInitBuiltinTemplatesScansAll(t *testing.T) {
	if err := InitBuiltinTemplates(); err != nil {
		t.Fatalf("InitBuiltinTemplates: %v", err)
	}
	entries, err := templatesFS.ReadDir("templates")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	want := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		want++
		key := strings.TrimSuffix(e.Name(), ".html")
		if !IsBuiltinTemplate(key) {
			t.Errorf("扫描到的 %q 未注册", key)
		}
	}
	if len(builtinTemplates) != want {
		t.Errorf("builtinTemplates 数量 = %d, want %d", len(builtinTemplates), want)
	}
}
