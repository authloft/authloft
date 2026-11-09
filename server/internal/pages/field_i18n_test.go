// 后端字段文案的跨端契约（docs/接口文档.md §1.3 / §5.3）：登录流程
// sso.v1.Field.label、注入快照 SnapshotField.label 与 admin 侧
// SchemaField.label / help 都只准下发前端 i18n 键（login.field.* /
// admin.schemaField.*），语言文案一律放在 web/src/shared/i18n 下。
//
// 与 dto/schema_i18n_test.go 的分工：那边按运行时 TypeMetas() 逐字段校验
// admin schema 的实际输出；这里静态扫描 server/internal 全部非测试 Go 源码的
// Label / Help 字面量，覆盖 factor 四件套、pages 注入快照、orchestrator 快照
// 等「运行时不易穷举」的声明点，双管齐下防止某处又写回中文。
//
// 字典读取用相对路径：go test 的工作目录恒为包目录 server/internal/pages，
// ../../../ 即仓库根；CI server-test / gen-gate 均整仓 checkout。
package pages

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	loginFieldPrefix = "login.field."
	adminFieldPrefix = "admin.schemaField."
)

// fieldDictKeys 抽取前端两个分域字典里本契约相关的键集（只认行首带引号的
// 键定义，注释里的示例键名不会误命中）。
func fieldDictKeys(t *testing.T, locale string) map[string]bool {
	t.Helper()
	keys := make(map[string]bool)
	re := regexp.MustCompile(`(?m)^\s*'((?:login\.field|admin\.schemaField|admin\.schemaOption)\.[^']+)'\s*:`)
	for _, domain := range []string{"login", "admin"} {
		path := filepath.Join("..", "..", "..", "web", "src", "shared", "i18n", locale, domain+".ts")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读取前端 %s/%s 字典失败（字段文案唯一数据源，需整仓 checkout）: %v", locale, domain, err)
		}
		for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
			keys[m[1]] = true
		}
	}
	return keys
}

// TestFieldLabelsAreI18nKeys 所有字段文案字面量都是可译的 i18n 键，且
// zh / en 两套字典都已落地；任一端漏改（又写回中文、键名打错、漏译）都在这里
// 失败，而不是等用户在表单里看到一串键名或一段没翻译的中文。
func TestFieldLabelsAreI18nKeys(t *testing.T) {
	zh := fieldDictKeys(t, "zh")
	en := fieldDictKeys(t, "en")
	if len(zh) == 0 {
		t.Fatal("zh 字典未解析出任何字段键（正则或字典结构已变）")
	}
	// 两套字典键集镜像：前端 en 侧以 I18nMessages 编译期约束，这里从后端视角
	// 再复核一遍，避免只加中文漏英文。
	for key := range zh {
		if !en[key] {
			t.Errorf("字段键 %q 缺 en 译文", key)
		}
	}
	for key := range en {
		if !zh[key] {
			t.Errorf("字段键 %q 缺 zh 译文", key)
		}
	}

	// Label: "..." / Label = "..." / Help: "..."（含 m.Fields[i].Label = 这类
	// 运行时覆盖）。逐行扫描并跳过整行注释，避免注释里的示例被误判。
	literal := regexp.MustCompile(`\b(?:Label|Help)\s*[:=]\s*"([^"]+)"`)
	root := filepath.Join("..") // server/internal
	checked := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			m := literal.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			checked++
			key := m[1]
			if !strings.HasPrefix(key, loginFieldPrefix) && !strings.HasPrefix(key, adminFieldPrefix) {
				t.Errorf("%s: 字段文案 %q 不是 %s* / %s* i18n 键（后端不得下发展示文案）",
					path, key, loginFieldPrefix, adminFieldPrefix)
				continue
			}
			for _, r := range key {
				if r > 127 {
					t.Errorf("%s: 字段文案 %q 含非 ASCII 字符（疑似中文残留）", path, key)
					break
				}
			}
			if !zh[key] || !en[key] {
				t.Errorf("%s: 字段键 %q 前端字典缺译（zh=%v en=%v）", path, key, zh[key], en[key])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("扫描 %s 失败: %v", root, err)
	}
	if checked == 0 {
		t.Fatal("未扫描到任何 Label / Help 字面量（正则或源码结构已变）")
	}
}
