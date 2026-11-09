// GetProviderSchema 文案的跨端契约（docs/接口文档.md §5.3）：后端 label /
// help 只准下发前端 i18n 键（admin.schemaField.*），语言文案一律放在
// web/src/shared/i18n/{zh,en}/admin.ts。本测试把「键形态」与「两套字典都已
// 落地」一并钉死：任一端漏改（后端又写回中文、前端漏译或键名打错）都会在这里
// 失败，而不是等管理员在表单里看到一串键名。
//
// 字典读取用相对路径：go test 的工作目录恒为包目录 server/internal/dto，
// ../../../ 即仓库根；CI server-test / gen-gate 均整仓 checkout。
package dto

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"authloft/internal/provider"
	// 全量注册表自注册：TypeMetas() 要覆盖 oauth / 消息 / 虚拟三源所有
	// 渠道的 FieldMeta 覆盖（alipay / microsoft / oauth2 / oidc 的语义化标签
	// 与 help 都在 init() 里改写，漏 import 即漏校验）。
	_ "authloft/internal/provider/email/smtp"
	_ "authloft/internal/provider/oauth/alipay"
	_ "authloft/internal/provider/oauth/baidu"
	_ "authloft/internal/provider/oauth/feishu"
	_ "authloft/internal/provider/oauth/gitee"
	_ "authloft/internal/provider/oauth/github"
	_ "authloft/internal/provider/oauth/google"
	_ "authloft/internal/provider/oauth/microsoft"
	_ "authloft/internal/provider/oauth/oauth2"
	_ "authloft/internal/provider/oauth/oidc"
	_ "authloft/internal/provider/oauth/qq"
	_ "authloft/internal/provider/oauth/wechat"
	_ "authloft/internal/provider/oauth/wechat_mp"
	_ "authloft/internal/provider/oauth/wechat_mp_scan"
	_ "authloft/internal/provider/oauth/weibo"
	_ "authloft/internal/provider/sms/aliyun_sms"
)

const schemaI18nPrefix = "admin.schemaField."

// schemaDictKeys 从前端分域字典里抽出本契约相关的键集（只认行首带引号的
// 键定义，注释里的示例键名不会误命中）。
func schemaDictKeys(t *testing.T, locale string) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "..", "web", "src", "shared", "i18n", locale, "admin.ts")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取前端 %s 字典失败（schema 文案唯一数据源，需整仓 checkout）: %v", locale, err)
	}
	re := regexp.MustCompile(`(?m)^\s*'(admin\.schema(?:Field|Option)\.[^']+)'\s*:`)
	keys := make(map[string]bool)
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		keys[m[1]] = true
	}
	return keys
}

// TestSchemaTextI18nKeys 全部已注册类型的 schema 文案都是可译的 i18n 键；
// ui_group 这类 select 的 options 仍是 wire 取值，但要能查到显示名译文。
func TestSchemaTextI18nKeys(t *testing.T) {
	zh := schemaDictKeys(t, "zh")
	en := schemaDictKeys(t, "en")
	if len(zh) == 0 {
		t.Fatal("zh 字典未解析出任何 schema 键（正则或字典结构已变）")
	}
	// 两套字典键集镜像：前端 en/admin.ts 以 I18nMessages 编译期约束，这里再
	// 从后端视角复核一遍，避免只加中文漏英文。
	for key := range zh {
		if !en[key] {
			t.Errorf("schema 键 %q 缺 en 译文", key)
		}
	}
	for key := range en {
		if !zh[key] {
			t.Errorf("schema 键 %q 缺 zh 译文", key)
		}
	}

	checkKey := func(typeName, fieldKey, kind, key string) {
		t.Helper()
		if !strings.HasPrefix(key, schemaI18nPrefix) {
			t.Errorf("%s/%s %s = %q，不是 %s* i18n 键（后端不得下发展示文案）",
				typeName, fieldKey, kind, key, schemaI18nPrefix)
			return
		}
		for _, r := range key {
			if r > 127 {
				t.Errorf("%s/%s %s = %q，含非 ASCII 字符（疑似中文文案残留）",
					typeName, fieldKey, kind, key)
				return
			}
		}
		if !zh[key] || !en[key] {
			t.Errorf("%s/%s %s = %q，前端字典缺键（zh=%v en=%v）",
				typeName, fieldKey, kind, key, zh[key], en[key])
		}
	}

	metas := provider.TypeMetas()
	if len(metas) == 0 {
		t.Fatal("注册表为空（_ import 缺失）")
	}
	for _, meta := range metas {
		resp := AdminSchema(meta.Type, meta.Category, meta.Fields, nil)
		for _, f := range resp.GetFields() {
			checkKey(meta.Type, f.GetKey(), "label", f.GetLabel())
			if f.GetHelp() != "" {
				checkKey(meta.Type, f.GetKey(), "help", f.GetHelp())
			}
			if f.GetKey() == "ui_group" {
				for _, option := range f.GetOptions() {
					key := "admin.schemaOption.ui_group." + option
					if !zh[key] || !en[key] {
						t.Errorf("ui_group option %q 缺显示名译文 %s（zh=%v en=%v）",
							option, key, zh[key], en[key])
					}
				}
			}
		}
	}
}
