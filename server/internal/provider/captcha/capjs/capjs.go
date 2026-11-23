// Package capjs Capjs（capd 自托管）人机校验实现（docs/后端架构.md §9.1 /
// §15.5）：siteverify 请求 {secret, response}、响应 {success} 与 reCAPTCHA
// 同构，差异仅 Content-Type 为 JSON 与端点带 site key 路径段——校验复用
// captchacore 骨架的 JSON body 分支（NewJSON），本包只声明 type 字面量、
// Schema 差异字段与端点派生（§15.5 薄封装总则：复用兄弟包基座构造器，
// 不另下沉公共基座）。
//
// capd 模式才有 /siteverify（capjs-core 自建模式无该端点、不能套用统一
// 校验）；token 单次使用由 capd 保证，Authloft 侧零存储（§9.2）。
package capjs

import (
	"errors"
	"strings"

	"authloft/internal/provider"
	captchacore "authloft/internal/provider/captcha/captcha-core"
	"authloft/internal/provider/schemafield"
)

// Type 注册类型。字面量暂落实现子包（同 storage s3 / oss / cos 先例，
// servicetype.go 常量上移统一另行处理）。
const Type = "capjs"

// init 注册进统一注册表（§15.3）：Schema 是 /schema 的唯一数据源（表列 +
// Ext + 引用键，接口文档 §5.3 capjs 行），校验走 captchacore JSON 编码分支。
func init() {
	provider.RegisterVerifier(Type, provider.Meta{
		DisplayName: "Capjs",
		Category:    provider.CategoryCaptcha,
		Schema:      schema,
		// CSP 源声明随实现走（§9.4；源值 = 接口文档 §8 参考源清单 capjs 行，
		// 不在 csp.go 写死厂商域）：worker-src blob: 放行 PoW Web Worker。
		CSPSources: map[string][]string{
			"worker-src": {"blob:"},
		},
	}, newVerifier)
}

// schema /schema 唯一数据源：表列基线与三家一致（schemafield 单一来源），
// Ext 按 capjs 行序 client_id / client_secret / widget_api_base / endpoint /
// widget_script_url。widget_api_base 必填——前端拼 <base>/<site key>/ 加载
// widget 与 challenge/redeem，与服务端 siteverify 地址（endpoint）语义分离、
// 路径不同；widget_script_url 可选，空 = 官方 CDN。is_enabled / 登录建号
// 开关是 auth 专属，captcha 类别不下发也不消费（生效实例判定只看 settings
// 键 → 行命中，captcha/catalog.go）。
func schema() []provider.FieldMeta {
	fields := make([]provider.FieldMeta, 0, 12)
	fields = append(fields, schemafield.ProviderKey(), schemafield.DisplayName())
	common := schemafield.CaptchaFields()
	fields = append(fields, common[0], common[1])
	fields = append(fields,
		provider.FieldMeta{Key: "widget_api_base", Label: "admin.schemaField.widgetApiBaseLabel", Type: "text", Section: "endpoint", Required: true,
			Help: "admin.schemaField.widgetApiBaseHelp", Storage: provider.StorageExt},
		common[2],
		provider.FieldMeta{Key: "widget_script_url", Label: "admin.schemaField.widgetScriptUrlLabel", Type: "text", Section: "endpoint", Advanced: true,
			Help: "admin.schemaField.widgetScriptUrlHelp", Storage: provider.StorageExt},
	)
	fields = append(fields, schemafield.IconURL(), schemafield.SortOrder(), schemafield.Remark(), schemafield.ProxyRef())
	return fields
}

// newVerifier 注册表工厂：endpoint 取 ext.endpoint（captchacore 口径），空
// 时按 widget_api_base + site key 派生校验地址；两者皆空构造期即报错——
// widget_api_base 是 Schema 必填项，缺省属配置残缺，fail-fast（同 storage
// 构造期缺失报错口径），不留空 URL 校验器到运行期才失败。
func newVerifier(p *provider.Provider) (provider.Verifier, error) {
	if p == nil || p.Ext == nil {
		// nil ext 错误口径单一来源在 captchacore
		return captchacore.NewJSON(p, "")
	}
	if strings.TrimSpace(p.Ext.GetEndpoint()) != "" {
		return captchacore.NewJSON(p, "")
	}
	verifyURL := deriveVerifyURL(p.Ext.GetWidgetApiBase(), p.Ext.GetClientId())
	if verifyURL == "" {
		return nil, errors.New("captcha: capjs endpoint 与 widget_api_base/site key 均为空，无法派生校验地址")
	}
	return captchacore.NewJSON(p, verifyURL)
}

// deriveVerifyURL capd siteverify 端点派生：<base>/<site key>/siteverify，
// 端点带 site key 路径段（§9.1）；base 去尾部斜杠防双斜杠。任一为空返回
// 空串（调用方报错）。
func deriveVerifyURL(base, siteKey string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	siteKey = strings.TrimSpace(siteKey)
	if base == "" || siteKey == "" {
		return ""
	}
	return base + "/" + siteKey + "/siteverify"
}
