// template_render.go 客户端自定义模板的解析与渲染（接口文档 §8.1 模板渲染
// 链路）：按 client_id 查客户端行取 template_key / template_vars，经窄接口
// Resolve 取模板内容，再交 renderHTML 做五占位符替换。本包仍为零 DB / Redis
// 运行期依赖的纯渲染包——行读取与模板解析全部经 Deps 注入的窄接口完成，
// 未装配（setup / 测试）一律回落默认文件壳。
package pages

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"authloft/internal/repo/model"
)

// TemplateResolver 模板内容解析窄接口（§8.1）：admin 侧 TemplateService
// 天然满足；Resolve 未命中返回 error，调用方据此回落默认文件壳。
type TemplateResolver interface {
	Resolve(ctx context.Context, key string) (string, error)
}

// SsoClientReader sso_client 行读取窄接口（§8.1 第 2 步）：*repo.ClientRepo
// 天然满足。OIDC 入口沿用 Deps.Clients（OidcClientReader），两族分列。
type SsoClientReader interface {
	FindSsoClientByClientID(ctx context.Context, clientID string) (*model.SsoClient, error)
}

// clientTemplate 解析成功的客户端模板内容：html 为 Resolve 返回的可信 HTML，
// varsJSON 为已按 INIT_JSON 同口径转义的模板变量 JSON 文本（§8.1）。
type clientTemplate struct {
	html     string
	varsJSON string
}

// resolveClientTemplate 按 §8.1 链路解析客户端模板：取 client_id → 按族查
// 行 → 取 template_key / template_vars → Resolve 内容。无 client_id、Templ
// -ates 未装配、查无行、template_key 空、Resolve 未命中任一命中即回落
// （ok=false），不抛 500、不改变 setup / account / admin 壳。oidc 为 true
// 取 oidc_client（授权入口，client_id 已由 OIDC 校验层确认），false 取
// sso_client（登录端入口）。err 恒为 nil——所有解析失败均按回落处理。
func resolveClientTemplate(ctx context.Context, deps Deps, clientID string, oidc bool) (html, varsJSON string, ok bool, err error) {
	if clientID == "" || deps.Templates == nil {
		return "", "", false, nil
	}

	var templateKey, templateVars string
	if oidc {
		if deps.Clients == nil {
			return "", "", false, nil
		}
		row, e := deps.Clients.FindOidcClientByClientID(ctx, clientID)
		if e != nil || row == nil {
			return "", "", false, nil
		}
		templateKey, templateVars = row.TemplateKey, row.TemplateVars
	} else {
		if deps.SsoClients == nil {
			return "", "", false, nil
		}
		row, e := deps.SsoClients.FindSsoClientByClientID(ctx, clientID)
		if e != nil || row == nil {
			return "", "", false, nil
		}
		templateKey, templateVars = row.TemplateKey, row.TemplateVars
	}

	if templateKey == "" {
		return "", "", false, nil
	}
	content, e := deps.Templates.Resolve(ctx, templateKey)
	if e != nil || content == "" {
		return "", "", false, nil
	}
	return content, templateVarsInject(templateVars), true, nil
}

// resolveClientTpl Handler 侧薄封装：解析成功返回模板内容，失败（含 setup
// 模式 Templates 为 nil）返回 nil——renderShell 据此走文件壳回落。oidc 区分
// 客户端族。
func (h *Handler) resolveClientTpl(ctx context.Context, clientID string, oidc bool) *clientTemplate {
	html, varsJSON, ok, err := resolveClientTemplate(ctx, h.deps, clientID, oidc)
	if err != nil || !ok {
		return nil
	}
	return &clientTemplate{html: html, varsJSON: varsJSON}
}

// templateVarsInject 构造 {{AUTHLOFT_TEMPLATE_VARS}} 注入值（§8.1）：template
// _vars 未配置 / 空白 → "{}"；否则逐字符转义 < > & 与 U+2028 / U+2029，
// 与 INIT_JSON（json.Marshal 默认 HTML 转义）同口径，防 </script> 提前闭合
// 与 JS 字符串换行注入。仅改字符编码表示，不重组键、不转换类型；其余字节
// 原样保留。
func templateVarsInject(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "{}"
	}
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch r {
		case '<':
			b.WriteString(`\u003c`)
		case '>':
			b.WriteString(`\u003e`)
		case '&':
			b.WriteString(`\u0026`)
		case '\u2028':
			b.WriteString(`\u2028`)
		case '\u2029':
			b.WriteString(`\u2029`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// RenderClientShell 以已解析的自定义模板内容渲染 SPA 壳（§8.1 第 5 步）：
// renderHTML 一次完成五占位符替换后交 writeShell 输出，响应头 / no-store /
// 500 语义与 RenderGinShell 完全一致。html 与 varsJSON 须来自
// resolveClientTemplate 的成功结果；siteName 由 Handler.siteName() 取
// settings.site_name（setup 直调传默认 Authloft）。
func RenderClientShell(c *gin.Context, html string, init any, staticBase, varsJSON, siteName string) {
	nonce, ok := shellNonce(c, staticBase)
	if !ok {
		return
	}
	body, err := renderHTML(html, init, staticBase, nonce, varsJSON, siteName)
	if err != nil {
		slog.Error("pages: render client shell", "err", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	writeShell(c, body)
}
