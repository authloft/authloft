// render.go 壳层统一渲染入口（阶段 C，接口文档 §8 行 1500 壳层模板契约：
// 模板唯一来源 = 前端构建产物 sync-templates.mjs 原样落位，本包以
// //go:embed 嵌入、缺失即编译失败〔防漏构建〕；渲染 = 读模板 + 三占位符
// 纯字符串全量替换，不解析 HTML、不假设固定结构、不自行注入属性）。
// 三端空壳（login / account / admin）、/auth/authorize 登录壳与 setup 壳
// （internal/setup 复用同一入口——本包零 DB / Redis 运行期依赖，setup
// 模式可安全引用）共用 RenderGinShell。
package pages

import (
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"authloft/internal/middleware"
	"authloft/internal/settings"
)

// templatesFS 四份壳层模板（templates/{login,account,admin,setup}.html，
// 前端构建产物；禁手改——pnpm build 经同步脚本覆盖写入）。
//
//go:embed templates
var templatesFS embed.FS

// 三占位符（§8 行 1504-1508 运行期占位符清单，全部由后端渲染期替换；
// 模板内其他 {{…}} 一律按字面输出，不报错）。
const (
	phStaticBase = "{{AUTHLOFT_STATIC_BASE}}"
	phCSPNonce   = "{{AUTHLOFT_CSP_NONCE}}"
	phInitJSON   = "{{AUTHLOFT_INIT_JSON}}"
)

// RenderGinShell 渲染 {entry} 壳层响应（三端壳 / authorize login 壳 /
// setup 壳共用的统一渲染出口，硬约束 4）。流程：nonce 优先消费 CSP 中间件
// 写入 ctx 的 CSPNonceKey（§3.3 行 314——bootstrap 页面路由组与 setup 引擎
// 均已挂 middleware.CSP，响应头由中间件输出）；不经中间件的调用路径
// （测试 / 未来挂载点 / 中间件 nonce 生成失败降级）自生成 nonce 并自设
// 同终稿基线响应头（含 CDN 追加，cspDirectives）。模板读 / INIT marshal
// 失败 → 空体 500（§1.5 行 225 豁免端点按 HTTP 语义）；no-store（§8 行
// 1498）。
func RenderGinShell(c *gin.Context, entry string, init any, staticBase string) {
	nonce := ""
	if v, ok := c.Get(middleware.CSPNonceKey); ok {
		nonce, _ = v.(string)
	}
	if nonce == "" {
		var err error
		if nonce, err = genNonce(); err != nil {
			slog.Error("pages: gen nonce", "err", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.Header("Content-Security-Policy", cspDirectives(nonce, staticBase))
	}
	body, err := renderTemplate(entry, init, staticBase, nonce)
	if err != nil {
		slog.Error("pages: render shell", "entry", entry, "err", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/html; charset=utf-8", body)
}

// renderTemplate 读嵌入模板 templates/{entry}.html 并做三占位符纯字符串
// 全量替换（硬约束 2：出现几次替换几次——nonce 一模板十几处，漏一处页面
// 即挂；替换基于字面量，不分析标签、不依赖占位符位置或存在性）。INIT
// JSON 由 json.Marshal 编码：默认 <>& HTML 转义 + \u2028/\u2029 转义
// （§8 行 1498）；static_base 尾斜杠归一后再替换（防 CDN 绝对地址 +
// /chunk.js 出现 //）。替换顺序 nonce → static_base → init，三占位符
// 互不为前缀，顺序不影响结果。
func renderTemplate(entry string, init any, staticBase, nonce string) ([]byte, error) {
	tpl, err := templatesFS.ReadFile("templates/" + entry + ".html")
	if err != nil {
		return nil, fmt.Errorf("read template %s: %w", entry, err)
	}
	initJSON, err := json.Marshal(init)
	if err != nil {
		return nil, fmt.Errorf("marshal init: %w", err)
	}
	html := string(tpl)
	html = strings.ReplaceAll(html, phCSPNonce, nonce)
	html = strings.ReplaceAll(html, phStaticBase, strings.TrimRight(staticBase, "/"))
	html = strings.ReplaceAll(html, phInitJSON, string(initJSON))
	return []byte(html), nil
}

// cspDirectives CSP 终稿指令串（接口文档 §8 行 1521-1532 逐项表，
// 正常模式与 setup 模式统一基线）——RenderGinShell 未经中间件时的自设头
// 与单测共用：default-src 'self'；script-src 'nonce-…' 'strict-dynamic'；
// style-src 'nonce-…' 'self'；font-src 'self'；img-src 'self' data:
// https:；connect-src 'self'。static_base 为 CDN 绝对地址（http(s):// 开头）
// 时 script / style / font 三条资源类指令追加该 CDN 源——script-src 的
// CDN 源仅为不支持 strict-dynamic 的旧浏览器回退（CSP3 下 host 源被忽略，
// §8 行 1526 注）；img-src 的 https: 已覆盖 CDN、connect-src 恒同源
// （API 与页面恒同源、不经 CDN），两者不追加。
func cspDirectives(nonce, staticBase string) string {
	directives := []string{
		"default-src 'self'",
		"script-src 'nonce-" + nonce + "' 'strict-dynamic'",
		"style-src 'nonce-" + nonce + "' 'self'",
		"font-src 'self'",
		"img-src 'self' data: https:",
		"connect-src 'self'",
	}
	if origin := cdnOrigin(staticBase); origin != "" {
		directives[1] += " " + origin
		directives[2] += " " + origin
		directives[3] += " " + origin
	}
	return strings.Join(directives, "; ")
}

// cdnOrigin static_base 为 CDN 绝对地址（以 http(s):// 开头，§8 行 1506）
// 时返回其源 scheme://host[:port]，否则空串（同域 /assets 或相对路径
// 无需追加，'self' 已覆盖）。
func cdnOrigin(staticBase string) string {
	u, err := url.Parse(staticBase)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// staticBaseCSP 生产装配的 CSP 追加 supporter（§3.13 行 488 / §12.1：
// 每请求现算——static_base 可热更，不在构造期固化）。
type staticBaseCSP struct{ settings SettingsReader }

// StaticBaseCSPSupporter 构造把 CDN static_base 追加进 CSP 资源类指令的
// middleware.CSPSupporter（bootstrap 页面路由组装配注入 settings 快照；
// CSP 规范同名指令多次出现取并集，追加片段与中间件基线直接拼接即语义
// 合并，见 csp.go CSPSupporter 注）。非 CDN（同域 /assets 或相对路径）时
// 返回空片段，不产生空指令。
func StaticBaseCSPSupporter(s SettingsReader) middleware.CSPSupporter {
	return staticBaseCSP{settings: s}
}

// CSP 每请求读 settings 键 static_base（§5.6，可热更），为 CDN 绝对地址时
// 追加三条资源类指令（script / style / font 各追加 CDN 源；语义注记见
// cspDirectives）。
func (s staticBaseCSP) CSP() string {
	if s.settings == nil {
		return ""
	}
	v, ok := s.settings.GetString(settings.KeyStaticBase)
	if !ok || v == "" {
		return ""
	}
	origin := cdnOrigin(v)
	if origin == "" {
		return ""
	}
	return "script-src " + origin + "; style-src " + origin + "; font-src " + origin
}
