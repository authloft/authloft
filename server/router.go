// Package main 装配 Authloft HTTP 服务（docs/后端架构.md §18 调用链）。
package main

import (
	"net/http"

	"github.com/labstack/echo/v5"

	"authloft/internal/middleware"
	"authloft/internal/service/orchestrator"
)

// newRouter 装配生产 echo 引擎（docs/后端架构.md §3.3 行 296）：
//   - 全局链（挂载顺序即执行顺序）：recover 最外层最先挂（兜住全链 panic）
//     → requestid（先于一切错误出口，所有响应统一回写 X-Request-Id 响应头）
//     → logger（访问日志要取到 request_id）→ metrics（defer
//     累加，panic 经 unwind 也计数）→ origin（对写方法生效；Content-Type
//     校验由 Connect 框架与 OIDC 各自承担，不再设独立中间件）；
//   - /metrics 运维端点挂全局 engine、不进 /api 组——不受 origin 约束
//     （既定口径，§3.3 行 296）；
//   - Connect 域不经 echo 兜底路由（已删除该桥：历史引擎 serveError 预置
//     404 的缺陷结构性消除，§3.1 行 243 分流口径）——connect handler 由
//     装配层经顶层 http.ServeMux 按路径前缀挂载（bootstrap.go buildHandler，
//     Connect 域的 requestid / origin 等效链在 mux 前缀上，§3.1 行 243）；
//     未注册路径（含未注册的 connect 形态路径）由 echo 错误体 404 兜底
//     （DefaultHTTPErrorHandler，JSON {"message":"Not Found"}；HEAD 空体）；
//   - /api 组保留给 REST 豁免端点（OIDC /api/oidc/**、gateway
//     /api/gateway/**、multipart 头像直传）注册——origin 已在全局链，
//     组上不再挂任何中间件。
//
// 返回 /api 组供豁免端点 handler 挂载——测试在该组上注册临时路由验证链路。
//
// 用 echo.NewWithConfig 自定两处：NoGroupAutoRegister404Routes=true 保持
// 「组中间件不作用于未注册路径」的既有口径（未注册路径走全局链 404 兜底，
// 不经页面组 CSP 等组中间件）；IPExtractor 注入与 connect 前缀链同源的
// 来源 IP 取值闭包（orchestrator.ClientIPFromRequest，采信头名由装配层
// 注入 clientIPHeader 动态源、每请求读 settings 键 client_ip_header，
// 热更新不固化；未配置仅取直连，§13.0 / 审计 IP 消费位）。
//
// rootOrigin（{al_root}，接口文档 §1.1）由 bootstrap.go 从 *config.Config
// 注入（§3.2 约定 1，传具体值而非 *Config——router 不依赖 config 包，保持装配
// 层单一职责）；小程序 appid Referer 白名单为动态来源（middleware.AllowlistFunc，
// 见 §13.0）：装配层注入 provider 查询函数并随 provider 变更热更新，
// 不再是启动期静态快照——来源为 nil（测试口径）或查询失败（归一为 nil）时，
// origin 中间件对非免检无 Origin 写请求保守 403（见 origin.go）。
func newRouter(rootOrigin string, refererAllowlist middleware.AllowlistFunc, clientIPHeader func() string) (*echo.Echo, *echo.Group) {
	e := echo.NewWithConfig(echo.Config{NoGroupAutoRegister404Routes: true})
	e.IPExtractor = func(r *http.Request) string {
		header := ""
		if clientIPHeader != nil {
			header = clientIPHeader()
		}
		return orchestrator.ClientIPFromRequest(r, header)
	}
	// 尾斜杠 301 归一（原 RedirectTrailingSlash 默认语义保真）：Pre 链
	// 先于路由匹配，剥尾斜杠命中已注册路由才 301（见 trailingslash.go）。
	e.Pre(middleware.TrailingSlashRedirect(e))
	e.Use(
		middleware.Recover(),
		middleware.RequestID(),
		middleware.Logger(),
		middleware.Metrics(),
		middleware.OriginFunc(rootOrigin, refererAllowlist),
	)
	e.GET("/metrics", middleware.Handler())
	return e, e.Group("/api")
}
