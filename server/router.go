// Package main 装配 Authloft HTTP 服务（docs/后端架构.md §18 行 1726 调用链）。
package main

import (
	"github.com/gin-gonic/gin"

	"authloft/internal/middleware"
)

// newRouter 装配生产 gin 引擎（docs/后端架构.md §3.3 行 296）：
//   - 全局链（挂载顺序即执行顺序）：recover 最外层最先挂（兜住全链 panic）
//     → requestid（先于一切错误出口，所有响应统一回写 X-Request-Id 响应头）
//     → logger（访问日志要取到 request_id）→ metrics（defer
//     累加，panic 经 unwind 也计数）→ origin（对写方法生效；Content-Type
//     校验由 Connect 框架与 OIDC 各自承担，不再设独立中间件）；
//   - /metrics 运维端点挂全局 engine、不进 /api 组——不受 origin 约束
//     （既定口径，§3.3 行 296）；
//   - Connect 域不经 gin.NoRoute 兜底（已删除该桥：gin serveError 预置
//     404 的缺陷结构性消除，§3.1 行 243 分流口径）——connect handler 由
//     装配层经顶层 http.ServeMux 按路径前缀挂载（bootstrap.go buildHandler，
//     Connect 域的 requestid / origin 等效链在 mux 前缀上，§3.1 行 243）；
//     未注册路径（含未注册的 connect 形态路径）由 gin 原生 404 兜底；
//   - /api 组保留给 REST 豁免端点（OIDC /api/oidc/**、gateway
//     /api/gateway/**、multipart 头像直传）注册——origin 已在全局链，
//     组上不再挂任何中间件。
//
// 返回 /api 组供豁免端点 handler 挂载——当前尚无这些 handler，测试在该
// 组上注册临时路由验证链路。
//
// 用 gin.New() 而非 gin.Default()：脚手架的 Logger / Recovery 与 §3.3 行 294 的
// logger.go / recover.go 职责重复，此处挂自建版本。
//
// rootOrigin（{al_root}，接口文档 §1.1 行 76）与小程序 appid Referer 白名单由
// bootstrap.go 从 *config.Config 构造注入（§3.2 约定 1，传具体值而非 *Config——
// router 不依赖 config 包，保持装配层单一职责）；空值下 origin 中间件对非免检
// 写请求保守 403（见 origin.go）。
func newRouter(rootOrigin string, refererAllowlist []string) (*gin.Engine, *gin.RouterGroup) {
	r := gin.New()
	r.Use(
		middleware.Recover(),
		middleware.RequestID(),
		middleware.Logger(),
		middleware.Metrics(),
		middleware.Origin(rootOrigin, refererAllowlist),
	)
	r.GET("/metrics", middleware.Handler())
	return r, r.Group("/api")
}
