// Package main 装配 Authloft HTTP 服务（docs/后端架构.md §18 行 1726 调用链）。
package main

import (
	"github.com/gin-gonic/gin"

	"authloft/internal/connect"
	"authloft/internal/middleware"
)

// newRouter 装配生产路由（docs/后端架构.md §3.3 行 296）：
//   - 全局链（挂载顺序即执行顺序）：recover 最外层最先挂（兜住全链 panic）
//     → requestid（先于一切错误出口，所有响应统一回写 X-Request-Id 响应头）
//     → logger（访问日志要取到 request_id）→ metrics（defer
//     累加，panic 经 unwind 也计数）→ origin（对写方法生效，Connect 请求
//     在进入 connect handler 前被拦截；Content-Type 校验由 Connect 框架与
//     OIDC 各自承担，不再设独立中间件）；
//   - /metrics 运维端点挂全局 engine、不进 /api 组——不受 origin 约束
//     （既定口径，§3.3 行 296）；
//   - connect mux 经 gin.NoRoute 兜底接管（§3.3 行 296、§3.14 行 472）：
//     页面 / 静态 / OIDC / gateway 等 gin 路由先注册则优先匹配；未匹配的
//     connect 形态路径 /api.<域>.v1.<XxxService>/<Method> 进 connect mux
//     （暂无 service 可挂，未注册路径由装配层
//     返回 Connect 错误形态 404）；
//   - /api 组保留给 REST 豁免端点（OIDC /api/oidc/**、gateway
//     /api/gateway/**、multipart 头像直传）注册——origin 已在全局链，
//     组上不再挂任何中间件。
//
// 返回 /api 组供豁免端点 handler 挂载路由——当前尚无这些 handler，测试在该
// 组上注册临时路由验证链路。
//
// 用 gin.New() 而非 gin.Default()：脚手架的 Logger / Recovery 与 §3.3 行 294 的
// logger.go / recover.go 职责重复，此处挂自建版本。
//
// rootOrigin（{al_root}，接口文档 §1.1 行 76）与小程序 appid Referer 白名单由
// bootstrap.go 从 *config.Config 构造注入（§3.2 约定 1，传具体值而非 *Config——
// router 不依赖 config 包，保持装配层单一职责）；空值下 origin 中间件对非免检
// 写请求保守 403（见 origin.go）。
func newRouter(rootOrigin string, refererAllowlist []string, connectMux *connect.Server) (*gin.Engine, *gin.RouterGroup) {
	r := gin.New()
	r.Use(
		middleware.Recover(),
		middleware.RequestID(),
		middleware.Logger(),
		middleware.Metrics(),
		middleware.Origin(rootOrigin, refererAllowlist),
	)
	r.GET("/metrics", middleware.Handler())

	// connect 兜底接管未匹配的 connect 形态路径（全局链对 NoRoute 同样生效：
	// X-Request-Id 头已写入、origin 已校验、panic 由 recover 兜底）。
	r.NoRoute(func(c *gin.Context) {
		connectMux.ServeHTTP(c.Writer, c.Request)
		// gin 的 serveError（gin v1.12.0 gin.go）对「只写了状态码、未写 body」
		// 的响应会追加默认 "404 page not found" body——非 connect 路径的空体
		// 404 在此强制落盘（WriteHeaderNow 为 no-op 当 mux 已写出 body）。
		c.Writer.WriteHeaderNow()
	})

	return r, r.Group("/api")
}
