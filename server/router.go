// Package main 装配 Authloft HTTP 服务（docs/后端架构.md §18 行 1665 调用链）。
package main

import (
	"github.com/gin-gonic/gin"

	"authloft/internal/middleware"
)

// newRouter 装配生产路由（docs/后端架构.md §18 行 1665：
// origin + contenttype → codec.Negotiate → handler → codec.Bind）：
//   - 全局链（挂载顺序即执行顺序）：recover 最外层最先挂（兜住全链 panic，
//     §3.3 行 309）→ requestid（链路 ID 先于一切错误出口，保证 403 / 415 /
//     500 错误体也携带 request_id）→ logger（访问日志在 requestid 之后，
//     取到 request_id）→ metrics（最内层，defer 累加保证 panic 请求也计数）；
//   - /metrics 运维端点挂全局 engine、不进 /api 组——不受 origin /
//     contenttype / negotiate 约束，不走 codec（§3.3 行 309）；
//   - /api 组挂 origin + contenttype + negotiate（页面路由 /assets ** 不受影响）。
//
// 返回 /api 组供业务域 handler 挂载路由——当前尚无业务路由，生产 router 不注册任何
// 业务端点；测试在该组上注册临时路由验证链路。
//
// 用 gin.New() 而非 gin.Default()：脚手架的 Logger / Recovery 与 §3.3 行 309 的
// logger.go / recover.go 职责重复，此处挂自建版本。
//
// TODO(config)：项目尚无 config 系统，rootOrigin（{al_root}，接口文档 §1.1 行 54）
// 与小程序 appid Referer 白名单由 main 以空值装配——空值下 origin 中间件对非免检
// 写请求保守 403（见 origin.go）。codec.SetMaxBodyBytes 不调用，回落默认 1 MiB
//（docs/后端架构.md §3.14 行 492 已约定）。
func newRouter(rootOrigin string, refererAllowlist []string) (*gin.Engine, *gin.RouterGroup) {
	r := gin.New()
	r.Use(
		middleware.Recover(),
		middleware.RequestID(),
		middleware.Logger(),
		middleware.Metrics(),
	)
	r.GET("/metrics", middleware.Handler())

	api := r.Group("/api")
	api.Use(
		middleware.Origin(rootOrigin, refererAllowlist),
		middleware.ContentType(),
		middleware.NegotiateFormat(),
	)
	return r, api
}
