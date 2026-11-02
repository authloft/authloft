// Package main 装配 Authloft HTTP 服务（docs/后端架构.md §18 行 1665 调用链）。
package main

import (
	"github.com/gin-gonic/gin"

	"authloft/internal/middleware"
)

// newRouter 装配生产路由（docs/后端架构.md §18 行 1665：
// origin + contenttype → codec.Negotiate → handler → codec.Bind）：
//   - requestid 挂全局：链路 ID 先于一切，保证 403 / 415 错误体也携带 request_id；
//   - /api 组挂 origin + contenttype + negotiate（页面路由 /assets ** 不受影响）。
//
// 返回 /api 组供业务域 handler 挂载路由——当前尚无业务路由，生产 router 不注册任何
// 业务端点；测试在该组上注册临时路由验证链路。
//
// 用 gin.New() 而非 gin.Default()：脚手架的 Logger / Recovery 与 §3.3 行 309 规划的
// logger.go / recover.go 中间件重复，待其落地后在此挂载。
//
// TODO(config)：项目尚无 config 系统，rootOrigin（{al_root}，接口文档 §1.1 行 54）
// 与小程序 appid Referer 白名单由 main 以空值装配——空值下 origin 中间件对非免检
// 写请求保守 403（见 origin.go）。codec.SetMaxBodyBytes 不调用，回落默认 1 MiB
//（docs/后端架构.md §3.14 行 492 已约定）。
func newRouter(rootOrigin string, refererAllowlist []string) (*gin.Engine, *gin.RouterGroup) {
	r := gin.New()
	r.Use(middleware.RequestID())

	api := r.Group("/api")
	api.Use(
		middleware.Origin(rootOrigin, refererAllowlist),
		middleware.ContentType(),
		middleware.NegotiateFormat(),
	)
	return r, api
}
