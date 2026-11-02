package middleware

import (
	"github.com/gin-gonic/gin"

	"authloft/internal/codec"
)

// NegotiateFormat 按 Accept 头协商响应格式并写入 ctx
// （docs/后端架构.md §3.14 行 485、§18 行 1665：codec.Negotiate 在 handler 前执行）。
// 本函数只提供通用中间件；挂载到哪个路由组由装配层决定（§3.14：挂到 /api/** 组）。
func NegotiateFormat() gin.HandlerFunc {
	return func(c *gin.Context) {
		codec.SetFormat(c, codec.Negotiate(c.Request))
		c.Next()
	}
}
