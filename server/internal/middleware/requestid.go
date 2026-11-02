// Package middleware 提供 gin 中间件：链路 ID、内容协商等（docs/后端架构.md §3.3）。
package middleware

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/gin-gonic/gin"

	"authloft/internal/codec"
)

// RequestID 生成每请求的链路 ID 并写入 ctx，供 codec.WriteError / writeFallback
// 消费（docs/后端架构.md §3.3 行 309、§3.14 行 488；docs/接口文档.md §1.5 行 201）。
// 生成规则文档未规定，本实现口径：纯生成、不透传入站头（防客户端伪造/注入），
// crypto/rand 16 字节 hex（128-bit）；不回写 X-Request-Id 响应头（文档未规定）。
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		var b [16]byte
		if _, err := rand.Read(b[:]); err == nil {
			c.Set(codec.RequestIDKey, hex.EncodeToString(b[:]))
		}
		// rand.Read 失败（Go 1.24+ 实际不可达）时跳过写入：request_id 留空串，
		// 与 codec.requestID 的"不伪造值"口径一致。
		c.Next()
	}
}
