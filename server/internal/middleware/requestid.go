// Package middleware 提供 gin 中间件：链路 ID、Origin/CSRF、CSP、网关鉴权、
// panic 兜底、访问日志、指标（docs/后端架构.md §3.3）。
package middleware

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/gin-gonic/gin"
)

// RequestIDKey 是链路 ID 在 *gin.Context 中的键：requestid 写入，
// logger / recover（本包）与 setup 错误信封（internal/setup）读取。
const RequestIDKey = "request_id"

// XRequestIDHeader 链路 ID 响应头名（docs/接口文档.md §1.1 行 83）。
const XRequestIDHeader = "X-Request-Id"

// RequestID 生成每请求的链路 ID 并写入 ctx 与响应头（docs/后端架构.md
// §3.3 行 294、docs/接口文档.md §1.1 行 83）：
//   - 生成口径：crypto/rand 16 字节 hex（128-bit、32 字符）；不读、不透传、
//     不信任入站同名头（防客户端伪造/注入）；rand 失败留空串（不伪造值）；
//   - 所有响应（成功 / 失败 / 豁免端点）统一回写 X-Request-Id 响应头
//     （错误体内不重复携带）：c.Header 在中间件入口即写入
//     gin 头表，后续 origin 403 / 404 / recover 500 / connect 错误响应
//     均携带该头。
//
// 须先于一切错误出口挂载（§3.3 行 296 全局链序：recover → requestid → …）。
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		var b [16]byte
		if _, err := rand.Read(b[:]); err == nil {
			c.Set(RequestIDKey, hex.EncodeToString(b[:]))
		}
		// rand.Read 失败（Go 1.24+ 实际不可达）时 ctx 与响应头均为空串，
		// 不伪造值（§3.3 行 294）。
		c.Header(XRequestIDHeader, c.GetString(RequestIDKey))
		c.Next()
	}
}
