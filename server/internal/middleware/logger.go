package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"

	"authloft/internal/codec"
)

// Logger 在请求结束后输出一条结构化访问日志（docs/后端架构.md §3.3 行 309）：
// request_id / method / path / status / latency 五个字段。只记录这五个字段，
// 不打印 body、query、头等任何请求内容——login_token / 密码 / Authorization
// 天然不可能出现在日志里（§3.3 行 309 敏感信息约束）。
//
// 最终状态码取 c.Writer.Status()，不包装 writer：gin.ResponseWriter 自带
// 延迟状态机（c.Status 延迟设置、真正 Write 前经 WriteHeaderNow 落盘、
// handler 未设置时为 200），且全站响应只经 codec.Write → c.Writer 唯一出口
// （§3.14 行 486），不存在绕过 gin 的状态写入；NoRoute 404 由 gin serveError
// 写入，同样可见。包装 writer 则需逐一转发 WriteHeader / WriteHeaderNow /
// Flush / Hijack 等，徒增半截输出风险，不采用。
//
// 须挂载在 RequestID 之后（更内层），request_id 才非空。
// 日志库：标准库 log/slog（结构化、零第三方依赖）。
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		slog.Info("access",
			"request_id", c.GetString(codec.RequestIDKey),
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"latency", time.Since(start),
		)
	}
}
