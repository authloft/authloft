package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// Logger 在请求结束后输出一条结构化访问日志（docs/后端架构.md §3.3 行 309）：
// request_id / method / path / status / latency 五个字段。只记录这五个字段，
// 不打印 body、query、头等任何请求内容——login_token / 密码 / Authorization
// 天然不可能出现在日志里（§3.3 行 309 敏感信息约束）。
//
// 最终状态码取 c.Writer.Status()，不包装 writer：gin.ResponseWriter 自带
// 延迟状态机（c.Status 延迟设置、真正 Write 前经 WriteHeaderNow 落盘、
// handler 未设置时为 200），且 connect 域响应经 gin.NoRoute 兜底同样写入
// c.Writer，不存在绕过 gin 的状态写入；NoRoute 404 亦可见。包装 writer 则
// 需逐一转发 WriteHeader / WriteHeaderNow / Flush / Hijack 等，徒增半截
// 输出风险，不采用。
//
// 须挂载在 RequestID 之后（更内层），request_id 才非空。
// 日志库：标准库 log/slog（结构化、零第三方依赖）。
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		logAccess(c.GetString(RequestIDKey), c.Request.Method, c.Request.URL.Path, c.Writer.Status(), time.Since(start))
	}
}

// logAccess 输出一条访问日志——gin 版 Logger 与 http 版 HTTPLogger
//（httpmw.go）共用的唯一字段口径：request_id / method / path / status /
// latency 五字段经 slog 单条结构化输出，不打印 body、query、头等任何
// 请求内容（敏感信息约束见上）。禁止在任一侧另立字段口径。
func logAccess(requestID, method, path string, status int, latency time.Duration) {
	slog.Info("access",
		"request_id", requestID,
		"method", method,
		"path", path,
		"status", status,
		"latency", latency,
	)
}
