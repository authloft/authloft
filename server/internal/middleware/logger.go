package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
)

// Logger 在请求结束后输出一条结构化访问日志（docs/后端架构.md §3.3 行 309）：
// request_id / method / path / status / latency 五个字段。只记录这五个字段，
// 不打印 body、query、头等任何请求内容——login_token / 密码 / Authorization
// 天然不可能出现在日志里（§3.3 行 309 敏感信息约束）。
//
// 最终状态码经 echo.ResolveResponseStatus 归一：已 Committed 取已写出状态；
// handler 返回错误（echo 的 404 / 405 是错误值而非响应写出，HTTPErrorHandler
// 在链解旋之后才写响应）按错误码归一；均无则回落 200（net/http 隐式语义）。
// 不包装 writer：echo.UnwrapResponse 取框架原生 *echo.Response，自带
// Status / Committed，不存在绕过的状态写入。
//
// panic 语义：本层不用 defer，handler panic 时访问日志不输出（unwind 只
// 触发 Metrics 的 defer 计数；panic 由最外层 Recover 兜底），与既有口径一致。
//
// 须挂载在 RequestID 之后（更内层），request_id 才非空。
// 日志库：标准库 log/slog（结构化、零第三方依赖）。
func Logger() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			start := time.Now()
			err := next(c)
			_, status := echo.ResolveResponseStatus(c.Response(), err)
			if status == 0 {
				status = http.StatusOK
			}
			logAccess(contextString(c, RequestIDKey), c.Request().Method, c.Request().URL.Path, status, time.Since(start))
			return err
		}
	}
}

// logAccess 输出一条访问日志——echo 版 Logger 与 http 版 HTTPLogger
// （httpmw.go）共用的唯一字段口径：request_id / method / path / status /
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
