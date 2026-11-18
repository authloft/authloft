package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/labstack/echo/v5"
)

// Recover 捕获 handler 链中的 panic 并兜底为原生最小 500 空体
// (docs/后端架构.md §3.3 行 294、§3.14)：
//   - 响应尚未写过（echo.UnwrapResponse(...).Committed 为 false）→
//     NoContent(500)：不再构造错误信封（codec 时代出口已随 Connect 改造
//     删除）；Connect 域 handler 内部的错误经 connect-go 框架出口返回
//     connect.Error，echo 链上的 panic 由本层兜底为纯状态码，线上不透出
//     panic 内容；
//   - X-Request-Id 响应头由 requestid 中间件在入口写入的头表保留
//     （所有失败响应亦携带）；
//   - 已写过部分响应 → 只记日志、不再二次写：半截响应无法修复，追加错误体
//     只会产出混合字节流（§3.14 行 486「禁止半截输出」）；
//   - panic 之后链上后续中间件/handler 一律不再执行：Echo 的中间件是函数
//     组合链（内层 handler 由外层闭包调用），panic 沿调用栈 unwind 时剩余
//     链段从未被调用（结构上不存在 gin 引擎侧 index+1 续跑的问题）；
//   - panic 值与堆栈写入结构化日志并携带 request_id，便于排障；日志不含
//     body / query / 头等请求内容（§3.3 行 294 敏感信息约束）。
//
// 日志走 slog 默认 logger：标准库、结构化、零第三方依赖，装配层可用
// slog.SetDefault 统一接管输出目的地。须最先 Use（最外层）以兜住全链 panic。
func Recover() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) (err error) {
			defer func() {
				r := recover()
				if r == nil {
					return
				}
				slog.Error("panic recovered",
					"request_id", contextString(c, RequestIDKey),
					"method", c.Request().Method,
					"path", c.Request().URL.Path,
					"panic", fmt.Sprint(r),
					"stack", string(debug.Stack()),
				)
				// 已写过部分响应 → 不再二次写（半截输出防护）；未写过 →
				// 500 原生最小空体。响应写出即返回（HTTPErrorHandler 见
				// 已 Committed 直接跳过，不会追加错误体）。
				if resp, rerr := echo.UnwrapResponse(c.Response()); rerr == nil && resp.Committed {
					return
				}
				_ = c.NoContent(http.StatusInternalServerError)
			}()
			return next(c)
		}
	}
}

// contextString 读 echo.Context store 中的字符串值（缺失 / 类型不符返回空串）。
func contextString(c *echo.Context, key string) string {
	v, _ := c.Get(key).(string)
	return v
}
