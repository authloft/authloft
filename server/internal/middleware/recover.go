package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

// Recover 捕获 handler 链中的 panic 并兜底为原生最小 500 空体
// (docs/后端架构.md §3.3 行 294、§3.14)：
//   - 响应尚未写过（c.Writer.Written() 为 false）→ AbortWithStatus(500)：
//     不再构造错误信封（codec 时代出口已随 Connect 改造删除）；Connect 域
//     handler 内部的错误经 connect-go 框架出口返回 connect.Error，gin 链上
//     的 panic 由本层兜底为纯状态码，线上不透出 panic 内容；
//   - X-Request-Id 响应头由 requestid 中间件在入口写入的头表保留
//     （所有失败响应亦携带）；
//   - 已写过部分响应 → 只记日志、不再二次写：半截响应无法修复，追加错误体
//     只会产出混合字节流（§3.14 行 486「禁止半截输出」）；
//   - 无论哪个分支，恢复后一律 Abort：panic 之后链上后续中间件/handler
//     一律不再执行（gin 的 Next 是共享 index 的循环，见 defer 内注释）；
//   - panic 值与堆栈写入结构化日志并携带 request_id，便于排障；日志不含
//     body / query / 头等请求内容（§3.3 行 294 敏感信息约束）。
//
// 日志走 slog 默认 logger：标准库、结构化、零第三方依赖，装配层可用
// slog.SetDefault 统一接管输出目的地。须最先 Use（最外层）以兜住全链 panic。
func Recover() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			err := recover()
			if err == nil {
				return
			}
			slog.Error("panic recovered",
				"request_id", c.GetString(RequestIDKey),
				"method", c.Request.Method,
				"path", c.Request.URL.Path,
				"panic", fmt.Sprint(err),
				"stack", string(debug.Stack()),
			)
			// gin 的 Next 是共享 index 的 for 循环（gin v1.12.0 context.go:188-196）：
			// panic 点非链尾时 unwind 回 engine 侧循环会从 index+1 继续执行
			// 后续中间件与 handler，500 已写后再跑 handler 会产出半截混合输出。
			// 与官方 recovery.go:109-111 同契约：恢复后 Abort 截断剩余链段。
			// 已写响应的分支同样 Abort：panic 后链一律终止，Abort 只改 index 无副作用。
			c.Abort()
			if c.Writer.Written() {
				return
			}
			c.AbortWithStatus(http.StatusInternalServerError)
		}()
		c.Next()
	}
}
