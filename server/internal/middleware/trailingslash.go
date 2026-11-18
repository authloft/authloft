package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
)

// TrailingSlashRedirect 尾斜杠归一（原 RedirectTrailingSlash 默认开启的
// 语义保真，docs/后端架构.md §3.1 装配层全局链）：请求路径带尾斜杠且
// **剥掉一个尾斜杠后**恰好命中本方法已注册路由时，301 重定向到无尾斜杠
// 形态（保留 query）；未注册路径不受影响（保持 404 兜底）。
//
// Echo v5 路由为精确匹配、无内置尾斜杠重定向（v4 的 RedirectTrailingSlash
// 已随 v5 移除），故以 Pre 中间件在路由匹配前探测注册表补齐该语义：
//   - 探测经 echo.NewContext 克隆请求 + Router.Route 完成，仅在带尾斜杠的
//     请求上发生（常态路径零成本）；
//   - 404 / 405 兜底 RouteInfo（echo.NotFoundRouteName /
//     echo.MethodNotAllowedRouteName）不触发重定向——原 tsr 判定同样
//     只在本方法树内命中才 301；
//   - 多重尾斜杠（/account//）剥一个后仍不命中 → 404，与 gin 一致。
//
// 用法：e.Pre(TrailingSlashRedirect(e))（须在路由注册前挂，Pre 链先于
// 路由匹配执行）。
func TrailingSlashRedirect(e *echo.Echo) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			p := c.Request().URL.Path
			if len(p) > 1 && strings.HasSuffix(p, "/") {
				trimmed := strings.TrimSuffix(p, "/")
				probeReq := c.Request().Clone(context.Background())
				probeReq.URL.Path = trimmed
				probe := e.NewContext(probeReq, nil)
				if e.Router().Route(probe) != nil {
					// RouteInfo 在 Route 探测时写入：404 / 405 兜底名不重定向。
					switch name := probe.RouteInfo().Name; name {
					case echo.NotFoundRouteName, echo.MethodNotAllowedRouteName:
					default:
						target := trimmed
						if q := c.Request().URL.RawQuery; q != "" {
							target += "?" + q
						}
						return c.Redirect(http.StatusMovedPermanently, target)
					}
				}
			}
			return next(c)
		}
	}
}
