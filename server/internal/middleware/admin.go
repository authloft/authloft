package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"authloft/internal/codec"
	"authloft/internal/session"
)

// adminUID 管理员固定 UID：安装时创建的 user.id = 1 账号，不设角色表、
// 不加 is_admin 列（docs/接口文档.md §5 行 1143）。
const adminUID int64 = 1

// Admin 管理员会话校验中间件（docs/接口文档.md §5 行 1145、docs/后端架构.md
// §3.3 行 312）：挂在 Session 之后（依赖其注入的会话身份）。
//
//   - ctx 无 uid（未携带有效会话 / Session 放行的未登录请求）→ 401 unauthorized；
//   - uid 有但 != 1 → 404 not_found（掩护管理面存在，§1.5 行 210：不向非
//     管理员暴露 admin 路径的存在）；
//   - uid == 1 放行。
//
// 管理员判定只有这一处（§3.3 行 312 约束「禁止散落」）；两个错误均由
// 中间件产生、不进 §1.6 的业务 status 表（行 1145）。
func Admin() gin.HandlerFunc {
	return func(c *gin.Context) {
		uid, ok := session.UIDFromContext(c.Request.Context())
		if !ok {
			codec.WriteError(c, http.StatusUnauthorized, codec.CodeUnauthorized, "authentication required")
			c.Abort()
			return
		}
		if uid != adminUID {
			// 文案与普通资源 404 一致，不透露「路径存在但无权」。
			codec.WriteError(c, http.StatusNotFound, codec.CodeNotFound, "not found")
			c.Abort()
			return
		}
		c.Next()
	}
}
