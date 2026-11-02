package middleware

import (
	"mime"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"authloft/internal/codec"
)

const (
	mediaJSON = "application/json"
	mediaProto = "application/octet-stream"
)

// multipartUploadPaths 是 multipart 上传端点清单（docs/接口文档.md §1.1 行 65-67，
// 当前仅头像上传）。这些端点按路径免检 JSON / Protobuf 白名单，其 Content-Type
// 与 MIME 校验由上传服务层负责（后端架构 §21 行 1779）。
var multipartUploadPaths = []string{"/api/account/avatar"}

// ContentType 校验写请求的 Content-Type 只允许 application/json 或
// application/octet-stream，其余 415（docs/后端架构.md §3.3 行 303、
// docs/接口文档.md §1.1 行 55）。免检：/api/oidc/**（x-www-form-urlencoded）
// 与 multipart 端点清单。只判头、不读 body——请求体解码在 codec.Bind（§3.3 行 303）。
//
// 匹配口径与 codec.Bind 一致：mime.ParseMediaType 取 media type、忽略 charset 等
// 参数（§1.1 行 55 的「application/json; charset=utf-8」在 media type 层等价于
// application/json，protojson 本就按 UTF-8 解码）；头缺失或解析失败按 415 拒绝。
func ContentType() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isWriteMethod(c.Request.Method) || isContentTypeExemptPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
		if err != nil || (mediaType != mediaJSON && mediaType != mediaProto) {
			codec.WriteError(c, http.StatusUnsupportedMediaType, codec.CodeUnsupportedMediaType, "content type not allowed")
			c.Abort()
			return
		}
		c.Next()
	}
}

// isContentTypeExemptPath 覆盖 Content-Type 白名单免检（docs/接口文档.md §1.1 行 55-56、
// 行 65-67）：/api/oidc/**（x-www-form-urlencoded）与 multipart 端点清单。
func isContentTypeExemptPath(path string) bool {
	if path == "/api/oidc" || strings.HasPrefix(path, "/api/oidc/") {
		return true
	}
	for _, p := range multipartUploadPaths {
		if path == p {
			return true
		}
	}
	return false
}
