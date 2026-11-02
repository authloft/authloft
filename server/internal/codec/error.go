package codec

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	api "authloft/gen/go/api/common"
)

// RequestIDKey 是链路 ID 在 *gin.Context 中的键；middleware/requestid.go 写入，error.go 读取。
const RequestIDKey = "request_id"

// 框架层错误码：封闭集合见 docs/接口文档.md §1.5 行 199，与 HTTP 状态码一一对应。
const (
	CodeBadRequest           = "bad_request"
	CodeUnauthorized         = "unauthorized"
	CodeForbidden            = "forbidden"
	CodeNotFound             = "not_found"
	CodeUnsupportedMediaType = "unsupported_media_type"
	CodeInternalError        = "internal_error"
)

var errorStatus = map[string]int{
	CodeBadRequest:           http.StatusBadRequest,
	CodeUnauthorized:         http.StatusUnauthorized,
	CodeForbidden:            http.StatusForbidden,
	CodeNotFound:             http.StatusNotFound,
	CodeUnsupportedMediaType: http.StatusUnsupportedMediaType,
	CodeInternalError:        http.StatusInternalServerError,
}

// WriteError 构造 api.Error 并复用 Write 编码（docs/后端架构.md §3.14 行 488）。
// code 越界属于编程错误，直接 panic（§21.1 行 1738 允许 panic 或 500）；
// 合法 code 与 HTTP 状态码一一对应（§1.5 行 199），调用方须传匹配的 status。
func WriteError(c *gin.Context, status int, code, message string) {
	if _, ok := errorStatus[code]; !ok {
		panic(fmt.Sprintf("codec: unknown error code %q", code))
	}
	Write(c, status, &api.Error{
		Code:      code,
		Message:   message,
		RequestId: requestID(c),
	})
}

// WriteBindError 把 Bind 的错误统一写成 §1.5 错误体：格式不支持 → 415，其余解码失败 → 400。
// 响应文案固定，不透出底层解码错误（§3.14 行 488）。
func WriteBindError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrUnsupportedMediaType):
		WriteError(c, http.StatusUnsupportedMediaType, CodeUnsupportedMediaType, "unsupported media type")
	case errors.Is(err, ErrEmptyBody):
		WriteError(c, http.StatusBadRequest, CodeBadRequest, "empty request body")
	default:
		WriteError(c, http.StatusBadRequest, CodeBadRequest, "invalid request body")
	}
}

// requestID 从 ctx 取链路 ID；middleware/requestid.go 尚未接入时为空串，不伪造值。
func requestID(c *gin.Context) string {
	return c.GetString(RequestIDKey)
}
