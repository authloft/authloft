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

// 信封状态词（docs/接口文档.md §1.0 行 56-58）：成功恒 success，失败恒 error。
// 登录流程域（/api/sso/**）的流程态词汇（next / mfa_required / pending…，§1.6）
// 属于 sso 豁免信封，不经 codec 常量消费。
const (
	StatusSuccess = "success"
	StatusError   = "error"
)

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

// WriteError 是框架拒绝出口（docs/接口文档.md §1.0 行 58、§1.5 行 214）：
// 非 200 + 统一错误信封 {"status":"error","error":{code,message,request_id}}，
// 构造 api.ErrorEnvelope 包裹 api.Error 并复用 Write 编码（docs/后端架构.md §3.14 行 496）。
// code 越界属于编程错误，直接 panic（§21.1 行 1738 允许 panic 或 500）；
// 合法 code 与 HTTP 状态码一一对应（§1.5 行 199），调用方须传匹配的 status。
func WriteError(c *gin.Context, status int, code, message string) {
	if _, ok := errorStatus[code]; !ok {
		panic(fmt.Sprintf("codec: unknown error code %q", code))
	}
	writeErrorEnvelope(c, status, code, message)
}

// WriteBizError 是业务失败出口（docs/接口文档.md §1.0 行 57）：HTTP 200 +
// 同一错误信封，error.code 取 §1.6 对应取值（如 password_weak）或域内定义值
// （如 §13 的 config_invalid）——业务码开放，不做 §1.5 封闭集校验。
// 供 account / admin / rpc / setup 域 handler 消费；登录流程域（/api/sso/**）
// 豁免本信封、由流程态信封表达业务分支（§1.0 行 63、§1.5 行 202），不走本出口。
func WriteBizError(c *gin.Context, code, message string) {
	writeErrorEnvelope(c, http.StatusOK, code, message)
}

// writeErrorEnvelope 构造 ErrorEnvelope 并复用 Write 编码；HTTP 状态码由调用方给定。
func writeErrorEnvelope(c *gin.Context, status int, code, message string) {
	Write(c, status, &api.ErrorEnvelope{
		Status: StatusError,
		Error: &api.Error{
			Code:      code,
			Message:   message,
			RequestId: requestID(c),
		},
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
