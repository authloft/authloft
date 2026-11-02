package codec

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	api "authloft/gen/go/api/common"
)

var marshalJSON = protojson.MarshalOptions{
	UseProtoNames:     true,
	EmitDefaultValues: true,
	AllowPartial:      false,
}

// internalErrorMessage 是编码失败兜底的固定文案，不透出内部错误细节。
const internalErrorMessage = "internal error"

// 兜底编码再次失败时（如 request_id 含非法 UTF-8）写死的最小 api.Error 字节，
// 保证响应完整、不递归调用 Write；字段号见 server/proto/api/common/error.proto。
const (
	fallbackProtoBody = "\x0a\x0einternal_error" // 字段 1（code）= "internal_error"
	fallbackJSONBody  = `{"code":"internal_error","message":"","request_id":""}`
)

// Write 是全站唯一的响应出口：先完整编码，成功后再写状态码、响应头与响应体。
func Write(c *gin.Context, status int, msg proto.Message) {
	format, ok := formatFromContext(c)
	if !ok {
		format = FormatJSON // 未挂协商中间件时按“协商失败回落 JSON”
	}

	h := c.Writer.Header()
	// 所有响应（含编码失败兜底）都必须在写状态码之前带 Vary: Accept（docs/后端架构.md §1.6 行 105）。
	h.Set("Vary", "Accept")

	var body []byte
	var err error
	if format == FormatProto {
		body, err = proto.Marshal(msg)
	} else {
		body, err = marshalJSON.Marshal(msg)
	}
	if err != nil {
		// 编码失败兜底：docs/后端架构.md §3.14 行 486 要求直接 500 + internal_error，禁止半截输出；
		// 兜底体同样按协商格式编码（docs/接口文档.md §1.5 行 195、§1.1.1 行 87）。
		writeFallback(c, format)
		return
	}

	if format == FormatProto {
		h.Set("Content-Type", mediaProto)
		h.Set("Content-Length", strconv.Itoa(len(body)))
	} else {
		h.Set("Content-Type", "application/json; charset=utf-8")
	}

	c.Status(status)
	_, _ = c.Writer.Write(body)
}

// writeFallback 写编码失败的兜底响应：由 codec 构造 api.Error 并按协商格式编码
// （docs/接口文档.md §1.5 行 195）。不递归调用 Write；兜底编码再次失败时
// 写死最小 api.Error 字节，保证不半截输出。
func writeFallback(c *gin.Context, format Format) {
	errMsg := &api.Error{
		Code:      CodeInternalError,
		Message:   internalErrorMessage,
		RequestId: requestID(c), // middleware/requestid 未接入时为空串，不伪造值
	}

	var body []byte
	var err error
	if format == FormatProto {
		body, err = proto.Marshal(errMsg)
	} else {
		body, err = marshalJSON.Marshal(errMsg)
	}
	if err != nil {
		if format == FormatProto {
			body = []byte(fallbackProtoBody)
		} else {
			body = []byte(fallbackJSONBody)
		}
	}

	h := c.Writer.Header()
	if format == FormatProto {
		h.Set("Content-Type", mediaProto)
		h.Set("Content-Length", strconv.Itoa(len(body)))
	} else {
		h.Set("Content-Type", "application/json; charset=utf-8")
	}
	c.Status(http.StatusInternalServerError)
	_, _ = c.Writer.Write(body)
}
