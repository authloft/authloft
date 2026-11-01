package codec

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var marshalJSON = protojson.MarshalOptions{
	UseProtoNames:     true,
	EmitDefaultValues: true,
	AllowPartial:      false,
}

// internalErrorMessage 是编码失败兜底的固定文案，不透出内部错误细节。
const internalErrorMessage = "internal error"

// fallbackError 是编码失败兜底体，字段口径见 docs/接口文档.md §1.5。
type fallbackError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

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
		// 编码失败兜底：docs/后端架构.md §3.14 行 484 要求直接 500 + internal_error，禁止半截输出。
		// 该兜底体后续由 codec/error.go（api.Error 生成后）接管。
		h.Set("Content-Type", "application/json; charset=utf-8")
		errBody, _ := json.Marshal(fallbackError{
			Code:      "internal_error",
			Message:   internalErrorMessage,
			RequestID: "", // 待 middleware/requestid 接入后取链路 ID。
		})
		c.Status(http.StatusInternalServerError)
		_, _ = c.Writer.Write(errBody)
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
