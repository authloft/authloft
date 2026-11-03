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

// 兜底编码再次失败时（如 request_id 含非法 UTF-8）写死的最小 ErrorEnvelope 字节，
// 保证响应完整、不递归调用 Write；字段号见 server/proto/api/common/response.proto。
//   proto：字段 1（status）= "error"；字段 2（error）内嵌字段 1（code）= "internal_error"
//   json ：键序按字段号（protojson 口径）
const (
	fallbackProtoBody = "\x0a\x05error\x12\x10\x0a\x0einternal_error"
	fallbackJSONBody  = `{"status":"error","error":{"code":"internal_error","message":"","request_id":""}}`
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

// WriteSuccess 是成功响应的信封出口（docs/接口文档.md §1.0 行 56）：
// HTTP 200 + {"status":"success", …数据字段平铺}（数据与 status 同层、不设 data 包裹）。
//   - JSON 分支：protojson 输出数据消息后在顶层注入 status 字段；数据消息为空对象
//     时输出 {"status":"success"}。不经过 SuccessEnvelope——protojson 对 bytes 只能
//     出 base64 字符串，无法平铺（见 response.proto 的取舍说明）。
//   - Protobuf 分支：SuccessEnvelope{status, data=数据消息序列化字节}，客户端按
//     端点契约两步解码；两种编码语义等价（§1.1.1 行 105）。
// 编码失败走 writeFallback（500 + internal_error，§3.14 行 494 禁止半截输出）。
func WriteSuccess(c *gin.Context, msg proto.Message) {
	format, ok := formatFromContext(c)
	if !ok {
		format = FormatJSON // 未挂协商中间件时按“协商失败回落 JSON”
	}

	if format == FormatProto {
		data, err := proto.Marshal(msg)
		if err != nil {
			writeFallback(c, format)
			return
		}
		Write(c, http.StatusOK, &api.SuccessEnvelope{Status: StatusSuccess, Data: data})
		return
	}

	out, err := marshalJSON.Marshal(msg)
	// protojson 对普通 message 恒输出 JSON 对象；非对象（如 wrappers 的标量输出）
	// 说明调用方传了非数据消息，按编码失败兜底，不出半截畸形体。
	if err != nil || len(out) == 0 || out[0] != '{' {
		writeFallback(c, format)
		return
	}
	body := []byte(`{"status":"success"`)
	if string(out) != "{}" {
		body = append(body, ',')
		body = append(body, out[1:len(out)-1]...) // 去掉外层 '{' 与 '}'，数据字段平铺到顶层
	}
	body = append(body, '}')

	h := c.Writer.Header()
	h.Set("Vary", "Accept")
	h.Set("Content-Type", "application/json; charset=utf-8")
	c.Status(http.StatusOK)
	_, _ = c.Writer.Write(body)
}

// writeFallback 写编码失败的兜底响应：由 codec 构造统一错误信封 ErrorEnvelope
// 并按协商格式编码（docs/接口文档.md §1.5 行 214）。不递归调用 Write；
// 兜底编码再次失败时写死最小 ErrorEnvelope 字节，保证不半截输出。
func writeFallback(c *gin.Context, format Format) {
	errMsg := &api.ErrorEnvelope{
		Status: StatusError,
		Error: &api.Error{
			Code:      CodeInternalError,
			Message:   internalErrorMessage,
			RequestId: requestID(c), // middleware/requestid 未接入时为空串，不伪造值
		},
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
