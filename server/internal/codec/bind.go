package codec

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// defaultMaxBodyBytes 是未注入 SetMaxBodyBytes 时的回落上限：1 MiB（1048576 字节）。
const defaultMaxBodyBytes int64 = 1 << 20

// maxBodyBytes 是请求体解码上限（docs/后端架构.md §3.14 行 487 要求 http.MaxBytesReader），
// 上限由装配层（main / 依赖注入处）在服务启动阶段经 SetMaxBodyBytes 注入（§3.14 行 492）；
// codec 是叶子包、不 import config，未注入时回落 defaultMaxBodyBytes。
var maxBodyBytes int64 = defaultMaxBodyBytes

// SetMaxBodyBytes 设置请求体解码上限（§3.14 行 492）：须在服务启动、接受请求前由装配层调用。
// n <= 0 时不生效（保持当前值），避免误传把上限关成 0 而拒掉所有请求。
func SetMaxBodyBytes(n int64) {
	if n <= 0 {
		return
	}
	maxBodyBytes = n
}

// 请求解码的三类可区分错误；调用方用 WriteBindError 统一转成 §1.5 错误体。
var (
	ErrUnsupportedMediaType = errors.New("codec: unsupported media type")
	ErrEmptyBody            = errors.New("codec: empty request body")
	ErrDecode               = errors.New("codec: decode request body")
)

// unmarshalJSON 与 §1.6 行 87 的 JSON 解码口径一致：未知字段一律拒绝（严格入参）。
var unmarshalJSON = protojson.UnmarshalOptions{DiscardUnknown: false}

// Bind 按 Content-Type 把请求体解码到 msg（docs/后端架构.md §3.14 行 487）：
// application/json → protojson；application/octet-stream → proto.Unmarshal；其余报 415 语义错误。
func Bind(c *gin.Context, msg proto.Message) error {
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsupportedMediaType, err)
	}

	var decode func([]byte) error
	switch mediaType {
	case mediaJSON:
		decode = func(body []byte) error { return unmarshalJSON.Unmarshal(body, msg) }
	case mediaProto:
		decode = func(body []byte) error { return proto.Unmarshal(body, msg) }
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedMediaType, mediaType)
	}

	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDecode, err)
	}
	if len(body) == 0 {
		return ErrEmptyBody
	}
	if err := decode(body); err != nil {
		return fmt.Errorf("%w: %w", ErrDecode, err)
	}
	return nil
}
