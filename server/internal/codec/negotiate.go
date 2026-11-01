package codec

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// Format 是响应体的字节表示。
type Format int

const (
	FormatJSON Format = iota
	FormatProto
)

const (
	mediaJSON  = "application/json"
	mediaProto = "application/octet-stream"
)

// Negotiate 按 Accept 头选择响应格式。协商失败一律回落 JSON，绝不返回 406。
func Negotiate(r *http.Request) Format {
	if isAlwaysJSONPath(r.URL.Path) {
		return FormatJSON
	}

	accept := r.Header.Get("Accept")
	protoQ, hasProto := maxQuality(accept, mediaProto)
	if !hasProto {
		return FormatJSON
	}
	jsonQ, hasJSON := maxQuality(accept, mediaJSON)
	if hasJSON && protoQ < jsonQ {
		return FormatJSON
	}
	return FormatProto
}

// isAlwaysJSONPath 覆盖 /api/oidc/** 与 /api/gateway/** 免协商白名单。
func isAlwaysJSONPath(path string) bool {
	for _, prefix := range []string{"/api/oidc", "/api/gateway"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// maxQuality 返回指定媒体类型在 Accept 中的最高 q 值；q <= 0 视为不可接受。
func maxQuality(accept, media string) (float64, bool) {
	var best float64
	var found bool
	for _, part := range strings.Split(accept, ",") {
		mt, q, ok := parseMediaRange(part)
		if !ok || mt != media || q <= 0 {
			continue
		}
		if !found || q > best {
			best, found = q, true
		}
	}
	return best, found
}

func parseMediaRange(s string) (string, float64, bool) {
	params := strings.Split(s, ";")
	mt := strings.ToLower(strings.TrimSpace(params[0]))
	if mt == "" {
		return "", 0, false
	}
	q := 1.0
	for _, p := range params[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "q") {
			continue
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			continue
		}
		q = parsed
	}
	return mt, q, true
}

const formatCtxKey = "codec.format"

// SetFormat 把协商结果写入 ctx；handler 不得覆盖。
func SetFormat(c *gin.Context, f Format) { c.Set(formatCtxKey, f) }

func formatFromContext(c *gin.Context) (Format, bool) {
	f, ok := c.Get(formatCtxKey)
	v, ok := f.(Format)
	return v, ok
}
