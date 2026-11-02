package codec

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	api "authloft/gen/go/api/common"
)

func newTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	return c, rec
}

func TestWriteJSON(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatJSON)
	Write(c, http.StatusOK, &descriptorpb.FileDescriptorProto{PublicDependency: []int32{1}})

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Accept" {
		t.Errorf("Vary = %q, want %q", got, "Accept")
	}
	if got := rec.Body.String(); !strings.Contains(got, `"public_dependency":[1]`) {
		t.Errorf("body = %s", got)
	}
}

func TestWriteProto(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatProto)
	Write(c, http.StatusOK, wrapperspb.String("hello"))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Accept" {
		t.Errorf("Vary = %q, want %q", got, "Accept")
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(rec.Body.Len()) {
		t.Errorf("Content-Length = %q, body length %d", got, rec.Body.Len())
	}

	var decoded wrapperspb.StringValue
	if err := proto.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if decoded.GetValue() != "hello" {
		t.Errorf("value = %q, want %q", decoded.GetValue(), "hello")
	}
}

func TestWriteStatusPassThrough(t *testing.T) {
	for _, status := range []int{http.StatusCreated, http.StatusNoContent} {
		c, rec := newTestContext()
		SetFormat(c, FormatJSON)
		Write(c, status, wrapperspb.String("ok"))

		if rec.Code != status {
			t.Errorf("status = %d, want %d", rec.Code, status)
		}
	}
}

func TestWriteJSONUsesProtoNames(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatJSON)
	Write(c, http.StatusOK, &descriptorpb.FileDescriptorProto{PublicDependency: []int32{1}})

	body := rec.Body.String()
	if !strings.Contains(body, `"public_dependency":[1]`) {
		t.Errorf("body = %s, want proto field name public_dependency", body)
	}
	if strings.Contains(body, `"publicDependency"`) {
		t.Errorf("body = %s, want no lowerCamelCase field name", body)
	}
}

func TestWriteJSONEmitsDefaultValues(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatJSON)
	Write(c, http.StatusOK, &descriptorpb.FileDescriptorProto{})

	body := rec.Body.String()
	if !strings.Contains(body, `"dependency":[]`) {
		t.Errorf("body = %s, want empty repeated field emitted", body)
	}
	if !strings.Contains(body, `"message_type":[]`) {
		t.Errorf("body = %s, want empty repeated field emitted", body)
	}
}

func TestWriteWithoutFormatFallsBackToJSON(t *testing.T) {
	c, rec := newTestContext()
	Write(c, http.StatusOK, wrapperspb.String("hello"))

	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Body.String(); got != `"hello"` {
		t.Errorf("body = %s", got)
	}
}

func TestWriteMarshalErrorFallbackProto(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatProto)
	// proto3 string 含非法 UTF-8，proto.Marshal 编码失败。
	Write(c, http.StatusOK, wrapperspb.String("\xff"))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Accept" {
		t.Errorf("Vary = %q, want %q", got, "Accept")
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(rec.Body.Len()) {
		t.Errorf("Content-Length = %q, body length %d", got, rec.Body.Len())
	}

	var decoded api.Error
	if err := proto.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal fallback body %q: %v", rec.Body.String(), err)
	}
	if decoded.GetCode() != "internal_error" {
		t.Errorf("code = %q, want internal_error", decoded.GetCode())
	}
	if decoded.GetMessage() != "internal error" {
		t.Errorf("message = %q, want %q", decoded.GetMessage(), "internal error")
	}
	if decoded.GetRequestId() != "" {
		t.Errorf("request_id = %q, want empty when requestid middleware absent", decoded.GetRequestId())
	}

	raw := rec.Body.String()
	if strings.Contains(raw, "\xff") || strings.Contains(raw, "invalid UTF-8") {
		t.Errorf("body = %q, must not expose internal error details", raw)
	}
}

func TestWriteMarshalErrorFallbackJSON(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatJSON)
	// protojson 同样拒绝含非法 UTF-8 的 string 字段，编码失败。
	Write(c, http.StatusOK, wrapperspb.String("\xff"))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Accept" {
		t.Errorf("Vary = %q, want %q", got, "Accept")
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal fallback body %q: %v", rec.Body.String(), err)
	}
	if got := body["code"]; got != "internal_error" {
		t.Errorf("code = %v, want internal_error", got)
	}
	if got, ok := body["message"]; !ok || got != "internal error" {
		t.Errorf("message = %v, want internal error", got)
	}
	if got, ok := body["request_id"]; !ok || got != "" {
		t.Errorf("request_id = %v, want empty string when requestid middleware absent", got)
	}

	raw := rec.Body.String()
	if strings.Contains(raw, "\xff") || strings.Contains(raw, "invalid UTF-8") {
		t.Errorf("body = %q, must not expose internal error details", raw)
	}
}

func TestWriteMarshalErrorFallbackWithRequestID(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatProto)
	c.Set(RequestIDKey, "req-123")
	Write(c, http.StatusOK, wrapperspb.String("\xff"))

	var decoded api.Error
	if err := proto.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal fallback body %q: %v", rec.Body.String(), err)
	}
	if decoded.GetRequestId() != "req-123" {
		t.Errorf("request_id = %q, want req-123", decoded.GetRequestId())
	}
}

func TestWriteMarshalErrorFallbackHardcodedWhenFallbackEncodeFails(t *testing.T) {
	// request_id 含非法 UTF-8 → 兜底体二次编码失败 → 写死最小 api.Error 字节，不递归调用 Write。
	t.Run("proto", func(t *testing.T) {
		c, rec := newTestContext()
		SetFormat(c, FormatProto)
		c.Set(RequestIDKey, "\xff")
		Write(c, http.StatusOK, wrapperspb.String("\xff"))

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("Content-Type = %q", got)
		}
		var decoded api.Error
		if err := proto.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("unmarshal hardcoded fallback body %q: %v", rec.Body.String(), err)
		}
		if decoded.GetCode() != "internal_error" {
			t.Errorf("code = %q, want internal_error", decoded.GetCode())
		}
	})
	t.Run("json", func(t *testing.T) {
		c, rec := newTestContext()
		SetFormat(c, FormatJSON)
		c.Set(RequestIDKey, "\xff")
		Write(c, http.StatusOK, wrapperspb.String("\xff"))

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Errorf("Content-Type = %q", got)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal hardcoded fallback body %q: %v", rec.Body.String(), err)
		}
		if got := body["code"]; got != "internal_error" {
			t.Errorf("code = %v, want internal_error", got)
		}
	})
}
