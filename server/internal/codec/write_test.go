package codec

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/emptypb"
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

	var decoded api.ErrorEnvelope
	if err := proto.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal fallback body %q: %v", rec.Body.String(), err)
	}
	if decoded.GetStatus() != "error" {
		t.Errorf("status = %q, want error (envelope shape)", decoded.GetStatus())
	}
	if decoded.GetError().GetCode() != "internal_error" {
		t.Errorf("code = %q, want internal_error", decoded.GetError().GetCode())
	}
	if decoded.GetError().GetMessage() != "internal error" {
		t.Errorf("message = %q, want %q", decoded.GetError().GetMessage(), "internal error")
	}
	if decoded.GetError().GetRequestId() != "" {
		t.Errorf("request_id = %q, want empty when requestid middleware absent", decoded.GetError().GetRequestId())
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
	if got := body["status"]; got != "error" {
		t.Errorf("status = %v, want error (envelope shape)", got)
	}
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("fallback body missing error object: %v", body)
	}
	if got := errObj["code"]; got != "internal_error" {
		t.Errorf("error.code = %v, want internal_error", got)
	}
	if got, ok := errObj["message"]; !ok || got != "internal error" {
		t.Errorf("error.message = %v, want internal error", got)
	}
	if got, ok := errObj["request_id"]; !ok || got != "" {
		t.Errorf("error.request_id = %v, want empty string when requestid middleware absent", got)
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

	var decoded api.ErrorEnvelope
	if err := proto.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal fallback body %q: %v", rec.Body.String(), err)
	}
	if decoded.GetError().GetRequestId() != "req-123" {
		t.Errorf("error.request_id = %q, want req-123", decoded.GetError().GetRequestId())
	}
}

func TestWriteMarshalErrorFallbackHardcodedWhenFallbackEncodeFails(t *testing.T) {
	// request_id 含非法 UTF-8 → 兜底体二次编码失败 → 写死最小 ErrorEnvelope 字节，不递归调用 Write。
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
		var decoded api.ErrorEnvelope
		if err := proto.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("unmarshal hardcoded fallback body %q: %v", rec.Body.String(), err)
		}
		if decoded.GetStatus() != "error" {
			t.Errorf("status = %q, want error (envelope shape)", decoded.GetStatus())
		}
		if decoded.GetError().GetCode() != "internal_error" {
			t.Errorf("error.code = %q, want internal_error", decoded.GetError().GetCode())
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
		if got := body["status"]; got != "error" {
			t.Errorf("status = %v, want error (envelope shape)", got)
		}
		errObj, ok := body["error"].(map[string]any)
		if !ok {
			t.Fatalf("hardcoded fallback body missing error object: %v", body)
		}
		if got := errObj["code"]; got != "internal_error" {
			t.Errorf("error.code = %v, want internal_error", got)
		}
	})
}

// WriteSuccess 的 JSON 分支（§1.0 行 56）：HTTP 200 + {"status":"success", …数据平铺}，
// status 与数据字段同层、不设 data 包裹。
func TestWriteSuccessJSONFlattensDataFields(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatJSON)
	WriteSuccess(c, &descriptorpb.FileDescriptorProto{PublicDependency: []int32{1}})

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Accept" {
		t.Errorf("Vary = %q, want %q", got, "Accept")
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body %q: %v", rec.Body.String(), err)
	}
	if got := body["status"]; got != "success" {
		t.Errorf("status = %v, want success", got)
	}
	if got := body["public_dependency"]; !reflect.DeepEqual(got, []any{float64(1)}) {
		t.Errorf("public_dependency = %v, want data field flattened to top level", got)
	}
	if _, exists := body["data"]; exists {
		t.Errorf("body has data wrapper %v, want no data wrapper (§1.0 行 56)", body["data"])
	}
}

// 数据消息 protojson 输出空对象（emptypb.Empty 无字段）→ 输出 {"status":"success"}，
// 不产生悬挂逗号。
func TestWriteSuccessJSONEmptyDataMessage(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatJSON)
	WriteSuccess(c, &emptypb.Empty{})

	if got := rec.Body.String(); got != `{"status":"success"}` {
		t.Errorf("body = %s, want {\"status\":\"success\"}", got)
	}
}

// 未挂协商中间件 → WriteSuccess 同样回落 JSON（与 Write 同口径）。
func TestWriteSuccessWithoutFormatFallsBackToJSON(t *testing.T) {
	c, rec := newTestContext()
	WriteSuccess(c, &emptypb.Empty{})

	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Body.String(); got != `{"status":"success"}` {
		t.Errorf("body = %s", got)
	}
}

// Protobuf 分支：SuccessEnvelope{status, data}，data 为数据消息序列化字节，
// 两步解码（先信封、再数据）后与原消息等价（取舍说明见 response.proto）。
func TestWriteSuccessProtoEnvelope(t *testing.T) {
	msg := &descriptorpb.FileDescriptorProto{PublicDependency: []int32{1, 2}}
	c, rec := newTestContext()
	SetFormat(c, FormatProto)
	WriteSuccess(c, msg)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(rec.Body.Len()) {
		t.Errorf("Content-Length = %q, body length %d", got, rec.Body.Len())
	}

	var envelope api.SuccessEnvelope
	if err := proto.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal SuccessEnvelope: %v", err)
	}
	if envelope.GetStatus() != "success" {
		t.Errorf("status = %q, want success", envelope.GetStatus())
	}
	var decoded descriptorpb.FileDescriptorProto
	if err := proto.Unmarshal(envelope.GetData(), &decoded); err != nil {
		t.Fatalf("unmarshal nested data: %v", err)
	}
	if !proto.Equal(&decoded, msg) {
		t.Errorf("nested data = %v, want round-trip equal", &decoded)
	}
}

// 编码失败（数据消息含非法 UTF-8）→ 500 + internal_error 信封兜底，
// 不出半截输出（§3.14 行 494）。
func TestWriteSuccessMarshalErrorFallback(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		c, rec := newTestContext()
		SetFormat(c, FormatJSON)
		WriteSuccess(c, wrapperspb.String("\xff"))

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal fallback body %q: %v", rec.Body.String(), err)
		}
		if got := body["status"]; got != "error" {
			t.Errorf("status = %v, want error (fallback envelope)", got)
		}
	})
	t.Run("proto", func(t *testing.T) {
		c, rec := newTestContext()
		SetFormat(c, FormatProto)
		WriteSuccess(c, wrapperspb.String("\xff"))

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
		}
		var decoded api.ErrorEnvelope
		if err := proto.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("unmarshal fallback body %q: %v", rec.Body.String(), err)
		}
		if decoded.GetStatus() != "error" {
			t.Errorf("status = %q, want error (fallback envelope)", decoded.GetStatus())
		}
		if decoded.GetError().GetCode() != "internal_error" {
			t.Errorf("error.code = %q, want internal_error", decoded.GetError().GetCode())
		}
	})
}
