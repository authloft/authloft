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

func TestWriteMarshalErrorReturns500WithInternalError(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatProto)
	// proto3 string 含非法 UTF-8，proto.Marshal 编码失败。
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
	if _, ok := body["message"]; !ok {
		t.Errorf("body = %s, want message field", rec.Body.String())
	}
	if _, ok := body["request_id"]; !ok {
		t.Errorf("body = %s, want request_id field", rec.Body.String())
	}

	raw := rec.Body.String()
	if strings.Contains(raw, "\xff") || strings.Contains(raw, "invalid UTF-8") {
		t.Errorf("body = %q, must not expose internal error details", raw)
	}
}
