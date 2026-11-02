package codec

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	api "authloft/gen/go/api/common"
	"google.golang.org/protobuf/proto"
)

func decodeErrorMap(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal error body %q: %v", body, err)
	}
	return got
}

func TestWriteErrorJSON(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatJSON)
	c.Set(RequestIDKey, "req-json")
	WriteError(c, http.StatusBadRequest, CodeBadRequest, "invalid request body")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Accept" {
		t.Errorf("Vary = %q, want %q", got, "Accept")
	}

	body := decodeErrorMap(t, rec.Body.Bytes())
	if got := body["code"]; got != CodeBadRequest {
		t.Errorf("code = %v, want %q", got, CodeBadRequest)
	}
	if got := body["message"]; got != "invalid request body" {
		t.Errorf("message = %v, want %q", got, "invalid request body")
	}
	if got := body["request_id"]; got != "req-json" {
		t.Errorf("request_id = %v, want %q", got, "req-json")
	}

	raw := rec.Body.String()
	if !strings.Contains(raw, `"request_id"`) || strings.Contains(raw, `"requestId"`) {
		t.Errorf("body = %s, want snake_case request_id (write.go UseProtoNames)", raw)
	}
}

func TestWriteErrorJSONRequestIDDefaultsToEmpty(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatJSON)
	WriteError(c, http.StatusUnauthorized, CodeUnauthorized, "")

	body := decodeErrorMap(t, rec.Body.Bytes())
	if got, ok := body["request_id"]; !ok || got != "" {
		t.Errorf("request_id = %v (present=%v), want present empty string", got, ok)
	}
}

func TestWriteErrorProto(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatProto)
	c.Set(RequestIDKey, "req-proto")
	WriteError(c, http.StatusNotFound, CodeNotFound, "")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if got := rec.Header().Get("Content-Type"); got != mediaProto {
		t.Errorf("Content-Type = %q, want %q", got, mediaProto)
	}
	if got := rec.Header().Get("Vary"); got != "Accept" {
		t.Errorf("Vary = %q, want %q", got, "Accept")
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(rec.Body.Len()) {
		t.Errorf("Content-Length = %q, body length %d", got, rec.Body.Len())
	}

	var errBody api.Error
	if err := proto.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("unmarshal api.Error: %v", err)
	}
	if errBody.GetCode() != CodeNotFound {
		t.Errorf("code = %q, want %q", errBody.GetCode(), CodeNotFound)
	}
	if errBody.GetRequestId() != "req-proto" {
		t.Errorf("request_id = %q, want %q", errBody.GetRequestId(), "req-proto")
	}
}

func TestWriteErrorCodeStatusMatrix(t *testing.T) {
	tests := []struct {
		code   string
		status int
	}{
		{code: CodeBadRequest, status: http.StatusBadRequest},
		{code: CodeUnauthorized, status: http.StatusUnauthorized},
		{code: CodeForbidden, status: http.StatusForbidden},
		{code: CodeNotFound, status: http.StatusNotFound},
		{code: CodeUnsupportedMediaType, status: http.StatusUnsupportedMediaType},
		{code: CodeInternalError, status: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			c, rec := newTestContext()
			SetFormat(c, FormatJSON)
			WriteError(c, tt.status, tt.code, "")

			if rec.Code != tt.status {
				t.Errorf("status = %d, want %d", rec.Code, tt.status)
			}
			if got := decodeErrorMap(t, rec.Body.Bytes())["code"]; got != tt.code {
				t.Errorf("code = %v, want %q", got, tt.code)
			}
		})
	}
}

func TestWriteErrorPanicsOnUnknownCode(t *testing.T) {
	deferred := func() {
		if r := recover(); r == nil {
			t.Error("WriteError must panic on code outside §1.5 closed set")
		}
	}
	defer deferred()

	c, _ := newTestContext()
	SetFormat(c, FormatJSON)
	WriteError(c, http.StatusBadRequest, "teapot", "")
}

func TestWriteBindErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "格式不支持",
			err:        fmt.Errorf("%w: %q", ErrUnsupportedMediaType, "text/plain"),
			wantStatus: http.StatusUnsupportedMediaType,
			wantCode:   CodeUnsupportedMediaType,
		},
		{
			name:       "体为空",
			err:        ErrEmptyBody,
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeBadRequest,
		},
		{
			name:       "解码失败",
			err:        fmt.Errorf("%w: %v", ErrDecode, errors.New("boom secret token")),
			wantStatus: http.StatusBadRequest,
			wantCode:   CodeBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, rec := newTestContext()
			SetFormat(c, FormatJSON)
			c.Set(RequestIDKey, "req-bind")
			WriteBindError(c, tt.err)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			body := decodeErrorMap(t, rec.Body.Bytes())
			if got := body["code"]; got != tt.wantCode {
				t.Errorf("code = %v, want %q", got, tt.wantCode)
			}
			if got := body["request_id"]; got != "req-bind" {
				t.Errorf("request_id = %v, want %q", got, "req-bind")
			}
			if raw := rec.Body.String(); strings.Contains(raw, "boom") || strings.Contains(raw, "secret token") {
				t.Errorf("body = %s, must not expose internal decode error", raw)
			}
		})
	}
}

func TestWriteBindErrorProto(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatProto)
	c.Set(RequestIDKey, "req-bind-proto")
	WriteBindError(c, ErrEmptyBody)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var errBody api.Error
	if err := proto.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("unmarshal api.Error: %v", err)
	}
	if errBody.GetCode() != CodeBadRequest {
		t.Errorf("code = %q, want %q", errBody.GetCode(), CodeBadRequest)
	}
	if errBody.GetRequestId() != "req-bind-proto" {
		t.Errorf("request_id = %q, want %q", errBody.GetRequestId(), "req-bind-proto")
	}
}
