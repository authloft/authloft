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

// errorObject 取出信封内层 error 对象（§1.0 行 57：{"status":"error","error":{…}}）。
func errorObject(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	obj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("envelope missing \"error\" object: %v", body)
	}
	return obj
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
	if got := body["status"]; got != StatusError {
		t.Errorf("status = %v, want %q", got, StatusError)
	}
	if _, exists := body["code"]; exists {
		t.Errorf("body has top-level code %v, want code only inside error object (§1.0 envelope)", body["code"])
	}
	errObj := errorObject(t, body)
	if got := errObj["code"]; got != CodeBadRequest {
		t.Errorf("error.code = %v, want %q", got, CodeBadRequest)
	}
	if got := errObj["message"]; got != "invalid request body" {
		t.Errorf("error.message = %v, want %q", got, "invalid request body")
	}
	if got := errObj["request_id"]; got != "req-json" {
		t.Errorf("error.request_id = %v, want %q", got, "req-json")
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
	if got := body["status"]; got != StatusError {
		t.Errorf("status = %v, want %q", got, StatusError)
	}
	if got, ok := errorObject(t, body)["request_id"]; !ok || got != "" {
		t.Errorf("error.request_id = %v (present=%v), want present empty string", got, ok)
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

	var envelope api.ErrorEnvelope
	if err := proto.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal api.ErrorEnvelope: %v", err)
	}
	if envelope.GetStatus() != StatusError {
		t.Errorf("status = %q, want %q", envelope.GetStatus(), StatusError)
	}
	errBody := envelope.GetError()
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
			body := decodeErrorMap(t, rec.Body.Bytes())
			if got := body["status"]; got != StatusError {
				t.Errorf("status word = %v, want %q (envelope shape)", got, StatusError)
			}
			if got := errorObject(t, body)["code"]; got != tt.code {
				t.Errorf("error.code = %v, want %q", got, tt.code)
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
			if got := body["status"]; got != StatusError {
				t.Errorf("status = %v, want %q (envelope shape)", got, StatusError)
			}
			errObj := errorObject(t, body)
			if got := errObj["code"]; got != tt.wantCode {
				t.Errorf("error.code = %v, want %q", got, tt.wantCode)
			}
			if got := errObj["request_id"]; got != "req-bind" {
				t.Errorf("error.request_id = %v, want %q", got, "req-bind")
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
	var envelope api.ErrorEnvelope
	if err := proto.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal api.ErrorEnvelope: %v", err)
	}
	if envelope.GetStatus() != StatusError {
		t.Errorf("status = %q, want %q (envelope shape)", envelope.GetStatus(), StatusError)
	}
	if envelope.GetError().GetCode() != CodeBadRequest {
		t.Errorf("error.code = %q, want %q", envelope.GetError().GetCode(), CodeBadRequest)
	}
	if envelope.GetError().GetRequestId() != "req-bind-proto" {
		t.Errorf("error.request_id = %q, want %q", envelope.GetError().GetRequestId(), "req-bind-proto")
	}
}

// WriteBizError 是业务失败出口（§1.0 行 57）：HTTP 200 + status:"error" 信封，
// error.code 取 §1.6 词汇或域内定义值——不做 §1.5 封闭集校验；request_id 同样注入。
func TestWriteBizErrorJSON(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatJSON)
	c.Set(RequestIDKey, "req-biz")
	WriteBizError(c, "password_weak", "password too weak")

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d（业务失败一律 200，§1.5 行 202）", rec.Code, http.StatusOK)
	}
	body := decodeErrorMap(t, rec.Body.Bytes())
	if got := body["status"]; got != StatusError {
		t.Errorf("status = %v, want %q", got, StatusError)
	}
	errObj := errorObject(t, body)
	if got := errObj["code"]; got != "password_weak" {
		t.Errorf("error.code = %v, want %q（§1.6 词汇，不校验 §1.5 封闭集）", got, "password_weak")
	}
	if got := errObj["message"]; got != "password too weak" {
		t.Errorf("error.message = %v, want %q", got, "password too weak")
	}
	if got := errObj["request_id"]; got != "req-biz" {
		t.Errorf("error.request_id = %v, want %q", got, "req-biz")
	}
}

func TestWriteBizErrorProto(t *testing.T) {
	c, rec := newTestContext()
	SetFormat(c, FormatProto)
	c.Set(RequestIDKey, "req-biz-proto")
	WriteBizError(c, "config_invalid", "")

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != mediaProto {
		t.Errorf("Content-Type = %q, want %q", got, mediaProto)
	}
	var envelope api.ErrorEnvelope
	if err := proto.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("unmarshal api.ErrorEnvelope: %v", err)
	}
	if envelope.GetStatus() != StatusError {
		t.Errorf("status = %q, want %q", envelope.GetStatus(), StatusError)
	}
	if envelope.GetError().GetCode() != "config_invalid" {
		t.Errorf("error.code = %q, want config_invalid（§13 域内定义值）", envelope.GetError().GetCode())
	}
	if envelope.GetError().GetRequestId() != "req-biz-proto" {
		t.Errorf("error.request_id = %q, want %q", envelope.GetError().GetRequestId(), "req-biz-proto")
	}
}
