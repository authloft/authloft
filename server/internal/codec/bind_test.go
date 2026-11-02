package codec

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/proto"

	ssoapi "authloft/gen/go/api/sso"
)

func newBindContext(contentType string, body []byte) *gin.Context {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/sso/login/default", bytes.NewReader(body))
	if contentType != "" {
		c.Request.Header.Set("Content-Type", contentType)
	}
	return c
}

func TestBindProto(t *testing.T) {
	want := &ssoapi.LoginDefaultRequest{LoginToken: "lt-1", Method: "password", Step: "verify"}
	body, err := proto.Marshal(want)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	c := newBindContext(mediaProto, body)
	got := &ssoapi.LoginDefaultRequest{}
	if err := Bind(c, got); err != nil {
		t.Fatalf("Bind(octet-stream) error: %v", err)
	}
	if !proto.Equal(got, want) {
		t.Errorf("decoded = %v, want %v", got, want)
	}
}

func TestBindJSON(t *testing.T) {
	// 接口文档 §1.1.1 行 74：application/json 含 charset；字段名必须是 snake_case。
	c := newBindContext("application/json; charset=utf-8", []byte(`{"login_token":"lt-1","method":"password","step":"verify"}`))
	got := &ssoapi.LoginDefaultRequest{}
	if err := Bind(c, got); err != nil {
		t.Fatalf("Bind(application/json) error: %v", err)
	}
	if got.GetLoginToken() != "lt-1" || got.GetMethod() != "password" || got.GetStep() != "verify" {
		t.Errorf("decoded = %v, want login_token/method/step from snake_case body", got)
	}
}

func TestBindJSONRejectsUnknownField(t *testing.T) {
	// §1.6 行 87：DiscardUnknown=false，未知字段 → 400。
	c := newBindContext(mediaJSON, []byte(`{"method":"password","unknown_field":"x"}`))
	err := Bind(c, &ssoapi.LoginDefaultRequest{})
	if err == nil {
		t.Fatal("Bind must reject unknown field")
	}
	if !errors.Is(err, ErrDecode) {
		t.Errorf("error = %v, want ErrDecode", err)
	}
}

func TestBindUnsupportedMediaType(t *testing.T) {
	for _, contentType := range []string{"", "text/plain", "multipart/form-data; boundary=x"} {
		c := newBindContext(contentType, []byte(`{}`))
		err := Bind(c, &ssoapi.LoginDefaultRequest{})
		if !errors.Is(err, ErrUnsupportedMediaType) {
			t.Errorf("Content-Type=%q error = %v, want ErrUnsupportedMediaType", contentType, err)
		}
	}
}

func TestBindEmptyBody(t *testing.T) {
	for _, contentType := range []string{mediaJSON, mediaProto} {
		c := newBindContext(contentType, nil)
		err := Bind(c, &ssoapi.LoginDefaultRequest{})
		if !errors.Is(err, ErrEmptyBody) {
			t.Errorf("Content-Type=%q error = %v, want ErrEmptyBody", contentType, err)
		}
	}
}

func TestBindInvalidBody(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{name: "非法 JSON", contentType: mediaJSON, body: []byte(`{"method":`)},
		{name: "非法 Protobuf", contentType: mediaProto, body: []byte{0x08}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newBindContext(tt.contentType, tt.body)
			err := Bind(c, &ssoapi.LoginDefaultRequest{})
			if !errors.Is(err, ErrDecode) {
				t.Errorf("error = %v, want ErrDecode", err)
			}
		})
	}
}

func TestBindRejectsOversizedBody(t *testing.T) {
	body := bytes.Repeat([]byte("a"), int(maxBodyBytes)+1)
	c := newBindContext(mediaJSON, body)
	err := Bind(c, &ssoapi.LoginDefaultRequest{})
	if !errors.Is(err, ErrDecode) {
		t.Fatalf("error = %v, want ErrDecode", err)
	}
	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) {
		t.Errorf("error = %v, want http.MaxBytesError (MaxBytesReader must reject)", err)
	}
	if maxErr.Limit != maxBodyBytes {
		t.Errorf("MaxBytesError limit = %d, want %d", maxErr.Limit, maxBodyBytes)
	}
}

// 保证错误包装链可被 handler 用 errors.Is 判别（fmt 多 %w）。
func TestBindErrorsRemainDistinguishable(t *testing.T) {
	c := newBindContext(mediaJSON, []byte(`{`))
	err := Bind(c, &ssoapi.LoginDefaultRequest{})
	if !errors.Is(err, ErrDecode) || errors.Is(err, ErrEmptyBody) || errors.Is(err, ErrUnsupportedMediaType) {
		t.Errorf("error = %v, want only ErrDecode", err)
	}
}
