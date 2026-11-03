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

func newBindContextRec(contentType string, body []byte) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/sso/login/default", bytes.NewReader(body))
	if contentType != "" {
		c.Request.Header.Set("Content-Type", contentType)
	}
	return c, rec
}

func newBindContext(contentType string, body []byte) *gin.Context {
	c, _ := newBindContextRec(contentType, body)
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

// exactBody 构造总长 n 字节且合法的 JSON body（login_token 填充到恰好 n 字节）。
func exactBody(n int) []byte {
	prefix, suffix := []byte(`{"login_token":"`), []byte(`"}`)
	body := make([]byte, 0, n)
	body = append(body, prefix...)
	body = append(body, bytes.Repeat([]byte("a"), n-len(prefix)-len(suffix))...)
	body = append(body, suffix...)
	return body
}

// ① 未注入时回落默认 1 MiB（§3.14 行 492）：恰好 1 MiB 成功、超 1 字节失败。
func TestBindDefaultMaxBodyBytes(t *testing.T) {
	if maxBodyBytes != defaultMaxBodyBytes {
		t.Fatalf("maxBodyBytes = %d, want default %d（未注入 SetMaxBodyBytes）", maxBodyBytes, defaultMaxBodyBytes)
	}

	c := newBindContext(mediaJSON, exactBody(int(defaultMaxBodyBytes)))
	if err := Bind(c, &ssoapi.LoginDefaultRequest{}); err != nil {
		t.Errorf("Bind(恰好 %d 字节) error: %v", defaultMaxBodyBytes, err)
	}

	c = newBindContext(mediaJSON, bytes.Repeat([]byte("a"), int(defaultMaxBodyBytes)+1))
	err := Bind(c, &ssoapi.LoginDefaultRequest{})
	if !errors.Is(err, ErrDecode) {
		t.Fatalf("error = %v, want ErrDecode", err)
	}
	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) || maxErr.Limit != defaultMaxBodyBytes {
		t.Errorf("MaxBytesError limit = %v, want %d", maxErr, defaultMaxBodyBytes)
	}
}

// ② SetMaxBodyBytes 注入后立即生效（§3.14 行 492）；n <= 0 不生效，防止上限被关成 0。
func TestSetMaxBodyBytes(t *testing.T) {
	t.Cleanup(func() { SetMaxBodyBytes(defaultMaxBodyBytes) })

	SetMaxBodyBytes(64)
	SetMaxBodyBytes(0)  // 非正值必须被忽略
	SetMaxBodyBytes(-1) // 同上

	c := newBindContext(mediaJSON, exactBody(64))
	if err := Bind(c, &ssoapi.LoginDefaultRequest{}); err != nil {
		t.Errorf("Bind(恰好 64 字节) error: %v", err)
	}

	c = newBindContext(mediaJSON, bytes.Repeat([]byte("a"), 65))
	err := Bind(c, &ssoapi.LoginDefaultRequest{})
	var maxErr *http.MaxBytesError
	if !errors.Is(err, ErrDecode) || !errors.As(err, &maxErr) || maxErr.Limit != 64 {
		t.Errorf("error = %v, want ErrDecode with MaxBytesError{Limit: 64}", err)
	}
}

// ③ 超限经 WriteBindError 落成 400 bad_request（§1.5 行 199 封闭集合，不新增 413）。
func TestBindOversizedBodyWritesBadRequest(t *testing.T) {
	SetMaxBodyBytes(64)
	t.Cleanup(func() { SetMaxBodyBytes(defaultMaxBodyBytes) })

	c, rec := newBindContextRec(mediaJSON, bytes.Repeat([]byte("a"), 65))
	err := Bind(c, &ssoapi.LoginDefaultRequest{})
	if !errors.Is(err, ErrDecode) {
		t.Fatalf("Bind error = %v, want ErrDecode", err)
	}
	WriteBindError(c, err)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if got := errorObject(t, decodeErrorMap(t, rec.Body.Bytes()))["code"]; got != CodeBadRequest {
		t.Errorf("error.code = %v, want %q", got, CodeBadRequest)
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
