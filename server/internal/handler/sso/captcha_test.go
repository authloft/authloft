// captcha_test.go 覆盖 SsoService/CreateCaptchaImage（接口文档
// §2.5 行 491-498）：经生成的 Connect handler + httptest 端到端断言 200
// 响应结构（id 非空 / imageBase64 为合法 PNG / expiresIn=300）与答案落存。
package sso

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/api/sso/v1/ssov1connect"
	"authloft/internal/captcha"
)

// fakeImageStore 模拟 cache.CaptchaStore：Set 记录答案（al:cap:{id} 的
// fake 形态），Verify 一次性消费（比对即删，对应 Lua GETDEL）。
type fakeImageStore struct {
	answers map[string]string
	setN    int
}

func (f *fakeImageStore) Set(_ context.Context, id, answer string) error {
	f.setN++
	f.answers[id] = answer
	return nil
}

func (f *fakeImageStore) Verify(_ context.Context, id, answer string) (bool, error) {
	stored, ok := f.answers[id]
	delete(f.answers, id)
	return ok && stored == answer, nil
}

// TestCreateCaptchaImageConnect 端到端：POST CreateCaptchaImage → HTTP
// 200，响应 {id 非空, imageBase64 非空且为 PNG, expiresIn=300}，答案已
// 写入存储（对应 al:cap:{id} EX 300）。
func TestCreateCaptchaImageConnect(t *testing.T) {
	store := &fakeImageStore{answers: map[string]string{}}
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, captcha.NewImageCaptcha(store)))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+ssov1connect.SsoServiceCreateCaptchaImageProcedure,
		"application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST CreateCaptchaImage: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, http.StatusOK, raw)
	}

	var got ssov1.CreateCaptchaImageResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetId() == "" {
		t.Fatalf("id 为空 (body %s)", raw)
	}
	if got.GetImageBase64() == "" {
		t.Fatalf("image_base64 为空 (body %s)", raw)
	}
	if got.GetExpiresIn() != 300 {
		t.Fatalf("expires_in = %d, want 300", got.GetExpiresIn())
	}
	png, err := base64.StdEncoding.DecodeString(got.GetImageBase64())
	if err != nil {
		t.Fatalf("image_base64 解码: %v", err)
	}
	if len(png) < 4 || string(png[:4]) != "\x89PNG" {
		t.Fatalf("image_base64 不是 PNG（前缀 %q）", png[:4])
	}
	if store.setN != 1 {
		t.Fatalf("Set 调用次数 = %d, want 1", store.setN)
	}
	if _, ok := store.answers[got.GetId()]; !ok {
		t.Fatalf("答案未写入存储（id %q）", got.GetId())
	}
}

// TestCreateCaptchaImageNotConfigured 未注入图形码实现（测试 / 半装配
// 口径）→ Connect internal 错误，不 panic。
func TestCreateCaptchaImageNotConfigured(t *testing.T) {
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceCreateCaptchaImageProcedure, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "internal") {
		t.Fatalf("code = %s, want internal (body %s)", rec.Body.String(), rec.Body.String())
	}
}
