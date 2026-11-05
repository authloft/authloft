package sso

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/api/sso/v1/ssov1connect"
	"authloft/internal/service/orchestrator"
)

// fakeEngine 记录 handler 传入的 flow 与引擎入参，返回固定信封——本用例
// 只验证 handler 绑定 / 组装，不连真实 DB / Redis（自测要求）。
type fakeEngine struct {
	flow string
	req  orchestrator.Request
	resp *ssov1.LoginFlowResponse
}

func (f *fakeEngine) Submit(_ context.Context, flow string, req orchestrator.Request) *ssov1.LoginFlowResponse {
	f.flow, f.req = flow, req
	return f.resp
}

// TestLoginDefaultConnect 端到端经生成的 Connect handler + httptest 打
// SsoService/LoginDefault：HTTP 200，响应为登录流程信封而非 404。
func TestLoginDefaultConnect(t *testing.T) {
	engine := &fakeEngine{resp: &ssov1.LoginFlowResponse{
		Status:     "next",
		LoginToken: "tok-1",
		UserId:     10086,
	}}
	_, handler := ssov1connect.NewSsoServiceHandler(New(engine, nil))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	body := `{"method":"password","step":"verify","payload":{"username":"alice","password":"p"}}`
	resp, err := http.Post(srv.URL+ssov1connect.SsoServiceLoginDefaultProcedure,
		"application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST LoginDefault: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, http.StatusOK, raw)
	}

	var got ssov1.LoginFlowResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetStatus() != "next" || got.GetLoginToken() != "tok-1" || got.GetUserId() != 10086 {
		t.Fatalf("response = %+v", &got)
	}

	if engine.flow != loginFlow {
		t.Errorf("flow = %q, want %q", engine.flow, loginFlow)
	}
	if engine.req.Method != "password" || engine.req.Step != "verify" ||
		engine.req.Payload == nil || engine.req.Payload.Username != "alice" {
		t.Errorf("engine request = %+v", engine.req)
	}
}

// TestOtherMethodsUnimplemented 校验其余 5 个方法由生成基类返回
// unimplemented（CreateCaptchaImage、Register、ResetPassword 已实装，
// 移出桩清单）。
func TestOtherMethodsUnimplemented(t *testing.T) {
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil))
	cases := []string{
		ssov1connect.SsoServiceAuthorizeProcedure,
		ssov1connect.SsoServiceLoginOauthProcedure,
		ssov1connect.SsoServiceCreateQrcodeProcedure,
		ssov1connect.SsoServiceGetLoginTicketProcedure,
		ssov1connect.SsoServiceConfirmLoginTicketProcedure,
	}
	for _, procedure := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, procedure, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		var errBody struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
			t.Fatalf("%s: decode error body %q: %v", procedure, rec.Body.String(), err)
		}
		if errBody.Code != "unimplemented" {
			t.Errorf("%s: code = %q, want unimplemented (body %s)", procedure, errBody.Code, rec.Body.String())
		}
	}
}

// TestRegisterConnect 端到端经生成的 Connect handler + httptest 打
// SsoService/Register：HTTP 200 信封、flow=register、payload 逐项映射。
func TestRegisterConnect(t *testing.T) {
	engine := &fakeEngine{resp: &ssov1.LoginFlowResponse{
		Status:    "success",
		UserId:    10086,
		SessionId: "sid-1",
	}}
	_, handler := ssov1connect.NewSsoServiceHandler(New(engine, nil))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	body := `{"method":"password","step":"set_password","payload":{"username":"alice01","password":"p","captcha":{"providerKey":"builtin_image","id":"cap-1","answer":"1234"}}}`
	resp, err := http.Post(srv.URL+ssov1connect.SsoServiceRegisterProcedure,
		"application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST Register: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, http.StatusOK, raw)
	}

	var got ssov1.LoginFlowResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetStatus() != "success" || got.GetUserId() != 10086 {
		t.Fatalf("response = %+v", &got)
	}

	if engine.flow != registerFlow {
		t.Errorf("flow = %q, want %q", engine.flow, registerFlow)
	}
	if engine.req.Method != "password" || engine.req.Step != "set_password" ||
		engine.req.Payload == nil || engine.req.Payload.Username != "alice01" {
		t.Errorf("engine request = %+v", engine.req)
	}
	if engine.req.Captcha == nil || engine.req.Captcha.ProviderKey != "builtin_image" ||
		engine.req.Captcha.ID != "cap-1" || engine.req.Captcha.Answer != "1234" {
		t.Errorf("engine captcha = %+v", engine.req.Captcha)
	}
}

// TestResetPasswordConnect 端到端经生成的 Connect handler + httptest 打
// SsoService/ResetPassword：HTTP 200 信封、flow=reset、payload 逐项映射。
func TestResetPasswordConnect(t *testing.T) {
	engine := &fakeEngine{resp: &ssov1.LoginFlowResponse{
		Status:     "next",
		LoginToken: "tok-2",
	}}
	_, handler := ssov1connect.NewSsoServiceHandler(New(engine, nil))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	body := `{"loginToken":"tok-1","method":"otp_email","step":"set_password","payload":{"password":"new-secret"}}`
	resp, err := http.Post(srv.URL+ssov1connect.SsoServiceResetPasswordProcedure,
		"application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST ResetPassword: %v", err)
	}
	defer resp.Body.Close()
	raw := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, http.StatusOK, raw)
	}

	var got ssov1.LoginFlowResponse
	if err := protojson.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	if got.GetStatus() != "next" || got.GetLoginToken() != "tok-2" {
		t.Fatalf("response = %+v", &got)
	}

	if engine.flow != resetFlow {
		t.Errorf("flow = %q, want %q", engine.flow, resetFlow)
	}
	if engine.req.LoginToken != "tok-1" || engine.req.Method != "otp_email" ||
		engine.req.Step != "set_password" || engine.req.Payload == nil ||
		engine.req.Payload.Password != "new-secret" {
		t.Errorf("engine request = %+v", engine.req)
	}
}

func readBody(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
