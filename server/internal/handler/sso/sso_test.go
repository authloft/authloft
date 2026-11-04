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
// 只验证 handler 绑定 / 组装，不连真实 DB / Redis（卡面自测要求）。
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
	_, handler := ssov1connect.NewSsoServiceHandler(New(engine))
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

// TestOtherMethodsUnimplemented 校验其余 8 个方法由生成基类返回
// unimplemented（卡面 NON-GOALS）。
func TestOtherMethodsUnimplemented(t *testing.T) {
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}))
	cases := []string{
		ssov1connect.SsoServiceRegisterProcedure,
		ssov1connect.SsoServiceResetPasswordProcedure,
		ssov1connect.SsoServiceCreateCaptchaImageProcedure,
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

func readBody(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
