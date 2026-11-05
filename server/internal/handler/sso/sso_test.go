package sso

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/api/sso/v1/ssov1connect"
	"authloft/internal/service/orchestrator"
	"authloft/internal/session"
)

// fakeEngine 记录 handler 传入的 flow 与引擎入参，返回固定信封——本用例
// 只验证 handler 绑定 / 组装，不连真实 DB / Redis（自测要求）。
// sinkToken 非空时模拟引擎契约：Submit 内经 ctx 写点回调一次
//（真实引擎仅在 status=success 终点建会话后回调；失败态 / 中间态不回调）。
type fakeEngine struct {
	flow      string
	req       orchestrator.Request
	resp      *ssov1.LoginFlowResponse
	sinkToken string
}

func (f *fakeEngine) Submit(ctx context.Context, flow string, req orchestrator.Request) *ssov1.LoginFlowResponse {
	f.flow, f.req = flow, req
	if f.sinkToken != "" {
		if sink, ok := orchestrator.SessionTokenSinkFromContext(ctx); ok {
			sink(f.sinkToken)
		}
	}
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
	_, handler := ssov1connect.NewSsoServiceHandler(New(engine, nil, nil, nil))
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

// TestOtherMethodsUnimplemented 校验其余 3 个扫码方法由生成基类返回
// unimplemented（CreateCaptchaImage、Register、ResetPassword 已实装；
// Authorize / LoginOauth 已实装，均移出桩清单；扫码三方法暂不实装）。
// 未装配三方 service 时 Authorize / LoginOauth 亦 unimplemented（oauth_test.go
// TestThirdpartyNotConfigured 单测覆盖）。
func TestOtherMethodsUnimplemented(t *testing.T) {
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, nil))
	cases := []string{
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
	_, handler := ssov1connect.NewSsoServiceHandler(New(engine, nil, nil, nil))
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
	_, handler := ssov1connect.NewSsoServiceHandler(New(engine, nil, nil, nil))
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

// TestSuccessIssuesSessionCookie 三个登录端点的 status=success 均
// 经引擎写点下发 Set-Cookie: al_session（名 / 值 / 完整属性
// HttpOnly; Secure; SameSite=None; Path=/ + TTL=7 天，§1.9 行 288），且
// 浏览器成功响应 body 零 session_token 字段（§1.3 行 135 仅无 Cookie 场景返回）。
func TestSuccessIssuesSessionCookie(t *testing.T) {
	cases := []struct {
		name      string
		procedure string
		body      string
	}{
		{
			name:      "LoginDefault密码成功",
			procedure: ssov1connect.SsoServiceLoginDefaultProcedure,
			body:      `{"method":"password","step":"verify","payload":{"username":"alice","password":"p"}}`,
		},
		{
			name:      "Register set_password成功",
			procedure: ssov1connect.SsoServiceRegisterProcedure,
			body:      `{"method":"password","step":"set_password","payload":{"username":"alice01","password":"p","captcha":{"providerKey":"builtin_image","id":"cap-1","answer":"1234"}}}`,
		},
		{
			name:      "ResetPassword成功",
			procedure: ssov1connect.SsoServiceResetPasswordProcedure,
			body:      `{"loginToken":"tok-1","method":"otp_email","step":"set_password","payload":{"password":"new-secret"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := &fakeEngine{
				resp:      &ssov1.LoginFlowResponse{Status: "success", SessionId: "sid-1", UserId: 42},
				sinkToken: "stok-1",
			}
			_, handler := ssov1connect.NewSsoServiceHandler(
				New(engine, nil, session.NewCookie("al_session", "", 7*24*time.Hour), nil),
			)
			srv := httptest.NewServer(handler)
			defer srv.Close()

			resp, err := http.Post(srv.URL+tc.procedure, "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("POST %s: %v", tc.name, err)
			}
			defer resp.Body.Close()
			raw := readBody(t, resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: status = %d, want %d (body %s)", tc.name, resp.StatusCode, http.StatusOK, raw)
			}

			cookies := resp.Cookies()
			if len(cookies) != 1 {
				t.Fatalf("%s: Set-Cookie 出现 %d 枚, want 1: %v", tc.name, len(cookies), resp.Header.Values("Set-Cookie"))
			}
			ck := cookies[0]
			if ck.Name != "al_session" || ck.Value != "stok-1" {
				t.Errorf("%s: cookie 名/值 = %q/%q, want al_session/stok-1", tc.name, ck.Name, ck.Value)
			}
			if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteNoneMode || ck.Path != "/" {
				t.Errorf("%s: 属性 HttpOnly=%v Secure=%v SameSite=%v Path=%q, want true/true/None//（§1.9 行 288）",
					tc.name, ck.HttpOnly, ck.Secure, ck.SameSite, ck.Path)
			}
			if ck.MaxAge != 7*24*3600 {
				t.Errorf("%s: MaxAge = %d, want %d（注入 ttl=7 天）", tc.name, ck.MaxAge, 7*24*3600)
			}
			// 浏览器成功响应 body 不得出现 session_token（protojson 零值省略）。
			if strings.Contains(raw, "sessionToken") {
				t.Errorf("%s: success body 不得含 session_token 字段: %s", tc.name, raw)
			}
		})
	}
}

// TestNonSuccessZeroSetCookie 失败态 / 中间态零 Set-Cookie：引擎契约
// 仅 status=success 建会话后回调写点，failed / next 响应不携带任何 Set-Cookie。
func TestNonSuccessZeroSetCookie(t *testing.T) {
	for _, status := range []string{"failed", "next"} {
		engine := &fakeEngine{resp: &ssov1.LoginFlowResponse{Status: status, LoginToken: "tok-2"}}
		_, handler := ssov1connect.NewSsoServiceHandler(
			New(engine, nil, session.NewCookie("al_session", "", 7*24*time.Hour), nil),
		)
		srv := httptest.NewServer(handler)
		defer srv.Close()

		body := `{"method":"password","step":"verify","payload":{"username":"alice","password":"p"}}`
		resp, err := http.Post(srv.URL+ssov1connect.SsoServiceLoginDefaultProcedure,
			"application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST LoginDefault: %v", err)
		}
		defer resp.Body.Close()
		readBody(t, resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status=%s: HTTP %d, want 200", status, resp.StatusCode)
		}
		if got := resp.Header.Values("Set-Cookie"); len(got) != 0 {
			t.Errorf("status=%s: Set-Cookie = %v, want 空（失败/中间态零 Set-Cookie）", status, got)
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
