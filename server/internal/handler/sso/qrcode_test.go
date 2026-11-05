// qrcode_test.go 覆盖扫码三桩的 handler 层用例：CreateQrcode 响应透传 +
// 哨兵错误映射（captcha_required / captcha_invalid 带 ErrorInfo、bind 无
// 会话 401、provider_disabled 400）；GetLoginTicket 信封透传 + 命中建会话
// 后 Set-Cookie: al_session；ConfirmLoginTicket 的 uid 从 ctx 注入与
// TicketStatus 回显、同 uid 校验失败 400 / 无会话 401；未装配扫码 service
// unimplemented；小程序端无 Origin 走 Referer 白名单的实证接线（与 bootstrap
// 同款 HTTPOriginFunc + 动态 allowlist 组链）。全部走 fake，不连 DB / Redis。
package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/api/sso/v1/ssov1connect"
	"authloft/gen/go/token"
	"authloft/internal/middleware"
	"authloft/internal/service"
	"authloft/internal/session"
)

// fakeQrcode service.QRCode 的 fake：记录入参、返回预置产物。
type fakeQrcode struct {
	createOut   *service.CreateQrcodeOutput
	createErr   error
	gotCreate   service.CreateQrcodeInput
	captchaSet  bool
	captchaSeen *ssov1CaptchaView

	pollOut   *service.GetLoginTicketOutput
	gotPoll   service.GetLoginTicketInput
	pollCalls int

	confirmOut   *ssov1.TicketStatus
	confirmErr   error
	gotConfirm   service.ConfirmLoginTicketInput
	confirmCalls int
}

// ssov1CaptchaView 测试内联视图（避免直接引用 CaptchaPayload 生成类型的
// 字段名拼写）：仅记录 providerKey / id / answer 三个断言面。
type ssov1CaptchaView struct {
	ProviderKey string
	ID          string
	Answer      string
}

func (f *fakeQrcode) CreateQrcode(_ context.Context, in service.CreateQrcodeInput) (*service.CreateQrcodeOutput, error) {
	f.gotCreate = in
	if in.Captcha != nil {
		f.captchaSet = true
		f.captchaSeen = &ssov1CaptchaView{ProviderKey: in.Captcha.ProviderKey, ID: in.Captcha.ID, Answer: in.Captcha.Answer}
	}
	return f.createOut, f.createErr
}

func (f *fakeQrcode) GetLoginTicket(_ context.Context, in service.GetLoginTicketInput) *service.GetLoginTicketOutput {
	f.pollCalls++
	f.gotPoll = in
	return f.pollOut
}

func (f *fakeQrcode) ConfirmLoginTicket(_ context.Context, in service.ConfirmLoginTicketInput) (*ssov1.TicketStatus, error) {
	f.confirmCalls++
	f.gotConfirm = in
	return f.confirmOut, f.confirmErr
}

// TestCreateQrcodeConnect 200 透传 + captcha payload 映射 + bind 的 uid
// 从 ctx 注入。
func TestCreateQrcodeConnect(t *testing.T) {
	qr := &fakeQrcode{createOut: &service.CreateQrcodeOutput{
		Ticket: "sealed-ticket", TicketID: "c7Kx9", QrcodeURL: "https://cdn.example.com/qr/c7Kx9.jpg", ExpiresIn: 600,
	}}
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, nil, qr))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	body := `{"providerKey":"wechat_mp_scan","scene":"bind","captcha":{"providerKey":"builtin_image","id":"cap-1","answer":"123456"}}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+ssov1connect.SsoServiceCreateQrcodeProcedure, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST CreateQrcode: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP = %d, want 200", resp.StatusCode)
	}
	var got struct {
		Ticket    string `json:"ticket"`
		TicketID  string `json:"ticketId"`
		QrcodeURL string `json:"qrcodeUrl"`
		ExpiresIn string `json:"expiresIn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Ticket != "sealed-ticket" || got.TicketID != "c7Kx9" ||
		got.QrcodeURL != "https://cdn.example.com/qr/c7Kx9.jpg" || got.ExpiresIn != "600" {
		t.Fatalf("body = %+v", got)
	}
	if qr.gotCreate.ProviderKey != "wechat_mp_scan" || qr.gotCreate.Scene != "bind" {
		t.Errorf("service 入参 = %+v", qr.gotCreate)
	}
	if !qr.captchaSet || qr.captchaSeen.ProviderKey != "builtin_image" || qr.captchaSeen.ID != "cap-1" || qr.captchaSeen.Answer != "123456" {
		t.Errorf("captcha 映射 = %+v", qr.captchaSeen)
	}
}

// TestCreateQrcodeErrorMapping 哨兵错误映射：captcha_required 400+ErrorInfo /
// captcha_invalid 400+ErrorInfo / bind 无会话 401 / provider_disabled 400 /
// 未知错误 500。
func TestCreateQrcodeErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantHTTP   int
		wantDetail string
	}{
		{"captcha 缺失", service.ErrQrcodeCaptchaRequired, http.StatusBadRequest, "captcha_required"},
		{"captcha 无效", service.ErrQrcodeCaptchaInvalid, http.StatusBadRequest, "captcha_invalid"},
		{"bind 无会话", service.ErrQrcodeUnauthenticated, http.StatusUnauthorized, ""},
		{"provider 未配置", service.ErrQrcodeProviderDisabled, http.StatusBadRequest, "provider_disabled"},
		{"参数非法", service.ErrQrcodeInvalidRequest, http.StatusBadRequest, "invalid_request"},
		{"内部错误", context.DeadlineExceeded, http.StatusInternalServerError, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qr := &fakeQrcode{createErr: tc.err}
			_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, nil, qr))
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceCreateQrcodeProcedure, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantHTTP {
				t.Fatalf("HTTP = %d, want %d (body %s)", rec.Code, tc.wantHTTP, rec.Body.String())
			}
			if tc.wantDetail != "" && !strings.Contains(rec.Body.String(), tc.wantDetail) {
				// ErrorInfo detail 为 base64 调试视图，此处断言 code 出现在
				// 错误体 JSON（含 details debug 字段）。
				var body struct {
					Details []struct {
						Debug map[string]string `json:"debug"`
					} `json:"details"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Details) == 0 ||
					body.Details[0].Debug["code"] != tc.wantDetail {
					t.Errorf("ErrorInfo code 缺失 %q (body %s)", tc.wantDetail, rec.Body.String())
				}
			}
		})
	}
}

// TestGetLoginTicketConnect 信封透传 + SessionToken 下发 al_session（§1.9
// 行 288 与 LoginOauth redirect 同一构造器与属性）。
func TestGetLoginTicketConnect(t *testing.T) {
	qr := &fakeQrcode{pollOut: &service.GetLoginTicketOutput{
		Envelope: &ssov1.LoginFlowResponse{
			Status: "success",
			Ticket: &ssov1.TicketStatus{Status: "success", TicketId: "c7Kx9"},
			Login:  &ssov1.LoginFlowResponse{Status: "success", UserId: 7},
		},
		SessionToken: "stok-poll-1",
	}}
	_, handler := ssov1connect.NewSsoServiceHandler(
		New(&fakeEngine{}, nil, sessionCookieForTest(), nil, qr))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+ssov1connect.SsoServiceGetLoginTicketProcedure,
		"application/json", strings.NewReader(`{"ticket":"sealed","poll":"15"}`))
	if err != nil {
		t.Fatalf("POST GetLoginTicket: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP = %d, want 200", resp.StatusCode)
	}
	if qr.gotPoll.Ticket != "sealed" || qr.gotPoll.Poll != 15 {
		t.Errorf("service 入参 = %+v", qr.gotPoll)
	}
	var cookie string
	for _, c := range resp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, "al_session=") {
			cookie = c
		}
	}
	if !strings.Contains(cookie, "stok-poll-1") {
		t.Errorf("应下发 Set-Cookie: al_session=stok-poll-1, got %q", cookie)
	}
	got := decodeEnvelope(t, readBody(t, resp.Body))
	if got.GetStatus() != "success" || got.GetTicket().GetStatus() != "success" ||
		got.GetTicket().GetTicketId() != "c7Kx9" || got.GetLogin().GetUserId() != 7 {
		t.Errorf("envelope = %+v", got)
	}
}

// TestGetLoginTicketNoSessionTokenNoCookie 非 success 轮询（pending）零
// Set-Cookie、信封透传。
func TestGetLoginTicketNoSessionTokenNoCookie(t *testing.T) {
	qr := &fakeQrcode{pollOut: &service.GetLoginTicketOutput{
		Envelope: &ssov1.LoginFlowResponse{
			Status: "pending", Ticket: &ssov1.TicketStatus{Status: "pending", TicketId: "c7Kx9"},
		},
	}}
	_, handler := ssov1connect.NewSsoServiceHandler(
		New(&fakeEngine{}, nil, sessionCookieForTest(), nil, qr))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceGetLoginTicketProcedure,
		strings.NewReader(`{"ticket":"sealed"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP = %d, want 200", rec.Code)
	}
	for _, c := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(c, "al_session=") {
			t.Errorf("pending 轮询不应下发会话, got %q", c)
		}
	}
	if !strings.Contains(rec.Body.String(), `"pending"`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

// TestConfirmLoginTicketConnect uid 从 ctx 注入（session.WithSessionContext，
// 会话拦截器等效）+ TicketStatus 回显 + body session 透传 + 错误映射
// （同 uid 校验失败 400 / 无会话 401）。
func TestConfirmLoginTicketConnect(t *testing.T) {
	// 主体用例：ctx 带 uid=9（模拟会话拦截器注入），body session 缺省 →
	// service 收到 SessionUID=9；同 uid 校验失败与无会话映射。
	t.Run("ctx uid 注入 + 回显", func(t *testing.T) {
		qr := &fakeQrcode{confirmOut: &ssov1.TicketStatus{Status: "success", TicketId: "c7Kx9"}}
		_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, nil, qr),
			connect.WithInterceptors(connect.UnaryInterceptorFunc(
				func(next connect.UnaryFunc) connect.UnaryFunc {
					return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
						return next(session.WithSessionContext(ctx,
							&token.SessionTokenPayload{Id: 9, Epoch: 1, Exp: time.Now().Add(time.Hour).Unix()}), req)
					}
				})))
		srv := httptest.NewServer(handler)
		defer srv.Close()

		resp, err := http.Post(srv.URL+ssov1connect.SsoServiceConfirmLoginTicketProcedure,
			"application/json", strings.NewReader(`{"ticketId":"c7Kx9"}`))
		if err != nil {
			t.Fatalf("POST ConfirmLoginTicket: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("HTTP = %d, want 200", resp.StatusCode)
		}
		var got struct {
			Status   string `json:"status"`
			TicketID string `json:"ticketId"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Status != "success" || got.TicketID != "c7Kx9" {
			t.Fatalf("body = %+v, want {success c7Kx9}", got)
		}
		if qr.gotConfirm.TicketID != "c7Kx9" || qr.gotConfirm.SessionUID != 9 || qr.gotConfirm.Session != "" {
			t.Errorf("service 入参 = %+v, want SessionUID=9（ctx 注入）", qr.gotConfirm)
		}
	})

	t.Run("body session 透传", func(t *testing.T) {
		qr := &fakeQrcode{confirmOut: &ssov1.TicketStatus{Status: "success", TicketId: "c7Kx9"}}
		_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, nil, qr))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceConfirmLoginTicketProcedure,
			strings.NewReader(`{"ticketId":"c7Kx9","session":"body-session-token"}`))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("HTTP = %d (body %s)", rec.Code, rec.Body.String())
		}
		if qr.gotConfirm.Session != "body-session-token" {
			t.Errorf("body session = %q, want 透传", qr.gotConfirm.Session)
		}
	})

	t.Run("错误映射", func(t *testing.T) {
		cases := []struct {
			name     string
			err      error
			wantHTTP int
		}{
			{"uid 不一致", service.ErrQrcodeInvalidRequest, http.StatusBadRequest},
			{"无会话", service.ErrQrcodeUnauthenticated, http.StatusUnauthorized},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				qr := &fakeQrcode{confirmErr: tc.err}
				_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, nil, qr))
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceConfirmLoginTicketProcedure,
					strings.NewReader(`{"ticketId":"c7Kx9"}`))
				req.Header.Set("Content-Type", "application/json")
				handler.ServeHTTP(rec, req)
				if rec.Code != tc.wantHTTP {
					t.Fatalf("HTTP = %d, want %d", rec.Code, tc.wantHTTP)
				}
			})
		}
	})
}

// TestQrcodeNotConfigured 未装配扫码 service：三桩返回 unimplemented。
func TestQrcodeNotConfigured(t *testing.T) {
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, nil, nil))
	for _, procedure := range []string{
		ssov1connect.SsoServiceCreateQrcodeProcedure,
		ssov1connect.SsoServiceGetLoginTicketProcedure,
		ssov1connect.SsoServiceConfirmLoginTicketProcedure,
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, procedure, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		var errBody struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
			t.Fatalf("%s: decode: %v", procedure, err)
		}
		if errBody.Code != "unimplemented" {
			t.Errorf("%s: code = %q, want unimplemented", procedure, errBody.Code)
		}
	}
}

// TestQrcodeRefererWhitelistWiring 小程序端无 Origin 走 Referer 白名单的
// 实证接线（§13.2 行 1597、§1.1 行 80）：与 bootstrap 同款
// middleware.HTTPOriginFunc + 动态 allowlist 组链，POST LoginOauth
// （小程序提交形态）带 Referer https://servicewechat.com/{appid}/… 放行；
// Referer 不在白名单 → 403。allowlist 即 bootstrap 注入的
// providerWhitelist.AppIDs 形态（复用既有链路，此处实证）。
func TestQrcodeRefererWhitelistWiring(t *testing.T) {
	tp := &fakeThirdparty{oauthOut: &service.OauthOutput{
		Envelope: &ssov1.LoginFlowResponse{Status: "success", SessionToken: "stok-mini"},
	}}
	_, handler := ssov1connect.NewSsoServiceHandler(
		New(&fakeEngine{}, nil, sessionCookieForTest(), tp, nil))
	srv := httptest.NewServer(middleware.HTTPOriginFunc("https://auth.example.com", func(context.Context) []string {
		return []string{"wx-app-001"} // providerWhitelist.AppIDs 等效形态
	}, handler))
	defer srv.Close()

	do := func(referer string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+ssov1connect.SsoServiceLoginOauthProcedure,
			strings.NewReader(`{"providerKey":"wechat_mp_scan","code":"wx-code"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Referer", referer)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	// 无 Origin + Referer 命中 servicewechat.com/{appid} 白名单 → 放行。
	if code := do("https://servicewechat.com/wx-app-001/page-frame.html"); code != http.StatusOK {
		t.Fatalf("小程序 Referer 白名单应放行, HTTP = %d", code)
	}
	// appid 不在白名单 → 403（origin 中间件）。
	if code := do("https://servicewechat.com/wx-other-002/page-frame.html"); code != http.StatusForbidden {
		t.Fatalf("非白名单 Referer 应 403, HTTP = %d", code)
	}
}
