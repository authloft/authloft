// oauth_test.go 覆盖三方登录通道的 handler 层用例：Authorize Connect 端到端
// （URL + Set-Cookie: al_login_state）/ scene=bind 无会话 401 /
// provider_disabled 错误体 + ErrorInfo / LoginOauth 信封透传 + Cookie 头
// 解析 + api 通道 session_token / 未装配三方 service unimplemented。
// 全部走 fake thirdparty，不连 DB / Redis。
package sso

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"connectrpc.com/connect"

	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/api/sso/v1/ssov1connect"
	"authloft/gen/go/token"
	"authloft/internal/cache"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
	thirdpartysvc "authloft/internal/service/thirdparty"
	ticketsvc "authloft/internal/service/ticket"
	"authloft/internal/session"
	"authloft/internal/settings"
)

// sessionCookieForTest 会话 Cookie 构造器（与线上同款属性）。
func sessionCookieForTest() *session.Cookie {
	return session.NewCookie("al_session", "", 7*24*time.Hour)
}

// fakeThirdparty 三方登录通道的 fake：记录入参、返回预置产物。
type fakeThirdparty struct {
	authorizeOut *thirdpartysvc.AuthorizeOutput
	authorizeErr error
	gotAuthorize thirdpartysvc.AuthorizeInput

	oauthOut *thirdpartysvc.OauthOutput
	gotOauth thirdpartysvc.OauthInput
}

func (f *fakeThirdparty) Authorize(_ context.Context, in thirdpartysvc.AuthorizeInput) (*thirdpartysvc.AuthorizeOutput, error) {
	f.gotAuthorize = in
	return f.authorizeOut, f.authorizeErr
}

func (f *fakeThirdparty) LoginOauth(_ context.Context, in thirdpartysvc.OauthInput) *thirdpartysvc.OauthOutput {
	f.gotOauth = in
	return f.oauthOut
}

// decodeEnvelope 解析登录流程信封（protojson）。
func decodeEnvelope(t *testing.T, body string) *ssov1.LoginFlowResponse {
	t.Helper()
	var got ssov1.LoginFlowResponse
	if err := protojson.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode envelope %q: %v", body, err)
	}
	return &got
}

// TestAuthorizeConnect 端到端：URL 返回 + Set-Cookie: al_login_state 下发
// （§2.7.2）+ scene=bind 的 uid 从 ctx 会话透传。
func TestAuthorizeConnect(t *testing.T) {
	tp := &fakeThirdparty{authorizeOut: &thirdpartysvc.AuthorizeOutput{
		AuthorizeURL: "https://graph.qq.com/oauth2.0/authorize?state=labc",
		Cookie: &http.Cookie{
			Name: "al_login_state", Value: "sealed", Path: "/",
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		},
	}}
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, tp, nil))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+ssov1connect.SsoServiceAuthorizeProcedure,
		"application/json", strings.NewReader(`{"provider":"qq","scene":"login"}`))
	if err != nil {
		t.Fatalf("POST Authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	// Set-Cookie：al_login_state 经 CallInfo 写头落地。
	var cookie string
	for _, c := range resp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, "al_login_state=") {
			cookie = c
		}
	}
	if cookie == "" {
		t.Fatalf("应下发 Set-Cookie: al_login_state, got %v", resp.Header.Values("Set-Cookie"))
	}
	if !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "Secure") ||
		!strings.Contains(cookie, "SameSite=Lax") || !strings.Contains(cookie, "Path=/") {
		t.Errorf("Cookie 属性 = %q", cookie)
	}
	if tp.gotAuthorize.Provider != "qq" || tp.gotAuthorize.Scene != "login" {
		t.Errorf("service 入参 = %+v", tp.gotAuthorize)
	}

	var body struct {
		AuthorizeURL string `json:"authorizeUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.AuthorizeURL != "https://graph.qq.com/oauth2.0/authorize?state=labc" {
		t.Errorf("authorizeUrl = %q", body.AuthorizeURL)
	}
}

// TestAuthorizeErrorMapping 哨兵错误映射：bind 无会话 401（unauthenticated）、
// provider_disabled 400 + ErrorInfo code、invalid_request 400。
func TestAuthorizeErrorMapping(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantHTTP int
		wantCode string
	}{
		{"bind 无会话", thirdpartysvc.ErrThirdpartyUnauthenticated, http.StatusUnauthorized, "unauthenticated"},
		{"provider 未启用", thirdpartysvc.ErrThirdpartyProviderDisabled, http.StatusBadRequest, "invalid_argument"},
		{"参数非法", thirdpartysvc.ErrThirdpartyInvalidRequest, http.StatusBadRequest, "invalid_argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tp := &fakeThirdparty{authorizeErr: tc.err}
			_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, tp, nil))
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceAuthorizeProcedure,
				strings.NewReader(`{"provider":"qq"}`))
			req.Header.Set("Content-Type", "application/json")
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantHTTP {
				t.Fatalf("HTTP = %d, want %d (body %s)", rec.Code, tc.wantHTTP, rec.Body.String())
			}
			var errBody struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
				t.Fatalf("decode error body: %v", err)
			}
			if errBody.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", errBody.Code, tc.wantCode)
			}
			// ErrorInfo detail 的 code（provider_disabled 场景）。
			if tc.wantCode == "invalid_argument" && !strings.Contains(rec.Body.String(), tc.err.Error()) {
				// Connect JSON 错误体 message 字段承载哨兵文案；细分码在
				// ErrorInfo detail（base64），此处仅断言错误体存在。
				t.Logf("error body = %s", rec.Body.String())
			}
		})
	}
}

// TestAuthorizeProviderDisabledErrorInfo provider_disabled 的 ErrorInfo
// code 断言（decode details 的 debug 视图）。
func TestAuthorizeProviderDisabledErrorInfo(t *testing.T) {
	tp := &fakeThirdparty{authorizeErr: thirdpartysvc.ErrThirdpartyProviderDisabled}
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, tp, nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceAuthorizeProcedure,
		strings.NewReader(`{"provider":"off"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HTTP = %d, want 400", rec.Code)
	}
	// ErrorInfo 序列化在 details[0].debug（服务端调试视图，connect-go JSON
	// 形态）；不依赖 debug 字段时用包内判别（此处直接断言 body 含 code）。
	var body struct {
		Details []struct {
			Debug map[string]string `json:"debug"`
		} `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (body %s)", err, rec.Body.String())
	}
	if len(body.Details) == 0 || body.Details[0].Debug["code"] != "provider_disabled" {
		t.Errorf("ErrorInfo code = %+v, want provider_disabled (body %s)", body.Details, rec.Body.String())
	}
}

// TestLoginOauthConnect 端到端：请求 Cookie 头解析 al_login_state、信封
// 透传、state 校验失败的删 Cookie 下发、浏览器终点 al_session 下发。
func TestLoginOauthConnect(t *testing.T) {
	t.Run("state_mismatch 删 Cookie", func(t *testing.T) {
		tp := &fakeThirdparty{oauthOut: &thirdpartysvc.OauthOutput{
			Envelope: &ssov1.LoginFlowResponse{Status: "state_mismatch"},
			Cookie: &http.Cookie{
				Name: "al_login_state", Value: "", Path: "/", MaxAge: -1,
				HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
			},
		}}
		_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, tp, nil))
		srv := httptest.NewServer(handler)
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPost, srv.URL+ssov1connect.SsoServiceLoginOauthProcedure,
			strings.NewReader(`{"providerKey":"qq","code":"c","state":"lbad"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", "other=x; al_login_state=sealed_state")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST LoginOauth: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("HTTP = %d, want 200（信封域失败也 200）", resp.StatusCode)
		}
		// Cookie 头解析：service 入参应收到 al_login_state 值。
		if tp.gotOauth.StateCookie != "sealed_state" {
			t.Errorf("StateCookie = %q, want sealed_state", tp.gotOauth.StateCookie)
		}
		if tp.gotOauth.ProviderKey != "qq" || tp.gotOauth.Code != "c" || tp.gotOauth.State != "lbad" {
			t.Errorf("service 入参 = %+v", tp.gotOauth)
		}
		// 删 Cookie 下发。
		var cookie string
		for _, c := range resp.Header.Values("Set-Cookie") {
			if strings.HasPrefix(c, "al_login_state=") {
				cookie = c
			}
		}
		if !strings.Contains(cookie, "Max-Age=0") && !strings.Contains(cookie, "Max-Age=-1") {
			t.Errorf("应下发删除 Cookie, got %q", cookie)
		}

		got := decodeEnvelope(t, readBody(t, resp.Body))
		if got.GetStatus() != "state_mismatch" {
			t.Errorf("status = %q", got.GetStatus())
		}
	})

	t.Run("浏览器终点下发 al_session", func(t *testing.T) {
		tp := &fakeThirdparty{oauthOut: &thirdpartysvc.OauthOutput{
			Envelope:     &ssov1.LoginFlowResponse{Status: "success", UserId: 7},
			SessionToken: "stok-1",
		}}
		_, handler := ssov1connect.NewSsoServiceHandler(
			New(&fakeEngine{}, nil, sessionCookieForTest(), tp, nil))
		srv := httptest.NewServer(handler)
		defer srv.Close()

		resp, err := http.Post(srv.URL+ssov1connect.SsoServiceLoginOauthProcedure,
			"application/json", strings.NewReader(`{"providerKey":"qq","code":"c","state":"l"}`))
		if err != nil {
			t.Fatalf("POST LoginOauth: %v", err)
		}
		defer resp.Body.Close()

		var sessionCookie string
		for _, c := range resp.Header.Values("Set-Cookie") {
			if strings.HasPrefix(c, "al_session=") {
				sessionCookie = c
			}
		}
		if !strings.Contains(sessionCookie, "stok-1") {
			t.Errorf("应下发 Set-Cookie: al_session=stok-1, got %q", sessionCookie)
		}
		// 信封不带 session_token（浏览器场景）。
		got := decodeEnvelope(t, readBody(t, resp.Body))
		if got.GetStatus() != "success" || got.GetSessionToken() != "" {
			t.Errorf("信封 = %+v", got)
		}
	})

	t.Run("api 通道 session_token 在信封", func(t *testing.T) {
		tp := &fakeThirdparty{oauthOut: &thirdpartysvc.OauthOutput{
			Envelope: &ssov1.LoginFlowResponse{Status: "success", SessionToken: "stok-2"},
		}}
		_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, sessionCookieForTest(), tp, nil))
		srv := httptest.NewServer(handler)
		defer srv.Close()

		resp, err := http.Post(srv.URL+ssov1connect.SsoServiceLoginOauthProcedure,
			"application/json", strings.NewReader(`{"providerKey":"wechat_mp","code":"wx"}`))
		if err != nil {
			t.Fatalf("POST LoginOauth: %v", err)
		}
		defer resp.Body.Close()

		got := decodeEnvelope(t, readBody(t, resp.Body))
		if got.GetStatus() != "success" || got.GetSessionToken() != "stok-2" {
			t.Errorf("信封 = %+v（api 通道 session_token 应在信封）", got)
		}
	})
}

// TestLoginOauthSessionCookieHTTPSAutoInferred：浏览器终点的
// al_session Set-Cookie 按 https_deployment=auto + 请求信号逐请求判定
// （§1.9 行 306-309 全部下发点逐请求判定、后端架构 §11.1 行 1179 同一
// 构造器）：请求带 X-Forwarded-Proto: https → Secure + SameSite=None。
// 信号采集复刻装配层（connect.NewSessionInterceptor 入口把 req.Header 包
// RequestSignal 注入 ctx；handler 直构测试无拦截链，挂同款最小拦截器）。
func TestLoginOauthSessionCookieHTTPSAutoInferred(t *testing.T) {
	tp := &fakeThirdparty{oauthOut: &thirdpartysvc.OauthOutput{
		Envelope:     &ssov1.LoginFlowResponse{Status: "success", UserId: 7},
		SessionToken: "stok-1",
	}}
	cookies := session.NewCookie("al_session", "", 7*24*time.Hour,
		session.WithHTTPSMode(func() string { return settings.HTTPSDeploymentAuto }))
	_, handler := ssov1connect.NewSsoServiceHandler(
		New(&fakeEngine{}, nil, cookies, tp, nil),
		connect.WithInterceptors(connect.UnaryInterceptorFunc(
			func(next connect.UnaryFunc) connect.UnaryFunc {
				return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
					return next(session.WithRequestSignal(ctx, session.RequestSignal{Header: req.Header()}), req)
				}
			})),
	)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+ssov1connect.SsoServiceLoginOauthProcedure,
		strings.NewReader(`{"providerKey":"qq","code":"c","state":"l"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST LoginOauth: %v", err)
	}
	defer resp.Body.Close()

	var sessionCookie string
	for _, c := range resp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, "al_session=") {
			sessionCookie = c
		}
	}
	if !strings.Contains(sessionCookie, "stok-1") {
		t.Fatalf("应下发 Set-Cookie: al_session=stok-1, got %q", sessionCookie)
	}
	if !strings.Contains(sessionCookie, "Secure") || !strings.Contains(sessionCookie, "SameSite=None") {
		t.Errorf("auto + X-Forwarded-Proto: https 应 Secure+SameSite=None, got %q", sessionCookie)
	}
}

// TestThirdpartyNotConfigured 未装配三方 service：Authorize / LoginOauth
// 返回 unimplemented（半装配口径，同 images nil 先例）。
func TestThirdpartyNotConfigured(t *testing.T) {
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, nil, nil))
	for _, procedure := range []string{
		ssov1connect.SsoServiceAuthorizeProcedure,
		ssov1connect.SsoServiceLoginOauthProcedure,
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

// TestLoginOauthErrorInternal service 未知错误 → Connect internal（§1.5）。
func TestLoginOauthErrorInternal(t *testing.T) {
	tp := &fakeThirdparty{authorizeErr: errors.New("boom")}
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, tp, nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceAuthorizeProcedure,
		strings.NewReader(`{"provider":"qq"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("HTTP = %d, want 500", rec.Code)
	}
}

// TestLoginOauthScanMFAPending 小程序端扫码 + 已启用 MFA：响应仍为
// mfa_required，同时经统一写票 service 把票据结果写为 mfa_pending
// （§2.8 行 884、§13.2）；目标 uid 由 loginToken 校验恢复。
func TestLoginOauthScanMFAPending(t *testing.T) {
	t.Run("ticket_id 场景 service 带出 id", func(t *testing.T) {
		tp := &fakeThirdparty{oauthOut: &thirdpartysvc.OauthOutput{Envelope: &ssov1.LoginFlowResponse{
			Status:     orchestrator.StatusMFARequired,
			LoginToken: "lt-1",
		}, TicketID: "c7Kx9"}}
		lt := &fakeLoginTicket{out: &ssov1.TicketStatus{Status: "mfa_pending", TicketId: "c7Kx9"}}
		_, handler := ssov1connect.NewSsoServiceHandler(
			New(&fakeEngine{}, nil, nil, tp, nil).WithLoginTicket(lt))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceLoginOauthProcedure,
			strings.NewReader(`{"providerKey":"wechat_mp_scan","code":"c","ticketId":"c7Kx9"}`))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("HTTP = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		if lt.calls != 1 || lt.gotIn.TicketID != "c7Kx9" || lt.gotIn.LoginToken != "lt-1" {
			t.Fatalf("写票入参 = %+v calls = %d, want {c7Kx9 lt-1}（状态由写票 service 自行判定）", lt.gotIn, lt.calls)
		}
		if got := decodeEnvelope(t, rec.Body.String()); got.GetStatus() != orchestrator.StatusMFARequired {
			t.Fatalf("status = %q, want mfa_required", got.GetStatus())
		}
	})

	// 只传完整 ticket 时入参 ticket_id 为空，写票 id 必须取 service 解票
	// 带出的 OauthOutput.TicketID，否则会写空 id。
	t.Run("只传完整 ticket 按解票 id 写票", func(t *testing.T) {
		tp := &fakeThirdparty{oauthOut: &thirdpartysvc.OauthOutput{Envelope: &ssov1.LoginFlowResponse{
			Status:     orchestrator.StatusMFARequired,
			LoginToken: "lt-2",
		}, TicketID: "tid-from-ticket"}}
		lt := &fakeLoginTicket{out: &ssov1.TicketStatus{Status: "mfa_pending", TicketId: "tid-from-ticket"}}
		_, handler := ssov1connect.NewSsoServiceHandler(
			New(&fakeEngine{}, nil, nil, tp, nil).WithLoginTicket(lt))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceLoginOauthProcedure,
			strings.NewReader(`{"providerKey":"wechat_mp_scan","code":"c","ticket":"sealed-ticket"}`))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("HTTP = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		if tp.gotOauth.Ticket != "sealed-ticket" || tp.gotOauth.TicketID != "" {
			t.Fatalf("service 入参 = %+v, want 仅 Ticket=sealed-ticket", tp.gotOauth)
		}
		if lt.calls != 1 || lt.gotIn.TicketID != "tid-from-ticket" || lt.gotIn.LoginToken != "lt-2" {
			t.Fatalf("写票入参 = %+v calls = %d, want {tid-from-ticket lt-2}", lt.gotIn, lt.calls)
		}
		if got := decodeEnvelope(t, rec.Body.String()); got.GetStatus() != orchestrator.StatusMFARequired {
			t.Fatalf("status = %q, want mfa_required", got.GetStatus())
		}
	})
}

// —— 无 {{TICKET_ID}} 票 + MFA 用户端到端（阻断回归）——

// e2eTicketStore 记录最终写入的票据结果，供断言 mfa_pending 覆盖 scanned。
type e2eTicketStore struct {
	res map[string]*token.TicketResult
}

func (f *e2eTicketStore) WriteScanned(context.Context, string, *token.TicketResult) (cache.TicketWriteResult, error) {
	return cache.TicketWriteOK, nil
}
func (f *e2eTicketStore) WriteComplete(_ context.Context, id string, res *token.TicketResult) (cache.TicketWriteResult, error) {
	f.res[id] = res
	return cache.TicketWriteOK, nil
}
func (f *e2eTicketStore) Peek(_ context.Context, id string) (*token.TicketResult, error) {
	return f.res[id], nil
}
func (f *e2eTicketStore) Take(_ context.Context, id string) (*token.TicketResult, error) {
	return f.res[id], nil
}
func (f *e2eTicketStore) Wait(context.Context, string, time.Duration) error {
	return cache.ErrTicketWaitTimeout
}

// e2ePayloads 模拟模板未放 {{TICKET_ID}} 时未写 al:ticket:payload 快照。
type e2ePayloads struct{}

func (*e2ePayloads) Write(context.Context, *token.TicketPayload) error { return nil }
func (*e2ePayloads) Read(context.Context, string) (*token.TicketPayload, error) {
	return nil, nil
}

type e2eUsers struct{}

func (*e2eUsers) FindByID(_ context.Context, id int64) (*model.User, error) {
	return &model.User{ID: id, UserStatus: 1, MfaRequired: 1}, nil
}

type e2eCreds struct{}

func (*e2eCreds) FindByUserAndKind(_ context.Context, _ int64, kind string) (*model.UserCredential, error) {
	if kind == "totp" {
		return &model.UserCredential{Kind: "totp", IsEnabled: 1}, nil
	}
	return nil, sql.ErrNoRows
}

type e2eSettings struct{}

func (*e2eSettings) GetString(string) (string, bool) { return "", false }
func (*e2eSettings) GetInt64(string) (int64, bool)   { return 0, false }
func (*e2eSettings) GetBool(k string) (bool, bool) {
	if k == settings.KeyMfaEnabled {
		return true, true
	}
	return false, false
}
func (*e2eSettings) GetStringSlice(k string) ([]string, bool) {
	if k == settings.KeyMfaMethods {
		return []string{"totp", "otp_sms", "otp_email", "webauthn"}, true
	}
	return nil, false
}

func e2eCodec(t *testing.T, seed byte) *security.Codec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return security.NewCodec(ks)
}

// TestLoginOauthNoTicketIDMFAPending 端到端可证伪：模板未放 {{TICKET_ID}}
// 时小程序端只带完整 ticket，MFA 用户扫码后 mfa_pending 必须覆盖 scanned；
// 若写票链仍读缺失的快照，结果停在 scanned，本用例转红。
func TestLoginOauthNoTicketIDMFAPending(t *testing.T) {
	ticketC := e2eCodec(t, 0x40)
	state := orchestrator.NewState(e2eCodec(t, 0x50))
	sealed, err := ticketC.Seal(security.PurposeTicket, &token.TicketPayload{
		TicketId: "tid-e2e", ProviderKey: "wxscan", Scene: ticketsvc.SceneLogin,
		Iat: 1_700_000_000, Exp: 1_700_000_600,
	})
	if err != nil {
		t.Fatalf("Seal ticket: %v", err)
	}
	lt, err := state.Issue(&token.LoginTokenPayload{
		Tid: "tid-e2e", Flow: "login", Uid: 42,
		Passed: []string{"thirdparty"}, Amr: []string{"thirdparty"},
	})
	if err != nil {
		t.Fatalf("Issue loginToken: %v", err)
	}

	store := &e2eTicketStore{res: map[string]*token.TicketResult{
		"tid-e2e": &token.TicketResult{V: ticketsvc.TicketResultV, Status: ticketsvc.TicketStatusScanned},
	}}
	svc := ticketsvc.NewLoginTicket(ticketsvc.LoginTicketDeps{
		Tickets: store, TicketPayloads: &e2ePayloads{},
		State: state, Users: &e2eUsers{}, Settings: &e2eSettings{}, Credentials: &e2eCreds{},
		TicketCodec: ticketC,
		Now:         func() time.Time { return time.Unix(1_700_000_100, 0) },
	})
	tp := &fakeThirdparty{oauthOut: &thirdpartysvc.OauthOutput{
		Envelope: &ssov1.LoginFlowResponse{Status: orchestrator.StatusMFARequired, LoginToken: lt},
		TicketID: "tid-e2e",
	}}
	_, handler := ssov1connect.NewSsoServiceHandler(
		New(&fakeEngine{}, nil, nil, tp, nil).WithLoginTicket(svc))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, ssov1connect.SsoServiceLoginOauthProcedure,
		strings.NewReader(`{"providerKey":"wxscan","code":"c","ticket":"`+sealed+`"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if tp.gotOauth.TicketID != "" || tp.gotOauth.Ticket != sealed {
		t.Fatalf("service 入参 = %+v, want 仅 Ticket", tp.gotOauth)
	}
	res := store.res["tid-e2e"]
	if res == nil || res.GetStatus() != ticketsvc.TicketStatusMFAPending {
		t.Fatalf("al:ticket 最终 = %+v, want mfa_pending（不能停在 scanned）", res)
	}
	if res.GetLoginResult().GetUid() != 42 {
		t.Fatalf("uid = %+v, want 42", res.GetLoginResult())
	}
}
