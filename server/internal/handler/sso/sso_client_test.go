// sso_client_test.go 三方跳转 / 扫码链路的 sso_client_id 透传用例（接口文档
// §2.7.2 / §2.8）：请求消息字段原样进入 service 入参——Authorize 是三方链路
// 应用上下文的唯一入口，CreateQrcode 仅 scene=login 携带（bind 由 service
// 剥离）。全部走 fake service，不连 DB / Redis。
package sso

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"authloft/gen/go/api/sso/v1/ssov1connect"
	qrcodesvc "authloft/internal/service/qrcode"
	thirdpartysvc "authloft/internal/service/thirdparty"
)

// TestAuthorizeSsoClientIDPassthrough Authorize 请求 sso_client_id 透传
// service 入参（§2.7.2：三方链路应用上下文唯一入口）。
func TestAuthorizeSsoClientIDPassthrough(t *testing.T) {
	tp := &fakeThirdparty{authorizeOut: &thirdpartysvc.AuthorizeOutput{
		AuthorizeURL: "https://graph.qq.com/oauth2.0/authorize?state=labc",
	}}
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, tp, nil))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+ssov1connect.SsoServiceAuthorizeProcedure,
		"application/json", strings.NewReader(`{"provider":"qq","scene":"login","ssoClientId":"app-1"}`))
	if err != nil {
		t.Fatalf("POST Authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if tp.gotAuthorize.SsoClientID != "app-1" {
		t.Errorf("service 入参 SsoClientID = %q, want app-1", tp.gotAuthorize.SsoClientID)
	}
}

// TestCreateQrcodeSsoClientIDPassthrough CreateQrcode 请求 sso_client_id
// 透传 service 入参（§2.8：仅 scene=login 携带；透传后由 service 剥离
// bind 场景）。
func TestCreateQrcodeSsoClientIDPassthrough(t *testing.T) {
	qr := &fakeQrcode{createOut: &qrcodesvc.CreateQrcodeOutput{
		Ticket: "sealed-ticket", TicketID: "c7Kx9", QrcodeURL: "https://cdn.example.com/qr/c7Kx9.jpg", ExpiresIn: 600,
	}}
	_, handler := ssov1connect.NewSsoServiceHandler(New(&fakeEngine{}, nil, nil, nil, qr))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+ssov1connect.SsoServiceCreateQrcodeProcedure,
		strings.NewReader(`{"providerKey":"wechat_mp_scan","scene":"login","ssoClientId":"app-1","captcha":{"providerKey":"builtin_image","id":"cap-1","answer":"123456"}}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST CreateQrcode: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP = %d, want 200", resp.StatusCode)
	}
	if qr.gotCreate.SsoClientID != "app-1" {
		t.Errorf("service 入参 SsoClientID = %q, want app-1", qr.gotCreate.SsoClientID)
	}
}
