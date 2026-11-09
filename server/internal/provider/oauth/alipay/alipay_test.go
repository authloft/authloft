// alipay 适配器单测：测试内生成 RSA 密钥对自证签名链——
// httptest 扮演支付宝网关：服务端验请求签名（应用公钥）+ 用支付宝私钥
// 签响应（适配器经 cert 验签）；覆盖授权 URL、code→token（user_id 抽取）、
// user.info.share、error_response、验签失败与配置缺失。
// 真机联调未覆盖（无支付宝应用凭据）。
package alipay

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/provider"
	"authloft/internal/provider/oauth/oauthcore"
)

// keyset 测试密钥对：app = 应用侧（client_secret 私钥 / 服务端验签公钥），
// alipay = 平台侧（cert 公钥 / 服务端签名私钥）。
type keyset struct {
	appPrivPEM    string // 应用私钥（PEM，填 Ext.client_secret）
	alipayPrivPEM string // 支付宝私钥（服务端签响应用）
	alipayPubPEM  string // 支付宝公钥（PEM，填 Ext.cert）
	appPub        *rsa.PublicKey
}

func genKeyset(t *testing.T) keyset {
	t.Helper()
	appKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen app key: %v", err)
	}
	alipayKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen alipay key: %v", err)
	}
	return keyset{
		appPrivPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, appKey)})),
		alipayPrivPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, alipayKey)})),
		alipayPubPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY",
			Bytes: mustPKIX(t, &alipayKey.PublicKey)})),
		appPub: &appKey.PublicKey,
	}
}

func mustPKCS8(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return b
}

func mustPKIX(t *testing.T, k *rsa.PublicKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return b
}

// signWith 平台侧签名（服务端扮演支付宝时用）。
func signWith(t *testing.T, privPEM, content string) string {
	t.Helper()
	key, err := parsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("parse platform key: %v", err)
	}
	h := sha256.Sum256([]byte(content))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func testProvider(ks keyset, gateway string) *provider.Provider {
	return &provider.Provider{Key: "ali", Type: Type, Ext: &providerpb.Ext{
		ClientId:     "ali-appid",
		ClientSecret: ks.appPrivPEM,
		Cert:         ks.alipayPubPEM,
		ProviderUrl:  gateway,
	}}
}

// TestBuildAuthURL 授权 URL：publicAppAuthorize.htm + app_id + auth_user + state。
func TestBuildAuthURL(t *testing.T) {
	ks := genKeyset(t)
	a, err := build(testProvider(ks, "https://gw"), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	got, err := a.BuildAuthURL(&provider.AuthContext{State: "l-ali", RedirectURI: "https://app/cb"})
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	u, _ := url.Parse(got)
	q := u.Query()
	if !strings.Contains(got, "openauth.alipay.com/oauth2/publicAppAuthorize.htm") {
		t.Fatalf("url = %q", got)
	}
	if q.Get("app_id") != "ali-appid" || q.Get("scope") != "auth_user" || q.Get("state") != "l-ali" {
		t.Fatalf("query = %v", q)
	}
	if _, err := a.BuildAuthURL(&provider.AuthContext{}); !errors.Is(err, oauthcore.ErrEmptyState) {
		t.Fatalf("err = %v, want ErrEmptyState", err)
	}
}

// TestExchangeAndFetchUser 全链路：请求签名（服务端验签）→ 令牌响应验签 →
// user_id 抽取 → user.info.share 昵称头像。
func TestExchangeAndFetchUser(t *testing.T) {
	ks := genKeyset(t)
	var gotTokenBiz, gotShareBiz url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			return
		}
		form := r.PostForm
		// 服务端验请求签名（sign_type 除外的参数按 key 升序 k=v）。
		content := signContent(form)
		sig, err := base64.StdEncoding.DecodeString(form.Get("sign"))
		if err != nil {
			t.Errorf("decode sign: %v", err)
			return
		}
		h := sha256.Sum256([]byte(content))
		if err := rsa.VerifyPKCS1v15(ks.appPub, crypto.SHA256, h[:], sig); err != nil {
			t.Errorf("请求验签失败（sign 原文 %q）: %v", content, err)
			return
		}
		switch form.Get("method") {
		case methodToken:
			gotTokenBiz = form
			inner := `{"access_token":"ali-at","refresh_token":"ali-rt","expires_in":1296000,"re_expires_in":1296000,"user_id":"2088123456789012"}`
			fmt.Fprintf(w, `{"%s":%s,"sign":%q}`, methodResponseKey(methodToken), inner,
				signWith(t, ks.alipayPrivPEM, inner))
		case methodShare:
			gotShareBiz = form
			inner := `{"user_id":"2088123456789012","nick_name":"支付宝用户","avatar":"https://a/ali.jpg"}`
			fmt.Fprintf(w, `{"%s":%s,"sign":%q}`, methodResponseKey(methodShare), inner,
				signWith(t, ks.alipayPrivPEM, inner))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, err := build(testProvider(ks, srv.URL), nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// 网关覆盖生效。
	if a.gateway != srv.URL {
		t.Fatalf("gateway = %q, want %q", a.gateway, srv.URL)
	}
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "ali-code"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "ali-at" || tok.ExpiresIn != 1296000 {
		t.Fatalf("token = %+v", tok)
	}
	if gotTokenBiz.Get("app_id") != "ali-appid" || gotTokenBiz.Get("grant_type") != "authorization_code" ||
		gotTokenBiz.Get("code") != "ali-code" || gotTokenBiz.Get("sign_type") != "RSA2" || gotTokenBiz.Get("charset") != "utf-8" {
		t.Fatalf("token biz = %v", gotTokenBiz)
	}
	// FetchUser：user_id（openid）+ share 昵称头像。
	id, err := a.FetchUser(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "2088123456789012" || id.Nickname != "支付宝用户" || id.AvatarURL != "https://a/ali.jpg" {
		t.Fatalf("id = %+v", id)
	}
	if gotShareBiz.Get("auth_token") != "ali-at" {
		t.Fatalf("share biz auth_token = %q", gotShareBiz.Get("auth_token"))
	}
	// Raw 只落 share 响应，不含令牌字段。
	if _, ok := id.Raw["access_token"]; ok {
		t.Fatalf("Raw 不应含 access_token")
	}
}

// TestExchangeError error_response（sub_code / sub_msg）映射。
func TestExchangeError(t *testing.T) {
	ks := genKeyset(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"error_response":{"code":"aop.ERROR","msg":"系统繁忙","sub_code":"ISP_NULL_PARAMETER","sub_msg":"参数缺失"}}`)
	}))
	defer srv.Close()

	a, _ := build(testProvider(ks, srv.URL), nil)
	_, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "x"})
	pe, ok := oauthcore.AsProviderError(err)
	if !ok || pe.Code != "ISP_NULL_PARAMETER" || pe.Desc != "参数缺失" {
		t.Fatalf("err = %v", err)
	}
}

// TestSignVerifyFailure 响应验签失败必须报错（防篡改纵深防御）。
func TestSignVerifyFailure(t *testing.T) {
	ks := genKeyset(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen other key: %v", err)
	}
	otherPriv := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, other)}))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner := `{"access_token":"at","user_id":"2088x"}`
		// 用「错误」的私钥签响应 → 适配器验签必败。
		fmt.Fprintf(w, `{"%s":%s,"sign":%q}`, methodResponseKey(methodToken), inner,
			signWith(t, otherPriv, inner))
	}))
	defer srv.Close()

	a, _ := build(testProvider(ks, srv.URL), nil)
	if _, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"}); !errors.Is(err, ErrSignVerify) {
		t.Fatalf("err = %v, want ErrSignVerify", err)
	}
}

// TestNoCertSkipVerify cert 留空跳过验签（最小配置可跑通）。
func TestNoCertSkipVerify(t *testing.T) {
	ks := genKeyset(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"alipay_system_oauth_token_response":{"access_token":"at","user_id":"2088y"}}`)
	}))
	defer srv.Close()

	p := testProvider(ks, srv.URL)
	p.Ext.Cert = ""
	a, err := build(p, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tok, err := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
	if err != nil || tok.AccessToken != "at" {
		t.Fatalf("tok=%+v err=%v", tok, err)
	}
}

// TestShareBestEffort share 失败不阻断登录（openid 落库）。
func TestShareBestEffort(t *testing.T) {
	ks := genKeyset(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			return
		}
		switch r.PostForm.Get("method") {
		case methodToken:
			inner := `{"access_token":"at2","user_id":"2088z"}`
			fmt.Fprintf(w, `{"%s":%s,"sign":%q}`, methodResponseKey(methodToken), inner,
				signWith(t, ks.alipayPrivPEM, inner))
		default:
			fmt.Fprint(w, `{"error_response":{"code":"aop.ERROR","sub_code":"ISV_NOT_QUALIFIED","sub_msg":"无权限"}}`)
		}
	}))
	defer srv.Close()

	a, _ := build(testProvider(ks, srv.URL), nil)
	tok, _ := a.Exchange(context.Background(), provider.ExchangeInput{Code: "c"})
	id, err := a.FetchUser(context.Background(), tok)
	if err != nil {
		t.Fatalf("FetchUser: %v", err)
	}
	if id.OpenID != "2088z" || id.Nickname != "" {
		t.Fatalf("id = %+v, want openid 落库 + share best-effort 跳过", id)
	}
}

// TestNotConfigured 私钥缺失 / 私钥非法。
func TestNotConfigured(t *testing.T) {
	ks := genKeyset(t)
	if _, err := build(&provider.Provider{Key: "ali", Type: Type, Ext: &providerpb.Ext{
		ClientId: "id", ClientSecret: ks.appPrivPEM}}, nil); err != nil {
		t.Fatalf("合法私钥不应报错: %v", err)
	}
	if _, err := build(&provider.Provider{Key: "ali", Type: Type, Ext: &providerpb.Ext{
		ClientId: "id", ClientSecret: "not-a-pem"}}, nil); !errors.Is(err, ErrBadKey) {
		t.Fatalf("err = %v, want ErrBadKey", err)
	}
	if _, err := build(&provider.Provider{Key: "ali", Type: Type, Ext: &providerpb.Ext{
		ClientId: "id", ClientSecret: ks.appPrivPEM, Cert: "bad"}}, nil); !errors.Is(err, ErrBadCert) {
		t.Fatalf("err = %v, want ErrBadCert", err)
	}
}

func TestRegistry(t *testing.T) {
	ks := genKeyset(t)
	meta, ok := provider.Lookup(Type)
	if !ok || meta.DisplayName != "支付宝" {
		t.Fatalf("meta = %+v ok=%v", meta, ok)
	}
	// 凭证标签语义化。
	labels := map[string]string{}
	for _, f := range meta.Fields {
		labels[f.Key] = f.Label
	}
	if labels["client_secret"] != "admin.schemaField.alipayPrivateKeyLabel" ||
		labels["cert"] != "admin.schemaField.alipayPublicKeyLabel" ||
		labels["provider_url"] != "admin.schemaField.alipayGatewayLabel" {
		t.Fatalf("labels = %v", labels)
	}
	if _, err := provider.NewAdapter(testProvider(ks, "https://gw")); err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
}
