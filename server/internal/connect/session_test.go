// session 拦截器单测（全栈：真实
// connect.NewUnaryHandler + 拦截器 + httptest，零 ENV.md 实例依赖）。session
// 包的 §11.1 四步校验已有自身测试，此处只测拦截语义：Header 替代 Cookie、
// 未登录清 Cookie 放行、重签按来源两分支（Set-Cookie vs X-Authloft-Token）、
// epoch 读取链故障 internal、取值优先级不回落、注入 cookie 名生效。
package connect

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	commonv1 "authloft/gen/go/api/common/v1"
	"authloft/gen/go/token"
	"authloft/internal/security"
	"authloft/internal/session"
	"authloft/internal/settings"
)

// sessionEchoProcedure 测试用 Connect RPC 路径（文档口径的 <包>.<Service>/<Method>）。
const sessionEchoProcedure = "/api.account.v1.AccountService/GetProfile"

// fakeEpochReader 隔离型 epoch 读取（记录值 / 错误；单测试无并发，不加锁）。
type fakeEpochReader struct {
	values map[int64]int64
	err    error
}

func (f *fakeEpochReader) Current(ctx context.Context, uid int64) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.values[uid], nil
}

// sessionEnv 每用例独立装配（签发密钥 version=1 kid=1，同 session 包测试口径）。
type sessionEnv struct {
	tokens   *session.Tokens
	verifier *session.Verifier
	renewer  *session.Renewer
	cookie   *session.Cookie
	epochs   *fakeEpochReader
}

func newSessionEnv(t *testing.T) *sessionEnv {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x20 + i)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	tokens := session.NewTokens(security.NewCodec(ks))
	epochs := &fakeEpochReader{values: map[int64]int64{}}
	return &sessionEnv{
		tokens:   tokens,
		verifier: session.NewVerifier(tokens, epochs),
		renewer:  session.NewRenewer(tokens, time.Hour),
		cookie:   session.NewCookie("", "", time.Hour),
		epochs:   epochs,
	}
}

// validPayload 标准载荷（uid=42 epoch=7），exp 在未来 1 小时；EpochReader 同步放行。
func (e *sessionEnv) validPayload() *token.SessionTokenPayload {
	p := &token.SessionTokenPayload{
		Id:    42,
		Epoch: 7,
		Amr:   []string{"pwd", "otp"},
		Sid:   "sid-0001",
		Iat:   time.Now().Add(-time.Minute).Unix(),
		Exp:   time.Now().Add(time.Hour).Unix(),
	}
	e.epochs.values[p.Id] = p.Epoch
	return p
}

func (e *sessionEnv) sign(t *testing.T, p *token.SessionTokenPayload) string {
	t.Helper()
	tok, err := e.tokens.Sign(p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return tok
}

// sessionCapture handler 内捕获的 ctx 身份。
type sessionCapture struct {
	uid int64
	ok  bool
	amr []string
	sid string
}

// newSessionServer 挂载 session 拦截器 + 记录 ctx 身份的 echo handler，
// 返回 httptest 服务器与捕获器。
func newSessionServer(t *testing.T, env *sessionEnv, cookieName func() string) (*httptest.Server, *sessionCapture) {
	t.Helper()
	captured := &sessionCapture{}
	handler := connect.NewUnaryHandler(sessionEchoProcedure,
		func(ctx context.Context, req *connect.Request[commonv1.ErrorInfo]) (*connect.Response[commonv1.ErrorInfo], error) {
			captured.uid, captured.ok = session.UIDFromContext(ctx)
			captured.amr, _ = session.AMRFromContext(ctx)
			captured.sid, _ = session.SIDFromContext(ctx)
			return connect.NewResponse[commonv1.ErrorInfo](req.Msg), nil
		},
		connect.WithInterceptors(NewSessionInterceptor(env.verifier, env.renewer, env.cookie, cookieName)),
	)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, captured
}

// sessionBody unary 请求体：必须序列化为非空字节（全零值消息 marshal 后为
// 空 body，connect-go 会以 cardinality violation 拒绝、到不了拦截器）。
func sessionBody(t *testing.T) []byte {
	t.Helper()
	body, err := proto.Marshal(&commonv1.ErrorInfo{Code: "x"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return body
}

// doSessionRPC 发一次会话测试 RPC：token 经 headers（X-Authloft-Token）或
// cookies 传入，返回响应。
func doSessionRPC(t *testing.T, srv *httptest.Server, headers map[string]string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+sessionEchoProcedure, bytes.NewReader(sessionBody(t)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

// assertRenewed 断言重签令牌可解析且 §11.5 字段口径成立（iat/exp 刷新、
// id/epoch/sid 不变），返回新载荷。
func assertRenewed(t *testing.T, env *sessionEnv, renewed, old string) *token.SessionTokenPayload {
	t.Helper()
	if renewed == "" {
		t.Fatal("renewed token is empty")
	}
	if renewed == old {
		t.Errorf("renewed token equals the old one, want a fresh signature per request (§11.5)")
	}
	p, err := env.tokens.Parse(renewed)
	if err != nil {
		t.Fatalf("Parse renewed token: %v", err)
	}
	if p.GetId() != 42 || p.GetEpoch() != 7 || p.GetSid() != "sid-0001" {
		t.Errorf("renewed payload id/epoch/sid changed: id=%d epoch=%d sid=%q, want 42/7/sid-0001 (§11.5)", p.GetId(), p.GetEpoch(), p.GetSid())
	}
	if p.GetExp() <= p.GetIat() {
		t.Errorf("renewed exp=%d <= iat=%d, want refreshed window", p.GetExp(), p.GetIat())
	}
	return p
}

// lastSetCookie 解析响应中最后一枚 Set-Cookie；缺失返回 nil。
func lastSetCookie(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()
	values := resp.Header.Values("Set-Cookie")
	if len(values) == 0 {
		return nil
	}
	ck, err := http.ParseSetCookie(values[len(values)-1])
	if err != nil {
		t.Fatalf("ParseSetCookie %q: %v", values[len(values)-1], err)
	}
	return ck
}

// ① Header 可替代 Cookie（§1.2 行 120）：X-Authloft-Token 携带有效令牌 →
// 注入 uid/amr/sid，重签经 X-Authloft-Token 响应头下发、不下发 Set-Cookie。
func TestSessionHeaderTokenAuthenticatesAndRenewsViaHeader(t *testing.T) {
	env := newSessionEnv(t)
	tok := env.sign(t, env.validPayload())
	srv, captured := newSessionServer(t, env, nil)

	resp := doSessionRPC(t, srv, map[string]string{"X-Authloft-Token": tok}, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (Header 可替代 Cookie)", resp.StatusCode, http.StatusOK)
	}
	if !captured.ok || captured.uid != 42 {
		t.Errorf("ctx uid = (%d, %v), want (42, true)", captured.uid, captured.ok)
	}
	if len(captured.amr) != 2 || captured.amr[0] != "pwd" || captured.amr[1] != "otp" {
		t.Errorf("ctx amr = %v, want [pwd otp]", captured.amr)
	}
	if captured.sid != "sid-0001" {
		t.Errorf("ctx sid = %q, want sid-0001", captured.sid)
	}

	renewed := resp.Header.Get("X-Authloft-Token")
	assertRenewed(t, env, renewed, tok)
	if got := resp.Header.Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("Header 来源不应下发 Set-Cookie（§1.9 行 291），got %v", got)
	}
}

// ② Cookie 来源：默认名 al_session 有效令牌 → 注入身份，重签经 Set-Cookie
// 下发（HttpOnly; Secure; SameSite=None; Path=/——本用例构造器未注入
// https_deployment 三态源，沿旧默认恒 HTTPS；三态驱动见
// TestSessionCookieHTTPSDeploymentTriState），不下发 X-Authloft-Token。
func TestSessionCookieTokenAuthenticatesAndRenewsViaCookie(t *testing.T) {
	env := newSessionEnv(t)
	tok := env.sign(t, env.validPayload())
	srv, captured := newSessionServer(t, env, nil)

	resp := doSessionRPC(t, srv, nil, []*http.Cookie{{Name: "al_session", Value: tok}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !captured.ok || captured.uid != 42 {
		t.Errorf("ctx uid = (%d, %v), want (42, true)", captured.uid, captured.ok)
	}

	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie 出现 %d 次, want 1: %v", len(cookies), cookies)
	}
	ck := lastSetCookie(t, resp)
	if ck.Name != "al_session" || ck.Value == "" {
		t.Errorf("cookie name/value = %q/%q, want al_session/非空", ck.Name, ck.Value)
	}
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteNoneMode || ck.Path != "/" {
		t.Errorf("cookie 属性 HttpOnly=%v Secure=%v SameSite=%v Path=%q, want true/true/None//（§1.9 行 288）", ck.HttpOnly, ck.Secure, ck.SameSite, ck.Path)
	}
	if ck.MaxAge != 3600 {
		t.Errorf("cookie MaxAge = %d, want 3600（注入 ttl=1h）", ck.MaxAge)
	}
	assertRenewed(t, env, ck.Value, tok)
	if got := resp.Header.Get("X-Authloft-Token"); got != "" {
		t.Errorf("Cookie 来源不应下发 X-Authloft-Token 响应头（§1.9 行 290），got %q", got)
	}
}

// ②b 拦截器续期 Cookie 受 https_deployment 三态驱动（§1.9 行
// 288/292/299-310）：mode=false → 省略 Secure + SameSite=Lax（明文部署，
// 浏览器才保存）；mode=auto + X-Forwarded-Proto 头（拦截器采集请求头做
// 推断信号，头 https → Secure+None、头 http → 明文）。
func TestSessionCookieHTTPSDeploymentTriState(t *testing.T) {
	mode := "unset"
	env := newSessionEnv(t)
	env.cookie = session.NewCookie("al_session", "", time.Hour,
		session.WithHTTPSMode(func() string { return mode }))
	tok := env.sign(t, env.validPayload())
	srv, _ := newSessionServer(t, env, nil)

	cookieOK := func(t *testing.T, resp *http.Response, secure bool) {
		t.Helper()
		ck := lastSetCookie(t, resp)
		if ck == nil {
			t.Fatalf("应下发续期 Set-Cookie")
		}
		if secure {
			if !ck.Secure || ck.SameSite != http.SameSiteNoneMode {
				t.Errorf("HTTPS 判定应 Secure+None, got Secure=%v SameSite=%v", ck.Secure, ck.SameSite)
			}
		} else {
			if ck.Secure || ck.SameSite != http.SameSiteLaxMode {
				t.Errorf("明文判定应省略 Secure+SameSite=Lax, got Secure=%v SameSite=%v", ck.Secure, ck.SameSite)
			}
		}
	}

	// false：恒明文（无视头）。
	mode = settings.HTTPSDeploymentFalse
	resp := doSessionRPC(t, srv, map[string]string{"X-Forwarded-Proto": "https"}, []*http.Cookie{{Name: "al_session", Value: tok}})
	cookieOK(t, resp, false)
	resp.Body.Close()

	// auto + 头 https → HTTPS（反代 TLS 终止形态，头优先）。
	mode = settings.HTTPSDeploymentAuto
	resp = doSessionRPC(t, srv, map[string]string{"X-Forwarded-Proto": "https"}, []*http.Cookie{{Name: "al_session", Value: tok}})
	cookieOK(t, resp, true)
	resp.Body.Close()

	// auto + 头 http → 明文。
	resp = doSessionRPC(t, srv, map[string]string{"X-Forwarded-Proto": "http"}, []*http.Cookie{{Name: "al_session", Value: tok}})
	cookieOK(t, resp, false)
	resp.Body.Close()

	// auto + 无头（connect 链 TLS 不可得 → 兜底明文）。
	resp = doSessionRPC(t, srv, nil, []*http.Cookie{{Name: "al_session", Value: tok}})
	cookieOK(t, resp, false)
	resp.Body.Close()
}

// ③ 无令牌 → 未登录放行（不 401）：ctx 无身份 + 防御性清 Cookie（MaxAge=-1）。
func TestSessionNoTokenClearsCookieAndPasses(t *testing.T) {
	env := newSessionEnv(t)
	srv, captured := newSessionServer(t, env, nil)

	resp := doSessionRPC(t, srv, nil, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d（未登录放行，401 由下游判）", resp.StatusCode, http.StatusOK)
	}
	if captured.ok {
		t.Errorf("ctx uid 注入了 %d, want 未注入（未登录）", captured.uid)
	}
	if ck := lastSetCookie(t, resp); ck == nil || ck.MaxAge != -1 || ck.Value != "" {
		t.Errorf("未登录应清 Cookie（MaxAge=-1 空值），got %+v", ck)
	}
}

// ④ 无效令牌（解不开的垃圾值）→ 未登录放行 + 清 Cookie。
func TestSessionInvalidTokenClearsCookieAndPasses(t *testing.T) {
	env := newSessionEnv(t)
	srv, captured := newSessionServer(t, env, nil)

	resp := doSessionRPC(t, srv, map[string]string{"X-Authloft-Token": "garbage-token"}, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d（校验失败视为未登录放行）", resp.StatusCode, http.StatusOK)
	}
	if captured.ok {
		t.Errorf("ctx uid 注入了 %d, want 未注入", captured.uid)
	}
	if ck := lastSetCookie(t, resp); ck == nil || ck.MaxAge != -1 {
		t.Errorf("校验失败应清 Cookie，got %+v", ck)
	}
}

// ⑤ epoch 不一致（ErrSessionStale）→ 未登录放行 + 清 Cookie（§1.9 行 292）。
func TestSessionStaleEpochClearsCookieAndPasses(t *testing.T) {
	env := newSessionEnv(t)
	p := env.validPayload()
	env.epochs.values[p.Id] = p.Epoch + 1 // 令牌签发后 epoch 递增（改密）
	tok := env.sign(t, p)
	srv, captured := newSessionServer(t, env, nil)

	resp := doSessionRPC(t, srv, nil, []*http.Cookie{{Name: "al_session", Value: tok}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d（epoch 不一致视为未登录放行）", resp.StatusCode, http.StatusOK)
	}
	if captured.ok {
		t.Errorf("ctx uid 注入了 %d, want 未注入", captured.uid)
	}
	if ck := lastSetCookie(t, resp); ck == nil || ck.MaxAge != -1 {
		t.Errorf("epoch 不一致应清 Cookie，got %+v", ck)
	}
}

// ⑥ epoch 读取链故障（Redis 与回源均失败）→ 500 internal（§11.1：基础设施
// 错误不得误判为未登录放行）。
func TestSessionEpochReadErrorReturnsInternal(t *testing.T) {
	env := newSessionEnv(t)
	env.epochs.err = errInternal
	tok := env.sign(t, env.validPayload())
	srv, captured := newSessionServer(t, env, nil)

	resp := doSessionRPC(t, srv, map[string]string{"X-Authloft-Token": tok}, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d（epoch 读取链故障）", resp.StatusCode, http.StatusInternalServerError)
	}
	if captured.ok {
		t.Errorf("ctx 注入了 uid %d, want 未注入（请求被拒）", captured.uid)
	}
	if errObj := decodeConnectError(t, resp); errObj["code"] != "internal" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "internal")
	}
}

// ⑦ 取值优先级（§1.2 行 120）：Header 有值优先；Header 无效不回落 Cookie。
func TestSessionHeaderTakesPrecedenceOverCookie(t *testing.T) {
	env := newSessionEnv(t)
	tok := env.sign(t, env.validPayload())

	// Header 有效 + Cookie 垃圾 → 以 Header 为准通过。
	srv, captured := newSessionServer(t, env, nil)
	resp := doSessionRPC(t, srv,
		map[string]string{"X-Authloft-Token": tok},
		[]*http.Cookie{{Name: "al_session", Value: "garbage"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !captured.ok || captured.uid != 42 {
		t.Fatalf("Header 有效+Cookie 无效: status=%d uid=(%d,%v), want 200/(42,true)", resp.StatusCode, captured.uid, captured.ok)
	}

	// Header 无效 + Cookie 有效 → 不回落 Cookie，视为未登录。
	srv2, captured2 := newSessionServer(t, env, nil)
	resp2 := doSessionRPC(t, srv2,
		map[string]string{"X-Authloft-Token": "garbage"},
		[]*http.Cookie{{Name: "al_session", Value: tok}})
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d（未登录放行）", resp2.StatusCode, http.StatusOK)
	}
	if captured2.ok {
		t.Errorf("Header 无效时回落了 Cookie（uid=%d），优先级应为取值顺序而非回退", captured2.uid)
	}
}

// ⑧ 注入 cookie 名生效（settings 键 cookie_name 热更语义）：自定义名 my_sess
// 的 Cookie 通过校验，默认名 Cookie 被忽略。
func TestSessionCustomCookieName(t *testing.T) {
	env := newSessionEnv(t)
	tok := env.sign(t, env.validPayload())
	srv, captured := newSessionServer(t, env, func() string { return "my_sess" })

	resp := doSessionRPC(t, srv, nil, []*http.Cookie{
		{Name: "my_sess", Value: tok},
		{Name: "al_session", Value: "garbage"},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d（注入名生效）", resp.StatusCode, http.StatusOK)
	}
	if !captured.ok || captured.uid != 42 {
		t.Errorf("ctx uid = (%d, %v), want (42, true)", captured.uid, captured.ok)
	}
}

// ⑨ 续期闭环：重签下发的新令牌在下一请求（换 Cookie 来源）仍可校验通过。
func TestSessionRenewedTokenAcceptedOnNextRequest(t *testing.T) {
	env := newSessionEnv(t)
	tok := env.sign(t, env.validPayload())
	srv, _ := newSessionServer(t, env, nil)

	resp := doSessionRPC(t, srv, map[string]string{"X-Authloft-Token": tok}, nil)
	renewed := resp.Header.Get("X-Authloft-Token")
	resp.Body.Close()
	assertRenewed(t, env, renewed, tok)

	resp2 := doSessionRPC(t, srv, nil, []*http.Cookie{{Name: "al_session", Value: renewed}})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("续期令牌下一请求 status = %d, want %d", resp2.StatusCode, http.StatusOK)
	}
}
