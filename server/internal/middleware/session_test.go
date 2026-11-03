// Session 中间件单测（docs/后端架构.md §21.2 E 行 1871/1875）：
// Header 可替代 Cookie、失败清 Cookie 并放行、重签按来源两分支（Set-Cookie vs
// X-Authloft-Token）、epoch 读取链故障 500、注入 cookie 名生效、取值优先级不回落。
// 装配用真实 Tokens / Verifier / Renewer / Cookie + fake EpochReader（session 包
// 的 §11.1 四步已被 session 包测试覆盖，此处只测装配行为）。
package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"authloft/gen/go/token"
	"authloft/internal/codec"
	"authloft/internal/security"
	"authloft/internal/session"
)

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

// sessionEnv 每用例独立装配（sign 密钥 version=1 kid=1，同 session 包测试口径）。
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

// sessionRouter 装配 Session 中间件 + 记录 ctx 身份的 handler。
func (e *sessionEnv) sessionRouter(cookieName func() string) (*gin.Engine, *sessionCapture) {
	captured := &sessionCapture{}
	r := newTestRouter(Session(e.verifier, e.renewer, e.cookie, cookieName))
	r.GET("/api/account/x", func(c *gin.Context) {
		captured.uid, captured.ok = session.UIDFromContext(c.Request.Context())
		captured.amr, _ = session.AMRFromContext(c.Request.Context())
		captured.sid, _ = session.SIDFromContext(c.Request.Context())
		c.String(http.StatusOK, "ok")
	})
	return r, captured
}

// sessionCapture handler 内捕获的 ctx 身份。
type sessionCapture struct {
	uid int64
	ok  bool
	amr []string
	sid string
}

// assertRenewed 断言重签令牌可解析且 §11.5 字段口径成立（iat/exp 刷新、
// id/epoch/sid 不变），返回新载荷。
func assertRenewed(t *testing.T, e *sessionEnv, renewed, old string) *token.SessionTokenPayload {
	t.Helper()
	if renewed == "" {
		t.Fatal("renewed token is empty")
	}
	if renewed == old {
		t.Errorf("renewed token equals the old one, want a fresh signature per request (§11.5)")
	}
	p, err := e.tokens.Parse(renewed)
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

// ① Header 可替代 Cookie（§21.2 E 行 1875）：X-Authloft-Token 携带有效令牌 →
// 注入 uid/amr/sid，重签经 X-Authloft-Token 响应头下发、不下发 Set-Cookie。
func TestSessionHeaderTokenAuthenticatesAndRenewsViaHeader(t *testing.T) {
	env := newSessionEnv(t)
	tok := env.sign(t, env.validPayload())
	r, captured := env.sessionRouter(nil)

	rec := doRequest(r, http.MethodGet, "/api/account/x", map[string]string{"X-Authloft-Token": tok})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (Header 可替代 Cookie，body %s)", rec.Code, http.StatusOK, rec.Body.String())
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

	renewed := rec.Header().Get("X-Authloft-Token")
	assertRenewed(t, env, renewed, tok)
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("Header 来源不应下发 Set-Cookie（§1.9 行 291），got %v", got)
	}
}

// ② Cookie 来源：默认名 al_session 有效令牌 → 注入身份，重签经 Set-Cookie
// 下发（完整属性 HttpOnly; Secure; SameSite=None; Path=/），不下发 X-Authloft-Token。
func TestSessionCookieTokenAuthenticatesAndRenewsViaCookie(t *testing.T) {
	env := newSessionEnv(t)
	tok := env.sign(t, env.validPayload())
	r, captured := env.sessionRouter(nil)

	req := newSessionRequest("/api/account/x", nil)
	req.AddCookie(&http.Cookie{Name: "al_session", Value: tok})
	rec := serveRequest(r, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !captured.ok || captured.uid != 42 {
		t.Errorf("ctx uid = (%d, %v), want (42, true)", captured.uid, captured.ok)
	}

	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie 出现 %d 次, want 1: %v", len(cookies), cookies)
	}
	ck, err := http.ParseSetCookie(cookies[0])
	if err != nil {
		t.Fatalf("ParseSetCookie %q: %v", cookies[0], err)
	}
	if ck.Name != "al_session" || ck.Value == "" {
		t.Errorf("cookie name/value = %q/%q, want al_session/非空", ck.Name, ck.Value)
	}
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteNoneMode {
		t.Errorf("cookie 属性 HttpOnly=%v Secure=%v SameSite=%v, want true/true/None（§1.9 行 288）", ck.HttpOnly, ck.Secure, ck.SameSite)
	}
	if ck.MaxAge != 3600 {
		t.Errorf("cookie MaxAge = %d, want 3600（注入 ttl=1h）", ck.MaxAge)
	}
	assertRenewed(t, env, ck.Value, tok)
	if got := rec.Header().Get("X-Authloft-Token"); got != "" {
		t.Errorf("Cookie 来源不应下发 X-Authloft-Token 响应头（§1.9 行 290），got %q", got)
	}
}

// ③ 无令牌 → 未登录放行（不 401）：ctx 无身份 + 防御性清 Cookie（MaxAge=-1）。
func TestSessionNoTokenClearsCookieAndPasses(t *testing.T) {
	env := newSessionEnv(t)
	r, captured := env.sessionRouter(nil)

	rec := doRequest(r, http.MethodGet, "/api/account/x", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d（未登录放行，401 由下游判）", rec.Code, http.StatusOK)
	}
	if captured.ok {
		t.Errorf("ctx uid 注入了 %d, want 未注入（未登录）", captured.uid)
	}
	if ck := lastSetCookie(t, rec); ck == nil || ck.MaxAge != -1 || ck.Value != "" {
		t.Errorf("未登录应清 Cookie（MaxAge=-1 空值），got %+v", ck)
	}
}

// ④ 无效令牌（解不开的垃圾值）→ 未登录放行 + 清 Cookie。
func TestSessionInvalidTokenClearsCookieAndPasses(t *testing.T) {
	env := newSessionEnv(t)
	r, captured := env.sessionRouter(nil)

	rec := doRequest(r, http.MethodGet, "/api/account/x", map[string]string{"X-Authloft-Token": "garbage-token"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d（校验失败视为未登录放行）", rec.Code, http.StatusOK)
	}
	if captured.ok {
		t.Errorf("ctx uid 注入了 %d, want 未注入", captured.uid)
	}
	if ck := lastSetCookie(t, rec); ck == nil || ck.MaxAge != -1 {
		t.Errorf("校验失败应清 Cookie，got %+v", ck)
	}
}

// ⑤ epoch 不一致（ErrSessionStale）→ 未登录放行 + 清 Cookie（§1.9 行 292 改密后旧令牌失效）。
func TestSessionStaleEpochClearsCookieAndPasses(t *testing.T) {
	env := newSessionEnv(t)
	p := env.validPayload()
	env.epochs.values[p.Id] = p.Epoch + 1 // 令牌签发后 epoch 递增（改密）
	tok := env.sign(t, p)
	r, captured := env.sessionRouter(nil)

	req := newSessionRequest("/api/account/x", nil)
	req.AddCookie(&http.Cookie{Name: "al_session", Value: tok})
	rec := serveRequest(r, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d（epoch 不一致视为未登录放行）", rec.Code, http.StatusOK)
	}
	if captured.ok {
		t.Errorf("ctx uid 注入了 %d, want 未注入", captured.uid)
	}
	if ck := lastSetCookie(t, rec); ck == nil || ck.MaxAge != -1 {
		t.Errorf("epoch 不一致应清 Cookie，got %+v", ck)
	}
}

// ⑥ epoch 读取链故障（Redis 与回源均失败）→ 500 internal_error，
// 不得误判为未登录放行（session/verify.go 口径：基础设施错误）。
func TestSessionEpochReadErrorReturns500(t *testing.T) {
	env := newSessionEnv(t)
	env.epochs.err = errors.New("redis down")
	tok := env.sign(t, env.validPayload())
	r, captured := env.sessionRouter(nil)

	rec := doRequest(r, http.MethodGet, "/api/account/x", map[string]string{"X-Authloft-Token": tok})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d（epoch 读取链故障）", rec.Code, http.StatusInternalServerError)
	}
	if captured.ok {
		t.Errorf("ctx 注入了 uid %d, want 未注入（请求被拒）", captured.uid)
	}
	errObj := errorObject(t, decodeErrorBody(t, rec))
	if got := errObj["code"]; got != codec.CodeInternalError {
		t.Errorf("error.code = %v, want %q", got, codec.CodeInternalError)
	}
}

// ⑦ 取值优先级（§1.2 行 120）：Header 有值优先；Header 无效不回落 Cookie。
func TestSessionHeaderTakesPrecedenceOverCookie(t *testing.T) {
	env := newSessionEnv(t)
	tok := env.sign(t, env.validPayload())

	// Header 有效 + Cookie 垃圾 → 以 Header 为准通过。
	r, captured := env.sessionRouter(nil)
	req := newSessionRequest("/api/account/x", map[string]string{"X-Authloft-Token": tok})
	req.AddCookie(&http.Cookie{Name: "al_session", Value: "garbage"})
	rec := serveRequest(r, req)
	if rec.Code != http.StatusOK || !captured.ok || captured.uid != 42 {
		t.Fatalf("Header 有效+Cookie 无效: status=%d uid=(%d,%v), want 200/(42,true)", rec.Code, captured.uid, captured.ok)
	}

	// Header 无效 + Cookie 有效 → 不回落 Cookie，视为未登录。
	r2, captured2 := env.sessionRouter(nil)
	req2 := newSessionRequest("/api/account/x", map[string]string{"X-Authloft-Token": "garbage"})
	req2.AddCookie(&http.Cookie{Name: "al_session", Value: tok})
	rec2 := serveRequest(r2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d（未登录放行）", rec2.Code, http.StatusOK)
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
	r, captured := env.sessionRouter(func() string { return "my_sess" })

	req := newSessionRequest("/api/account/x", nil)
	req.AddCookie(&http.Cookie{Name: "my_sess", Value: tok})
	req.AddCookie(&http.Cookie{Name: "al_session", Value: "garbage"})
	rec := serveRequest(r, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d（注入名生效）", rec.Code, http.StatusOK)
	}
	if !captured.ok || captured.uid != 42 {
		t.Errorf("ctx uid = (%d, %v), want (42, true)", captured.uid, captured.ok)
	}
}

// ⑨ 续期闭环：重签下发的新令牌在下一请求（换 Cookie 来源）仍可校验通过——
// 中间件签发的令牌本身合法有效。
func TestSessionRenewedTokenAcceptedOnNextRequest(t *testing.T) {
	env := newSessionEnv(t)
	tok := env.sign(t, env.validPayload())
	r, _ := env.sessionRouter(nil)

	rec := doRequest(r, http.MethodGet, "/api/account/x", map[string]string{"X-Authloft-Token": tok})
	renewed := rec.Header().Get("X-Authloft-Token")
	assertRenewed(t, env, renewed, tok)

	req := newSessionRequest("/api/account/x", nil)
	req.AddCookie(&http.Cookie{Name: "al_session", Value: renewed})
	rec2 := serveRequest(r, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("续期令牌下一请求 status = %d, want %d", rec2.Code, http.StatusOK)
	}
}

// newSessionRequest 构造带自定义头的 GET 请求（session 测试专用，
// 与 doRequest 的差别是返回 *http.Request 供 AddCookie）。
func newSessionRequest(target string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// serveRequest 执行请求并返回 recorder（session 测试专用）。
func serveRequest(r *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// lastSetCookie 解析响应中唯一（或最后一枚）Set-Cookie；缺失返回 nil。
func lastSetCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	values := rec.Header().Values("Set-Cookie")
	if len(values) == 0 {
		return nil
	}
	ck, err := http.ParseSetCookie(values[len(values)-1])
	if err != nil {
		t.Fatalf("ParseSetCookie %q: %v", values[len(values)-1], err)
	}
	return ck
}
