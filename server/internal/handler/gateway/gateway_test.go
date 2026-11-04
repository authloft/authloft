// gateway_test.go 覆盖网关域唯一端点 `ANY /api/gateway/decode` 的 HTTP
// 契约（docs/接口文档.md §6 行 1346-1361）：有效令牌全字段响应头（含 amr
// 逗号分隔 / 空数组空值）、Cookie 回落与 Header 优先、无 / 篡改 / 过期 /
// epoch 不一致 → 恒 200 + invalid、epoch 基础设施故障 → 500 空体、
// X-Gateway-Token 无 / 错 → 403 空 body（对齐 middleware/gateway_test 口径，
// Gateway 中间件先于 handler）、tokens 动态源热更生效、ANY 多方法可达。
package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"authloft/gen/go/token"
	"authloft/internal/middleware"
	"authloft/internal/security"
	"authloft/internal/session"
)

// newTestCodec 构造测试 Codec（口径同 session/verify_test.go newTestCodec：
// 32 字节密钥 version=1 kid=1；跨包私有测试助手保持同口径副本）。
func newTestCodec(t *testing.T) *security.Codec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x20 + i)
	}
	ks, err := security.NewKeyStore(
		security.KeyEntry{ID: security.KeyID{Version: 1, Kid: 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return security.NewCodec(ks)
}

// fakeEpoch 可控 epoch 读取（口径同 oidc_test.go fakeEpoch，另加错误注入，
// 覆盖 Verify 的基础设施故障分支）。
type fakeEpoch struct {
	values map[int64]int64
	err    error
}

func (f *fakeEpoch) Current(_ context.Context, uid int64) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.values[uid], nil
}

// newTestEnv 构造 codec + Tokens + fakeEpoch（uid=42 当前 epoch=7）+ Verifier。
func newTestEnv(t *testing.T) (*session.Tokens, *fakeEpoch, *session.Verifier) {
	t.Helper()
	tokens := session.NewTokens(newTestCodec(t))
	epochs := &fakeEpoch{values: map[int64]int64{42: 7}}
	return tokens, epochs, session.NewVerifier(tokens, epochs)
}

// testPayload 标准测试载荷（id=42、epoch=7、amr=[pwd,otp]、sid-0001）。
// Verifier 的 now 为包外不可控的真实时钟，故 iat/exp 取真实时间
//（exp = now+1h 未过期）。
func testPayload() *token.SessionTokenPayload {
	now := time.Now().Unix()
	return &token.SessionTokenPayload{
		Id:    42,
		Epoch: 7,
		Amr:   []string{"pwd", "otp"},
		Sid:   "sid-0001",
		Iat:   now,
		Exp:   now + 3600,
	}
}

// signToken 签发测试会话令牌。
func signToken(t *testing.T, tokens *session.Tokens, p *token.SessionTokenPayload) string {
	t.Helper()
	tok, err := tokens.Sign(p)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return tok
}

// newGatewayRouter 按装配口径组链（同 bootstrap.registerGateway：/api/gateway
// 组 + Gateway 中间件先于 handler），tokens 为网关令牌动态源。
func newGatewayRouter(deps Deps, tokens func() []string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	gw := r.Group("/api/gateway")
	gw.Use(middleware.Gateway(tokens))
	Register(gw, deps)
	return r
}

// doDecode 发一次 decode 请求（headers 可空；cookies 为请求 Cookie）。
func doDecode(r http.Handler, method string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/gateway/decode", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// fixedTokens 固定网关令牌列表源。
func fixedTokens(list ...string) func() []string {
	return func() []string { return list }
}

// wantInvalid 断言恒 200 + X-Session-Status: invalid + 空体 + 无其余字段头。
func wantInvalid(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (恒 200，body %q)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get(headerStatus); got != statusInvalid {
		t.Errorf("X-Session-Status = %q, want %q", got, statusInvalid)
	}
	for _, h := range []string{headerID, headerEpoch, headerAMR, headerSID, headerIat, headerExp} {
		if got := rec.Header().Values(h); len(got) != 0 {
			t.Errorf("invalid 响应不应携带 %s，got %v", h, got)
		}
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty (纯响应头无响应体)", rec.Body.String())
	}
}

// ① 有效令牌 → 200 + payload 全字段逐项（§6 行 1350-1361；头名映射
// proto/token/session.proto 行 14-27，amr 逗号分隔）。
func TestDecodeValidTokenAllHeaders(t *testing.T) {
	tokens, _, verifier := newTestEnv(t)
	deps := Deps{Verify: verifier}
	r := newGatewayRouter(deps, fixedTokens("gw-tok"))

	p := testPayload()
	tok := signToken(t, tokens, p)
	rec := doDecode(r, http.MethodGet, map[string]string{
		"X-Gateway-Token":  "gw-tok",
		sessionTokenHeader: tok,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	want := map[string]string{
		headerStatus: statusValid,
		headerID:     strconv.FormatInt(p.GetId(), 10),
		headerEpoch:  strconv.FormatInt(p.GetEpoch(), 10),
		headerAMR:    "pwd,otp",
		headerSID:    p.GetSid(),
		headerIat:    strconv.FormatInt(p.GetIat(), 10),
		headerExp:    strconv.FormatInt(p.GetExp(), 10),
	}
	for h, v := range want {
		if got := rec.Header().Get(h); got != v {
			t.Errorf("%s = %q, want %q", h, got, v)
		}
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty (纯响应头无响应体)", rec.Body.String())
	}
}

// ② amr 空数组 → 头仍在、值为空（§6 行 1361：空数组输出空值，nil 同）。
func TestDecodeEmptyAMROutputsEmptyHeader(t *testing.T) {
	tokens, _, verifier := newTestEnv(t)
	r := newGatewayRouter(Deps{Verify: verifier}, fixedTokens("gw-tok"))

	p := testPayload()
	p.Amr = nil
	tok := signToken(t, tokens, p)
	rec := doDecode(r, http.MethodGet, map[string]string{
		"X-Gateway-Token":  "gw-tok",
		sessionTokenHeader: tok,
	})
	if rec.Code != http.StatusOK || rec.Header().Get(headerStatus) != statusValid {
		t.Fatalf("status/valid = %d/%q, want 200/valid", rec.Code, rec.Header().Get(headerStatus))
	}
	got := rec.Header().Values(headerAMR)
	if len(got) != 1 || got[0] != "" {
		t.Errorf("X-Session-AMR = %v, want 单个空值头（空数组输出空值）", got)
	}
}

// ③ Cookie 回落与 Header 优先（§6 行 1352、§1.2 行 120：优先级是取值
// 顺序而非失败回退——Header 无效不回落 Cookie；口径同 connect 拦截器）。
func TestDecodeCookieFallbackAndHeaderPriority(t *testing.T) {
	tokens, _, verifier := newTestEnv(t)
	tok := signToken(t, tokens, testPayload())
	gwHdr := map[string]string{"X-Gateway-Token": "gw-tok"}

	// a) 仅默认名 Cookie al_session → 有效。
	r := newGatewayRouter(Deps{Verify: verifier}, fixedTokens("gw-tok"))
	rec := doDecode(r, http.MethodGet, gwHdr, &http.Cookie{Name: "al_session", Value: tok})
	if rec.Header().Get(headerStatus) != statusValid {
		t.Errorf("cookie fallback: status = %q, want valid", rec.Header().Get(headerStatus))
	}

	// b) 自定义 Cookie 名（settings 键 cookie_name 注入口径）→ 有效；
	// b2) 默认名 Cookie 此时被忽略（换名不双读）。
	r = newGatewayRouter(Deps{Verify: verifier, CookieName: func() string { return "custom_sess" }}, fixedTokens("gw-tok"))
	rec = doDecode(r, http.MethodGet, gwHdr, &http.Cookie{Name: "custom_sess", Value: tok})
	if rec.Header().Get(headerStatus) != statusValid {
		t.Errorf("custom cookie name: status = %q, want valid", rec.Header().Get(headerStatus))
	}
	rec = doDecode(r, http.MethodGet, gwHdr, &http.Cookie{Name: "al_session", Value: tok})
	if rec.Header().Get(headerStatus) != statusInvalid {
		t.Errorf("custom name 下默认名 Cookie 应被忽略: status = %q, want invalid", rec.Header().Get(headerStatus))
	}

	// c) Header 有效 + Cookie 垃圾 → 以 Header 为准有效。
	rec = doDecode(r, http.MethodGet, map[string]string{
		"X-Gateway-Token":  "gw-tok",
		sessionTokenHeader: tok,
	}, &http.Cookie{Name: "al_session", Value: "garbage"})
	if rec.Header().Get(headerStatus) != statusValid {
		t.Errorf("header 优先: status = %q, want valid", rec.Header().Get(headerStatus))
	}

	// d) Header 垃圾 + Cookie 有效 → 不回落 Cookie，invalid。
	rec = doDecode(r, http.MethodGet, map[string]string{
		"X-Gateway-Token":  "gw-tok",
		sessionTokenHeader: "garbage",
	}, &http.Cookie{Name: "al_session", Value: tok})
	wantInvalid(t, rec)
}

// ④ 无令牌（Header 与 Cookie 皆空）→ 200 + invalid，不携带其余字段头。
func TestDecodeNoTokenInvalid(t *testing.T) {
	_, _, verifier := newTestEnv(t)
	r := newGatewayRouter(Deps{Verify: verifier}, fixedTokens("gw-tok"))
	wantInvalid(t, doDecode(r, http.MethodGet, map[string]string{"X-Gateway-Token": "gw-tok"}))
}

// ⑤ 篡改 / 过期 / epoch 不一致 → 一律恒 200 + invalid（§11.1 四步在
// Verifier 内，decode 只区分「会话无效」与「基础设施故障」两类语义）。
func TestDecodeInvalidTokenVariants(t *testing.T) {
	tokens, epochs, verifier := newTestEnv(t)
	r := newGatewayRouter(Deps{Verify: verifier}, fixedTokens("gw-tok"))

	// 篡改（乱码令牌，Parse 失败）。
	wantInvalid(t, doDecode(r, http.MethodGet, map[string]string{
		"X-Gateway-Token":  "gw-tok",
		sessionTokenHeader: "not-a-token",
	}))

	// 过期（exp = now-10）。
	expired := testPayload()
	expired.Exp = time.Now().Unix() - 10
	wantInvalid(t, doDecode(r, http.MethodGet, map[string]string{
		"X-Gateway-Token":  "gw-tok",
		sessionTokenHeader: signToken(t, tokens, expired),
	}))

	// epoch 不一致（token.epoch=7，当前已改密 → 8，ErrSessionStale）。
	epochs.values[42] = 8
	wantInvalid(t, doDecode(r, http.MethodGet, map[string]string{
		"X-Gateway-Token":  "gw-tok",
		sessionTokenHeader: signToken(t, tokens, testPayload()),
	}))
	epochs.values[42] = 7 // 还原，避免影响后续用例
}

// ⑥ epoch 读取链基础设施故障 → 500 空体，不误判登出态（verify.go 行
// 27-29 口径；X-Session-Status 不出）。
func TestDecodeEpochInfraErrorReturns500(t *testing.T) {
	tokens, epochs, verifier := newTestEnv(t)
	epochs.err = errors.New("redis and db both down")
	r := newGatewayRouter(Deps{Verify: verifier}, fixedTokens("gw-tok"))

	rec := doDecode(r, http.MethodGet, map[string]string{
		"X-Gateway-Token":  "gw-tok",
		sessionTokenHeader: signToken(t, tokens, testPayload()),
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (基础设施故障不得判为登出态)", rec.Code, http.StatusInternalServerError)
	}
	if got := rec.Header().Values(headerStatus); len(got) != 0 {
		t.Errorf("infra 500 不应携带 X-Session-Status，got %v", got)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty (豁免端点原生最小形态)", rec.Body.String())
	}
}

// ⑦ 无 / 错 X-Gateway-Token → 403 空 body（§1.5 行 188、§1.0 行 66 豁免
// 原生形态；对齐 middleware/gateway_test 口径，本组链 Gateway 先于 handler，
// decode 的会话令牌不参与）。
func TestGatewayTokenMissingOrWrongReturns403EmptyBody(t *testing.T) {
	_, _, verifier := newTestEnv(t)
	r := newGatewayRouter(Deps{Verify: verifier}, fixedTokens("gw-tok"))

	for name, hdr := range map[string]string{
		"missing": "",
		"wrong":   "gw-other",
	} {
		headers := map[string]string{sessionTokenHeader: "any"}
		if hdr != "" {
			headers["X-Gateway-Token"] = hdr
		}
		rec := doDecode(r, http.MethodGet, headers)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s X-Gateway-Token: status = %d, want %d", name, rec.Code, http.StatusForbidden)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("%s X-Gateway-Token: body = %q, want empty (403 空体)", name, rec.Body.String())
		}
		if got := rec.Header().Values(headerStatus); len(got) != 0 {
			t.Errorf("%s X-Gateway-Token: 不应携带 X-Session-Status，got %v", name, got)
		}
	}
}

// ⑧ tokens 动态源热更生效（middleware.Gateway 每请求读取；settings 变更
// → 新 token 放行的口径在本包用可变列表模拟，真 settings 链路见
// bootstrap 包 TestAssembleGatewaySettingsHotReload）。
func TestGatewayTokensHotReload(t *testing.T) {
	_, _, verifier := newTestEnv(t)
	list := []string{"tok-old"}
	r := newGatewayRouter(Deps{Verify: verifier}, func() []string { return list })

	rec := doDecode(r, http.MethodGet, map[string]string{"X-Gateway-Token": "tok-new"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("热更前 status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	list = append(list, "tok-new") // 模拟后台增配 gateway_tokens
	rec = doDecode(r, http.MethodGet, map[string]string{"X-Gateway-Token": "tok-new"})
	if rec.Code != http.StatusOK {
		t.Fatalf("热更后 status = %d, want %d (新 token 放行)", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get(headerStatus); got != statusInvalid {
		t.Errorf("放行后无会话令牌应为 invalid，got %q", got)
	}
}

// ⑨ ANY 方法语义（§6 行 1350）：GET/POST/PUT/PATCH/DELETE 均可达 handler。
func TestDecodeAnyMethod(t *testing.T) {
	tokens, _, verifier := newTestEnv(t)
	r := newGatewayRouter(Deps{Verify: verifier}, fixedTokens("gw-tok"))
	tok := signToken(t, tokens, testPayload())

	for _, method := range []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
	} {
		rec := doDecode(r, method, map[string]string{
			"X-Gateway-Token":  "gw-tok",
			sessionTokenHeader: tok,
		})
		if rec.Code != http.StatusOK || rec.Header().Get(headerStatus) != statusValid {
			t.Errorf("%s: status/valid = %d/%q, want 200/valid", method, rec.Code, rec.Header().Get(headerStatus))
		}
	}
}
