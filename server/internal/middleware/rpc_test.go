// RPC 鉴权中间件单测：覆盖 §21.2 E 行 1870（nonce 重放被拒 /
// 签名错被拒 / 签名对通过）+ GET 空 body 空串、path 不含 query 两边界；
// fake NonceStorer + 注入 SecretLookup，不依赖真实 Redis（真连覆盖在
// cache 包 TestNonceStoreReal）。rpcSign 按接口文档 §7 行 1371/1377 独立
// 实现签名公式，与被测代码不共享实现（固定契约）。
package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"authloft/internal/codec"
)

const (
	testRPCClientID = "web-1"
	testRPCSecret   = "s3cr3t"
	testRPCPath     = "/api/rpc/x"
)

// fakeRPCNonceStore 计数型 fake：seen 记录已见 (clientID, nonce)，err 模拟存储故障。
type fakeRPCNonceStore struct {
	mu    sync.Mutex
	calls int
	seen  map[string]bool
	err   error
}

func (f *fakeRPCNonceStore) Store(ctx context.Context, clientID, nonce string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	key := clientID + "\x00" + nonce
	if f.seen[key] {
		return false, nil
	}
	if f.seen == nil {
		f.seen = make(map[string]bool)
	}
	f.seen[key] = true
	return true, nil
}

func (f *fakeRPCNonceStore) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeSecretLookup 返回固定注册表 {testRPCClientID: testRPCSecret} 的查询函数。
func fakeSecretLookup() SecretLookup {
	return func(ctx context.Context, clientID string) (string, bool) {
		if clientID == testRPCClientID {
			return testRPCSecret, true
		}
		return "", false
	}
}

// rpcSign 按文档公式独立实现：HMAC-SHA256(key=secret,
// msg="client_id:nonce:path:body:client_secret")——五项以 ":" 连接整体入串，
// 密钥仍为 client_secret（§7 行 1371/1377）。
func rpcSign(clientID, nonce, path, body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(clientID + ":" + nonce + ":" + path + ":" + body + ":" + secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// TestRPCSignFiveItems 锚定签名串公式：rpcSign 输出必须等于
// 五项串 "client_id:nonce:path:body:client_secret" 的 HMAC，且不等于旧四项
// 公式输出——client_secret 须入串，防止公式静默回退。
func TestRPCSignFiveItems(t *testing.T) {
	const clientID, nonce, path, body, secret = "c1", "n1", "/p", "b", "k"

	fiveMac := hmac.New(sha256.New, []byte(secret))
	fiveMac.Write([]byte("c1:n1:/p:b:k"))
	fourMac := hmac.New(sha256.New, []byte(secret))
	fourMac.Write([]byte("c1:n1:/p:b"))

	got := rpcSign(clientID, nonce, path, body, secret)
	if want := hex.EncodeToString(fiveMac.Sum(nil)); got != want {
		t.Fatalf("rpcSign = %q, want %q（五项入串，§7 行 1371）", got, want)
	}
	if want := hex.EncodeToString(fourMac.Sum(nil)); got == want {
		t.Fatalf("rpcSign matches four-item formula %q, want five-item（client_secret 须入串）", want)
	}
}

// rpcHeaders 三鉴权头（头名用字面量而非生产常量，固定契约）。
func rpcHeaders(clientID, nonce, signature string) map[string]string {
	return map[string]string{
		"X-Client-ID":  clientID,
		"X-Nonce-ID":   nonce,
		"X-Signature":  signature,
	}
}

// doRPCRequest 带 body 与头的请求（rpc 测试专用，不复用 doRequest——它不带 body）。
func doRPCRequest(r *gin.Engine, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, reader)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// newRPCEchoRouter 构造挂 RPCAuth 的测试路由：handler 把 ctx 中的 client_id
// 与读到的 body 写进响应体（格式 "client_id|body"，同时验证 body 回填）；
// reached 记录 handler 是否被触达（可传 nil）。
func newRPCEchoRouter(store NonceStorer, lookup SecretLookup, reached *bool) *gin.Engine {
	r := newTestRouter(RPCAuth(store, lookup))
	r.Any("/api/rpc/x", func(c *gin.Context) {
		if reached != nil {
			*reached = true
		}
		clientID, _ := c.Get(RPCClientIDKey)
		id, _ := clientID.(string)
		body, _ := io.ReadAll(c.Request.Body)
		c.String(http.StatusOK, id+"|"+string(body))
	})
	return r
}

// ① 三头缺任一 → 403 forbidden（信封走 codec.WriteError），nonce 存储零调用
//（缺头时无 client_id/nonce 可去重），handler 不可达。
func TestRPCAuthMissingHeaders(t *testing.T) {
	for _, missing := range []string{"X-Client-ID", "X-Nonce-ID", "X-Signature"} {
		store := &fakeRPCNonceStore{}
		var reached bool
		r := newRPCEchoRouter(store, fakeSecretLookup(), &reached)

		headers := rpcHeaders(testRPCClientID, "n1",
			rpcSign(testRPCClientID, "n1", testRPCPath, "", testRPCSecret))
		delete(headers, missing)
		rec := doRPCRequest(r, http.MethodPost, testRPCPath, "", headers)

		if rec.Code != http.StatusForbidden {
			t.Errorf("missing %s: status = %d, want %d", missing, rec.Code, http.StatusForbidden)
			continue
		}
		if got := errorObject(t, decodeErrorBody(t, rec))["code"]; got != codec.CodeForbidden {
			t.Errorf("missing %s: error code = %v, want %q", missing, got, codec.CodeForbidden)
		}
		if store.callCount() != 0 {
			t.Errorf("missing %s: nonce store calls = %d, want 0", missing, store.callCount())
		}
		if reached {
			t.Errorf("missing %s: handler reached", missing)
		}
	}
}

// ② nonce 重放被拒（§21.2 E 行 1870）：同 (clientID, nonce) 二次请求、签名均
// 正确 → 第一次 200、第二次 403。
func TestRPCAuthNonceReplayRejected(t *testing.T) {
	store := &fakeRPCNonceStore{}
	r := newRPCEchoRouter(store, fakeSecretLookup(), nil)
	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCPath, "", testRPCSecret))

	if rec := doRPCRequest(r, http.MethodPost, testRPCPath, "", headers); rec.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", rec.Code, http.StatusOK)
	}
	rec := doRPCRequest(r, http.MethodPost, testRPCPath, "", headers)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("replay status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := errorObject(t, decodeErrorBody(t, rec))["code"]; got != codec.CodeForbidden {
		t.Fatalf("replay error code = %v, want %q", got, codec.CodeForbidden)
	}
}

// ③ 签名错被拒（§21.2 E 行 1870）：错误密钥签出的签名 → 403；且 nonce 已被
// 消耗（store calls = 1——去重先于签名）。
func TestRPCAuthBadSignatureRejected(t *testing.T) {
	store := &fakeRPCNonceStore{}
	r := newRPCEchoRouter(store, fakeSecretLookup(), nil)

	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCPath, "", "wrong-secret"))
	rec := doRPCRequest(r, http.MethodPost, testRPCPath, "", headers)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad signature status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := errorObject(t, decodeErrorBody(t, rec))["code"]; got != codec.CodeForbidden {
		t.Fatalf("bad signature error code = %v, want %q", got, codec.CodeForbidden)
	}
	if store.callCount() != 1 {
		t.Fatalf("nonce store calls = %d, want 1（去重先于签名）", store.callCount())
	}
}

// ④ 签名对通过（§21.2 E 行 1870）：POST 带 body、签名按文档公式构造 → 200；
// 响应体证明 client_id 已入 ctx 且 body 未被中间件消费（回填可读）。
func TestRPCAuthValidSignaturePasses(t *testing.T) {
	store := &fakeRPCNonceStore{}
	r := newRPCEchoRouter(store, fakeSecretLookup(), nil)

	body := `{"uid":7}`
	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCPath, body, testRPCSecret))
	rec := doRPCRequest(r, http.MethodPost, testRPCPath, body, headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got, want := rec.Body.String(), testRPCClientID+"|"+body; got != want {
		t.Fatalf("response = %q, want %q（client_id 入 ctx + body 回填）", got, want)
	}
}

// ⑤ 校验顺序硬约束（§3.3 行 314）：nonce 去重先于签名——第一次请求签名错误，
// nonce 仍被消耗；第二次同 nonce 带正确签名 → 403（重放拦截）。
func TestRPCAuthNonceDedupBeforeSignature(t *testing.T) {
	store := &fakeRPCNonceStore{}
	r := newRPCEchoRouter(store, fakeSecretLookup(), nil)

	bad := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCPath, "", "wrong"))
	doRPCRequest(r, http.MethodPost, testRPCPath, "", bad)
	if store.callCount() != 1 {
		t.Fatalf("nonce store calls after bad signature = %d, want 1（签名错也消耗 nonce）", store.callCount())
	}

	good := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCPath, "", testRPCSecret))
	if rec := doRPCRequest(r, http.MethodPost, testRPCPath, "", good); rec.Code != http.StatusForbidden {
		t.Fatalf("correct signature with consumed nonce: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// ⑥ GET 空 body 边界（§7 行 1376）：签名串 body 段为空串 → 200。
func TestRPCAuthGETEmptyBody(t *testing.T) {
	store := &fakeRPCNonceStore{}
	r := newRPCEchoRouter(store, fakeSecretLookup(), nil)

	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCPath, "", testRPCSecret))
	rec := doRPCRequest(r, http.MethodGet, testRPCPath, "", headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET empty body status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got, want := rec.Body.String(), testRPCClientID+"|"; got != want {
		t.Fatalf("GET response = %q, want %q（空 body 空串）", got, want)
	}
}

// ⑦ path 不含 query 边界（§7 行 1375）：target 带 ?a=1&b=2，签名只覆盖
// /api/rpc/x → 200；反例：签名把 query 算进 path → 403（证明实现排除 query）。
func TestRPCAuthPathExcludesQuery(t *testing.T) {
	store := &fakeRPCNonceStore{}
	r := newRPCEchoRouter(store, fakeSecretLookup(), nil)
	target := testRPCPath + "?a=1&b=2"

	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCPath, "", testRPCSecret))
	if rec := doRPCRequest(r, http.MethodPost, target, "", headers); rec.Code != http.StatusOK {
		t.Fatalf("path without query status = %d, want %d", rec.Code, http.StatusOK)
	}

	withQuery := rpcHeaders(testRPCClientID, "n2",
		rpcSign(testRPCClientID, "n2", target, "", testRPCSecret))
	if rec := doRPCRequest(r, http.MethodPost, target, "", withQuery); rec.Code != http.StatusForbidden {
		t.Fatalf("signature covering query status = %d, want %d（path 不得含 query）", rec.Code, http.StatusForbidden)
	}
}

// ⑧ client 未注册（lookup 未命中）→ 403；nonce 已消耗（去重先于密钥查询）。
func TestRPCAuthUnknownClient(t *testing.T) {
	store := &fakeRPCNonceStore{}
	r := newRPCEchoRouter(store, fakeSecretLookup(), nil)

	headers := rpcHeaders("ghost", "n1",
		rpcSign("ghost", "n1", testRPCPath, "", "whatever"))
	rec := doRPCRequest(r, http.MethodPost, testRPCPath, "", headers)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown client status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := errorObject(t, decodeErrorBody(t, rec))["code"]; got != codec.CodeForbidden {
		t.Fatalf("unknown client error code = %v, want %q", got, codec.CodeForbidden)
	}
	if store.callCount() != 1 {
		t.Fatalf("nonce store calls = %d, want 1", store.callCount())
	}
}

// ⑨ nonce 存储故障 → 500 internal_error（fail-closed 取舍见 rpc.go 注释）。
func TestRPCAuthNonceStoreError(t *testing.T) {
	store := &fakeRPCNonceStore{err: errors.New("redis down")}
	var reached bool
	r := newRPCEchoRouter(store, fakeSecretLookup(), &reached)

	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCPath, "", testRPCSecret))
	rec := doRPCRequest(r, http.MethodPost, testRPCPath, "", headers)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("store error status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := errorObject(t, decodeErrorBody(t, rec))["code"]; got != codec.CodeInternalError {
		t.Fatalf("store error code = %v, want %q", got, codec.CodeInternalError)
	}
	if reached {
		t.Fatal("handler reached on store error")
	}
}

// ⑩ 签名十六进制大小写不敏感（hex 解码后按字节比较）。
func TestRPCAuthSignatureCaseInsensitive(t *testing.T) {
	store := &fakeRPCNonceStore{}
	r := newRPCEchoRouter(store, fakeSecretLookup(), nil)

	sig := rpcSign(testRPCClientID, "n1", testRPCPath, "", testRPCSecret)
	headers := rpcHeaders(testRPCClientID, "n1", strings.ToUpper(sig))
	if rec := doRPCRequest(r, http.MethodPost, testRPCPath, "", headers); rec.Code != http.StatusOK {
		t.Fatalf("uppercase hex signature status = %d, want %d", rec.Code, http.StatusOK)
	}
}
