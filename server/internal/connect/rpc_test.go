// rpc HMAC 拦截器单测：覆盖重放被拒 /
// 错签被拒 / 对签通过 / 缺头 403 / 去重先于签名 / path 不含 query / 空 body
// 空串 / 未注册 client / 存储故障 fail-closed / 签名大小写不敏感 / 原始体捕获
// 缺失 fail-closed。全栈经真实 connect.NewUnaryHandler + CaptureRawBody
//（fake NonceStorer + 注入 SecretLookup，零 ENV.md 实例依赖，真连覆盖在
// cache 包 TestNonceStoreReal）。rpcSign 按接口文档 §7 行 1371/1377 独立实现
// 签名公式，与被测代码不共享实现（固定契约）；五项串公式由
// TestRPCSignFiveItems 锚定。
package connect

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	commonv1 "authloft/gen/go/api/common/v1"
)

const (
	testRPCClientID  = "web-1"
	testRPCSecret    = "s3cr3t"
	testRPCProcedure = "/api.rpc.v1.RpcService/GetUserProfile" // §7 行 1376 的 Connect RPC 路径形制
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

// rpcCapture handler 内捕获的调用方身份与解码后的请求消息。
type rpcCapture struct {
	clientID string
	ok       bool
	msg      string
	reached  bool
}

// newRPCHandler 构造挂 rpc HMAC 拦截器的测试 handler：handler 把 ctx 中的
// client_id 与解码后的请求消息码位记入捕获器。wrapCapture 控制是否包
// CaptureRawBody（装配层约定应包；不包用例验 fail-closed）。
func newRPCHandler(store NonceStorer, lookup SecretLookup, captured *rpcCapture, wrapCapture bool) http.Handler {
	inner := connect.NewUnaryHandler(testRPCProcedure,
		func(ctx context.Context, req *connect.Request[commonv1.ErrorInfo]) (*connect.Response[commonv1.ErrorInfo], error) {
			if captured != nil {
				captured.reached = true
				captured.clientID, captured.ok = ClientIDFromContext(ctx)
				captured.msg = req.Msg.GetCode()
			}
			return connect.NewResponse[commonv1.ErrorInfo](req.Msg), nil
		},
		connect.WithInterceptors(NewRPCHMACInterceptor(store, lookup)),
	)
	if !wrapCapture {
		return inner
	}
	return CaptureRawBody(inner)
}

// rpcBody 测试请求体：非空 proto 字节（proto.Marshal 确定性已由
// TestProtoMarshalDeterministic 锚定，可预计算签名）。
func rpcBody(t *testing.T) []byte {
	t.Helper()
	body, err := proto.Marshal(&commonv1.ErrorInfo{Code: "x", Message: "m"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return body
}

// doRPCRequest POST 一次 rpc 测试调用（target 可带 query），返回 recorder。
func doRPCRequest(handler http.Handler, target string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// sigBodyOf 返回 proto body 的签名串 body 段（与线上字节逐字一致，§7 行 1377）。
func sigBodyOf(body []byte) string { return string(body) }

// ① 三头缺任一 → 403 permission_denied，nonce 存储零调用（缺头时无
// client_id/nonce 可去重），handler 不可达。
func TestRPCHMACMissingHeaders(t *testing.T) {
	for _, missing := range []string{"X-Client-ID", "X-Nonce-ID", "X-Signature"} {
		store := &fakeRPCNonceStore{}
		captured := &rpcCapture{}
		h := newRPCHandler(store, fakeSecretLookup(), captured, true)

		body := rpcBody(t)
		headers := rpcHeaders(testRPCClientID, "n1",
			rpcSign(testRPCClientID, "n1", testRPCProcedure, sigBodyOf(body), testRPCSecret))
		delete(headers, missing)
		rec := doRPCRequest(h, testRPCProcedure, body, headers)

		if rec.Code != http.StatusForbidden {
			t.Errorf("missing %s: status = %d, want %d", missing, rec.Code, http.StatusForbidden)
			continue
		}
		if got := decodeConnectErrorBody(t, rec.Body)["code"]; got != "permission_denied" {
			t.Errorf("missing %s: error code = %q, want %q", missing, got, "permission_denied")
		}
		if store.callCount() != 0 {
			t.Errorf("missing %s: nonce store calls = %d, want 0", missing, store.callCount())
		}
		if captured.reached {
			t.Errorf("missing %s: handler reached", missing)
		}
	}
}

// ② nonce 重放被拒：同 (clientID, nonce) 二次请求、签名均正确 → 第一次 200、
// 第二次 403。
func TestRPCHMACNonceReplayRejected(t *testing.T) {
	store := &fakeRPCNonceStore{}
	h := newRPCHandler(store, fakeSecretLookup(), &rpcCapture{}, true)
	body := rpcBody(t)
	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCProcedure, sigBodyOf(body), testRPCSecret))

	if rec := doRPCRequest(h, testRPCProcedure, body, headers); rec.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", rec.Code, http.StatusOK)
	}
	rec := doRPCRequest(h, testRPCProcedure, body, headers)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("replay status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := decodeConnectErrorBody(t, rec.Body)["code"]; got != "permission_denied" {
		t.Fatalf("replay error code = %q, want %q", got, "permission_denied")
	}
}

// ③ 签名错被拒：错误密钥签出的签名 → 403；且 nonce 已被消耗
//（store calls = 1——去重先于签名）。
func TestRPCHMACBadSignatureRejected(t *testing.T) {
	store := &fakeRPCNonceStore{}
	h := newRPCHandler(store, fakeSecretLookup(), &rpcCapture{}, true)

	body := rpcBody(t)
	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCProcedure, sigBodyOf(body), "wrong-secret"))
	rec := doRPCRequest(h, testRPCProcedure, body, headers)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad signature status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := decodeConnectErrorBody(t, rec.Body)["code"]; got != "permission_denied" {
		t.Fatalf("bad signature error code = %q, want %q", got, "permission_denied")
	}
	if store.callCount() != 1 {
		t.Fatalf("nonce store calls = %d, want 1（去重先于签名）", store.callCount())
	}
}

// ④ 签名对通过：带 body、签名按文档公式构造 → 200；响应体证明 body 经
// CaptureRawBody 回填后可被 connect 解码、client_id 已入 ctx。
func TestRPCHMACValidSignaturePasses(t *testing.T) {
	store := &fakeRPCNonceStore{}
	captured := &rpcCapture{}
	h := newRPCHandler(store, fakeSecretLookup(), captured, true)

	body := rpcBody(t)
	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCProcedure, string(body), testRPCSecret))
	rec := doRPCRequest(h, testRPCProcedure, body, headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !captured.reached || !captured.ok || captured.clientID != testRPCClientID {
		t.Fatalf("ctx client_id = (%q,%v), want (%q,true)", captured.clientID, captured.ok, testRPCClientID)
	}
	var echoed commonv1.ErrorInfo
	if err := proto.Unmarshal(rec.Body.Bytes(), &echoed); err != nil {
		t.Fatalf("Unmarshal response: %v", err)
	}
	if echoed.GetCode() != "x" || echoed.GetMessage() != "m" {
		t.Fatalf("echo response = (code=%q message=%q), want 原样回显（解码自回填后的 body）", echoed.GetCode(), echoed.GetMessage())
	}
}

// ⑤ 校验顺序硬约束：nonce 去重先于签名——第一次请求签名错误，nonce 仍被
// 消耗；第二次同 nonce 带正确签名 → 403（重放拦截）。
func TestRPCHMACNonceDedupBeforeSignature(t *testing.T) {
	store := &fakeRPCNonceStore{}
	h := newRPCHandler(store, fakeSecretLookup(), &rpcCapture{}, true)

	body := rpcBody(t)
	bad := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCProcedure, sigBodyOf(body), "wrong"))
	doRPCRequest(h, testRPCProcedure, body, bad)
	if store.callCount() != 1 {
		t.Fatalf("nonce store calls after bad signature = %d, want 1（签名错也消耗 nonce）", store.callCount())
	}

	good := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCProcedure, sigBodyOf(body), testRPCSecret))
	if rec := doRPCRequest(h, testRPCProcedure, body, good); rec.Code != http.StatusForbidden {
		t.Fatalf("correct signature with consumed nonce: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// ⑥ 空 body 空串边界（§7 行 1377）：直调拦截器 + ctx 原始字节为空 → 签名串
// body 段为空串、校验通过。connect-go 对 0 字节请求体在拦截器之前按
// cardinality violation 拒绝（unary 必须有一条消息），故空 body 向量只能经
// 原始体捕获路径触达——这正是签名与捕获解耦的用例。
func TestRPCHMACEmptyBody(t *testing.T) {
	store := &fakeRPCNonceStore{}
	injected := false
	wrapped := NewRPCHMACInterceptor(store, fakeSecretLookup())(connect.UnaryFunc(
		func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			injected = true
			id, ok := ClientIDFromContext(ctx)
			if !ok || id != testRPCClientID {
				t.Errorf("client_id 注入 = (%q,%v), want (%q,true)", id, ok, testRPCClientID)
			}
			return connect.NewResponse(&commonv1.ErrorInfo{}), nil
		}))

	req := connect.NewRequest(&commonv1.ErrorInfo{})
	req.Header().Set(rpcHeaderClientID, testRPCClientID)
	req.Header().Set(rpcHeaderNonceID, "n1")
	// connect.NewRequest 未设 Spec（procedure 为空串）；本用例锚定 body 段
	// 空串向量，path 段同步以空串入签名。
	req.Header().Set(rpcHeaderSignature, rpcSign(testRPCClientID, "n1", "", "", testRPCSecret))

	ctx := context.WithValue(context.Background(), rawBodyKey{}, []byte{})
	resp, err := wrapped(ctx, req)
	if err != nil || resp == nil {
		t.Fatalf("wrapped = (%v, %v), want 成功（空 body 空串入签）", resp, err)
	}
	if !injected {
		t.Error("下游未被调")
	}
	if store.callCount() != 1 {
		t.Errorf("nonce store calls = %d, want 1", store.callCount())
	}
}

// ⑦ path 不含 query 边界（§7 行 1375-1376）：target 带 ?a=1&b=2，签名只覆盖
// Connect RPC 路径 → 200；反例：签名把 query 算进 path 段 → 403（证明实现
// 取不含 query 的路径）。
func TestRPCHMACPathExcludesQuery(t *testing.T) {
	store := &fakeRPCNonceStore{}
	h := newRPCHandler(store, fakeSecretLookup(), &rpcCapture{}, true)
	target := testRPCProcedure + "?a=1&b=2"
	body := rpcBody(t)

	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCProcedure, sigBodyOf(body), testRPCSecret))
	if rec := doRPCRequest(h, target, body, headers); rec.Code != http.StatusOK {
		t.Fatalf("path without query status = %d, want %d", rec.Code, http.StatusOK)
	}

	withQuery := rpcHeaders(testRPCClientID, "n2",
		rpcSign(testRPCClientID, "n2", target, sigBodyOf(body), testRPCSecret))
	if rec := doRPCRequest(h, target, body, withQuery); rec.Code != http.StatusForbidden {
		t.Fatalf("signature covering query status = %d, want %d（path 不得含 query）", rec.Code, http.StatusForbidden)
	}
}

// ⑧ client 未注册（lookup 未命中）→ 403；nonce 已消耗（去重先于密钥查询）。
func TestRPCHMACUnknownClient(t *testing.T) {
	store := &fakeRPCNonceStore{}
	h := newRPCHandler(store, fakeSecretLookup(), &rpcCapture{}, true)

	body := rpcBody(t)
	headers := rpcHeaders("ghost", "n1",
		rpcSign("ghost", "n1", testRPCProcedure, sigBodyOf(body), "whatever"))
	rec := doRPCRequest(h, testRPCProcedure, body, headers)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown client status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := decodeConnectErrorBody(t, rec.Body)["code"]; got != "permission_denied" {
		t.Fatalf("unknown client error code = %q, want %q", got, "permission_denied")
	}
	if store.callCount() != 1 {
		t.Fatalf("nonce store calls = %d, want 1", store.callCount())
	}
}

// ⑨ nonce 存储故障 → 500 internal（fail-closed：无法判定重放不得放行）。
func TestRPCHMACNonceStoreError(t *testing.T) {
	store := &fakeRPCNonceStore{err: errors.New("redis down")}
	captured := &rpcCapture{}
	h := newRPCHandler(store, fakeSecretLookup(), captured, true)

	body := rpcBody(t)
	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCProcedure, sigBodyOf(body), testRPCSecret))
	rec := doRPCRequest(h, testRPCProcedure, body, headers)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("store error status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := decodeConnectErrorBody(t, rec.Body)["code"]; got != "internal" {
		t.Fatalf("store error code = %q, want %q", got, "internal")
	}
	if captured.reached {
		t.Fatal("handler reached on store error")
	}
}

// ⑩ 签名十六进制大小写不敏感（hex 解码后按字节恒时比较）。
func TestRPCHMACSignatureCaseInsensitive(t *testing.T) {
	store := &fakeRPCNonceStore{}
	h := newRPCHandler(store, fakeSecretLookup(), &rpcCapture{}, true)

	body := rpcBody(t)
	sig := rpcSign(testRPCClientID, "n1", testRPCProcedure, sigBodyOf(body), testRPCSecret)
	headers := rpcHeaders(testRPCClientID, "n1", strings.ToUpper(sig))
	if rec := doRPCRequest(h, testRPCProcedure, body, headers); rec.Code != http.StatusOK {
		t.Fatalf("uppercase hex signature status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// ⑪ 装配层漏挂 CaptureRawBody → 原始 body 拿不到 → internal fail-closed，
// 不允许在空 body 向量上静默验签（防签名域被降级）。
func TestRPCHMACBodyUnavailableFailsClosed(t *testing.T) {
	store := &fakeRPCNonceStore{}
	captured := &rpcCapture{}
	h := newRPCHandler(store, fakeSecretLookup(), captured, false) // 不包捕获层

	body := rpcBody(t)
	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCProcedure, string(body), testRPCSecret))
	rec := doRPCRequest(h, testRPCProcedure, body, headers)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("body unavailable status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := decodeConnectErrorBody(t, rec.Body)["code"]; got != "internal" {
		t.Fatalf("body unavailable error code = %q, want %q", got, "internal")
	}
	if captured.reached {
		t.Fatal("handler reached without raw body capture")
	}
}
