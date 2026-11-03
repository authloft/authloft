// rpc HMAC 拦截器单测（断言迁移到 Connect interceptor，按读写分流改造）：
// 覆盖读写分流（写前缀集合表驱动、读接口不去重且 nonce 仍入签、写接口
// 重放被拒）/ 错签被拒 / 对签通过 / 缺头 403（读写都要求）/ 写接口去重
// 先于签名 / path 不含 query / 空 body 空串 / 未注册 client / 存储故障
// fail-closed / 签名大小写不敏感 / 原始体捕获缺失 fail-closed。全栈经真实
// connect.NewUnaryHandler + CaptureRawBody
//（fake NonceStorer + 注入 SecretLookup，零 ENV.md 实例依赖，真连覆盖在
// cache 包 TestNonceStoreReal）。rpcSign 按接口文档 §7 行 1374/1381 独立实现
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
	testRPCClientID = "web-1"
	testRPCSecret   = "s3cr3t"
	// 读写分流测试 procedure（拆分后的真实 Connect 路径，§7 行 1378；
	// 前缀判定口径 §7 行 1366）：
	testRPCReadProcedure   = "/api.rpc.v1.UserService/GetUserProfile"    // 读（Get 前缀）
	testRPCDecodeProcedure = "/api.rpc.v1.TokenService/DecodeSession"    // 读（Decode 前缀）
	testRPCWriteProcedure  = "/api.rpc.v1.UserService/UpdateUserProfile" // 写（Update 前缀）
)

// rpcReadProcedures 全部真实读接口 procedure（§7 行 1387/1389）。
var rpcReadProcedures = []string{testRPCReadProcedure, testRPCDecodeProcedure}

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
// 密钥仍为 client_secret（§7 行 1374/1381）。读写接口签名串
// 完全一致（nonce 均入串），区别仅在写接口额外做去重（§7 行 1381）。
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
		t.Fatalf("rpcSign = %q, want %q（五项入串，§7 行 1381）", got, want)
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

// newRPCHandler 构造挂 rpc HMAC 拦截器的测试 handler（procedure 即测试目标
// Connect 路径）：handler 把 ctx 中的 client_id 与解码后的请求消息码位记入
// 捕获器。wrapCapture 控制是否包 CaptureRawBody（装配层约定应包；不包用例
// 验 fail-closed）。
func newRPCHandler(procedure string, store NonceStorer, lookup SecretLookup, captured *rpcCapture, wrapCapture bool) http.Handler {
	inner := connect.NewUnaryHandler(procedure,
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

// sigBodyOf 返回 proto body 的签名串 body 段（与线上字节逐字一致，§7 行 1379）。
func sigBodyOf(body []byte) string { return string(body) }

// ① 三头缺任一 → 403 permission_denied（读写接口都要求三头，§7 行 1370-1374），
// nonce 存储零调用（缺头时无 client_id/nonce 可去重），handler 不可达。
func TestRPCHMACMissingHeaders(t *testing.T) {
	for _, procedure := range append(rpcReadProcedures, testRPCWriteProcedure) {
		for _, missing := range []string{"X-Client-ID", "X-Nonce-ID", "X-Signature"} {
			store := &fakeRPCNonceStore{}
			captured := &rpcCapture{}
			h := newRPCHandler(procedure, store, fakeSecretLookup(), captured, true)

			body := rpcBody(t)
			headers := rpcHeaders(testRPCClientID, "n1",
				rpcSign(testRPCClientID, "n1", procedure, sigBodyOf(body), testRPCSecret))
			delete(headers, missing)
			rec := doRPCRequest(h, procedure, body, headers)

			if rec.Code != http.StatusForbidden {
				t.Errorf("%s missing %s: status = %d, want %d", procedure, missing, rec.Code, http.StatusForbidden)
				continue
			}
			if got := decodeConnectErrorBody(t, rec.Body)["code"]; got != "permission_denied" {
				t.Errorf("%s missing %s: error code = %q, want %q", procedure, missing, got, "permission_denied")
			}
			if store.callCount() != 0 {
				t.Errorf("%s missing %s: nonce store calls = %d, want 0", procedure, missing, store.callCount())
			}
			if captured.reached {
				t.Errorf("%s missing %s: handler reached", procedure, missing)
			}
		}
	}
}

// ② 写接口 nonce 重放被拒（§7 行 1373/1383）：UpdateUserProfile 同
// (clientID, nonce) 二次请求、签名均正确（五项串）→ 第一次 200、第二次 403。
func TestRPCHMACWriteNonceReplayRejected(t *testing.T) {
	store := &fakeRPCNonceStore{}
	h := newRPCHandler(testRPCWriteProcedure, store, fakeSecretLookup(), &rpcCapture{}, true)
	body := rpcBody(t)
	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCWriteProcedure, sigBodyOf(body), testRPCSecret))

	if rec := doRPCRequest(h, testRPCWriteProcedure, body, headers); rec.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want %d", rec.Code, http.StatusOK)
	}
	rec := doRPCRequest(h, testRPCWriteProcedure, body, headers)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("replay status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := decodeConnectErrorBody(t, rec.Body)["code"]; got != "permission_denied" {
		t.Fatalf("replay error code = %q, want %q", got, "permission_denied")
	}
	if store.callCount() != 2 {
		t.Fatalf("nonce store calls = %d, want 2（写接口每次请求都去重）", store.callCount())
	}
}

// ③ 读接口不去重（§7 行 1373/1383：nonce 参与签名但不去重）：GetUserProfile
// 与 DecodeSession 同 (clientID, nonce) 重复请求两次均 200，store 零调用；
// store 故障同样放行（读链路根本不查 store，失败无从影响——不去重实证）。
func TestRPCHMACReadSkipsNonceDedup(t *testing.T) {
	for _, procedure := range rpcReadProcedures {
		store := &fakeRPCNonceStore{}
		h := newRPCHandler(procedure, store, fakeSecretLookup(), &rpcCapture{}, true)
		body := rpcBody(t)
		headers := rpcHeaders(testRPCClientID, "n1",
			rpcSign(testRPCClientID, "n1", procedure, sigBodyOf(body), testRPCSecret))

		for i := 1; i <= 2; i++ {
			if rec := doRPCRequest(h, procedure, body, headers); rec.Code != http.StatusOK {
				t.Fatalf("%s 第 %d 次（同 nonce）status = %d, want %d", procedure, i, rec.Code, http.StatusOK)
			}
		}
		if store.callCount() != 0 {
			t.Fatalf("%s nonce store calls = %d, want 0（读接口不去重）", procedure, store.callCount())
		}

		broken := &fakeRPCNonceStore{err: errors.New("redis down")}
		hb := newRPCHandler(procedure, broken, fakeSecretLookup(), &rpcCapture{}, true)
		if rec := doRPCRequest(hb, procedure, body, headers); rec.Code != http.StatusOK {
			t.Fatalf("%s store 故障时 status = %d, want %d（读接口不查 store）", procedure, rec.Code, http.StatusOK)
		}
		if broken.callCount() != 0 {
			t.Fatalf("%s broken store calls = %d, want 0", procedure, broken.callCount())
		}
	}
}

// ④ 签名串仍五项、nonce 入签（§7 行 1381：读写签名一致，nonce 均参与）：
// 头里 nonce 与签名串 nonce 项不一致 → 读写接口均 403（nonce 错则签名校验
// 失败）；读接口 store 仍零调用、写接口已消耗 1 次（去重先于签名）。
func TestRPCHMACNoncePartOfSignature(t *testing.T) {
	for _, procedure := range append(rpcReadProcedures, testRPCWriteProcedure) {
		store := &fakeRPCNonceStore{}
		h := newRPCHandler(procedure, store, fakeSecretLookup(), &rpcCapture{}, true)

		body := rpcBody(t)
		headers := rpcHeaders(testRPCClientID, "n1",
			rpcSign(testRPCClientID, "n2", procedure, sigBodyOf(body), testRPCSecret))
		rec := doRPCRequest(h, procedure, body, headers)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s nonce 项错 status = %d, want %d", procedure, rec.Code, http.StatusForbidden)
		}
		if got := decodeConnectErrorBody(t, rec.Body)["code"]; got != "permission_denied" {
			t.Fatalf("%s nonce 项错 error code = %q, want %q", procedure, got, "permission_denied")
		}
		wantCalls := 0
		if procedure == testRPCWriteProcedure {
			wantCalls = 1
		}
		if store.callCount() != wantCalls {
			t.Fatalf("%s nonce store calls = %d, want %d", procedure, store.callCount(), wantCalls)
		}
	}
}

// ⑤ 签名错被拒：错误密钥签出的签名 → 读写接口均 403；写接口 nonce 已被
// 消耗（store calls = 1——去重先于签名），读接口不消耗。
func TestRPCHMACBadSignatureRejected(t *testing.T) {
	for _, procedure := range append(rpcReadProcedures, testRPCWriteProcedure) {
		store := &fakeRPCNonceStore{}
		h := newRPCHandler(procedure, store, fakeSecretLookup(), &rpcCapture{}, true)

		body := rpcBody(t)
		headers := rpcHeaders(testRPCClientID, "n1",
			rpcSign(testRPCClientID, "n1", procedure, sigBodyOf(body), "wrong-secret"))
		rec := doRPCRequest(h, procedure, body, headers)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s bad signature status = %d, want %d", procedure, rec.Code, http.StatusForbidden)
		}
		if got := decodeConnectErrorBody(t, rec.Body)["code"]; got != "permission_denied" {
			t.Fatalf("%s bad signature error code = %q, want %q", procedure, got, "permission_denied")
		}
		wantCalls := 0
		if procedure == testRPCWriteProcedure {
			wantCalls = 1
		}
		if store.callCount() != wantCalls {
			t.Fatalf("%s nonce store calls = %d, want %d（写接口去重先于签名）", procedure, store.callCount(), wantCalls)
		}
	}
}

// ⑥ 签名对通过（读接口）：带 body、签名按文档五项公式构造 → 200；响应体
// 证明 body 经 CaptureRawBody 回填后可被 connect 解码、client_id 已入 ctx；
// 读接口全程零去重调用。
func TestRPCHMACValidSignaturePasses(t *testing.T) {
	store := &fakeRPCNonceStore{}
	captured := &rpcCapture{}
	h := newRPCHandler(testRPCReadProcedure, store, fakeSecretLookup(), captured, true)

	body := rpcBody(t)
	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCReadProcedure, string(body), testRPCSecret))
	rec := doRPCRequest(h, testRPCReadProcedure, body, headers)
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
	if store.callCount() != 0 {
		t.Fatalf("nonce store calls = %d, want 0（读接口不去重）", store.callCount())
	}
}

// ⑦ 写接口校验顺序硬约束：nonce 去重先于签名——第一次请求签名错误，nonce
// 仍被消耗；第二次同 nonce 带正确签名 → 403（重放拦截）。
func TestRPCHMACNonceDedupBeforeSignature(t *testing.T) {
	store := &fakeRPCNonceStore{}
	h := newRPCHandler(testRPCWriteProcedure, store, fakeSecretLookup(), &rpcCapture{}, true)

	body := rpcBody(t)
	bad := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCWriteProcedure, sigBodyOf(body), "wrong"))
	doRPCRequest(h, testRPCWriteProcedure, body, bad)
	if store.callCount() != 1 {
		t.Fatalf("nonce store calls after bad signature = %d, want 1（签名错也消耗 nonce）", store.callCount())
	}

	good := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCWriteProcedure, sigBodyOf(body), testRPCSecret))
	if rec := doRPCRequest(h, testRPCWriteProcedure, body, good); rec.Code != http.StatusForbidden {
		t.Fatalf("correct signature with consumed nonce: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// ⑧ 空 body 空串边界（§7 行 1379）：直调拦截器 + ctx 原始字节为空 → 签名串
// body 段为空串、校验通过。connect-go 对 0 字节请求体在拦截器之前按
// cardinality violation 拒绝（unary 必须有一条消息），故空 body 向量只能经
// 原始体捕获路径触达——这正是签名与捕获解耦的用例。connect.NewRequest
// 未设 Spec（procedure 为空串 → 读路径），store 零调用。
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
	// connect.NewRequest 未设 Spec（procedure 为空串，走读路径不去重）；本用例
	// 锚定 body 段空串向量，path 段同步以空串入签名。
	req.Header().Set(rpcHeaderSignature, rpcSign(testRPCClientID, "n1", "", "", testRPCSecret))

	ctx := context.WithValue(context.Background(), rawBodyKey{}, []byte{})
	resp, err := wrapped(ctx, req)
	if err != nil || resp == nil {
		t.Fatalf("wrapped = (%v, %v), want 成功（空 body 空串入签）", resp, err)
	}
	if !injected {
		t.Error("下游未被调")
	}
	if store.callCount() != 0 {
		t.Errorf("nonce store calls = %d, want 0（procedure 空串 → 读路径不去重）", store.callCount())
	}
}

// ⑨ path 不含 query 边界（§7 行 1378）：target 带 ?a=1&b=2，签名只覆盖
// Connect RPC 路径 → 200；反例：签名把 query 算进 path 段 → 403（证明实现
// 取不含 query 的路径）。
func TestRPCHMACPathExcludesQuery(t *testing.T) {
	store := &fakeRPCNonceStore{}
	h := newRPCHandler(testRPCReadProcedure, store, fakeSecretLookup(), &rpcCapture{}, true)
	target := testRPCReadProcedure + "?a=1&b=2"
	body := rpcBody(t)

	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCReadProcedure, sigBodyOf(body), testRPCSecret))
	if rec := doRPCRequest(h, target, body, headers); rec.Code != http.StatusOK {
		t.Fatalf("path without query status = %d, want %d", rec.Code, http.StatusOK)
	}

	withQuery := rpcHeaders(testRPCClientID, "n2",
		rpcSign(testRPCClientID, "n2", target, sigBodyOf(body), testRPCSecret))
	if rec := doRPCRequest(h, target, body, withQuery); rec.Code != http.StatusForbidden {
		t.Fatalf("signature covering query status = %d, want %d（path 不得含 query）", rec.Code, http.StatusForbidden)
	}
}

// ⑩ client 未注册（lookup 未命中）→ 403（写接口）；nonce 已消耗（去重先于
// 密钥查询）。
func TestRPCHMACUnknownClient(t *testing.T) {
	store := &fakeRPCNonceStore{}
	h := newRPCHandler(testRPCWriteProcedure, store, fakeSecretLookup(), &rpcCapture{}, true)

	body := rpcBody(t)
	headers := rpcHeaders("ghost", "n1",
		rpcSign("ghost", "n1", testRPCWriteProcedure, sigBodyOf(body), "whatever"))
	rec := doRPCRequest(h, testRPCWriteProcedure, body, headers)
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

// ⑪ 写接口 nonce 存储故障 → 500 internal（fail-closed：无法判定重放不得
// 放行；读接口不查 store，故障无影响——见 ③）。
func TestRPCHMACNonceStoreError(t *testing.T) {
	store := &fakeRPCNonceStore{err: errors.New("redis down")}
	captured := &rpcCapture{}
	h := newRPCHandler(testRPCWriteProcedure, store, fakeSecretLookup(), captured, true)

	body := rpcBody(t)
	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCWriteProcedure, sigBodyOf(body), testRPCSecret))
	rec := doRPCRequest(h, testRPCWriteProcedure, body, headers)
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

// ⑫ 签名十六进制大小写不敏感（hex 解码后按字节恒时比较）。
func TestRPCHMACSignatureCaseInsensitive(t *testing.T) {
	store := &fakeRPCNonceStore{}
	h := newRPCHandler(testRPCReadProcedure, store, fakeSecretLookup(), &rpcCapture{}, true)

	body := rpcBody(t)
	sig := rpcSign(testRPCClientID, "n1", testRPCReadProcedure, sigBodyOf(body), testRPCSecret)
	headers := rpcHeaders(testRPCClientID, "n1", strings.ToUpper(sig))
	if rec := doRPCRequest(h, testRPCReadProcedure, body, headers); rec.Code != http.StatusOK {
		t.Fatalf("uppercase hex signature status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// ⑬ 装配层漏挂 CaptureRawBody → 原始 body 拿不到 → internal fail-closed，
// 不允许在空 body 向量上静默验签（防签名域被降级）。
func TestRPCHMACBodyUnavailableFailsClosed(t *testing.T) {
	store := &fakeRPCNonceStore{}
	captured := &rpcCapture{}
	h := newRPCHandler(testRPCReadProcedure, store, fakeSecretLookup(), captured, false) // 不包捕获层

	body := rpcBody(t)
	headers := rpcHeaders(testRPCClientID, "n1",
		rpcSign(testRPCClientID, "n1", testRPCReadProcedure, string(body), testRPCSecret))
	rec := doRPCRequest(h, testRPCReadProcedure, body, headers)
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

// ⑭ 写前缀集合表驱动（§7 行 1366「命名决定校验」长期口径；后端 §22 第
// 23 条）：方法名以 Update / Delete / Set / Create / Revoke 任一前缀开头 =
// 写接口；其余（Get / Decode / List / 大小写不匹配 / 空方法名）= 读接口。
// 前缀匹配取 procedure 末段方法名、大小写敏感。
func TestRPCWriteProcedureClassification(t *testing.T) {
	cases := []struct {
		procedure string
		write     bool
	}{
		{testRPCWriteProcedure, true},                      // Update 前缀（真实写接口）
		{"/api.rpc.v1.TokenService/RevokeSession", true},   // Revoke 前缀
		{"/api.rpc.v1.UserService/DeleteAvatar", true},     // Delete 前缀
		{"/api.rpc.v1.UserService/SetProfile", true},       // Set 前缀
		{"/api.rpc.v1.UserService/CreateExport", true},     // Create 前缀
		{"/api.rpc.v1.UserService/Updated", true},          // 前缀开头即写，不要求整词
		{testRPCReadProcedure, false},                      // Get 前缀（真实读接口）
		{testRPCDecodeProcedure, false},                    // Decode 前缀（真实读接口）
		{"/api.rpc.v1.UserService/ListProfiles", false},    // 其余方法名
		{"/api.rpc.v1.UserService/updateProfile", false},   // 前缀大小写敏感（PascalCase 外形态不命中）
		{"", false}, // 直调拦截器无 Spec（procedure 空串）→ 读路径
	}
	for _, c := range cases {
		if got := isRPCWriteProcedure(c.procedure); got != c.write {
			t.Errorf("isRPCWriteProcedure(%q) = %v, want %v", c.procedure, got, c.write)
		}
	}
}
