// admin 拦截器、错误包装拦截器、CaptureRawBody 装配助手与 ErrorInfo 助手的
// 单测。admin 按 §5 行 1145 口径挂 session 拦截器之内（链序同装配）全栈验证
// 401/404/放行三态与线上错误体；错误包装双覆盖：全栈验线上文本消毒，直调验
// 类型化断言（connect.Error code / detail / Unwrap 链）。
package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	commonv1 "authloft/gen/go/api/common/v1"
	"authloft/gen/go/token"
	"authloft/internal/session"
)

// adminEchoProcedure admin 域测试用 Connect RPC 路径。
const adminEchoProcedure = "/api.admin.v1.AdminService/GetSettings"

// decodeConnectErrorBody 从 io.Reader 解码 Connect 协议错误体 JSON
//（§1.5 行 197-211：{"code","message"}），返回 code / message
//（session_test / rpc_test 共用；http.Response 与 Recorder 两类入口同核心）。
func decodeConnectErrorBody(t *testing.T, r io.Reader) map[string]string {
	t.Helper()
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r).Decode(&body); err != nil {
		t.Fatalf("decode connect error body: %v", err)
	}
	return map[string]string{"code": body.Code, "message": body.Message}
}

// decodeConnectError 解码 http 响应中的 Connect 协议错误体（负责关闭 body）。
func decodeConnectError(t *testing.T, resp *http.Response) map[string]string {
	t.Helper()
	defer resp.Body.Close()
	return decodeConnectErrorBody(t, resp.Body)
}

// adminPayload 构造指定 uid 的有效会话载荷（epoch 同步放行）。
func adminPayload(env *sessionEnv, uid int64) *token.SessionTokenPayload {
	p := &token.SessionTokenPayload{
		Id:    uid,
		Epoch: 7,
		Amr:   []string{"pwd"},
		Sid:   "sid-admin",
		Iat:   time.Now().Add(-time.Minute).Unix(),
		Exp:   time.Now().Add(time.Hour).Unix(),
	}
	env.epochs.values[p.Id] = p.Epoch
	return p
}

// newAdminServer 挂载 session + admin 拦截链（session 在外层注入 ctx 身份），
// 返回服务器与捕获器。
func newAdminServer(t *testing.T, env *sessionEnv) (*httptest.Server, *sessionCapture) {
	t.Helper()
	captured := &sessionCapture{}
	handler := connect.NewUnaryHandler(adminEchoProcedure,
		func(ctx context.Context, req *connect.Request[commonv1.ErrorInfo]) (*connect.Response[commonv1.ErrorInfo], error) {
			captured.uid, captured.ok = session.UIDFromContext(ctx)
			return connect.NewResponse[commonv1.ErrorInfo](req.Msg), nil
		},
		connect.WithInterceptors(
			NewSessionInterceptor(env.verifier, env.renewer, env.cookie, nil),
			NewAdminInterceptor(),
		),
	)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, captured
}

// doAdminRPC 发一次 admin 测试 RPC（token 经 X-Authloft-Token）。
func doAdminRPC(t *testing.T, srv *httptest.Server, token string) *http.Response {
	t.Helper()
	headers := map[string]string{}
	if token != "" {
		headers["X-Authloft-Token"] = token
	}
	resp := doSessionRPC(t, srv, headers, nil)
	return resp
}

// ① 无会话（session 放行匿名）→ 401 unauthenticated（§1.5 行 187）。
func TestAdminNoSessionReturns401(t *testing.T) {
	env := newSessionEnv(t)
	srv, captured := newAdminServer(t, env)

	resp := doAdminRPC(t, srv, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if captured.ok {
		t.Errorf("ctx uid 注入了 %d, want 未注入", captured.uid)
	}
	if errObj := decodeConnectError(t, resp); errObj["code"] != "unauthenticated" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "unauthenticated")
	}
}

// ② uid 有但 != 1 → 404 not_found（掩护管理面存在，§1.5 行 189）。
func TestAdminNonAdminUIDReturns404(t *testing.T) {
	env := newSessionEnv(t)
	tok := env.sign(t, adminPayload(env, 42))
	srv, captured := newAdminServer(t, env)

	resp := doAdminRPC(t, srv, tok)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
	if captured.ok {
		t.Errorf("handler 被触达（uid=%d），want 拒绝", captured.uid)
	}
	errObj := decodeConnectError(t, resp)
	if errObj["code"] != "not_found" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "not_found")
	}
	if errObj["message"] != "not found" {
		t.Errorf("error.message = %q, want %q（文案与普通 404 一致，不透露路径存在）", errObj["message"], "not found")
	}
}

// ③ uid == 1 → 放行，handler 触达。
func TestAdminUID1Passes(t *testing.T) {
	env := newSessionEnv(t)
	tok := env.sign(t, adminPayload(env, 1))
	srv, captured := newAdminServer(t, env)

	resp := doAdminRPC(t, srv, tok)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if !captured.ok || captured.uid != 1 {
		t.Errorf("ctx uid = (%d, %v), want (1, true)", captured.uid, captured.ok)
	}
}

// ④ 错误包装全栈：handler 返回普通 error → HTTP 500 + 错误体 code=internal +
// 线上文本消毒为 internal error（原文 "boom" 属内部信息，不得透出）。
func TestErrorWrapperSanitizesPlainErrorOnWire(t *testing.T) {
	handler := connect.NewUnaryHandler(adminEchoProcedure,
		func(ctx context.Context, req *connect.Request[commonv1.ErrorInfo]) (*connect.Response[commonv1.ErrorInfo], error) {
			return nil, errors.New("boom: database password leaked")
		},
		connect.WithInterceptors(NewErrorWrapperInterceptor()),
	)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+adminEchoProcedure, bytes.NewReader(sessionBody(t)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	errObj := decodeConnectError(t, resp)
	if errObj["code"] != "internal" {
		t.Errorf("error.code = %q, want %q", errObj["code"], "internal")
	}
	if errObj["message"] != "internal error" {
		t.Errorf("error.message = %q, want %q（消毒）", errObj["message"], "internal error")
	}
	if strings.Contains(errObj["message"], "boom") {
		t.Errorf("error.message 泄露内部信息: %q", errObj["message"])
	}
}

// ⑤ 错误包装直调：普通 error → connect.CodeInternal、无 ErrorInfo detail
// （§3.14 行 479 internal 兜底不挂）+ Message 消毒 + Unwrap 链保留原错误。
func TestErrorWrapperWrapsPlainErrorWithoutDetail(t *testing.T) {
	original := errors.New("boom: secret")
	wrapped := NewErrorWrapperInterceptor()(connect.UnaryFunc(
		func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			return nil, original
		}))

	resp, err := wrapped(context.Background(), connect.NewRequest(&commonv1.ErrorInfo{}))
	if resp != nil || err == nil {
		t.Fatalf("wrapped = (%v, %v), want (nil, error)", resp, err)
	}
	var coded *connect.Error
	if !errors.As(err, &coded) {
		t.Fatalf("err 类型 = %T, want *connect.Error", err)
	}
	if coded.Code() != connect.CodeInternal {
		t.Errorf("code = %v, want %v", coded.Code(), connect.CodeInternal)
	}
	if coded.Message() != "internal error" {
		t.Errorf("message = %q, want %q（消毒）", coded.Message(), "internal error")
	}
	if info, ok := ErrorInfoOf(err); ok {
		t.Fatalf("internal 兜底不应挂 ErrorInfo detail（§3.14 行 479），got domain=%q code=%q", info.Domain, info.Code)
	}
	if !errors.Is(err, original) {
		t.Errorf("Unwrap 链未保留原错误（errors.Is = false）")
	}
}

// ⑥ 错误包装直调：connect.Error 原样透传（同一实例、不追加 detail）。
func TestErrorWrapperPassesThroughConnectError(t *testing.T) {
	coded := connect.NewError(connect.CodeNotFound, errors.New("nope"))
	passed := false
	wrapped := NewErrorWrapperInterceptor()(connect.UnaryFunc(
		func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			passed = true
			return nil, coded
		}))

	_, err := wrapped(context.Background(), connect.NewRequest(&commonv1.ErrorInfo{}))
	if !passed {
		t.Fatal("inner func 未被调")
	}
	if err != coded {
		t.Fatalf("透传失败：got %p, want 同一实例 %p", err, coded)
	}
	if details := coded.Details(); len(details) != 0 {
		t.Errorf("不应追加 detail, got %d", len(details))
	}
}

// ⑦ NewErrorInfo / WithErrorInfo / ErrorInfoOf 助手往返。
func TestErrorInfoHelpers(t *testing.T) {
	info := NewErrorInfo("sso", "password_weak", "密码强度不足")
	if info.Domain != "sso" || info.Code != "password_weak" || info.Message != "密码强度不足" {
		t.Errorf("NewErrorInfo 字段 = %+v", info)
	}
	info.RetryAfter = 60
	info.AttemptsLeft = 3

	coded := WithErrorInfo(connect.NewError(connect.CodeFailedPrecondition, errors.New("x")), info)
	got, ok := ErrorInfoOf(coded)
	if !ok {
		t.Fatal("ErrorInfoOf 未找到 detail")
	}
	if got.Domain != "sso" || got.Code != "password_weak" || got.RetryAfter != 60 || got.AttemptsLeft != 3 {
		t.Errorf("detail 往返字段 = %+v", got)
	}
	if _, ok := ErrorInfoOf(errors.New("plain")); ok {
		t.Error("非 connect.Error 应返回 false")
	}
	if _, ok := ErrorInfoOf(connect.NewError(connect.CodeInternal, errors.New("no detail"))); ok {
		t.Error("无 detail 的 connect.Error 应返回 false")
	}
}

// ⑧ CaptureRawBody：读出-回填-入 ctx 三语义。body 可重复读、ctx 原始字节
// 与线上一致；读失败 → 500（fail-closed）。
func TestCaptureRawBody(t *testing.T) {
	var gotBody, gotStash string
	next := CaptureRawBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		if b, ok := r.Context().Value(rawBodyKey{}).([]byte); ok {
			gotStash = string(b)
		}
		w.WriteHeader(http.StatusOK)
	}))

	// 非空 body：回填后内层可读，ctx 原始字节一致。
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader([]byte("hello"))))
	if rec.Code != http.StatusOK || gotBody != "hello" || gotStash != "hello" {
		t.Fatalf("非空 body: code=%d body=%q stash=%q, want 200/hello/hello", rec.Code, gotBody, gotStash)
	}

	// 空 body：回填空读、ctx 空字节串（§7 行 1377 空 body 即空串的来源）。
	rec = httptest.NewRecorder()
	next.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
	if rec.Code != http.StatusOK || gotBody != "" || gotStash != "" {
		t.Fatalf("空 body: code=%d body=%q stash=%q, want 200/空/空", rec.Code, gotBody, gotStash)
	}

	// 读失败 → 500，内层不可达。
	unreachable := false
	failing := CaptureRawBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		unreachable = true
	}))
	rec = httptest.NewRecorder()
	failing.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", errReader{}))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("读失败 status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if unreachable {
		t.Error("读失败时内层 handler 不可达")
	}
}

// errReader 一读即错的 body（模拟客户端传输中断）。
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failure") }

// ⑨ proto 序列化确定性（rpc 测试的前置假设）：同一消息两次 marshal 字节一致，
// 测试端可预计算被签名的线上字节。
func TestProtoMarshalDeterministic(t *testing.T) {
	msg := &commonv1.ErrorInfo{Code: "x", Message: "m"}
	a, _ := proto.Marshal(msg)
	b, _ := proto.Marshal(msg)
	if !bytes.Equal(a, b) {
		t.Fatal("proto.Marshal 非确定输出，rpc 签名测试的预计算假设不成立")
	}
}
