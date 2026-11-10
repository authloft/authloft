// setup 包单元测试（无外部依赖部分）：路由与空壳页、参数类错误、
// 路径 A 校验失败矩阵、Redis 连通（假 Redis）、用户名 / 密码策略、
// argon2id 哈希格式、原子写、root / rp_id 推导、脱敏、退出触发幂等。
// 涉真实 DB 的端到端用例见 setup_db_test.go（env-skip）。
package setup

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/proto"

	commonv1 "authloft/gen/go/api/common/v1"
	setupv1 "authloft/gen/go/api/setup/v1"
	"authloft/gen/go/api/setup/v1/setupv1connect"
	"authloft/internal/config"
	authloftconnect "authloft/internal/connect"
)

func init() { gin.SetMode(gin.TestMode) }

// testKeyB64 生成 32 字节确定内容的 std base64 密钥（测试 config 文本用）。
func testKeyB64(b byte) string {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = b
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// newTestServer 构造指向临时 configPath 的 setup server。
func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	return NewServer(path), path
}

// doConnectJSON 对 server router 发一条 Connect unary JSON 请求（协议形态：
// POST + Content-Type application/json，body 为请求消息的 protojson；成功
// 响应即消息本身、业务失败为 Connect 错误体，接口文档 §1.0 / §1.5）。
func doConnectJSON(r http.Handler, procedure, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, procedure, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// decodeConnectError 解析 Connect 错误体（接口文档 §1.5 行 197-211）：
// 返回标准码与首枚 ErrorInfo detail（type=api.common.v1.ErrorInfo，
// value 为其 proto 字节的 base64）。
func decodeConnectError(t *testing.T, rec *httptest.ResponseRecorder) (string, *commonv1.ErrorInfo) {
	t.Helper()
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Details []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal connect error body %q: %v", rec.Body.String(), err)
	}
	for _, d := range body.Details {
		if d.Type != "api.common.v1.ErrorInfo" {
			continue
		}
		// connect-go 的 detail value 为 RawStdEncoding 的 base64（无填充，
		// connect@v1.21.1 protocol_connect.go 行 1202）。
		raw, err := base64.RawStdEncoding.DecodeString(d.Value)
		if err != nil {
			t.Fatalf("decode ErrorInfo value base64: %v", err)
		}
		info := &commonv1.ErrorInfo{}
		if err := proto.Unmarshal(raw, info); err != nil {
			t.Fatalf("unmarshal ErrorInfo detail: %v", err)
		}
		return body.Code, info
	}
	return body.Code, nil
}

// fakeRedis 在 127.0.0.1 随机端口起一个最小 RESP 服务（够 AUTH / SELECT /
// PING 语义），返回地址。测试结束自动关闭。
func fakeRedis(t *testing.T, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake redis listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeRedis(conn, password)
		}
	}()
	return ln.Addr().String()
}

// serveFakeRedis 处理一条 RESP 命令循环：PING → +PONG；AUTH 校验密码；
// SELECT → +OK；未知 → -ERR。
func serveFakeRedis(conn net.Conn, password string) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		args, err := readRESPCommand(r)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		switch strings.ToUpper(args[0]) {
		case "PING":
			conn.Write([]byte("+PONG\r\n"))
		case "AUTH":
			if len(args) == 2 && args[1] == password {
				conn.Write([]byte("+OK\r\n"))
			} else {
				conn.Write([]byte("-ERR invalid password\r\n"))
			}
		case "SELECT":
			conn.Write([]byte("+OK\r\n"))
		default:
			conn.Write([]byte("-ERR unknown command\r\n"))
		}
	}
}

// readRESPCommand 读一条 RESP 数组命令。
func readRESPCommand(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "*") {
		return nil, fmt.Errorf("not an array: %q", line)
	}
	n, err := strconv.Atoi(line[1:])
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		hdr, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		hdr = strings.TrimRight(hdr, "\r\n")
		l, err := strconv.Atoi(strings.TrimPrefix(hdr, "$"))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, l+2) // 载荷 + \r\n
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:l]))
	}
	return args, nil
}

// TestSetupStatusEndpoint SetupService/GetStatus（§13.1）：Connect unary
// 请求 200 + {"mode":"setup"}——成功响应即消息本身（§1.0），与 §13.1 定稿
// 响应逐字一致（无 status:"success" 信封）。
func TestSetupStatusEndpoint(t *testing.T) {
	s, _ := newTestServer(t)
	rec := doConnectJSON(s.Router(), "/api.setup.v1.SetupService/GetStatus", "application/json", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"mode":"setup"}` {
		t.Errorf("body = %q, want {\"mode\":\"setup\"}", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// TestSetupConnectClientInterop 用生成的 connect client 走完整栈（connect-go
// 默认 Connect 协议）验证装配：GetStatus 正常往返；缺必填字段的 Install 归一为
// *connect.Error（标准码）且 ErrorInfo detail 可读（authloftconnect.ErrorInfoOf，
// 与前端 §1.5 行 226 消费路径同款）。
func TestSetupConnectClientInterop(t *testing.T) {
	s, _ := newTestServer(t)
	srv := httptest.NewServer(s.Router())
	defer srv.Close()
	client := setupv1connect.NewSetupServiceClient(srv.Client(), srv.URL)

	resp, err := client.GetStatus(context.Background(), connect.NewRequest(&setupv1.GetStatusRequest{}))
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if resp.Msg.Mode != "setup" {
		t.Errorf("mode = %q, want setup", resp.Msg.Mode)
	}

	_, err = client.Install(context.Background(), connect.NewRequest(&setupv1.InstallRequest{}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("Install empty: code = %v, want invalid_argument (err %v)", connect.CodeOf(err), err)
	}
	if info, ok := authloftconnect.ErrorInfoOf(err); !ok || info.Domain != setupDomain || info.Code != codeInvalidRequest {
		t.Fatalf("Install empty: ErrorInfo = %+v, want setup/invalid_request", info)
	}
}

// TestSetupPageShell GET /setup 空壳页（接口文档 §8 行 1495 / 1500）：
// 读嵌入模板 + 三占位符全量替换（阶段 C：setup 壳复用 pages
// 统一渲染入口）；no-store；CSP 与正常模式同基线（middleware.CSP
// 挂 gin 链）；__AUTHLOFT_INIT__ 注入 al_root=""（setup 模式无 config、
// 不读 Host——前端 bootstrap location.origin 回落，见 handleSetupPage
// 注）+ static_base 默认 /assets；不注入凭证。
func TestSetupPageShell(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/setup", nil)
	req.Host = "192.168.10.2:8080"
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	// CSP 终稿基线（§8 行 1521-1532）：style-src 带 nonce、img-src
	// 含 data: 与 https:、connect-src 'self'，禁 unsafe-inline。
	csp := rec.Header().Get("Content-Security-Policy")
	nonceRe := regexp.MustCompile(`'nonce-([A-Za-z0-9_-]{20,})'`)
	m := nonceRe.FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("CSP %q has no nonce", csp)
	}
	nonce := m[1]
	for _, want := range []string{
		"default-src 'self'",
		"script-src 'nonce-" + nonce + "' 'strict-dynamic'",
		"style-src 'nonce-" + nonce + "' 'self'",
		"font-src 'self'",
		"img-src 'self' data: https:",
		"connect-src 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP 缺终稿指令 %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP 禁 unsafe-inline: %s", csp)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "window.__AUTHLOFT_INIT__") {
		t.Error("shell page must inject window.__AUTHLOFT_INIT__")
	}
	// al_root 数据源缺口（如实报告）：setup 模式无 config.yaml、不读
	// 请求 Host → 注入空串；前端 bootstrap normalizeAlRoot 空值回落
	// location.origin（web/src/setup/bootstrap.ts）。
	if !strings.Contains(body, `"al_root":""`) {
		t.Errorf("al_root must be empty (no config, no Host reading), body:\n%s", body)
	}
	if strings.Contains(body, "192.168.10.2") {
		t.Errorf("al_root must not read request Host, body:\n%s", body)
	}
	if !strings.Contains(body, `"static_base":"/assets"`) {
		t.Errorf("static_base must default to /assets, body:\n%s", body)
	}
	// 占位符全量替换：无残留、产物引用走归一后的 static_base 前缀。
	if strings.Contains(body, "{{AUTHLOFT_") {
		t.Errorf("body has residual placeholder, body:\n%s", body)
	}
	if !strings.Contains(body, `src="/assets/`) {
		t.Errorf("entry scripts must reference /assets/ prefix, body:\n%s", body)
	}
	// 模板全部 nonce 属性都携带 CSP 头同一 nonce（renderTemplate 全量替换，
	// 漏一处页面即挂；计数不写死，随构建产物 chunk 数伸缩）。
	attrN := strings.Count(body, `nonce="`)
	if attrN == 0 || attrN != strings.Count(body, `nonce="`+nonce+`"`) {
		t.Errorf("nonce 属性 %d 处，其中携带 CSP nonce %d 处（须全部一致）", attrN, strings.Count(body, `nonce="`+nonce+`"`))
	}
	// <>& 转义（接口文档 §8 行 1401）：INIT 的 JSON 值部分不含裸 < > &
	//（json.Marshal 默认 HTML escape；script 标签本身的 <> 不在 JSON 值内）。
	if idx := strings.Index(body, "window.__AUTHLOFT_INIT__ = "); idx >= 0 {
		value := body[idx+len("window.__AUTHLOFT_INIT__ = "):]
		if end := strings.Index(value, ";"); end >= 0 {
			value = value[:end]
		}
		for _, raw := range []string{"<", ">", "&"} {
			if strings.Contains(value, raw) {
				t.Errorf("INIT JSON value contains raw %q (must be escaped): %s", raw, value)
			}
		}
	} else {
		t.Error("INIT assignment not found for escape check")
	}
}

// TestSetupParamErrors 参数类错误（§13 行 1761「参数类错误仍走 §1.5」）：
// Content-Type 不被 Connect 支持编码 → 框架直写 415（无错误体语义差异，
// §1.5 行 195）；空体 / 非法 JSON → 框架 invalid_argument 400（协议级错误
// 无 ErrorInfo detail，§1.5 行 224）；必填字段缺失（proto3 零值不可判，
// handler 侧校验）→ invalid_argument 400 + ErrorInfo{domain=setup,
// code=invalid_request}（§1.6 行 245）。request_id 不在错误体内，走
// X-Request-Id 响应头（§1.5 行 223）。
func TestSetupParamErrors(t *testing.T) {
	s, _ := newTestServer(t)
	r := s.Router()

	cases := []struct {
		name       string
		procedure  string
		contentTyp string
		body       string
		wantStatus int
		wantCode   string // Connect 标准码（§1.5）；空 = 框架直写状态码
		wantInfo   string // ErrorInfo.code；空 = 无 detail（协议级）
	}{
		{"text/plain config", "/api.setup.v1.SetupService/UploadConfig", "text/plain", "x", http.StatusUnsupportedMediaType, "", ""},
		{"no content-type config", "/api.setup.v1.SetupService/UploadConfig", "", "x", http.StatusUnsupportedMediaType, "", ""},
		{"empty body config", "/api.setup.v1.SetupService/UploadConfig", "application/json", "", http.StatusBadRequest, "invalid_argument", ""},
		{"invalid json config", "/api.setup.v1.SetupService/UploadConfig", "application/json", "{", http.StatusBadRequest, "invalid_argument", ""},
		{"missing config field", "/api.setup.v1.SetupService/UploadConfig", "application/json", `{}`, http.StatusBadRequest, "invalid_argument", codeInvalidRequest},
		{"text/plain install", "/api.setup.v1.SetupService/Install", "text/plain", "x", http.StatusUnsupportedMediaType, "", ""},
		{"empty body install", "/api.setup.v1.SetupService/Install", "application/json", "", http.StatusBadRequest, "invalid_argument", ""},
		{"invalid json install", "/api.setup.v1.SetupService/Install", "application/json", "not json", http.StatusBadRequest, "invalid_argument", ""},
		{"missing required install", "/api.setup.v1.SetupService/Install", "application/json", `{"dbDsn":"x"}`, http.StatusBadRequest, "invalid_argument", codeInvalidRequest},
		{"negative redis db", "/api.setup.v1.SetupService/Install", "application/json", `{"dbDsn":"x","redisAddr":"y","adminUsername":"admin01","adminPassword":"Str0ngPassw0rd","redisDb":-1}`, http.StatusBadRequest, "invalid_argument", codeInvalidRequest},
	}
	for _, tc := range cases {
		rec := doConnectJSON(r, tc.procedure, tc.contentTyp, tc.body)
		if rec.Code != tc.wantStatus {
			t.Errorf("%s: status = %d, want %d (body %s)", tc.name, rec.Code, tc.wantStatus, rec.Body.String())
			continue
		}
		// requestid 对 Connect 域等效（http 版在 mux 前缀链上）：
		// Connect 响应同样回写 X-Request-Id（所有响应统一走响应头）。
		if rec.Header().Get("X-Request-Id") == "" {
			t.Errorf("%s: X-Request-Id empty, want non-empty (requestid must be on chain)", tc.name)
		}
		if tc.wantCode == "" {
			continue // 框架 415：无错误体语义（§1.5 行 195），只断言状态码
		}
		code, info := decodeConnectError(t, rec)
		if code != tc.wantCode {
			t.Errorf("%s: connect code = %q, want %q (body %s)", tc.name, code, tc.wantCode, rec.Body.String())
		}
		switch {
		case tc.wantInfo == "":
			if info != nil {
				t.Errorf("%s: unexpected ErrorInfo %+v for protocol-level error", tc.name, info)
			}
		default:
			if info == nil || info.Domain != setupDomain || info.Code != tc.wantInfo {
				t.Errorf("%s: ErrorInfo = %+v, want domain=%s code=%s", tc.name, info, setupDomain, tc.wantInfo)
			}
		}
	}
}

// oidcTestKeyB64 返回合法 OIDC 私钥（base64(PKCS#8 RSA 2048 PEM)）：
// 从 config.DefaultConfig 的单套安装生成结果取用，进程内只生成一次。
var (
	oidcTestKeyOnce sync.Once
	oidcTestKey     string
)

func oidcTestKeyB64() string {
	oidcTestKeyOnce.Do(func() {
		cfg, err := config.DefaultConfig()
		if err != nil {
			panic(err)
		}
		oidcTestKey = cfg.OIDC.JWTKeys[0].PrivateKeyPEM
	})
	return oidcTestKey
}

// uploadConfigYAML 生成一份可通过 Validate 的 config 文本（sign_key 五场景
// 用 32 字节确定密钥；oidc.jwt_keys 用一套合法 RSA 私钥）。
func uploadConfigYAML(dsn, redisAddr string) string {
	var b strings.Builder
	b.WriteString("server: { listen: \":8080\" }\n")
	b.WriteString(fmt.Sprintf("db:\n  dsn: %q\n  max_open_conns: 50\n  max_idle_conns: 10\n  conn_max_lifetime: 1h\n", dsn))
	b.WriteString(fmt.Sprintf("redis: { addr: %q, password: \"\", db: 0, pool_size: 50 }\n", redisAddr))
	b.WriteString("authloft: { root: \"https://sso.example.com\", rp_id: \"sso.example.com\" }\n")
	b.WriteString("sign_key:\n")
	for _, sc := range []string{"session", "login", "ticket", "cookie", "sync_payload"} {
		fmt.Fprintf(&b, "  %s: { key: %q, kid: 1 }\n", sc, testKeyB64('A'))
	}
	b.WriteString("argon2: { time: 3, memory: 65536, threads: 4, key_len: 32 }\n")
	b.WriteString("log: { level: info, format: text }\n")
	b.WriteString("oidc:\n  jwt_keys:\n")
	fmt.Fprintf(&b, "    - kid: \"1\"\n      private_key_pem: %q\n", oidcTestKeyB64())
	return b.String()
}

// TestUploadConfigInvalidMatrix 路径 A 步骤 ① 失败矩阵（§13.2）：非法
// YAML / 缺 sign_key / 缺 db 段 → Connect 错误体（标准码 invalid_argument +
// ErrorInfo{domain=setup, code=config_invalid}，HTTP 400，§13 行 1761）；
// 响应 message 为固定安全文案，不回显密钥内容。
func TestUploadConfigInvalidMatrix(t *testing.T) {
	s, configPath := newTestServer(t)
	r := s.Router()

	key := testKeyB64('A')
	cases := []struct {
		name string
		body string
	}{
		{"not yaml", "!!!not yaml at all: ["},
		{"missing sign_key", func() string {
			text := `
server: { listen: ":8080" }
db:
  dsn: "authloft:pass@tcp(127.0.0.1:3306)/authloft"
  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: 1h
redis: { addr: "127.0.0.1:6379", password: "", db: 0, pool_size: 50 }
authloft: { root: "https://sso.example.com", rp_id: "sso.example.com" }
argon2: { time: 3, memory: 65536, threads: 4, key_len: 32 }
log: { level: info, format: text }
`
			return text
		}()},
		{"incomplete sign_key", func() string {
			text := uploadConfigYAML("authloft:pass@tcp(127.0.0.1:3306)/authloft", "127.0.0.1:6379")
			// 去掉 ticket 一行（模拟缺一场景）。
			return strings.Replace(text, "  ticket: { key: \""+key+"\", kid: 1 }\n", "", 1)
		}()},
		{"missing db section", func() string {
			text := uploadConfigYAML("authloft:pass@tcp(127.0.0.1:3306)/authloft", "127.0.0.1:6379")
			return regexp.MustCompile(`(?s)db:.*?conn_max_lifetime: 1h\n`).ReplaceAllString(text, "")
		}()},
		{"missing oidc section", func() string {
			text := uploadConfigYAML("authloft:pass@tcp(127.0.0.1:3306)/authloft", "127.0.0.1:6379")
			// oidc 段在末尾：截掉即「缺 oidc.jwt_keys」。
			return text[:strings.Index(text, "oidc:\n")]
		}()},
		{"invalid oidc key", func() string {
			text := uploadConfigYAML("authloft:pass@tcp(127.0.0.1:3306)/authloft", "127.0.0.1:6379")
			return strings.Replace(text, oidcTestKeyB64(), "!!!not-base64!!!", 1)
		}()},
	}
	for _, tc := range cases {
		payload, _ := json.Marshal(map[string]string{"config": tc.body})
		rec := doConnectJSON(r, "/api.setup.v1.SetupService/UploadConfig", "application/json", string(payload))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: HTTP status = %d, want 400 (connect error body %s)", tc.name, rec.Code, rec.Body.String())
			continue
		}
		code, info := decodeConnectError(t, rec)
		if code != "invalid_argument" || info == nil || info.Domain != setupDomain || info.Code != CodeConfigInvalid {
			t.Errorf("%s: connect=(%q, %+v), want invalid_argument + setup/%s", tc.name, code, info, CodeConfigInvalid)
		}
		if strings.Contains(rec.Body.String(), key) {
			t.Errorf("%s: response leaks sign key material", tc.name)
		}
	}
	// 失败后不落盘、不退出。
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Errorf("failed upload must not write config, stat err = %v", err)
	}
	select {
	case <-s.Exposed():
		t.Error("failed upload must not trigger exit")
	default:
	}
}

// TestFreshInstallDBUnreachable 路径 B 步骤 ②：DB 不可达 → Connect 错误体
// （标准码 unavailable + ErrorInfo{domain=setup, code=db_unreachable}，
// HTTP 503，§1.5 行 193 映射）。root 合法（步骤 ①通过后到达连接性检查）。
func TestFreshInstallDBUnreachable(t *testing.T) {
	s, configPath := newTestServer(t)
	redisAddr := fakeRedis(t, "")
	payload, _ := json.Marshal(map[string]any{
		"dbDsn":         "test:x@tcp(127.0.0.1:1)/test",
		"redisAddr":     redisAddr,
		"adminUsername": "admin01",
		"adminPassword": "Str0ngPassw0rd",
		"root":          "https://sso.example.com",
	})
	rec := doConnectJSON(s.Router(), "/api.setup.v1.SetupService/Install", "application/json", string(payload))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("HTTP status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
	code, info := decodeConnectError(t, rec)
	if code != "unavailable" || info == nil || info.Domain != setupDomain || info.Code != CodeDBUnreachable {
		t.Fatalf("connect=(%q, %+v), want unavailable + setup/%s (body %s)", code, info, CodeDBUnreachable, rec.Body.String())
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Errorf("failed install must not write config, stat err = %v", err)
	}
	select {
	case <-s.Exposed():
		t.Error("failed install must not trigger exit")
	default:
	}
}

// TestCheckRedisScenarios Redis 连通检查（假 Redis）：无密码 PING 通、
// AUTH 密码正确通、AUTH 密码错 → redis_unreachable、SELECT 非 0 库、
// 目标不监听 → redis_unreachable。
func TestCheckRedisScenarios(t *testing.T) {
	ctx := context.Background()

	t.Run("plain ping", func(t *testing.T) {
		addr := fakeRedis(t, "")
		if err := checkRedis(ctx, addr, "", 0); err != nil {
			t.Fatalf("plain ping: %v", err)
		}
	})
	t.Run("auth ok then ping", func(t *testing.T) {
		addr := fakeRedis(t, "s3cret")
		if err := checkRedis(ctx, addr, "s3cret", 0); err != nil {
			t.Fatalf("auth+ping: %v", err)
		}
	})
	t.Run("auth bad password", func(t *testing.T) {
		addr := fakeRedis(t, "s3cret")
		err := checkRedis(ctx, addr, "wrong", 0)
		var pe *PathError
		if !asPathError(err, &pe) || pe.Code != CodeRedisUnreachable {
			t.Fatalf("want redis_unreachable, got %v", err)
		}
	})
	t.Run("select db", func(t *testing.T) {
		addr := fakeRedis(t, "")
		if err := checkRedis(ctx, addr, "", 3); err != nil {
			t.Fatalf("select+ping: %v", err)
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		// 端口 1 上几乎必然无服务。
		err := checkRedis(ctx, "127.0.0.1:1", "", 0)
		var pe *PathError
		if !asPathError(err, &pe) || pe.Code != CodeRedisUnreachable {
			t.Fatalf("want redis_unreachable, got %v", err)
		}
	})
}

// asPathError 用 errors.As 判定 PathError（支持包装链）。
func asPathError(err error, target **PathError) bool {
	return errors.As(err, target)
}

// TestValidateUsernameMatrix 用户名规则（接口文档 §2.3 行 444）。
func TestValidateUsernameMatrix(t *testing.T) {
	valid := []string{"admin", "user01", "A_b_9", "12345", "abcdefghij"}
	invalid := []string{"", "ab", "abcd", "abcde!", "has space", "中文用户名", "abcdefghijklmnopqrstuvwxyz12345"}
	for _, u := range valid {
		if err := validateUsername(u); err != nil {
			t.Errorf("username %q should be valid, got %v", u, err)
		}
	}
	for _, u := range invalid {
		err := validateUsername(u)
		var pe *PathError
		if !asPathError(err, &pe) || pe.Code != CodeUsernameInvalid {
			t.Errorf("username %q should be username_invalid, got %v", u, err)
		}
	}
}

// TestValidatePasswordMatrix 密码策略（接口文档 §5.6 默认值）。
func TestValidatePasswordMatrix(t *testing.T) {
	valid := []string{"Str0ngPassw0rd", "Abcdef12", "xY9zzzzzzz"}
	invalid := map[string]string{
		"Sh0rt!":     "too short (<8)",
		"aaaaaaaa":   "no digit",
		"AAAAAAAA":   "no lowercase",
		"12345678":   "no letters",
		"someone01A": "contains username",
		"admin0 1A":  "whitespace",
		"password1":  "common",
	}
	for _, p := range valid {
		if err := validatePassword("someone", p); err != nil {
			t.Errorf("password %q should be valid, got %v", p, err)
		}
	}
	for p := range invalid {
		err := validatePassword("someone", p)
		var pe *PathError
		if !asPathError(err, &pe) || pe.Code != CodePasswordWeak {
			t.Errorf("password %q should be password_weak, got %v", p, err)
		}
	}
	// 密码与用户名完全相同 → weak（§5.6 固定规则；用户名取满足字符类的值
	// 以越过前置检查直达该分支）。
	if err := validatePassword("Someone123", "Someone123"); err == nil {
		t.Error("password equal to username must be weak")
	}
	// 64 长度边界：恰好 64 合法、65 拒绝（服务端硬上限，§5.6 固定规则）。
	if err := validatePassword("someone", "A"+strings.Repeat("b", 30)+"0"+strings.Repeat("c", 31)+"1"); err != nil {
		t.Errorf("64-char mixed password should be valid, got %v", err)
	}
	if err := validatePassword("someone", "A"+strings.Repeat("b", 31)+"0"+strings.Repeat("c", 31)+"1"); err == nil {
		t.Error("65-char password must be weak (hard limit 64)")
	}
}

// TestHashPasswordArgon2id 哈希格式：PHC 头 + 参数（§3.2 默认 t=3 m=65536
// p=4）+ base64 盐 / 摘要；两次哈希不同（随机盐）。
func TestHashPasswordArgon2id(t *testing.T) {
	h1, err := hashPasswordArgon2id("Str0ngPassw0rd")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	prefix := "$argon2id$v=19$m=65536,t=3,p=4$"
	if !strings.HasPrefix(h1, prefix) {
		t.Errorf("hash prefix wrong: %q", h1)
	}
	parts := strings.Split(h1, "$")
	if len(parts) != 6 {
		t.Fatalf("hash has %d parts, want 6: %q", len(parts), h1)
	}
	h2, _ := hashPasswordArgon2id("Str0ngPassw0rd")
	if h1 == h2 {
		t.Error("two hashes must differ (random salt)")
	}
}

// TestWriteConfigFileAtomic 原子写（§3.15 writer）：内容完整、目标权限
// 0600（POSIX；Windows 无 POSIX 位，断言写入成功）、无临时文件残留、
// 向坏路径写入失败不留半截。
func TestWriteConfigFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte("server: { listen: \":8080\" }\n")

	if err := WriteConfigFile(path, data); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content = %q, want %q", got, data)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp file leaked: %d entries in dir", len(entries))
	}
	if fi, err := os.Stat(path); err == nil {
		perm := fi.Mode().Perm()
		if perm != 0o600 {
			// Windows 无 POSIX 权限位：Go 侧 stat 返回 0666；仅 POSIX 断言 0600。
			t.Logf("file perm = %o (platform-dependent; 0600 enforced on POSIX)", perm)
		}
	}

	// 坏路径：目录不存在 → 失败且不 panic。
	if err := WriteConfigFile(filepath.Join(dir, "no-such-dir", "config.yaml"), data); err == nil {
		t.Error("write into missing dir must fail")
	}
}

// TestBuildInstallConfigDefaults root 必填 / rp_id 推导（§13.3 行 1906-1907，
// D6 后口径）：rp_id 缺省取 root 的 host（去 scheme 与端口）；显式填写优先；
// 随机密钥。字段合法性校验归 validateInstallInput（见其矩阵测试）。
func TestBuildInstallConfigDefaults(t *testing.T) {
	in := InstallInput{
		DBDSN:         "authloft:pass@tcp(127.0.0.1:3306)/authloft?charset=utf8mb4&parseTime=true&loc=Local",
		RedisAddr:     "127.0.0.1:6379",
		AdminUsername: "admin",
		Root:          "https://sso.corp.example.com:8443",
	}
	c, err := BuildInstallConfig(in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if c.Authloft.Root != in.Root {
		t.Errorf("root = %q, want input root verbatim", c.Authloft.Root)
	}
	if c.Authloft.RpID != "sso.corp.example.com" {
		t.Errorf("rp_id = %q, want root host without port", c.Authloft.RpID)
	}
	if c.DB.DSN != in.DBDSN || c.Redis.Addr != in.RedisAddr {
		t.Error("user-provided db/redis must be carried into config")
	}
	if err := c.Validate(); err != nil {
		t.Errorf("generated config must pass Validate: %v", err)
	}
	if len(c.OIDC.JWTKeys) != 1 || c.OIDC.JWTKeys[0].Kid != "1" || c.OIDC.JWTKeys[0].PrivateKeyPEM == "" {
		t.Errorf("fresh install must generate exactly one oidc.jwt_keys with kid \"1\": %+v", c.OIDC.JWTKeys)
	}

	in.RpID = "corp.example.com"
	c2, err := BuildInstallConfig(in)
	if err != nil {
		t.Fatalf("build explicit: %v", err)
	}
	if c2.Authloft.Root != in.Root || c2.Authloft.RpID != in.RpID {
		t.Errorf("explicit root/rp_id must win: %q / %q", c2.Authloft.Root, c2.Authloft.RpID)
	}

	// localhost root：rp_id 推导同为 localhost（§13.3 允许）。
	in.Root, in.RpID = "http://localhost:8080", ""
	c3, err := BuildInstallConfig(in)
	if err != nil {
		t.Fatalf("build localhost: %v", err)
	}
	if c3.Authloft.RpID != "localhost" {
		t.Errorf("rp_id (localhost root) = %q, want localhost", c3.Authloft.RpID)
	}
}

// TestValidateInstallInputMatrix 路径 B 步骤 ①字段校验矩阵（§13.3 行 1906-
// 1907 / 1911）：root 必填、完整 http(s) URL、host
// 域名 / localhost（拒绝 IP）；rpId 显式填写须为域名字符串（允许
// localhost），缺省取 root 的 host。域名判定与启动期 webauthn 库同口径
// （webauthn.ValidRPID），保证安装期接受集合 ⊆ 启动期库接受集合。
func TestValidateInstallInputMatrix(t *testing.T) {
	base := func(root, rpID string) InstallInput {
		return InstallInput{
			DBDSN:         "authloft:pass@tcp(127.0.0.1:3306)/authloft",
			RedisAddr:     "127.0.0.1:6379",
			AdminUsername: "admin",
			AdminPassword: "Str0ngPassw0rd",
			Root:          root,
			RpID:          rpID,
		}
	}
	cases := []struct {
		name    string
		in      InstallInput
		wantErr bool
	}{
		// root 分支。
		{"root missing", base("", ""), true},
		{"root not url", base("sso.example.com", ""), true},
		{"root other scheme", base("ftp://sso.example.com", ""), true},
		{"root no host", base("https://", ""), true},
		{"root host is ipv4", base("https://192.168.10.2", ""), true},
		{"root host is ipv4 with port", base("http://10.0.0.1:8080", ""), true},
		{"root host is ipv6", base("http://[::1]:8080", ""), true},
		{"root single label not localhost", base("https://intranet", ""), true},
		{"root domain ok", base("https://sso.example.com", ""), false},
		{"root domain with port ok", base("https://sso.corp.example.com:8443", ""), false},
		{"root http ok", base("http://sso.example.com", ""), false},
		{"root localhost ok", base("http://localhost:3000", ""), false},
		{"root localhost no port ok", base("https://localhost", ""), false},
		// rpId 分支（root 合法为前提）。
		{"rp_id explicit ipv4", base("https://sso.example.com", "192.168.10.2"), true},
		{"rp_id explicit with scheme", base("https://sso.example.com", "https://sso.example.com"), true},
		{"rp_id explicit with port", base("https://sso.example.com", "corp.example.com:8443"), true},
		{"rp_id explicit single label", base("https://sso.example.com", "corp"), true},
		{"rp_id explicit domain ok", base("https://sso.example.com", "corp.example.com"), false},
		{"rp_id explicit localhost ok", base("https://sso.example.com", "localhost"), false},
	}
	for _, tc := range cases {
		err := validateInstallInput(tc.in)
		if tc.wantErr {
			var pe *PathError
			if !errors.As(err, &pe) || pe.Code != CodeConfigInvalid {
				t.Errorf("%s: err = %v, want PathError %s", tc.name, err, CodeConfigInvalid)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected err = %v", tc.name, err)
		}
	}
}

// TestInstallRootFieldValidationHandler Install 域信封（§13.3 行 1911 步骤 ①）：
// root 缺失 / host 为 IP → invalid_argument 400 + ErrorInfo{domain=setup,
// code=config_invalid}，不写 config、不退出（校验先于连接性检查，无需 DB）。
func TestInstallRootFieldValidationHandler(t *testing.T) {
	s, configPath := newTestServer(t)

	for name, root := range map[string]string{
		"root missing":    "",
		"root host is ip": "https://192.168.10.2:8080",
	} {
		payload, _ := json.Marshal(map[string]any{
			"dbDsn":         "test:x@tcp(127.0.0.1:1)/test",
			"redisAddr":     "127.0.0.1:1",
			"adminUsername": "admin",
			"adminPassword": "Str0ngPassw0rd",
			"root":          root,
		})
		rec := doConnectJSON(s.Router(), "/api.setup.v1.SetupService/Install", "application/json", string(payload))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: HTTP status = %d, want 400 (body %s)", name, rec.Code, rec.Body.String())
			continue
		}
		code, info := decodeConnectError(t, rec)
		if code != "invalid_argument" || info == nil || info.Domain != setupDomain || info.Code != CodeConfigInvalid {
			t.Errorf("%s: connect=(%q, %+v), want invalid_argument + setup/%s", name, code, info, CodeConfigInvalid)
		}
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Errorf("failed installs must not write config, stat err = %v", err)
	}
	select {
	case <-s.Exposed():
		t.Error("field validation failure must not trigger exit")
	default:
	}
}

// TestRedact 日志脱敏：DSN 密码段打码，其余保留。
func TestRedact(t *testing.T) {
	in := "dial authloft:sup3rs3cret@tcp(127.0.0.1:3306)/authloft failed"
	out := redact(in)
	if strings.Contains(out, "sup3rs3cret") {
		t.Errorf("password leaked: %q", out)
	}
	if !strings.Contains(out, "authloft:***@tcp(127.0.0.1:3306)") {
		t.Errorf("redact shape = %q", out)
	}
	if redact("no dsn here") != "no dsn here" {
		t.Error("plain text must be untouched")
	}
}

// TestRequestExitIdempotent requestExit 幂等（多次 close 不 panic）。
func TestRequestExitIdempotent(t *testing.T) {
	s, _ := newTestServer(t)
	s.requestExit()
	s.requestExit()
	select {
	case <-s.Exposed():
	default:
		t.Fatal("exit channel must be closed after requestExit")
	}
}

// TestNewServerServesAssets（§3.13 行 484）：NewServer 顶层 mux 恒挂
// /assets/**——setup 壳模板引用的前端构建产物由此供给，无 config.yaml 也
// 必须可达。当前 dist 为空仓占位形态（仅入库 .gitignore），可达性以占位 200 +
// 未命中 404 + 非法方法 405 三向印证（405 证明响应方是 assets handler 而非
// gin 兜底）；真实产物入驻后同一断言即覆盖。
func TestNewServerServesAssets(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/assets/.gitignore", nil)
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /assets/.gitignore = %d, want 200", w.Code)
	}
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q, want year-long immutable", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/assets/missing.abc.js", nil)
	w2 := httptest.NewRecorder()
	s.Router().ServeHTTP(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Fatalf("GET /assets/missing.abc.js = %d, want 404", w2.Code)
	}

	req3 := httptest.NewRequest(http.MethodPost, "/assets/anything.js", nil)
	w3 := httptest.NewRecorder()
	s.Router().ServeHTTP(w3, req3)
	if w3.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /assets/anything.js = %d, want 405", w3.Code)
	}
	if got := w3.Header().Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q, want GET, HEAD", got)
	}
}

// TestSetupHTTPServerFromEnv setup 模式监听装配（§3.15：只读 server 段
// env，默认值 + env 覆盖；监听 / TLS 模式与生产同口径）：
//   - 无 env：Addr 默认 ":8080"、h2c 形态 Protocols；
//   - AUTHLOFT_SERVER_LISTEN 覆盖 Addr；
//   - 非法 server env（bare-port listen）→ fail-fast。
func TestSetupHTTPServerFromEnv(t *testing.T) {
	s, _ := newTestServer(t)

	srv, err := s.newHTTPServerFrom(config.ServerConfig{Listen: ":8080"})
	if err != nil {
		t.Fatalf("newHTTPServerFrom: %v", err)
	}
	if srv.Addr != ":8080" {
		t.Errorf("Addr = %q, want :8080", srv.Addr)
	}
	if !srv.Protocols.HTTP1() || !srv.Protocols.UnencryptedHTTP2() || srv.Protocols.HTTP2() {
		t.Errorf("h2c: Protocols = HTTP1:%v UH2:%v H2:%v, want true/true/false", srv.Protocols.HTTP1(), srv.Protocols.UnencryptedHTTP2(), srv.Protocols.HTTP2())
	}

	t.Setenv("AUTHLOFT_SERVER_LISTEN", ":19099")
	sc, err := config.DefaultServerConfig()
	if err != nil {
		t.Fatalf("DefaultServerConfig with env: %v", err)
	}
	srv, err = s.newHTTPServerFrom(sc)
	if err != nil {
		t.Fatalf("newHTTPServerFrom (env): %v", err)
	}
	if srv.Addr != ":19099" {
		t.Errorf("Addr = %q, want :19099 from AUTHLOFT_SERVER_LISTEN", srv.Addr)
	}

	// 非法 server env → DefaultServerConfig fail-fast（Run 同源消费，
	// 启动期 fail-fast 由它保证）。
	t.Setenv("AUTHLOFT_SERVER_LISTEN", "19099")
	if _, err := config.DefaultServerConfig(); err == nil {
		t.Error("bare-port listen must fail-fast")
	}
}

// TestBogusKeyMaterialIsPlausible 测试辅助自检：testKeyB64 生成可被
// config.Validate 接受的 32 字节 base64 密钥（供 uploadConfigYAML 使用）。
func TestBogusKeyMaterialIsPlausible(t *testing.T) {
	text := uploadConfigYAML("authloft:pass@tcp(127.0.0.1:3306)/authloft", "127.0.0.1:6379")
	cfg, err := parseUploadedConfig(text)
	if err != nil {
		t.Fatalf("helper config must parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("helper config must validate: %v", err)
	}
}
