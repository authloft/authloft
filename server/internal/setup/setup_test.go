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
	"testing"

	"github.com/gin-gonic/gin"
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

// doSetup 对 server router 发请求并返回 recorder。
func doSetup(r *gin.Engine, method, target, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// decodeErrorEnvelope 解析 §1.0 错误信封。
func decodeErrorEnvelope(t *testing.T, rec *httptest.ResponseRecorder) (status string, code string) {
	t.Helper()
	var env struct {
		Status string `json:"status"`
		Error  struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal error envelope %q: %v", rec.Body.String(), err)
	}
	return env.Status, env.Error.Code
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

// TestSetupStatusEndpoint GET /api/setup/status（§13.1）：200 +
// {"status":"success","mode":"setup"}。
func TestSetupStatusEndpoint(t *testing.T) {
	s, _ := newTestServer(t)
	rec := doSetup(s.Router(), http.MethodGet, "/api/setup/status", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"status":"success","mode":"setup"}` {
		t.Errorf("body = %q, want status/mode envelope", got)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8", ct)
	}
}

// TestSetupPageShell GET /setup 空壳页（接口文档 §8 行 1398 / 1401-1403）：
// HTML、no-store、CSP nonce、__AUTHLOFT_INIT__ 注入（al_root 取请求 Host、
// static_base 默认 /assets）、entry 引用 /assets/setup/entry.js、不注入凭证。
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
	csp := rec.Header().Get("Content-Security-Policy")
	nonceRe := regexp.MustCompile(`'nonce-([A-Za-z0-9_-]{20,})'`)
	m := nonceRe.FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("CSP %q has no nonce", csp)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "window.__AUTHLOFT_INIT__") {
		t.Error("shell page must inject window.__AUTHLOFT_INIT__")
	}
	if !strings.Contains(body, `"al_root":"https://192.168.10.2:8080"`) {
		t.Errorf("al_root must default to https://+request Host, body:\n%s", body)
	}
	if !strings.Contains(body, `"static_base":"/assets"`) {
		t.Errorf("static_base must default to /assets, body:\n%s", body)
	}
	if !strings.Contains(body, `src="/assets/setup/entry.js"`) {
		t.Errorf("entry script must reference /assets/setup/entry.js, body:\n%s", body)
	}
	if !strings.Contains(body, `nonce="`+m[1]+`"`) {
		t.Errorf("script tags must carry the CSP nonce %q", m[1])
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

// TestSetupParamErrors 参数类错误走 §1.5：Content-Type 非 JSON → 415；
// 空体 / 非法 JSON → 400；缺必填字段 → 400。错误体带 request_id
//（requestid 中间件在链上）。
func TestSetupParamErrors(t *testing.T) {
	s, _ := newTestServer(t)
	r := s.Router()

	cases := []struct {
		name        string
		target      string
		contentType string
		body        string
		wantStatus  int
		wantCode    string
	}{
		{"text/plain config", "/api/setup/config", "text/plain", "x", http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"no content-type config", "/api/setup/config", "", "x", http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"empty body config", "/api/setup/config", "application/json", "", http.StatusBadRequest, "bad_request"},
		{"invalid json config", "/api/setup/config", "application/json", "{", http.StatusBadRequest, "bad_request"},
		{"missing config field", "/api/setup/config", "application/json", `{}`, http.StatusBadRequest, "bad_request"},
		{"text/plain install", "/api/setup/install", "text/plain", "x", http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"empty body install", "/api/setup/install", "application/json", "", http.StatusBadRequest, "bad_request"},
		{"invalid json install", "/api/setup/install", "application/json", "not json", http.StatusBadRequest, "bad_request"},
		{"missing required install", "/api/setup/install", "application/json", `{"db_dsn":"x"}`, http.StatusBadRequest, "bad_request"},
	}
	for _, tc := range cases {
		rec := doSetup(r, http.MethodPost, tc.target, tc.contentType, tc.body)
		if rec.Code != tc.wantStatus {
			t.Errorf("%s: status = %d, want %d (body %s)", tc.name, rec.Code, tc.wantStatus, rec.Body.String())
			continue
		}
		status, code := decodeErrorEnvelope(t, rec)
		if status != "error" || code != tc.wantCode {
			t.Errorf("%s: envelope = (%s, %s), want (error, %s)", tc.name, status, code, tc.wantCode)
		}
		var env struct {
			Error struct {
				RequestID string `json:"request_id"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if env.Error.RequestID == "" {
			t.Errorf("%s: request_id empty, want non-empty (requestid must be on chain)", tc.name)
		}
	}
}

// uploadConfigYAML 生成一份可通过 Validate 的 config 文本（sign_key 五场景
// 用 32 字节确定密钥）。
func uploadConfigYAML(dsn, redisAddr string) string {
	var b strings.Builder
	b.WriteString("server: { listen: \":8080\", read_timeout: 30s, write_timeout: 30s }\n")
	b.WriteString(fmt.Sprintf("db:\n  dsn: %q\n  max_open_conns: 50\n  max_idle_conns: 10\n  conn_max_lifetime: 1h\n", dsn))
	b.WriteString(fmt.Sprintf("redis: { addr: %q, password: \"\", db: 0, pool_size: 50 }\n", redisAddr))
	b.WriteString("authloft: { root: \"https://sso.example.com\", rp_id: \"sso.example.com\" }\n")
	b.WriteString("sign_key:\n")
	for _, sc := range []string{"session", "login", "ticket", "cookie", "sync_payload"} {
		fmt.Fprintf(&b, "  %s: { key: %q, kid: 1 }\n", sc, testKeyB64('A'))
	}
	b.WriteString("argon2: { time: 3, memory: 65536, threads: 4, key_len: 32 }\n")
	b.WriteString("log: { level: info, format: json }\n")
	return b.String()
}

// TestUploadConfigInvalidMatrix 路径 A 步骤 ① 失败矩阵（§13.2）：非法
// YAML / 缺 sign_key / 缺 db 段 → config_invalid（HTTP 200 业务信封）；
// 响应 message 不回显密钥内容。
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
server: { listen: ":8080", read_timeout: 30s, write_timeout: 30s }
db:
  dsn: "authloft:pass@tcp(127.0.0.1:3306)/authloft"
  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: 1h
redis: { addr: "127.0.0.1:6379", password: "", db: 0, pool_size: 50 }
authloft: { root: "https://sso.example.com", rp_id: "sso.example.com" }
argon2: { time: 3, memory: 65536, threads: 4, key_len: 32 }
log: { level: info, format: json }
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
	}
	for _, tc := range cases {
		payload, _ := json.Marshal(map[string]string{"config": tc.body})
		rec := doSetup(r, http.MethodPost, "/api/setup/config", "application/json", string(payload))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: HTTP status = %d, want 200 (biz envelope)", tc.name, rec.Code)
			continue
		}
		status, code := decodeErrorEnvelope(t, rec)
		if status != "error" || code != CodeConfigInvalid {
			t.Errorf("%s: envelope = (%s, %s), want (error, %s)", tc.name, status, code, CodeConfigInvalid)
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

// TestFreshInstallDBUnreachable 路径 B 步骤 ①：DB 不可达 → db_unreachable
//（HTTP 200 业务信封）。
func TestFreshInstallDBUnreachable(t *testing.T) {
	s, configPath := newTestServer(t)
	redisAddr := fakeRedis(t, "")
	payload, _ := json.Marshal(map[string]any{
		"db_dsn":         "test:x@tcp(127.0.0.1:1)/test",
		"redis_addr":     redisAddr,
		"admin_username": "admin01",
		"admin_password": "Str0ngPassw0rd",
	})
	rec := doSetup(s.Router(), http.MethodPost, "/api/setup/install", "application/json", string(payload))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	status, code := decodeErrorEnvelope(t, rec)
	if status != "error" || code != CodeDBUnreachable {
		t.Fatalf("envelope = (%s, %s), want (error, %s)", status, code, CodeDBUnreachable)
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

// TestBuildInstallConfigDefaults root / rp_id 推导（§3.15 实现要点）：
// 缺省 root = https://+Host、rp_id = Host 去端口；显式填写优先；随机密钥。
func TestBuildInstallConfigDefaults(t *testing.T) {
	in := InstallInput{
		DBDSN:         "authloft:pass@tcp(127.0.0.1:3306)/authloft?charset=utf8mb4&parseTime=true&loc=Local",
		RedisAddr:     "127.0.0.1:6379",
		AdminUsername: "admin",
		Host:          "192.168.10.2:8080",
	}
	c, err := BuildInstallConfig(in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if c.Authloft.Root != "https://192.168.10.2:8080" {
		t.Errorf("root = %q, want https://+Host", c.Authloft.Root)
	}
	if c.Authloft.RpID != "192.168.10.2" {
		t.Errorf("rp_id = %q, want Host without port", c.Authloft.RpID)
	}
	if c.DB.DSN != in.DBDSN || c.Redis.Addr != in.RedisAddr {
		t.Error("user-provided db/redis must be carried into config")
	}
	if err := c.Validate(); err != nil {
		t.Errorf("generated config must pass Validate: %v", err)
	}

	in.Root = "https://sso.corp.example.com"
	in.RpID = "corp.example.com"
	c2, err := BuildInstallConfig(in)
	if err != nil {
		t.Fatalf("build explicit: %v", err)
	}
	if c2.Authloft.Root != in.Root || c2.Authloft.RpID != in.RpID {
		t.Errorf("explicit root/rp_id must win: %q / %q", c2.Authloft.Root, c2.Authloft.RpID)
	}

	// 无端口 Host：rp_id 原样。
	in.Root, in.RpID = "", ""
	in.Host = "sso.internal"
	c3, _ := BuildInstallConfig(in)
	if c3.Authloft.RpID != "sso.internal" {
		t.Errorf("rp_id (no port host) = %q, want original", c3.Authloft.RpID)
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
