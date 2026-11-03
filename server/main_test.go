package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"authloft/internal/config"
	"authloft/internal/connect"
)

const (
	assembledRootOrigin = "https://authloft.example.com"
	assembledAppID      = "wx1234567890abcdef"
)

// ok 标记请求到达业务 handler（装配测试临时路由用）。
func ok(c *gin.Context) {
	c.String(http.StatusOK, "ok")
}

// doRequest 发起带自定义头的请求（装配链路测试用；经顶层分流 handler
// ——§3.1 行 243 的 http.ServeMux，gin 路由与 connect 前缀链都从它进）。
// 临时路由注册在 buildHandler 返回的 /api 组上。
func doRequest(h http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// configuredHandler 构造生产口径的顶层分流 handler（rootOrigin 与 appid
// 白名单齐全形态——allowlist 生产暂为空表，TODO(appid)，此处同生产留空；
// 无 service 可挂，connect 前缀链为空）。
func configuredHandler() (http.Handler, *gin.RouterGroup) {
	gin.SetMode(gin.TestMode)
	return buildHandler(&config.Config{
		Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com"},
	}, connect.NewServer(1<<20))
}

// emptyConfigHandler main 传空配置形态（rootOrigin 空 → 同源也 403）。
func emptyConfigHandler() (http.Handler, *gin.RouterGroup) {
	gin.SetMode(gin.TestMode)
	return buildHandler(&config.Config{}, connect.NewServer(1<<20))
}

// 装配链路（docs/后端架构.md §18 行 1726：origin → connect handler →
// connect interceptor → handler）：gin 全局链 recover → requestid → logger
// → metrics → origin（§3.3 行 296）；Connect 前缀链 requestid → origin
//（http 版等效，§3.1 行 243）。contenttype / negotiate 中间件已随 Connect
// 改造删除（Content-Type 校验由 Connect 框架与 OIDC 各自承担）。
func TestNewRouterMiddlewareChain(t *testing.T) {
	h, apiGroup := configuredHandler()
	apiGroup.POST("/x", ok)

	// 无 Origin 无 Referer → 403 Connect 错误形态（code=permission_denied，
	// §1.5 行 188）；X-Request-Id 响应头非空（requestid 挂全局、先于 origin）。
	rec := doRequest(h, http.MethodPost, "/api/x", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no origin: status = %d, want %d (body %s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	var errBody struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("unmarshal error body %q: %v", rec.Body.String(), err)
	}
	if errBody.Code != "permission_denied" {
		t.Errorf("error.code = %q, want permission_denied (§1.5 行 188)", errBody.Code)
	}
	if got := rec.Header().Get("X-Request-Id"); got == "" {
		t.Errorf("X-Request-Id is empty, want non-empty (requestid 须先于 origin 挂载)")
	}

	// 跨站 Origin → 403。
	if rec := doRequest(h, http.MethodPost, "/api/x", map[string]string{"Origin": "https://evil.example.com"}); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// 同源（Content-Type 不再由中间件校验）→ 到达 handler（正向链）。
	jsonHeaders := map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json"}
	if rec := doRequest(h, http.MethodPost, "/api/x", jsonHeaders); rec.Code != http.StatusOK {
		t.Errorf("same-origin: status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// 免检组整链（§1.1 行 79 例外、§3.3 行 289）：/api/oidc/**（x-www-form-urlencoded
// 到达 handler）；rpc 域 Connect 路径 /api.rpc.v1.** 经顶层 mux 分流——
// 本处无 rpc service 可挂（前缀未注册），落 gin 原生 404（§3.1 行 243：
// 其余全部交给 gin；非 403 即证明 origin 放行后进 gin 兜底）。
func TestNewRouterExemptGroups(t *testing.T) {
	h, apiGroup := configuredHandler()
	apiGroup.POST("/oidc/y", ok)

	if rec := doRequest(h, http.MethodPost, "/api/oidc/y", map[string]string{
		"Origin": "https://evil.example.com", "Content-Type": "application/x-www-form-urlencoded",
	}); rec.Code != http.StatusOK {
		t.Errorf("oidc exempt: status = %d, want %d", rec.Code, http.StatusOK)
	}
	// rpc 域 Connect 路径：origin 免检放行（未注册 → 顶层 "/" → gin 原生 404
	// 纯文本，非 403 即证明免检链路）。
	rec := doRequest(h, http.MethodPost, "/api.rpc.v1.UserService/GetUserProfile", map[string]string{
		"Origin": "https://evil.example.com", "Content-Type": "application/json",
	})
	if rec.Code != http.StatusNotFound {
		t.Errorf("rpc connect path: status = %d, want %d (免检放行后未注册路径由 gin 兜底)", rec.Code, http.StatusNotFound)
	}
	if got := rec.Header().Get("X-Request-Id"); got == "" {
		t.Errorf("X-Request-Id is empty, want non-empty")
	}
}

// 顶层分流兜底（§3.1 行 243，删 gin.NoRoute 桥后）：未注册的 connect
// 形态路径与其余未知路径全部由 gin 原生 404 兜底（"404 page not found"
// 纯文本）；X-Request-Id 头经 gin 全局链 requestid 回写。已注册 service
// 前缀的 connect 成功响应非 404 见 TestConnectSuccessResponseNot404。
func TestNewRouterConnectFallbackAndXRequestID(t *testing.T) {
	h, _ := configuredHandler()

	// 未注册 connect 路径（同源请求，放行后由 gin 兜底）→ gin 原生 404。
	rec := doRequest(h, http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", map[string]string{
		"Origin": assembledRootOrigin, "Content-Type": "application/json",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unregistered connect path: status = %d, want %d (body %s)", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	if rec.Body.String() != "404 page not found" {
		t.Errorf("connect fallback body = %q, want gin native 404 page not found", rec.Body.String())
	}
	if got := rec.Header().Get("X-Request-Id"); got == "" {
		t.Errorf("X-Request-Id is empty, want non-empty (404 亦回写)")
	}

	// 未知非 connect 路径 → gin 原生 404 + X-Request-Id 头。
	rec = doRequest(h, http.MethodGet, "/nope", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown path: status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if rec.Body.Len() == 0 {
		t.Errorf("unknown path body empty, want gin native 404 body")
	}
	if got := rec.Header().Get("X-Request-Id"); got == "" {
		t.Errorf("X-Request-Id is empty, want non-empty (404 亦回写)")
	}
}

// 装配链 panic 兜底：recover 挂 gin 全局链最外层，/api 组上的 panic 路由
// 整链下返回 500 原生空体，X-Request-Id 响应头仍非空（requestid 先于一切
// 错误出口）。
func TestNewRouterRecoverPanicRoute(t *testing.T) {
	h, apiGroup := configuredHandler()
	apiGroup.POST("/panic", func(c *gin.Context) { panic("assembled boom") })

	headers := map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json"}
	rec := doRequest(h, http.MethodPost, "/api/panic", headers)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic route: status = %d, want %d (body %s)", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("panic route body = %q, want empty (原生最小 500)", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "assembled boom") {
		t.Errorf("panic route body leaks panic value: %s", rec.Body.String())
	}
	if got := rec.Header().Get("X-Request-Id"); got == "" {
		t.Errorf("X-Request-Id is empty, want non-empty (panic 响应亦回写)")
	}
}

// accessLogCap 捕获 slog 默认 logger 输出的属性表（装配层访问日志断言用；
// middleware 包的 slogCapture 不跨包复用，此处做最小实现）。
type accessLogCap struct {
	attrs []map[string]string
}

func (h *accessLogCap) Enabled(context.Context, slog.Level) bool { return true }

func (h *accessLogCap) Handle(_ context.Context, r slog.Record) error {
	m := make(map[string]string, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.String()
		return true
	})
	h.attrs = append(h.attrs, m)
	return nil
}

func (h *accessLogCap) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *accessLogCap) WithGroup(string) slog.Handler { return h }

// 装配链访问日志：logger 挂 gin 全局链且在 requestid 之后 → 正常请求输出
// 含非空 request_id 与最终 status 的访问日志（docs/后端架构.md §3.3 行 309）。
func TestNewRouterAccessLog(t *testing.T) {
	lc := &accessLogCap{}
	old := slog.Default()
	slog.SetDefault(slog.New(lc))
	t.Cleanup(func() { slog.SetDefault(old) })

	h, apiGroup := configuredHandler()
	apiGroup.POST("/ok", ok)

	headers := map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json"}
	if rec := doRequest(h, http.MethodPost, "/api/ok", headers); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if len(lc.attrs) == 0 {
		t.Fatalf("no access log captured; logger 须挂全局")
	}
	last := lc.attrs[len(lc.attrs)-1]
	if last["request_id"] == "" {
		t.Errorf("access log request_id is empty, want non-empty (logger 须挂载在 requestid 之后)")
	}
	if last["status"] != "200" {
		t.Errorf("access log status = %q, want \"200\"", last["status"])
	}
}

// 生产装配口径：main 传空配置时保守拒绝（同源也 403），免检组仍可用。
func TestNewRouterEmptyConfigConservative(t *testing.T) {
	h, apiGroup := emptyConfigHandler()
	apiGroup.POST("/x", ok)
	apiGroup.POST("/oidc/z", ok)

	if rec := doRequest(h, http.MethodPost, "/api/x", map[string]string{"Origin": assembledRootOrigin}); rec.Code != http.StatusForbidden {
		t.Errorf("empty config same-origin: status = %d, want %d (rootOrigin 未配置 → 同源判断恒失败)", rec.Code, http.StatusForbidden)
	}
	if rec := doRequest(h, http.MethodPost, "/api/oidc/z", map[string]string{"Origin": "https://evil.example.com", "Content-Type": "application/x-www-form-urlencoded"}); rec.Code != http.StatusOK {
		t.Errorf("empty config exempt group: status = %d, want %d (免检组不受配置影响)", rec.Code, http.StatusOK)
	}
}

// TestConnectSuccessResponseNot404 核验点（404 残留缺陷的结构性消除实证）：
// 顶层 ServeMux 分流后，已注册 connect service 的成功响应由 handler 直接
// 写出（无 gin serveError 预置 404 残留）——经 mux 前缀链到达 200。
func TestConnectSuccessResponseNot404(t *testing.T) {
	gin.SetMode(gin.TestMode)
	csrv := connect.NewServer(1 << 20)
	csrv.Register("/api.test.v1.TService/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	h, _ := buildHandler(&config.Config{
		Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com"},
	}, csrv)

	rec := doRequest(h, http.MethodPost, "/api.test.v1.TService/Do", map[string]string{
		"Origin": assembledRootOrigin, "Content-Type": "application/json",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("connect success: status = %d, want %d (body %s)——分流后不得残留 gin 预置 404", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("X-Request-Id"); got == "" {
		t.Error("X-Request-Id is empty, want non-empty (connect 前缀链 requestid 等效)")
	}
}

// TestConnectDomainMiddlewareEquivalent Connect 域中间件等效
// 的测试实证：ServeMux 分流后 Connect 请求不经 gin 全局链——requestid
//（X-Request-Id 全响应回写）与 origin 防护必须在 mux 前缀链上等效生效。
func TestConnectDomainMiddlewareEquivalent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	csrv := connect.NewServer(1 << 20)
	csrv.Register("/api.sso.v1.SsoService/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	csrv.RegisterRPC("/api.rpc.v1.UserService/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h, _ := buildHandler(&config.Config{
		Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com"},
	}, csrv)

	// 写方法无 Origin → 403 permission_denied（origin 等效）+ X-Request-Id
	//（requestid 等效且先于 origin）。
	rec := doRequest(h, http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no origin: status = %d, want %d (body %s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"permission_denied"`) {
		t.Errorf("403 body %q missing permission_denied connect code", rec.Body.String())
	}
	if got := rec.Header().Get("X-Request-Id"); got == "" {
		t.Error("X-Request-Id is empty on 403, want non-empty (requestid 等效、先于 origin)")
	}

	// 跨站 Origin → 403。
	if rec := doRequest(h, http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", map[string]string{"Origin": "https://evil.example.com"}); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// 同源 → 到达 handler（origin 放行 + 成功非 404）。
	if rec := doRequest(h, http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", map[string]string{"Origin": assembledRootOrigin}); rec.Code != http.StatusOK {
		t.Errorf("same-origin: status = %d, want %d", rec.Code, http.StatusOK)
	}

	// rpc 域免检前缀（RegisterRPC 装配形态）：跨站 Origin 放行到达 handler
	//（§1.1 行 79 例外）。
	if rec := doRequest(h, http.MethodPost, "/api.rpc.v1.UserService/GetUserProfile", map[string]string{"Origin": "https://evil.example.com"}); rec.Code != http.StatusOK {
		t.Errorf("rpc exempt: status = %d, want %d (免检组放行)", rec.Code, http.StatusOK)
	}
}

// bootstrapConfig 构造自造 *config.Config（§3.2 约定 1 / §20：测试传自造实例，
// 只填装配链实际读取的字段——Authloft.Root 与 server 段监听项）。
func bootstrapConfig() *config.Config {
	return &config.Config{
		Server:   config.ServerConfig{Listen: ":18080"},
		Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com"},
	}
}

// bootstrap 装配注入（§3.2 约定 1）：buildHandler 从自造 *config.Config
// 取 authloft.root 注入 origin——同源请求过、跨站 403，证明注入的是配置值而非
// 空配置（空配置下同源也 403）；/metrics 端点装配后可用。
func TestBootstrapInjectsRootOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := bootstrapConfig()
	h, apiGroup := buildRouter(cfg)
	apiGroup.POST("/x", ok)

	sameOrigin := map[string]string{"Origin": cfg.Authloft.Root, "Content-Type": "application/json"}
	if rec := doRequest(h, http.MethodPost, "/api/x", sameOrigin); rec.Code != http.StatusOK {
		t.Errorf("same-origin from config: status = %d, want %d (rootOrigin 未注入则同源恒 403)", rec.Code, http.StatusOK)
	}
	crossOrigin := map[string]string{"Origin": "https://evil.example.com", "Content-Type": "application/json"}
	if rec := doRequest(h, http.MethodPost, "/api/x", crossOrigin); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if rec := doRequest(h, http.MethodGet, "/metrics", nil); rec.Code != http.StatusOK {
		t.Errorf("metrics endpoint: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// http.Server 装配参数（§3.1 行 244-245）：
// Addr 取自 server 段 listen；未配 cert+key → Protocols 为 HTTP/1.1 +
// H2C（SetHTTP1 + SetUnencryptedHTTP2）、TLSConfig 为 nil（min_tls_version
// 不生效）；handler 为注入的顶层分流 handler。
func TestBootstrapHTTPServerConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := bootstrapConfig()
	handler, _ := buildRouter(cfg)
	srv, err := newHTTPServer(cfg, handler)
	if err != nil {
		t.Fatalf("newHTTPServer: %v", err)
	}

	if srv.Addr != cfg.Server.Listen {
		t.Errorf("Addr = %q, want %q", srv.Addr, cfg.Server.Listen)
	}
	if srv.Protocols == nil {
		t.Fatal("Protocols is nil, want HTTP/1 + unencrypted HTTP/2 set")
	}
	if !srv.Protocols.HTTP1() || !srv.Protocols.UnencryptedHTTP2() {
		t.Errorf("h2c mode: Protocols = HTTP1:%v UnencryptedHTTP2:%v, want true/true (§3.1 行 245)", srv.Protocols.HTTP1(), srv.Protocols.UnencryptedHTTP2())
	}
	if srv.Protocols.HTTP2() {
		t.Error("h2c mode: HTTP2() = true, want false (TLS-only)")
	}
	if srv.TLSConfig != nil {
		t.Errorf("h2c mode: TLSConfig = %+v, want nil", srv.TLSConfig)
	}
	if srv.Handler == nil {
		t.Error("Handler is nil, want injected handler")
	}
}

// bootstrap 启动分支（§3.1 行 253 / §3.15）：正常模式（config 存在）
// 下生产路由不注册任何 setup 路由——/setup 页面与 /api/setup/** 一律 404
//（接口文档 §13：本域仅 setup 模式可达）。POST 系带同源 Origin：origin 已挂
// gin 全局链（§3.3 行 296），缺 Origin 的写请求在路由匹配前即被 403；
// connect 形态的 setup 路径未注册 → 顶层 "/" → gin 原生 404。
func TestBootstrapSetupRoutesNotFoundInNormalMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, _ := buildRouter(bootstrapConfig())

	for _, target := range []string{
		"/setup",
		"/api/setup/status",
		"/api/setup/config",
		"/api/setup/install",
	} {
		if rec := doRequest(h, http.MethodGet, target, nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s in normal mode: status = %d, want %d", target, rec.Code, http.StatusNotFound)
		}
	}
	if rec := doRequest(h, http.MethodPost, "/api/setup/install", map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json"}); rec.Code != http.StatusNotFound {
		t.Errorf("POST /api/setup/install in normal mode: status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	// connect 形态的 setup 路径（Connect 命名口径）未注册 → gin 原生 404 兜底。
	rec := doRequest(h, http.MethodPost, "/api.setup.v1.SetupService/Install", map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json"})
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /api.setup.v1.SetupService/Install in normal mode: status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if rec.Body.String() != "404 page not found" {
		t.Errorf("unregistered setup connect path body = %q, want gin native 404", rec.Body.String())
	}
}

// setupMode 判定（§3.1 行 253）：config.yaml 不存在 → true（首次启动转
// setup）；文件存在 → false；目录视为存在（非「不存在」语义）。
func TestSetupModeDetection(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "config.yaml")
	if !setupMode(missing) {
		t.Error("missing config.yaml must be detected as setup mode")
	}

	existing := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(existing, []byte("server: { listen: \":8080\" }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if setupMode(existing) {
		t.Error("existing config.yaml must not be setup mode")
	}
}
