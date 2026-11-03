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
	"time"

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

// doRequest 发起带自定义头的请求（装配链路测试用；临时路由注册在 newRouter
// 返回的 /api 组上——gin 的 Group 每次派生新组，不能再 r.Group("/api") 绕过组中间件）。
func doRequest(r *gin.Engine, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func configuredRouter() (*gin.Engine, *gin.RouterGroup) {
	gin.SetMode(gin.TestMode)
	return newRouter(assembledRootOrigin, []string{assembledAppID}, connect.NewServer(1<<20))
}

func emptyConfigRouter() (*gin.Engine, *gin.RouterGroup) {
	gin.SetMode(gin.TestMode)
	return newRouter("", nil, connect.NewServer(1<<20))
}

// 装配链路（docs/后端架构.md §18 行 1726：origin → connect handler →
// connect interceptor → handler）：recover → requestid → logger → metrics →
// origin 全局链；contenttype / negotiate 中间件已随 Connect 改造删除
//（Content-Type 校验由 Connect 框架与 OIDC 各自承担）。
func TestNewRouterMiddlewareChain(t *testing.T) {
	r, apiGroup := configuredRouter()
	apiGroup.POST("/x", ok)

	// 无 Origin 无 Referer → 403 Connect 错误形态（code=permission_denied，
	// §1.5 行 188）；X-Request-Id 响应头非空（requestid 挂全局、先于 origin）。
	rec := doRequest(r, http.MethodPost, "/api/x", nil)
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
	if rec := doRequest(r, http.MethodPost, "/api/x", map[string]string{"Origin": "https://evil.example.com"}); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// 同源（Content-Type 不再由中间件校验）→ 到达 handler（正向链）。
	jsonHeaders := map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json"}
	if rec := doRequest(r, http.MethodPost, "/api/x", jsonHeaders); rec.Code != http.StatusOK {
		t.Errorf("same-origin: status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// 免检组整链（§1.1 行 79 例外、§3.3 行 289）：/api/oidc/**（x-www-form-urlencoded
// 到达 handler）与 rpc 域 Connect 路径 /api.rpc.v1.**（跨站放行后进 connect
// 兜底、未注册返回 Connect 404——非 403 即证明 origin 放行且 mux 接管）。
func TestNewRouterExemptGroups(t *testing.T) {
	r, apiGroup := configuredRouter()
	apiGroup.POST("/oidc/y", ok)

	if rec := doRequest(r, http.MethodPost, "/api/oidc/y", map[string]string{
		"Origin": "https://evil.example.com", "Content-Type": "application/x-www-form-urlencoded",
	}); rec.Code != http.StatusOK {
		t.Errorf("oidc exempt: status = %d, want %d", rec.Code, http.StatusOK)
	}
	// rpc 域 Connect 新路径：origin 免检放行 → gin 未匹配 → connect mux 接管
	// → 未注册 service 返回 Connect 错误形态 404（尚未有域 handler）。
	rec := doRequest(r, http.MethodPost, "/api.rpc.v1.RpcService/GetUserProfile", map[string]string{
		"Origin": "https://evil.example.com", "Content-Type": "application/json",
	})
	if rec.Code != http.StatusNotFound {
		t.Errorf("rpc connect path: status = %d, want %d (免检放行后应由 connect 兜底接管)", rec.Code, http.StatusNotFound)
	}
	if !strings.Contains(rec.Body.String(), `"code":"not_found"`) {
		t.Errorf("rpc connect path body %q missing not_found connect code", rec.Body.String())
	}
	if got := rec.Header().Get("X-Request-Id"); got == "" {
		t.Errorf("X-Request-Id is empty, want non-empty")
	}
}

// connect 兜底接管（§3.3 行 296、§3.14 行 472）：未注册的 connect 形态路径
// 经 gin.NoRoute 进 connect mux → Connect 错误 JSON 404 + X-Request-Id 头；
// 非 connect 形态的未知路径保持原生 404 空体（不产生 Connect 错误体）。
func TestNewRouterConnectFallbackAndXRequestID(t *testing.T) {
	r, _ := configuredRouter()

	// 未注册 connect 路径（跨站 Origin 被 origin 层拦截 → 403；同源放行后
	// 由 mux 兜底 → 404）：取同源请求验证兜底链。
	rec := doRequest(r, http.MethodPost, "/api.sso.v1.SsoService/LoginDefault", map[string]string{
		"Origin": assembledRootOrigin, "Content-Type": "application/json",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unregistered connect path: status = %d, want %d (body %s)", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (Connect 错误形态)", got)
	}
	if !strings.Contains(rec.Body.String(), `"code":"not_found"`) {
		t.Errorf("connect fallback body %q missing not_found code", rec.Body.String())
	}
	if got := rec.Header().Get("X-Request-Id"); got == "" {
		t.Errorf("X-Request-Id is empty, want non-empty (404 亦回写)")
	}

	// 未知非 connect 路径 → 原生 404 空体 + X-Request-Id 头。
	rec = doRequest(r, http.MethodGet, "/nope", nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown path: status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("unknown path body = %q, want empty (非 connect 路径原生 404)", rec.Body.String())
	}
	if got := rec.Header().Get("X-Request-Id"); got == "" {
		t.Errorf("X-Request-Id is empty, want non-empty (404 亦回写)")
	}
}

// 装配链 panic 兜底：recover 挂全局最外层，/api 组上的 panic 路由整链下返回
// 500 原生空体（codec 信封出口已删），X-Request-Id 响应头
// 仍非空（requestid 先于一切错误出口）。
func TestNewRouterRecoverPanicRoute(t *testing.T) {
	r, apiGroup := configuredRouter()
	apiGroup.POST("/panic", func(c *gin.Context) { panic("assembled boom") })

	headers := map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json"}
	rec := doRequest(r, http.MethodPost, "/api/panic", headers)
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
func (h *accessLogCap) WithGroup(string) slog.Handler      { return h }

// 装配链访问日志：logger 挂全局且在 requestid 之后 → 正常请求输出含非空
// request_id 与最终 status 的访问日志（docs/后端架构.md §3.3 行 309）。
func TestNewRouterAccessLog(t *testing.T) {
	lc := &accessLogCap{}
	old := slog.Default()
	slog.SetDefault(slog.New(lc))
	t.Cleanup(func() { slog.SetDefault(old) })

	r, apiGroup := configuredRouter()
	apiGroup.POST("/ok", ok)

	headers := map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json"}
	if rec := doRequest(r, http.MethodPost, "/api/ok", headers); rec.Code != http.StatusOK {
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
	r, apiGroup := emptyConfigRouter()
	apiGroup.POST("/x", ok)
	apiGroup.POST("/oidc/z", ok)

	if rec := doRequest(r, http.MethodPost, "/api/x", map[string]string{"Origin": assembledRootOrigin}); rec.Code != http.StatusForbidden {
		t.Errorf("empty config same-origin: status = %d, want %d (rootOrigin 未配置 → 同源判断恒失败)", rec.Code, http.StatusForbidden)
	}
	if rec := doRequest(r, http.MethodPost, "/api/oidc/z", map[string]string{"Origin": "https://evil.example.com", "Content-Type": "application/x-www-form-urlencoded"}); rec.Code != http.StatusOK {
		t.Errorf("empty config exempt group: status = %d, want %d (免检组不受配置影响)", rec.Code, http.StatusOK)
	}
}

// bootstrapConfig 构造自造 *config.Config（§3.2 约定 1 / §20：测试传自造实例，
// 只填装配链实际读取的字段——Authloft.Root 与 Server 三项）。
func bootstrapConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Listen:       ":18080",
			ReadTimeout:  config.Duration{Duration: 5 * time.Second},
			WriteTimeout: config.Duration{Duration: 7 * time.Second},
		},
		Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com"},
	}
}

// bootstrap 装配注入（§3.2 约定 1）：buildRouter 从自造 *config.Config
// 取 authloft.root 注入 origin——同源请求过、跨站 403，证明注入的是配置值而非
// 空配置（空配置下同源也 403）；/metrics 端点装配后可用。
func TestBootstrapInjectsRootOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := bootstrapConfig()
	r, apiGroup := buildRouter(cfg)
	apiGroup.POST("/x", ok)

	sameOrigin := map[string]string{"Origin": cfg.Authloft.Root, "Content-Type": "application/json"}
	if rec := doRequest(r, http.MethodPost, "/api/x", sameOrigin); rec.Code != http.StatusOK {
		t.Errorf("same-origin from config: status = %d, want %d (rootOrigin 未注入则同源恒 403)", rec.Code, http.StatusOK)
	}
	crossOrigin := map[string]string{"Origin": "https://evil.example.com", "Content-Type": "application/json"}
	if rec := doRequest(r, http.MethodPost, "/api/x", crossOrigin); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if rec := doRequest(r, http.MethodGet, "/metrics", nil); rec.Code != http.StatusOK {
		t.Errorf("metrics endpoint: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// http.Server 装配参数：listen / read_timeout / write_timeout 取自
// 自造 *config.Config 的 server 段（§3.2 行 260-262），handler 为注入的 router。
func TestBootstrapHTTPServerConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := bootstrapConfig()
	router, _ := buildRouter(cfg)
	srv := newHTTPServer(cfg, router)

	if srv.Addr != cfg.Server.Listen {
		t.Errorf("Addr = %q, want %q", srv.Addr, cfg.Server.Listen)
	}
	if srv.ReadTimeout != 5*time.Second {
		t.Errorf("ReadTimeout = %v, want 5s", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 7*time.Second {
		t.Errorf("WriteTimeout = %v, want 7s", srv.WriteTimeout)
	}
	if srv.Handler == nil {
		t.Error("Handler is nil, want router")
	}
}

// bootstrap 启动分支（§3.1 行 253 / §3.15）：正常模式（config 存在）
// 下生产路由不注册任何 setup 路由——/setup 页面与 /api/setup/** 一律 404
//（接口文档 §13：本域仅 setup 模式可达）。POST 系带同源 Origin：origin 已挂
// 全局链（§3.3 行 296），缺 Origin 的写请求在路由匹配前即被 403。
func TestBootstrapSetupRoutesNotFoundInNormalMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r, _ := buildRouter(bootstrapConfig())

	for _, target := range []string{
		"/setup",
		"/api/setup/status",
		"/api/setup/config",
		"/api/setup/install",
	} {
		if rec := doRequest(r, http.MethodGet, target, nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s in normal mode: status = %d, want %d", target, rec.Code, http.StatusNotFound)
		}
	}
	if rec := doRequest(r, http.MethodPost, "/api/setup/install", map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json"}); rec.Code != http.StatusNotFound {
		t.Errorf("POST /api/setup/install in normal mode: status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	// connect 形态的 setup 路径同域兜底：未注册 → Connect 404。
	rec := doRequest(r, http.MethodPost, "/api.setup.v1.SetupService/Install", map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json"})
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST /api.setup.v1.SetupService/Install in normal mode: status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if !strings.Contains(rec.Body.String(), `"code":"not_found"`) {
		t.Errorf("connect setup path body %q missing not_found code", rec.Body.String())
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
