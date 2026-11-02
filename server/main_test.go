package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	api "authloft/gen/go/api/common"
	"authloft/internal/codec"
	"authloft/internal/config"
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
	return newRouter(assembledRootOrigin, []string{assembledAppID})
}

func emptyConfigRouter() (*gin.Engine, *gin.RouterGroup) {
	gin.SetMode(gin.TestMode)
	return newRouter("", nil)
}

// 装配链路（§18 行 1665：origin + contenttype → negotiate → handler）：
// recover → requestid → logger 全局 → /api 组 origin → contenttype → negotiate。
func TestNewRouterMiddlewareChain(t *testing.T) {
	r, apiGroup := configuredRouter()
	apiGroup.POST("/x", func(c *gin.Context) {
		codec.Write(c, http.StatusOK, &api.Error{Code: "payload"})
	})

	// 无 Origin 无 Referer → 403；错误体 code=forbidden 且 request_id 非空
	//（requestid 挂全局、先于 origin，保证中间件层错误也带链路 ID）。
	rec := doRequest(r, http.MethodPost, "/api/x", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no origin: status = %d, want %d (body %s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	var errBody map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("unmarshal error body %q: %v", rec.Body.String(), err)
	}
	if got := errBody["code"]; got != codec.CodeForbidden {
		t.Errorf("code = %v, want %q", got, codec.CodeForbidden)
	}
	if got, _ := errBody["request_id"].(string); got == "" {
		t.Errorf("request_id is empty, want non-empty (requestid 须先于 origin 挂载)")
	}

	// 跨站 Origin → 403。
	if rec := doRequest(r, http.MethodPost, "/api/x", map[string]string{"Origin": "https://evil.example.com"}); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// 同源 + text/plain → origin 过、contenttype 拦：415。
	ctHeaders := map[string]string{"Origin": assembledRootOrigin, "Content-Type": "text/plain"}
	if rec := doRequest(r, http.MethodPost, "/api/x", ctHeaders); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: status = %d, want %d", rec.Code, http.StatusUnsupportedMediaType)
	}

	// 同源 + json → 到达 handler（正向链）。
	jsonHeaders := map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json"}
	if rec := doRequest(r, http.MethodPost, "/api/x", jsonHeaders); rec.Code != http.StatusOK {
		t.Errorf("json same-origin: status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	// negotiate 在链上且位于 origin / contenttype 之后：同源 + json + Accept proto
	// → handler 的 codec.Write 输出 octet-stream。
	protoHeaders := map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json", "Accept": "application/octet-stream"}
	rec = doRequest(r, http.MethodPost, "/api/x", protoHeaders)
	if rec.Code != http.StatusOK {
		t.Fatalf("proto accept: status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want application/octet-stream (negotiate 须在链上)", got)
	}

	// 跨站 403 时协商尚未执行（origin 在 negotiate 前）→ 错误体回落 JSON。
	rec = doRequest(r, http.MethodPost, "/api/x", map[string]string{"Origin": "https://evil.example.com", "Accept": "application/octet-stream"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin with proto accept: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json; charset=utf-8 (链序：origin 先于 negotiate)", got)
	}
}

// 免检组整链：/api/oidc/** 对 origin 与 contenttype 双免检（x-www-form-urlencoded
// 到达 handler）；/api/rpc/** 只免 origin、不免 contenttype（JSON 通过）。
func TestNewRouterExemptGroups(t *testing.T) {
	r, apiGroup := configuredRouter()
	apiGroup.POST("/oidc/y", ok)
	apiGroup.POST("/rpc/y", ok)

	if rec := doRequest(r, http.MethodPost, "/api/oidc/y", map[string]string{
		"Origin": "https://evil.example.com", "Content-Type": "application/x-www-form-urlencoded",
	}); rec.Code != http.StatusOK {
		t.Errorf("oidc exempt: status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec := doRequest(r, http.MethodPost, "/api/rpc/y", map[string]string{
		"Origin": "https://evil.example.com", "Content-Type": "application/json",
	}); rec.Code != http.StatusOK {
		t.Errorf("rpc exempt: status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec := doRequest(r, http.MethodPost, "/api/rpc/y", map[string]string{
		"Origin": "https://evil.example.com", "Content-Type": "text/plain",
	}); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("rpc text/plain: status = %d, want %d (rpc 不免 contenttype)", rec.Code, http.StatusUnsupportedMediaType)
	}
}

// 装配链 panic 兜底：recover 挂全局最外层，/api 组上的 panic 路由整链下返回
// 500 统一错误体 internal_error 且 request_id 非空（docs/后端架构.md §3.3 行 309、
// §3.14 行 486；docs/接口文档.md §1.5 行 195-203）。
func TestNewRouterRecoverPanicRoute(t *testing.T) {
	r, apiGroup := configuredRouter()
	apiGroup.POST("/panic", func(c *gin.Context) { panic("assembled boom") })

	headers := map[string]string{"Origin": assembledRootOrigin, "Content-Type": "application/json"}
	rec := doRequest(r, http.MethodPost, "/api/panic", headers)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic route: status = %d, want %d (body %s)", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	var errBody map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("unmarshal error body %q: %v", rec.Body.String(), err)
	}
	if got := errBody["code"]; got != codec.CodeInternalError {
		t.Errorf("code = %v, want %q", got, codec.CodeInternalError)
	}
	if got, _ := errBody["request_id"].(string); got == "" {
		t.Errorf("request_id is empty, want non-empty")
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
