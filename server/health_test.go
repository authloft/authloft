package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"authloft/internal/app"
	"authloft/internal/config"
	"authloft/internal/connect"
)

// TestHealthWired：/health 经 buildHandlerWithSSO 注册到全局 gin 链（/metrics
// 同款，不进 /api 组）——fake 探活器全过 → 200 {"status":"ok"}；DB 项失败
// → 503 + failed 名单（§3.1 / §23.1）。响应经 gin 链统一回写 X-Request-Id。
func TestHealthWired(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com", RPDisplayName: config.DefaultRPDisplayName}}
	deps := buildWiredDeps(t, cfg)
	deps.healthProbes = []app.Probe{
		{Name: "db", Check: func(context.Context) error { return nil }},
		{Name: "redis", Check: func(context.Context) error { return nil }},
	}
	h, _ := buildHandlerWithSSO(cfg, connect.NewServer(defaultReadMaxBytes), deps)

	// 依赖健康：200 最小 JSON。
	rec := doRequest(h, http.MethodGet, "/health", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("health healthy: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("health body missing ok status: %s", rec.Body.String())
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("health response missing X-Request-Id (gin 链 requestid)")
	}

	// DB 断连模拟（fake 探活器返回 error，不真断库）：503，failed 只列 db。
	// 探活集在装配期注入并随路由注册捕获，运行期不可变——换探活器须重建
	// handler，与生产「探针集合启动期定死」语义一致。
	deps.healthProbes = []app.Probe{
		{Name: "db", Check: func(context.Context) error { return errors.New("db down") }},
		{Name: "redis", Check: func(context.Context) error { return nil }},
	}
	hDown, _ := buildHandlerWithSSO(cfg, connect.NewServer(defaultReadMaxBytes), deps)
	rec = doRequest(hDown, http.MethodGet, "/health", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("health db down: status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"failed":["db"]`) {
		t.Errorf("failed list should contain db only: %s", rec.Body.String())
	}
}

// TestHealthSetupModeAbsent：setup 模式（deps == nil）不注册 /health——
// 依赖未装配即未就绪，探针 404 如实反映，不伪装存活。
func TestHealthSetupModeAbsent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Authloft: config.AuthloftConfig{Root: assembledRootOrigin, RpID: "authloft.example.com", RPDisplayName: config.DefaultRPDisplayName}}
	h, _ := buildHandler(cfg, connect.NewServer(defaultReadMaxBytes))
	rec := doRequest(h, http.MethodGet, "/health", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("setup mode health: status = %d, want 404", rec.Code)
	}
}
