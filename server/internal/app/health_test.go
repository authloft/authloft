package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
)

// newTestRouter 构造最小 echo 引擎并注册 /health（测试直接走 handler 层，
// 全局中间件链由装配层测试覆盖）。
func newTestRouter(probes []Probe) *echo.Echo {
	r := echo.NewWithConfig(echo.Config{NoGroupAutoRegister404Routes: true})
	r.GET("/health", NewHandler(probes))
	return r
}

// doGet 发起 GET /health 并返回 recorder。
func doGet(t *testing.T, r *echo.Echo) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// TestNewHandlerAllHealthy：全部依赖探活通过 → 200，最小 JSON 状态词。
func TestNewHandlerAllHealthy(t *testing.T) {
	probes := []Probe{
		{Name: "db", Check: func(context.Context) error { return nil }},
		{Name: "redis", Soft: true, Check: func(context.Context) error { return nil }},
	}
	rec := doGet(t, newTestRouter(probes))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("body missing ok status: %s", body)
	}
	if strings.Contains(body, "degraded") {
		t.Errorf("全部健康不应出现 degraded 字段: %s", body)
	}
}

// TestNewHandlerRedisSoftDown：Redis 软探针失败 → 仍 200，只计入 degraded
// 名单（软降级口径：后端架构 §5.3 / 接口文档 §5.6 三形态之二）。
func TestNewHandlerRedisSoftDown(t *testing.T) {
	probes := []Probe{
		{Name: "db", Check: func(context.Context) error { return nil }},
		{Name: "redis", Soft: true, Check: func(context.Context) error { return errors.New("redis down") }},
	}
	rec := doGet(t, newTestRouter(probes))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200（redis 软失败不触发 503）(body %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("body missing ok status: %s", body)
	}
	if !strings.Contains(body, `"degraded":["redis"]`) {
		t.Errorf("degraded list should contain redis only: %s", body)
	}
	if strings.Contains(body, "failed") {
		t.Errorf("软失败不应出现 failed 字段: %s", body)
	}
}

// TestNewHandlerDBDown：硬探针失败 → 503，failed 名单只列硬失败项（DB 断连
// 模拟口径：fake 探活器返回 error，不真断库）。
func TestNewHandlerDBDown(t *testing.T) {
	probes := []Probe{
		{Name: "db", Check: func(context.Context) error { return errors.New("db down") }},
		{Name: "redis", Soft: true, Check: func(context.Context) error { return nil }},
	}
	rec := doGet(t, newTestRouter(probes))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"status":"unavailable"`) {
		t.Errorf("body missing unavailable status: %s", body)
	}
	if !strings.Contains(body, `"failed":["db"]`) {
		t.Errorf("failed list should contain db only: %s", body)
	}
	if strings.Contains(body, "degraded") {
		t.Errorf("redis 健康时不应出现 degraded 字段: %s", body)
	}
	if strings.Contains(body, "db down") {
		t.Errorf("error detail must not leak into body: %s", body)
	}
}

// TestNewHandlerBothDown：DB 硬失败 + Redis 软失败并列 → 503，failed 与
// degraded 同体（接口文档 §5.6：degraded 可与 failed 并列）。
func TestNewHandlerBothDown(t *testing.T) {
	probes := []Probe{
		{Name: "db", Check: func(context.Context) error { return errors.New("db down") }},
		{Name: "redis", Soft: true, Check: func(context.Context) error { return errors.New("redis down") }},
	}
	rec := doGet(t, newTestRouter(probes))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"status":"unavailable"`) {
		t.Errorf("body missing unavailable status: %s", body)
	}
	if !strings.Contains(body, `"failed":["db"]`) {
		t.Errorf("failed list should contain db only: %s", body)
	}
	if !strings.Contains(body, `"degraded":["redis"]`) {
		t.Errorf("degraded list should contain redis only: %s", body)
	}
}

// TestNewHandlerProbeTimeout：探活挂起时被 probeTimeout 截断判失败——
// 收短超时后用阻塞探活器验证（探测请求不因依赖挂起而拖死）。
func TestNewHandlerProbeTimeout(t *testing.T) {
	old := probeTimeout
	probeTimeout = 20 * time.Millisecond
	t.Cleanup(func() { probeTimeout = old })

	probes := []Probe{
		{Name: "db", Check: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}},
	}
	rec := doGet(t, newTestRouter(probes))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 on probe timeout (body %s)", rec.Code, rec.Body.String())
	}
}

// TestStandardProbesNilHandles：句柄未装配（nil）恒判失败——db 硬失败触发
// 503，redis 软探针失败只计入 degraded（软降级口径），不 panic（异常路径
// 如实报不健康）。
func TestStandardProbesNilHandles(t *testing.T) {
	rec := doGet(t, newTestRouter(StandardProbes(nil, nil)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"failed":["db"]`) {
		t.Errorf("failed list should contain db only: %s", body)
	}
	if !strings.Contains(body, `"degraded":["redis"]`) {
		t.Errorf("degraded list should contain redis only: %s", body)
	}
}
