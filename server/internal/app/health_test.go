package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// newTestRouter 构造 TestMode gin 引擎并注册 /health（测试直接走 gin 层，
// 全局中间件链由装配层测试覆盖）。
func newTestRouter(probes []Probe) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/health", NewHandler(probes))
	return r
}

// doGet 发起 GET /health 并返回 recorder。
func doGet(t *testing.T, r *gin.Engine) *httptest.ResponseRecorder {
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
		{Name: "redis", Check: func(context.Context) error { return nil }},
	}
	rec := doGet(t, newTestRouter(probes))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("body missing ok status: %s", rec.Body.String())
	}
}

// TestNewHandlerDBDown：单项失败 → 503，failed 名单只列失败项（DB 断连
// 模拟口径：fake 探活器返回 error，不真断库）。
func TestNewHandlerDBDown(t *testing.T) {
	probes := []Probe{
		{Name: "db", Check: func(context.Context) error { return errors.New("db down") }},
		{Name: "redis", Check: func(context.Context) error { return nil }},
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
	if strings.Contains(body, "db down") {
		t.Errorf("error detail must not leak into body: %s", body)
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

// TestStandardProbesNilHandles：句柄未装配（nil）恒判失败——两依赖均不健康，
// 不 panic（异常路径如实报不健康）。
func TestStandardProbesNilHandles(t *testing.T) {
	rec := doGet(t, newTestRouter(StandardProbes(nil, nil)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"failed":[`) || !strings.Contains(body, `"db"`) || !strings.Contains(body, `"redis"`) {
		t.Errorf("failed list should contain db and redis: %s", body)
	}
}
