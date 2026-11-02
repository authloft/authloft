package middleware

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// 计数器为包级共享，用例先归零再断言增量。
func resetMetrics() {
	requestsTotal.Store(0)
	durationNanosTotal.Store(0)
	inFlight.Store(0)
}

// ① 请求后 requests/duration 递增、handler 执行期间在途为 1、结束后归零。
// handler 睡 2ms 产生确定性耗时——空链路在本机单调时钟粒度下
// time.Since 可为 0，递增断言不能依赖时钟粒度。
func TestMetricsCountsRequests(t *testing.T) {
	resetMetrics()
	var inflightSeen int64
	r := newTestRouter(Metrics())
	r.GET("/ping", func(c *gin.Context) {
		inflightSeen = inFlight.Load()
		time.Sleep(2 * time.Millisecond)
		c.Status(http.StatusOK)
	})

	for i := 0; i < 3; i++ {
		if rec := serve(r, "/ping", ""); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want %d", i, rec.Code, http.StatusOK)
		}
	}
	if got := requestsTotal.Load(); got != 3 {
		t.Errorf("requests_total = %d, want 3", got)
	}
	if inflightSeen != 1 {
		t.Errorf("in_flight during handler = %d, want 1", inflightSeen)
	}
	if got := inFlight.Load(); got != 0 {
		t.Errorf("in_flight after requests = %d, want 0", got)
	}
	if got := durationNanosTotal.Load(); got < 1_000_000 {
		t.Errorf("duration_nanos_total = %d, want >= 1000000 (3x2ms sleeps)", got)
	}
}

// ② /metrics 输出指标名与数值、Content-Type 为 text/plain。
// 读 body 时 ping 已完成（requests_total 1），/metrics 自身挂在全局链、
// 读数时在途（in_flight 1）——运维端点自身也被计数，属预期语义。
func TestMetricsHandlerOutput(t *testing.T) {
	resetMetrics()
	r := newTestRouter(Metrics())
	r.GET("/ping", func(c *gin.Context) {
		time.Sleep(2 * time.Millisecond)
		c.Status(http.StatusOK)
	})
	r.GET("/metrics", Handler())

	serve(r, "/ping", "")
	rec := serve(r, "/metrics", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q, want text/plain", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"requests_total 1", "in_flight 1", "duration_nanos_total "} {
		if !strings.Contains(body, want) {
			t.Errorf("body %q missing %q", body, want)
		}
	}
	if strings.Contains(body, "duration_nanos_total 0") {
		t.Errorf("body %q: duration_nanos_total must be > 0", body)
	}
}

// ③ panic 请求也计数（defer 累加语义；Metrics 须挂 Recover 内层）。
func TestMetricsCountsPanickedRequest(t *testing.T) {
	resetMetrics()
	r := newTestRouter(Recover(), Metrics())
	r.GET("/boom", func(c *gin.Context) { panic("boom") })

	if rec := serve(r, "/boom", ""); rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if got := requestsTotal.Load(); got != 1 {
		t.Errorf("requests_total after panic = %d, want 1", got)
	}
	if got := inFlight.Load(); got != 0 {
		t.Errorf("in_flight after panic = %d, want 0", got)
	}
}
