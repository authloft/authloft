package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestProbeExitCodes：probe 按状态码给退出值——2xx → 0；非 2xx / 连接失败
// → 1（HEALTHCHECK 据此判容器健康态）。
func TestProbeExitCodes(t *testing.T) {
	cases := []struct {
		name string
		code int
		want int
	}{
		{name: "healthy", code: http.StatusOK, want: 0},
		{name: "unhealthy", code: http.StatusServiceUnavailable, want: 1},
		{name: "not found", code: http.StatusNotFound, want: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()

			if got := probe(srv.URL, srv.Client()); got != tc.want {
				t.Fatalf("probe(%d) = %d, want %d", tc.code, got, tc.want)
			}
		})
	}
}

// TestProbeConnRefused：目标不可达（连接失败）→ 1，不 panic、不重试悬挂。
func TestProbeConnRefused(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // 关闭后端口不可达

	client := &http.Client{Timeout: 2 * time.Second}
	if got := probe(url, client); got != 1 {
		t.Fatalf("probe unreachable = %d, want 1", got)
	}
}
