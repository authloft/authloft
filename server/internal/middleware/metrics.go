package middleware

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// 零第三方依赖的 HTTP 指标（docs/后端架构.md §3.3 行 309）：
// 热路径仅 sync/atomic 原子计数，禁 mutex、禁每请求 map 写、禁热路径
// 字符串分配；包级变量、进程生命周期单调递增。
var (
	requestsTotal      atomic.Uint64 // 累计完成请求数（含 panic 请求）
	durationNanosTotal atomic.Uint64 // 累计处理耗时（纳秒）
	inFlight           atomic.Int64  // 当前在途请求数
)

// Metrics 统计每请求数据。热路径成本：进入 1 次原子加 + 1 次 time.Now，
// 退出 3 次原子加 + 1 次 time.Since（单调时钟相减，nanotime 语义），
// 无锁、无堆分配。累加放 defer：handler panic 时 unwind 也会执行，
// 保证 panic 请求同样计数——前提是本中间件挂在 Recover() 内层（panic
// 只 unwind 到捕获它的 Recover 为止，Metrics 须在其内才被触发）。
func Metrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		inFlight.Add(1)
		start := time.Now()
		defer func() {
			durationNanosTotal.Add(uint64(time.Since(start).Nanoseconds()))
			requestsTotal.Add(1)
			inFlight.Add(-1)
		}()
		c.Next()
	}
}

// Handler 输出 /metrics 纯文本（运维端点：挂全局 engine、不进 /api 组，
// 不走 codec，接口文档口径见 §3.3）。读取时才格式化，格式化成本只在
// 拉取路径；三个计数器分次原子读，读间数值可能不一致——近似快照，
// 读间不一致可接受。
func Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(fmt.Sprintf(
			"requests_total %d\nduration_nanos_total %d\nin_flight %d\n",
			requestsTotal.Load(), durationNanosTotal.Load(), inFlight.Load(),
		)))
	}
}
