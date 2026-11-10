package middleware

import (
	"context"
	"net/http"
	"time"

	"authloft/internal/logx"
)

// 本文件提供 Connect 域（顶层 http.ServeMux 分流链，docs/后端架构.md
// §3.1 行 241-246）的 net/http 版中间件：ServeMux 分流后 Connect 请求不再
// 经 gin 全局链，requestid / logger / metrics / origin 由本文件对 Connect
// 域等效生效。与 gin 版共用同一实现、禁止
// 复制（§3.14 同口径）：requestid/origin 共用同包纯函数，logger 共用
// logAccess（logger.go），metrics 共用 metrics.go 的同一组包级原子变量。

// RequestIDFromContext 从请求 ctx 读取链路 ID（HTTPRequestID 写入；未写入
// 返回空串）。gin 版 RequestID 同样经 logx.WithRequestID 注入标准 ctx，
// 两域共用唯一键（下沉在 internal/logx，避免业务层依赖 middleware）；
// 保留本导出函数供 connect 错误包装 / HTTPLogger 消费。
func RequestIDFromContext(ctx context.Context) string {
	return logx.RequestID(ctx)
}

// HTTPRequestID http 版链路 ID 中间件（§3.3 行 302 requestid 职责的
// net/http 形态，Connect 域等效）：生成口径与 gin 版共用 newRequestID
// （crypto/rand 16 字节 hex，不读不透传入站头，失败留空不伪造）；
// X-Request-Id 在入口即写响应头（所有响应统一回写——
// origin 403 / connect 错误响应均携带）；id 非空时注入 r.Context()
// 供 connect 错误包装 / 日志读取（§3.3 行 302）。
func HTTPRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		if id != "" {
			r = r.WithContext(logx.WithRequestID(r.Context(), id))
		}
		w.Header().Set(XRequestIDHeader, id)
		next.ServeHTTP(w, r)
	})
}

// HTTPOrigin http 版 Origin/CSRF 中间件（§3.3 行 299 origin 职责的
// net/http 形态，Connect 域等效）：校验逻辑与 gin 版 Origin 共用同包
// 纯函数（requestOriginAllowed / isWriteMethod / isOriginExemptPath），
// 免检组与写方法口径一致；跨站 403 出口写 Connect 错误 JSON
// permission_denied（§1.5 行 188），X-Request-Id 头由 HTTPRequestID
// 先写入。
func HTTPOrigin(rootOrigin string, refererAllowlist []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWriteMethod(r.Method) || isOriginExemptPath(r.URL.Path) || requestOriginAllowed(r, rootOrigin, refererAllowlist) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(originRejectedBody))
	})
}

// HTTPLogger http 版访问日志中间件（§3.3 行 302 logger 职责的 net/http
// 形态，Connect 域等效）：字段口径与 gin 版 Logger 完全一致——共用
// 同包 logAccess（request_id / method / path / status / latency，无
// body / query / 头读取）；request_id 取 HTTPRequestID 注入的 ctx 值
//（RequestIDFromContext，须挂在其内层才非空）。
//
// 最终状态码经 statusWriter 捕获：net/http 的 ResponseWriter 没有状态
// 读取出口（gin.ResponseWriter 自带 Status()，故 gin 版不包装 writer），
// 包装是框架能力差异的最小必要补偿——只记录首次状态，不缓冲 body、
// 不触碰头（§3.1 行 246 分流链禁 body-capture 的语义不受影响）。
//
// panic 语义与 gin 版一致：本层不用 defer，handler panic 时访问日志不
// 输出（unwind 只触发 HTTPMetrics 的 defer 计数）；Connect 域的 panic
// 恢复由 connect-go WithRecover 在 handler 内归一为正常返回
//（internal/connect/server.go），彼时本层照常输出访问日志。
func HTTPLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		status := sw.status
		if status == 0 {
			status = http.StatusOK // handler 未写任何响应 → 标准库隐式 200
		}
		logAccess(RequestIDFromContext(r.Context()), r.Method, r.URL.Path, status, time.Since(start))
	})
}

// HTTPMetrics http 版指标中间件（§3.3 行 302 metrics 职责的 net/http
// 形态，Connect 域等效）：与 gin 版 Metrics 复用同一组包级原子
// 变量（requestsTotal / durationNanosTotal / inFlight，metrics.go）——
// Connect 域流量同样计入 /metrics，零复制、零新指标键。热路径同口径：
// 4 次原子操作 + 2 次时钟读，无锁、无堆分配；累加放 defer，panic 经
// unwind 也计数（connect-go WithRecover 归一后的正常返回同样计数）。
func HTTPMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inFlight.Add(1)
		start := time.Now()
		defer func() {
			durationNanosTotal.Add(uint64(time.Since(start).Nanoseconds()))
			requestsTotal.Add(1)
			inFlight.Add(-1)
		}()
		next.ServeHTTP(w, r)
	})
}

// statusWriter 捕获最终状态码的最小 writer 包装（HTTPLogger 专用）：只
// 记录首次 WriteHeader 的状态码（Write 隐式 200，标准库语义），其余方法
// 经内嵌转发，不缓冲 body、不读头。
//
// Flush 必须显式转发：connect-go 对 server 流式 RPC 断言 w 实现
// http.Flusher（connect v1.21.1 protocol.go checkServerStreamsCanFlush），
// 内嵌接口不会动态透传底层的 Flusher 能力，缺显式转发会误伤流式 RPC
//（当前各域均 unary，属前瞻保真）。
type statusWriter struct {
	http.ResponseWriter
	status int // 首次 WriteHeader 的状态码；Write 隐式 200；0 = 未写过
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK // 标准库语义：首个 Write 隐式 WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
