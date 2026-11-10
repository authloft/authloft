// Package logx 是全局结构化日志（标准库 log/slog）的唯一装配点与业务侧
// 日志入口（docs/后端架构.md §3.2 日志配置、§3.3 行 294 链路 ID 约束）。
//
// 分层约定：
//   - 本包不引入 net/http / gin / middleware：链路 ID 的 ctx 键与读写下沉
//     到这里，middleware 只负责生成并注入，service / handler 只依赖本包，
//     避免业务层反向依赖 HTTP 层，gin 域与 Connect 域共用同一口径；
//   - request_id 由 requestIDHandler 在 Handle 时从 ctx 自动补入记录，因此
//     任何 slog 的 ...Context 调用（含既有代码）都会带链路 ID，业务侧无需
//     每次手写 "request_id"；
//   - 不带 ctx 的 slog.Info / slog.Warn 不走自动注入，访问日志 / panic 日志
//     仍由 middleware 显式传字段（同一字段口径，不会重复）。
package logx

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// requestIDField 日志中链路 ID 的统一字段名（与 middleware/logger.go 的
// access 日志、recover.go 的 panic 日志同口径）。
const requestIDField = "request_id"

// requestIDKey 是链路 ID 在标准 context.Context 中的键；两域中间件写入，
// requestIDHandler / RequestID 读取。
type requestIDKey struct{}

// WithRequestID 把链路 ID 放进标准 context.Context（中间件入口调用）。
// 空 id 原样返回 ctx：rand 失败留空串、不伪造值（§3.3 行 294）。
func WithRequestID(ctx context.Context, id string) context.Context {
	if ctx == nil || id == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID 从 ctx 读链路 ID；未注入（或 ctx 为 nil）返回空串。
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// Setup 按启动配置装配全局 slog logger。level ∈ debug|info|warn|error、
// format ∈ json|text；空串或未知值回退默认 info/json（正式配置由
// config.Validate 保证合法；setup 模式与配置加载失败路径传空串走默认值）。
// 启动期一次调用，运行期不可变（§3.2：日志属 YAML 启动配置，不热更新）。
func Setup(level, format string) {
	slog.SetDefault(slog.New(NewHandler(os.Stderr, level, format)))
}

// NewHandler 构造带 request_id 自动注入的 slog.Handler（导出便于测试用
// bytes.Buffer 捕获输出）。配置只影响级别与格式，输出目的地由 w 决定。
func NewHandler(w io.Writer, level, format string) slog.Handler {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var base slog.Handler
	if format == "text" {
		base = slog.NewTextHandler(w, opts)
	} else {
		base = slog.NewJSONHandler(w, opts)
	}
	return &requestIDHandler{Handler: base}
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// requestIDHandler 在每条携带 ctx 的日志记录上补 request_id。
// Handle 前 Clone 记录再 AddAttrs，避免改写上游共享的 Record；
// WithAttrs / WithGroup 保留包装，logger.With(...) 派生后注入仍生效
//（项目当前不用 WithGroup；若将来启用，该字段按 slog 语义随 handler
// 的 group 状态落入组内）。Enabled 由嵌入的 slog.Handler 转发。
type requestIDHandler struct {
	slog.Handler
}

func (h *requestIDHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := RequestID(ctx); id != "" {
		r = r.Clone()
		r.AddAttrs(slog.String(requestIDField, id))
	}
	return h.Handler.Handle(ctx, r)
}

func (h *requestIDHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &requestIDHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *requestIDHandler) WithGroup(name string) slog.Handler {
	return &requestIDHandler{Handler: h.Handler.WithGroup(name)}
}

// logger 返回当前全局 logger。正常装配下 requestIDHandler 会自动注入
// request_id；若外部（如测试）用 slog.SetDefault 换成了裸 handler，则
// 显式 With 兜底，保证便捷函数的字段契约不依赖装配顺序。
func logger(ctx context.Context) *slog.Logger {
	l := slog.Default()
	if _, ok := l.Handler().(*requestIDHandler); ok {
		return l
	}
	if id := RequestID(ctx); id != "" {
		return l.With(slog.String(requestIDField, id))
	}
	return l
}

// Debug / Info / Warn / Error 是 service / handler 层的日志入口：等价于
// slog.Default().XxxContext(ctx, ...)，但保证带 request_id。用它们替代
// 无 ctx 的 slog.Warn / slog.Info 即可获得链路关联能力。
//
// 敏感信息约束不变（docs/CODE_GUIDE.md §3.2 第 7 条、§3.7）：不得打印
// login_token、session_token、验证码、密钥、完整手机号 / 邮箱。
func Debug(ctx context.Context, msg string, args ...any) {
	logger(ctx).DebugContext(ctx, msg, args...)
}

func Info(ctx context.Context, msg string, args ...any) {
	logger(ctx).InfoContext(ctx, msg, args...)
}

func Warn(ctx context.Context, msg string, args ...any) {
	logger(ctx).WarnContext(ctx, msg, args...)
}

func Error(ctx context.Context, msg string, args ...any) {
	logger(ctx).ErrorContext(ctx, msg, args...)
}
