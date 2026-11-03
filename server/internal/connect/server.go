// server.go 是 Connect 域的 HTTP 装配层（docs/后端架构.md §3.14 行 474）：
// 收集各域生成的 connect handler（protoc-gen-connect-go 产出的
// (mountPath, http.Handler) 对），经 Routes 交装配层按路径
// 前缀挂入顶层 http.ServeMux（§3.1 行 243 分流口径：页面 / 静态 / OIDC /
// gateway 等 gin 路由不经本层；未注册路径由顶层 "/" → gin 原生 404 兜底，
// 不再经 gin.NoRoute 桥——此前 serveError 404 残留缺陷随之结构性
// 消除：connect 成功响应直接由生成 handler 写出，无预置状态码）。
//
// 传输与编解码、请求体上限、Content-Type 校验均由 connect-go 框架承担
// （§1.6 行 82-87）；本文件只做路由收集与拦截链组装，不含业务逻辑。
package connect

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"
)

// defaultReadMaxBytes 请求体上限默认值（§1.6 行 86：1 MiB；超限由框架返回
// resource_exhausted）。
const defaultReadMaxBytes = 1 << 20

// Route 一条顶层挂载项（装配层 buildHandler 消费，§3.1 行 243）：Prefix
// 为生成物返回的挂载前缀（形如 "/api.sso.v1.SsoService/"，尾斜杠——顶层
// http.ServeMux 的前缀模式，不改写请求路径，handler 内部按完整 procedure
// 分发）；Handler 已含域拦截链（HandlerOptions）与 rpc 域的 CaptureRawBody
// 包装。
type Route struct {
	Prefix  string
	Handler http.Handler
}

// Server Connect 域的路由收集器与装配参数。readMaxBytes 经构造函数由装配层
// （bootstrap）注入（§3.14 行 486：包自身不读 config）。
type Server struct {
	routes       []Route
	readMaxBytes int
}

// NewServer 构造 Connect 装配层。readMaxBytes 为请求体上限（§1.6 行 86），
// n <= 0 时回落默认 1 MiB。
func NewServer(readMaxBytes int) *Server {
	if readMaxBytes <= 0 {
		readMaxBytes = defaultReadMaxBytes
	}
	return &Server{readMaxBytes: readMaxBytes}
}

// Routes 返回全部已注册路由（装配层按前缀挂顶层 http.ServeMux 用，
// §3.1 行 243；注册序保留，重复前缀由顶层 mux 自行冲突检测）。
func (s *Server) Routes() []Route { return s.routes }

// HandlerOptions 返回注册某域 connect handler（gen.NewXxxServiceHandler）
// 时的公共选项：请求体上限（WithReadMaxBytes，§1.6 行 86）+ panic 归一
// （WithRecover，最外层）+ 拦截链。
//
// WithRecover 是 §3.3 行 302「recover 最外层兜住全链 panic」对 Connect
// 域的等效（ServeMux 分流后 Connect 请求不经 gin 全局链的 Recover）：
// connect-go 内建选项，handler / 拦截器 panic 归一为 internal 错误，
// 不透出 panic 值（消毒口径同 middleware/recover.go）。
//
// interceptors 按外→内传入（connect-go WithInterceptors 保持同序、先传的
// 在外层）：session 应在最外（interceptors.go 行 67 口径）、admin 在其内；
// 错误包装由本函数固定补在最内层——§3.14 行 473「错误包装 interceptor
// （最内层）……先看到 handler 的错误」，使 handler 返回的裸错误先被消毒
// 成 internal、外层域拦截器只可能见到 connect.Error。
func (s *Server) HandlerOptions(interceptors ...connect.Interceptor) []connect.HandlerOption {
	return []connect.HandlerOption{
		connect.WithReadMaxBytes(s.readMaxBytes),
		connect.WithRecover(recoverToInternal),
		connect.WithInterceptors(append(interceptors, NewErrorWrapperInterceptor())...),
	}
}

// recoverToInternal handler / 拦截器 panic 的归一出口（WithRecover 的
// handle，connect@v1.21.1 option.go 行 153）：转 internal 错误，错误消息
// 为固定安全文案——panic 值可能携带敏感数据，不进错误也不落日志。
func recoverToInternal(context.Context, connect.Spec, http.Header, any) error {
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}

// Register 注册一个域的 connect handler。mountPath 为生成物返回值（形如
// "/api.sso.v1.SsoService/"，尾斜杠前缀匹配；ServeMux 不改写路径，handler
// 内部按完整 procedure 分发）。
func (s *Server) Register(mountPath string, h http.Handler) {
	s.routes = append(s.routes, Route{Prefix: mountPath, Handler: h})
}

// RegisterRPC 注册 rpc 域 connect handler：强制包 CaptureRawBody（本包
// interceptors.go 行 194-206：rpc HMAC 拦截器需要 ctx 中的原始请求体字节，
// 装配层漏挂时拦截器按 internal fail-closed）。
func (s *Server) RegisterRPC(mountPath string, h http.Handler) {
	s.routes = append(s.routes, Route{Prefix: mountPath, Handler: CaptureRawBody(h)})
}
