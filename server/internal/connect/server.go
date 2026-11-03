// server.go 是 Connect 域的 HTTP 装配层（docs/后端架构.md §3.14 行 472）：
// 注册各域生成的 connect handler（protoc-gen-connect-go 产出的
// (mountPath, http.Handler) 对，按域注册），并作为 gin.NoRoute 的兜底
// http.Handler 接管 /api.<域>.v1.<XxxService>/<Method> 形态路径（§3.3 行
// 296；页面 / 静态 / OIDC / gateway 等 gin 路由先注册则优先匹配，不进本层）。
//
// 传输与编解码、请求体上限、Content-Type 校验均由 connect-go 框架承担
// （§1.6 行 82-87）；本文件只做挂载与拦截链组装，不含业务逻辑。
package connect

import (
	"net/http"
	"strings"

	"connectrpc.com/connect"
)

// defaultReadMaxBytes 请求体上限默认值（§1.6 行 86：1 MiB；超限由框架返回
// resource_exhausted）。
const defaultReadMaxBytes = 1 << 20

// Server Connect 域的 mux 与装配参数。readMaxBytes 经构造函数由装配层
// （bootstrap）注入（§3.14 行 478：包自身不读 config）。
type Server struct {
	mux          *http.ServeMux
	readMaxBytes int
}

// NewServer 构造 Connect 装配层。readMaxBytes 为请求体上限（§1.6 行 86），
// n <= 0 时回落默认 1 MiB。
func NewServer(readMaxBytes int) *Server {
	if readMaxBytes <= 0 {
		readMaxBytes = defaultReadMaxBytes
	}
	mux := http.NewServeMux()
	// 兜底 "/"：完全未注册的 connect 形态路径（无框架 handler 可生成响应）
	// 由装配层直写 Connect 错误形态 404（§1.5 行 184-211 的 JSON 形态）。
	// 已注册 service 前缀下未知 method 的 404 由生成 handler 自身产生。
	mux.HandleFunc("/", writeNotFound)
	return &Server{mux: mux, readMaxBytes: readMaxBytes}
}

// HandlerOptions 返回注册某域 connect handler（gen.NewXxxServiceHandler）
// 时的公共选项：请求体上限（WithReadMaxBytes，§1.6 行 86）+ 拦截链。
//
// interceptors 按外→内传入（connect-go WithInterceptors 保持同序、先传的
// 在外层）：session 应在最外（interceptors.go 行 67 口径）、admin 在其内；
// 错误包装由本函数固定补在最内层——§3.14 行 473「错误包装 interceptor
// （最内层）……先看到 handler 的错误」，使 handler 返回的裸错误先被消毒
// 成 internal、外层域拦截器只可能见到 connect.Error。
func (s *Server) HandlerOptions(interceptors ...connect.Interceptor) []connect.HandlerOption {
	return []connect.HandlerOption{
		connect.WithReadMaxBytes(s.readMaxBytes),
		connect.WithInterceptors(append(interceptors, NewErrorWrapperInterceptor())...),
	}
}

// Register 注册一个域的 connect handler。mountPath 为生成物返回值（形如
// "/api.sso.v1.SsoService/"，尾斜杠前缀匹配；ServeMux 不改写路径，handler
// 内部按完整 procedure 分发）。
func (s *Server) Register(mountPath string, h http.Handler) {
	s.mux.Handle(mountPath, h)
}

// RegisterRPC 注册 rpc 域 connect handler：强制包 CaptureRawBody（本包
// interceptors.go 行 194-206：rpc HMAC 拦截器需要 ctx 中的原始请求体字节，
// 装配层漏挂时拦截器按 internal fail-closed）。
func (s *Server) RegisterRPC(mountPath string, h http.Handler) {
	s.mux.Handle(mountPath, CaptureRawBody(h))
}

// ServeHTTP 实现 http.Handler（gin.NoRoute 兜底入口，§3.3 行 296）：
// connect 形态路径进 mux（未注册 → 404 Connect 错误体）；其余路径保持
// gin 原生 404 空体形态。
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isConnectPath(r.URL.Path) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// isConnectPath 判定 Connect 路径形态 /api.<域>.v1.<XxxService>/<Method>
// （§1.6 行 84、接口文档 §1.0 行 55）：首段以 /api. 起、服务段含 .v1.、
// 且有非空方法段。OIDC / gateway 等 REST 豁免路径（/api/oidc/** 等）天然
// 不含 "/api." 点分前缀，不受本判定影响。
func isConnectPath(path string) bool {
	if !strings.HasPrefix(path, "/api.") {
		return false
	}
	svc, method, ok := strings.Cut(strings.TrimPrefix(path, "/api."), "/")
	return ok && method != "" && strings.Contains(svc, ".v1.")
}

// notFoundBody 未注册路径的 404 错误体：Connect 错误 JSON 形态
// （§1.5 行 199-211；无 ErrorInfo detail，not_found 归标准码语义）。
const notFoundBody = `{"code":"not_found","message":"no handler registered"}`

// writeNotFound 写未注册 connect 路径的 404 错误响应（JSON 编码，§1.5）。
func writeNotFound(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(notFoundBody))
}
