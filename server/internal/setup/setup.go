// Package setup 提供安装模式的 HTTP 服务（docs/后端架构.md §3.15、
// docs/接口文档.md §13）。
//
// 仅 setup 模式（configs/config.yaml 不存在，bootstrap 判定）下存活：
// 不加载 config、不初始化 DB / Redis、不挂业务链路；HTTP 侧只暴露 /setup
// 空壳页与 SetupService connect handler（/api/setup/** REST 三条路由
// 删除，Connect 路径 /api.setup.v1.SetupService/<Method>，§13 行 1759）。
// config 写入并重启后永久退出（正常模式下不注册，请求一律 404）。
//
// 重启机制（§3.15 安装决策）：两条路径成功（restarting:true 响应已完整
// 写出）后进程正常退出（exit 0），由 supervisor / Docker restart policy
// 拉起，不做 self-exec。
package setup

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/gin-gonic/gin"

	setupv1 "authloft/gen/go/api/setup/v1"
	"authloft/gen/go/api/setup/v1/setupv1connect"
	authloftconnect "authloft/internal/connect"
	"authloft/internal/middleware"
)

// listen 与超时：setup 模式不加载 config，监听地址文档未规定（缺口待定），
// 取 §3.2 默认值 :8080 与 30s 读写超时（与 config.yaml.example 同源）。
const (
	setupListen       = ":8080"
	setupReadTimeout  = 30 * time.Second
	setupWriteTimeout = 30 * time.Second
	// shutdownGrace 响应写出后优雅关闭的等待上限（在途响应 flush 完毕
	// 即返回，restart 语义不靠拉长该值）。
	shutdownGrace = 3 * time.Second
	// maxSetupBody Connect 请求体上限（与生产装配默认一致，docs/后端架构.md
	// §1.6 行 86；经 connect.NewServer → WithReadMaxBytes 注入，上传 config
	// 全文与安装表单均远小于此）。
	maxSetupBody = 1 << 20
)

// setupDomain ErrorInfo.domain 取值（接口文档 §1.5 行 217 封闭集）。
const setupDomain = "setup"

// codeInvalidRequest 参数缺失 / 格式错误的 ErrorInfo.code（接口文档 §1.6
// 行 245「参数缺失 / 格式错误」；呈现位置二：非登录域作 ErrorInfo.code，
// §1.6 行 267）。
const codeInvalidRequest = "invalid_request"

// setupCodeFor 把 §13 域内错误码映射为 Connect 标准码（§1.5 行 184-193
// 映射表口径；域码语义不变，由 ErrorInfo.code 承载，§13 行 1761）：
//   - 用户输入不合规（config_invalid / username_invalid / password_weak）→
//     invalid_argument（HTTP 400，§1.5 行 186「字段缺失 / 类型不符」）；
//   - 外部依赖不可达（db_unreachable / redis_unreachable）→ unavailable
//     （HTTP 503，§1.5 行 193）；
//   - 迁移失败（migration_failed）→ internal（HTTP 500，服务端自身故障，
//     细节只进日志）；
//   - 状态前置不满足（admin_missing——版本已最新但管理员缺失，提示改走
//     全新安装）→ failed_precondition（HTTP 400）；
//   - 其余 / 未知 → internal 兜底（不透出细节，§1.5 行 192）。
func setupCodeFor(code string) connect.Code {
	switch code {
	case CodeConfigInvalid, CodeUsernameInvalid, CodePasswordWeak:
		return connect.CodeInvalidArgument
	case CodeDBUnreachable, CodeRedisUnreachable:
		return connect.CodeUnavailable
	case CodeAdminMissing:
		return connect.CodeFailedPrecondition
	case CodeMigrationFailed:
		return connect.CodeInternal
	default:
		return connect.CodeInternal
	}
}

// setupFail 把安装路径错误转为 Connect 错误体出口（取代原
// writePathError 直写原生 JSON）：*PathError（§13 域码）→
// connect.NewError(标准码) + ErrorInfo detail（domain=setup、code=域码、
// message=固定安全文案，§1.5 行 197-224）；其余（写盘失败等服务端故障）
// 记日志后原样返回——错误包装 interceptor（internal/connect，最内层）
// 把非 connect.Error 的错误包成 internal 并消毒线上文本，不透出内部细节
//（§3.14 行 481）。日志侧经 redact 脱敏；Err 为 nil 的纯业务失败（如
// admin_missing）只记 code。
func setupFail(err error) error {
	var pe *PathError
	if !errors.As(err, &pe) {
		slog.Error("setup: unexpected failure", "err", redact(err.Error()))
		return err
	}
	if pe.Err != nil {
		slog.Error("setup: step failed", "code", pe.Code, "err", redact(pe.Err.Error()))
	} else {
		slog.Error("setup: step failed", "code", pe.Code)
	}
	cerr := connect.NewError(setupCodeFor(pe.Code), errors.New(pe.Message))
	return authloftconnect.WithErrorInfo(cerr, authloftconnect.NewErrorInfo(setupDomain, pe.Code, pe.Message))
}

// setupParamError 参数缺失 / 格式错误（§13 行 1761「参数类错误仍走 §1.5」；
// §1.5 行 186 invalid_argument 场景含「字段缺失」——proto3 无法区分未设置与
// 零值，必填校验在 handler 侧）：标准码 invalid_argument（HTTP 400）+
// ErrorInfo{domain=setup, code=invalid_request}。
func setupParamError(message string) error {
	cerr := connect.NewError(connect.CodeInvalidArgument, errors.New(message))
	return authloftconnect.WithErrorInfo(cerr, authloftconnect.NewErrorInfo(setupDomain, codeInvalidRequest, message))
}

// Server 安装模式 HTTP 服务：/setup 页面 gin 路由 + SetupService connect
// handler（实现 setupv1connect.SetupServiceHandler，安装流程本体接 paths.go）。
type Server struct {
	configPath string
	router     *gin.Engine
	exitOnce   sync.Once
	exited     chan struct{}
}

// NewServer 构造 setup server 并注册全部路由（仅 setup 模式使用）。
// 中间件链：recover 最外层 → requestid（所有响应回写 X-Request-Id 头，
//）；不挂 origin——安装期无 rootOrigin 可配（首次部署可能经 IP
// 访问），§13 响应恒为 Connect JSON。
//
// SetupService 经 internal/connect 装配（§3.14 行 480、行 489「setup 模式下
// 仅注册 SetupService」）：connect.NewServer 注入请求体上限，HandlerOptions
// 固定补错误包装 interceptor 于最内层；本域无 session / admin / rpc HMAC
// 域拦截器（安装期不初始化 DB / Redis 业务链路）。connect mux 经 gin.NoRoute
// 兜底接管 /api.setup.v1.SetupService/<Method>（生产 router.go 同款桥接，
// §3.3 行 296；非 Connect 形态路径维持空体 404）。
func NewServer(configPath string) *Server {
	s := &Server{
		configPath: configPath,
		exited:     make(chan struct{}),
	}
	r := gin.New()
	r.Use(middleware.Recover(), middleware.RequestID())
	r.GET("/setup", s.handleSetupPage)

	csrv := authloftconnect.NewServer(maxSetupBody)
	mount, handler := setupv1connect.NewSetupServiceHandler(s, csrv.HandlerOptions()...)
	csrv.Register(mount, handler)
	r.NoRoute(func(c *gin.Context) {
		// gin 的 serveError 在进 NoRoute 链前已把 writermem.status 置 404
		//（gin@v1.12.0 gin.go serveError 行 764-765）；而 connect-go 的
		// unary 成功路径只写 body、不调 WriteHeader（依赖 net/http 隐式
		// 200，connect@v1.21.1 protocol_connect.go connectUnaryMarshaler.
		// write），经 gin 写出时会落成残留的 404 状态码——先把已存状态
		// 复位 200，状态码交还 connect mux 自行表达（错误路径 connect 显式
		// WriteHeader 覆盖、未注册路径仍 404）。
		c.Writer.WriteHeader(http.StatusOK)
		csrv.ServeHTTP(c.Writer, c.Request)
		// gin 的 serveError（gin v1.12.0 gin.go）对「只写了状态码、未写
		// body」的响应会追加默认 "404 page not found" body——非 connect
		// 路径的空体 404 在此强制落盘（WriteHeaderNow 为 no-op 当 mux
		// 已写出 body）。
		c.Writer.WriteHeaderNow()
	})
	s.router = r
	return s
}

// Router 返回已注册路由的 engine（测试用；正常模式不挂载本 engine）。
func (s *Server) Router() *gin.Engine { return s.router }

// Run 阻塞运行 setup server。安装成功（requestExit）→ 优雅关闭（等在途
// 响应写出）后返回 nil，run() 随之返回 nil、进程 exit 0（§13.4）；
// 监听失败返回错误（fail-fast）。
func (s *Server) Run() error {
	srv := &http.Server{
		Addr:         setupListen,
		Handler:      s.router,
		ReadTimeout:  setupReadTimeout,
		WriteTimeout: setupWriteTimeout,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case err := <-errCh:
		return err
	case <-s.exited:
		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			return fmt.Errorf("setup: graceful shutdown: %w", err)
		}
		slog.Info("setup: installation finished, exiting for restart (exit 0)")
		return nil
	}
}

// requestExit 触发安装成功后的退出（幂等；由成功响应写完的 handler 调用）。
func (s *Server) requestExit() {
	s.exitOnce.Do(func() { close(s.exited) })
}

// Exposed 返回退出信号 channel（测试断言安装成功触发退出用）。
func (s *Server) Exposed() <-chan struct{} { return s.exited }

// GetStatus 是 SetupService/GetStatus（§13.1 行 1763）：模式判定 + 前端重启
// 轮询锚点（正常返回即处于 setup 模式；连接被拒 / 404 = 已处于正常模式，
// §13.4）。本 handler 存活即处于 setup 模式，响应恒 {"mode":"setup"}。
func (s *Server) GetStatus(_ context.Context, _ *connect.Request[setupv1.GetStatusRequest]) (*connect.Response[setupv1.GetStatusResponse], error) {
	return connect.NewResponse(&setupv1.GetStatusResponse{Mode: "setup"}), nil
}

// UploadConfig 是 SetupService/UploadConfig（§13.2 行 1767）：路径 A 上传
// 已有 config，执行体接 paths.go 的 UploadConfig（双路径状态机不动）。
// 成功先触发退出（exit 0 由部署环境拉起）再返回 restarting:true——响应
// 由 connect-go 在 handler 返回后写出，Run 的优雅关闭（shutdownGrace 3s）
// 等在途响应写出后才退出（§13.4 行 1791）。
func (s *Server) UploadConfig(ctx context.Context, req *connect.Request[setupv1.UploadConfigRequest]) (*connect.Response[setupv1.RestartingResponse], error) {
	if strings.TrimSpace(req.Msg.Config) == "" {
		return nil, setupParamError("config is required")
	}
	if err := UploadConfig(ctx, s.configPath, req.Msg.Config); err != nil {
		return nil, setupFail(err)
	}
	s.requestExit()
	return connect.NewResponse(&setupv1.RestartingResponse{Restarting: true}), nil
}

// Install 是 SetupService/Install（§13.3 行 1775）：路径 B 全新安装，执行体
// 接 paths.go 的 FreshInstall（双路径状态机不动）。root / rp_id 缺省推导取
// 当前请求 Host——connect-go handler 在分发前把 r.Host 注入 request.Header
//（connect@v1.21.1 handler.go 行 317-318 setHeaderCanonical(request.Header,
// "Host", request.Host)），AnyRequest.Header() 原样暴露，无需自造 ctx 注入。
func (s *Server) Install(ctx context.Context, req *connect.Request[setupv1.InstallRequest]) (*connect.Response[setupv1.RestartingResponse], error) {
	msg := req.Msg
	if msg.DbDsn == "" || msg.RedisAddr == "" || msg.AdminUsername == "" || msg.AdminPassword == "" {
		return nil, setupParamError("db_dsn, redis_addr, admin_username and admin_password are required")
	}
	if msg.RedisDb < 0 {
		return nil, setupParamError("redis_db must be >= 0")
	}
	host := req.Header().Get("Host")
	if host == "" {
		return nil, setupParamError("missing Host header")
	}
	in := InstallInput{
		DBDSN:         msg.DbDsn,
		RedisAddr:     msg.RedisAddr,
		RedisPassword: msg.RedisPassword,
		RedisDB:       int(msg.RedisDb),
		Root:          msg.Root,
		RpID:          msg.RpId,
		AdminUsername: msg.AdminUsername,
		AdminPassword: msg.AdminPassword,
		Host:          host,
	}
	if err := FreshInstall(ctx, s.configPath, in); err != nil {
		return nil, setupFail(err)
	}
	s.requestExit()
	return connect.NewResponse(&setupv1.RestartingResponse{Restarting: true}), nil
}

// setupPageTmpl /setup 安装页 SPA 空壳（接口文档 §8 行 1398 / 1401-1403）：
// 注入 window.__AUTHLOFT_INIT__（al_root / static_base，JSON 编码默认
// <>& 转义）、引用 {static_base}/{entry}/entry.js（entry=setup，static_base
// 默认 /assets）、no-store、CSP nonce、不注入任何凭证。
// 三个 %s 依次为：inline nonce、INIT JSON、entry 脚本 nonce。
const setupPageTmpl = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authloft Setup</title>
</head>
<body>
<div id="root"></div>
<script nonce="%s">window.__AUTHLOFT_INIT__ = %s;</script>
<script nonce="%s" src="/assets/setup/entry.js"></script>
</body>
</html>
`

// handleSetupPage GET /setup：渲染安装页空壳。setup 模式无 config，al_root
// 缺省取当前请求 Host（§3.15），static_base 取默认 /assets（§8 行 1410）。
// 页面路由是 §1.5 行 225 的豁免端点（错误形态按 HTTP 语义）：构造失败直接
// 空体 500，不套 Connect 错误体。
func (s *Server) handleSetupPage(c *gin.Context) {
	nonce, err := genNonce()
	if err != nil {
		slog.Error("setup: gen nonce", "err", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	init, err := json.Marshal(map[string]string{
		"al_root":     "https://" + c.Request.Host,
		"static_base": "/assets",
	})
	if err != nil { // map[string]string 的 Marshal，实际不可达
		slog.Error("setup: marshal init", "err", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(
		fmt.Sprintf(setupPageTmpl, nonce, init, nonce),
	))
}

// genNonce 生成 CSP nonce（crypto/rand 16 字节 base64url）。
func genNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
