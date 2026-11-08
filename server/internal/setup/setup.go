// Package setup 提供安装模式的 HTTP 服务（docs/后端架构.md §3.15、
// docs/接口文档.md §13）。
//
// 仅 setup 模式（配置文件不存在，bootstrap 判定）下存活：
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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/gin-gonic/gin"

	"authloft/assets"
	setupv1 "authloft/gen/go/api/setup/v1"
	"authloft/gen/go/api/setup/v1/setupv1connect"
	"authloft/internal/config"
	authloftconnect "authloft/internal/connect"
	"authloft/internal/middleware"
	"authloft/internal/pages"
)

// 监听（§3.1 行 247 / §3.15）：setup 模式同样读 server 段
// 环境变量（AUTHLOFT_SERVER_LISTEN / MIN_TLS_VERSION / CERT_FILE /
// KEY_FILE），只读 server 段、其他段不读；无 config.yaml 可加载，server 段
// 取值 = §3.2 默认值（listen :8080）+ env 覆盖（config.DefaultServerConfig）；
// 监听 / TLS 模式与生产同口径（config.ConfigureHTTPServer）。
const (
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
// （§3.14 行 481）。日志侧经 redact 脱敏；Err 为 nil 的纯业务失败（如
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
// handler 为顶层分流入口（§3.1 行 243：http.ServeMux——SetupService 前缀
// 挂 connect 链，其余全部交给 gin engine）。
type Server struct {
	configPath string
	router     *gin.Engine
	handler    http.Handler
	exitOnce   sync.Once
	exited     chan struct{}
}

// NewServer 构造 setup server 并注册全部路由（仅 setup 模式使用）。
// gin engine 链：recover 最外层 → requestid（页面响应回写 X-Request-Id 头）
// → CSP（阶段 C：每请求 nonce 写 ctx + 输出终稿基线 CSP 响应
// 头——setup 壳与正常模式统一基线，接口文档 §8 行 1521；
// handleSetupPage 经 pages.RenderGinShell 消费 ctx nonce）；不挂 origin——
// 安装期无 rootOrigin 可配（首次部署可能经 IP 访问），§13 响应恒为 Connect
// JSON。
//
// SetupService 经 internal/connect 装配（§3.14 行 480、行 489「setup 模式下
// 仅注册 SetupService」）：connect.NewServer 注入请求体上限，HandlerOptions
// 固定补 WithRecover + 错误包装 interceptor；本域无 session / admin / rpc
// HMAC 域拦截器（安装期不初始化 DB / Redis 业务链路）。顶层分流
//（§3.1 行 243）：Connect 前缀链挂 http 版 requestid（Connect 域等效——
// 不经 gin 全局链，middleware/httpmw.go；origin 同 gin 侧不挂）；其余
// 全部 mux.Handle("/", ginEngine)——未注册路径 gin 原生 404 兜底
// （不再经 gin.NoRoute 桥，connect 成功响应直接由
// 生成 handler 写出，无预置状态码）；/assets/** 静态资源同层挂载
// （§3.13 行 484：正常 / setup 两模式恒在）。
func NewServer(configPath string) *Server {
	s := &Server{
		configPath: configPath,
		exited:     make(chan struct{}),
	}
	r := gin.New()
	r.Use(middleware.Recover(), middleware.RequestID(), middleware.CSP())
	r.GET("/setup", s.handleSetupPage)
	s.router = r

	csrv := authloftconnect.NewServer(maxSetupBody)
	mount, handler := setupv1connect.NewSetupServiceHandler(s, csrv.HandlerOptions()...)
	csrv.Register(mount, handler)

	mux := http.NewServeMux()
	mux.Handle("/", r)
	for _, rt := range csrv.Routes() {
		mux.Handle(rt.Prefix, middleware.HTTPRequestID(rt.Handler))
	}
	// /assets/** 静态资源（§3.13 行 484：正常 / setup 两模式恒在——setup
	// 壳模板引用的前端构建产物同样由此供给，无 config.yaml 也必须可达；
	// 无鉴权、不进 gin 全局链，也不套 Connect 前缀中间件链）。
	assets.Register(mux)
	s.handler = mux
	return s
}

// Router 返回顶层分流 handler（setup_db_test 经它发请求；页面与未注册
// 路径走 gin、Connect 请求走 mux 前缀链，§3.1 行 243）。
func (s *Server) Router() http.Handler { return s.handler }

// Run 阻塞运行 setup server。监听取 server 段 env（§3.15：默认值 + env
// 覆盖，只读 server 段——config.DefaultServerConfig；非法 env / 单边 cert /
// 不可读路径在此 fail-fast）；监听 / TLS 模式与生产同口径（§3.1 行 244：
// 未配 cert+key → HTTP/1.1 + H2C；已配 → TLS 双协议 + min_tls_version）。
// 安装成功（requestExit）→ 优雅关闭（等在途响应写出）后返回 nil，run()
// 随之返回 nil、进程 exit 0（§13.4）；监听失败返回错误（fail-fast）。
func (s *Server) Run() error {
	sc, err := config.DefaultServerConfig()
	if err != nil {
		return err
	}
	srv, err := s.newHTTPServerFrom(sc)
	if err != nil {
		return err
	}
	errCh := make(chan error, 1)
	go func() {
		// 显式 net.Listen 拿真实监听地址（同 bootstrap.listenAndServe 口径），
		// 启动日志打印 ln.Addr() 真实值，不打印配置原串。
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			errCh <- err
			return
		}
		slog.Info("setup listening", "addr", ln.Addr().String())
		var serveErr error
		if sc.TLSEnabled() {
			serveErr = srv.ServeTLS(ln, sc.CertFile, sc.KeyFile)
		} else {
			serveErr = srv.Serve(ln)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
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

// newHTTPServerFrom 从 server 段构造 http.Server：监听地址与协议
// （Protocols / TLSConfig）经 config.ServerConfig.ConfigureHTTPServer 映射
// （与生产 bootstrap.newHTTPServer 同口径，§3.15）。
func (s *Server) newHTTPServerFrom(sc config.ServerConfig) (*http.Server, error) {
	srv := &http.Server{Handler: s.handler}
	if err := sc.ConfigureHTTPServer(srv); err != nil {
		return nil, err
	}
	return srv, nil
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
// 接 paths.go 的 FreshInstall（双路径状态机不动）。root 必填（字段校验在
// FreshInstall 步骤 ①，config_invalid——既定口径）；rpId 缺省
// 取 root 的 host（去 scheme 与端口），不再自动读取请求 Host（安装
// 不得靠自动推导的 IP 蒙混过关，IP rp_id 会被 WebAuthn 库校验拒绝）。
func (s *Server) Install(ctx context.Context, req *connect.Request[setupv1.InstallRequest]) (*connect.Response[setupv1.RestartingResponse], error) {
	msg := req.Msg
	if msg.DbDsn == "" || msg.RedisAddr == "" || msg.AdminUsername == "" || msg.AdminPassword == "" {
		return nil, setupParamError("db_dsn, redis_addr, admin_username and admin_password are required")
	}
	if msg.RedisDb < 0 {
		return nil, setupParamError("redis_db must be >= 0")
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
	}
	if err := FreshInstall(ctx, s.configPath, in); err != nil {
		return nil, setupFail(err)
	}
	s.requestExit()
	return connect.NewResponse(&setupv1.RestartingResponse{Restarting: true}), nil
}

// setupStaticBase setup 模式无 settings 可读，static_base 取默认 /assets
// （§5.6 行默认值；init 注入值与占位符替换值同源）。
const setupStaticBase = "/assets"

// setupInit __AUTHLOFT_INIT__ 注入体（§8 行 1534-1541 白名单中 setup entry
// 适用键：al_root / static_base；不注入 methods——安装态无业务配置，
// 前端架构 §6b）。
type setupInit struct {
	ALRoot     string `json:"al_root"`
	StaticBase string `json:"static_base"`
}

// handleSetupPage GET /setup：渲染安装页空壳——复用 pages.RenderGinShell
// 统一渲染入口（阶段 C：读嵌入模板 templates/setup.html + 三
// 占位符纯字符串全量替换；CSP 头与 nonce 由 gin 链上的 middleware.CSP
// 输出，setup 壳与正常模式同基线，§8 行 1521）。
//
// al_root 数据源（如实报告不粉饰）：setup 模式无 config.yaml
// （root 必填要等安装表单提交才落 config），后端无 al_root 数据
// 源，且按既定契约不自动读请求 Host——注入空串，不自造值。前端
// bootstrap 对空 al_root 有 location.origin 回落（web/src/setup/bootstrap.ts
// normalizeAlRoot，前端架构 §6b），跳 /sso/login 的目标即当前站点，语义
// 与读 Host 等价且由浏览器自身判定（优于服务端 XFP→TLS→明文推测）。
// 若改判（如恢复读 Host），只动本函数一处。
func (s *Server) handleSetupPage(c *gin.Context) {
	pages.RenderGinShell(c, "setup", setupInit{StaticBase: setupStaticBase}, setupStaticBase)
}
