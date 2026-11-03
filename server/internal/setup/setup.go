// Package setup 提供安装模式的 HTTP 服务（docs/后端架构.md §3.15、
// docs/接口文档.md §13）。
//
// 仅 setup 模式（configs/config.yaml 不存在，bootstrap 判定）下存活：
// 不加载 config、不初始化 DB / Redis、不挂业务链路；HTTP 侧只暴露 /setup
// 空壳页与 /api/setup/**（status / config / install）。config 写入并重启
// 后永久退出（正常模式下这些路由不注册，请求 404）。
//
// 重启机制（§3.15 安装决策）：两条路径成功（响应 restarting:true 已完整
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
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"authloft/internal/middleware"
)

// listen 与超时：setup 模式不加载 config，监听地址文档未规定（缺口已报），
// 取 §3.2 默认值 :8080 与 30s 读写超时（与 config.yaml.example 同源）。
const (
	setupListen       = ":8080"
	setupReadTimeout  = 30 * time.Second
	setupWriteTimeout = 30 * time.Second
	// shutdownGrace 响应写出后优雅关闭的等待上限（在途响应 flush 完毕
	// 即返回，restart 语义不靠拉长该值）。
	shutdownGrace = 3 * time.Second
	// maxSetupBody 请求体上限（与 connect 域默认 1 MiB 一致，docs/后端架构.md
	// §1.6 行 86；上传 config 全文与安装表单均远小于此）。
	maxSetupBody = 1 << 20
)

// 框架层错误码（setup 域原生 JSON 过渡形态的取值，原 codec 常量原值接管；
// setup 域 Connect 化后改走 connect.NewError，届时废弃）。
const (
	setupCodeBadRequest           = "bad_request"
	setupCodeUnsupportedMediaType = "unsupported_media_type"
	setupCodeInternalError        = "internal_error"
)

// setupErrorObj / setupErrorBody 原生 JSON 错误信封（编译救活的最小改造：
// 形态为旧信封 JSON 的字节级保留、编码不再经 codec；键序同旧 protojson
// 字段号序。错误体暂保留 request_id 字段以维持 setup entry 前端零改动，
// 后续统一按 §1.5 行 223 移除——request_id 届时只走 X-Request-Id 响应头）。
type setupErrorObj struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type setupErrorBody struct {
	Status string        `json:"status"`
	Error  setupErrorObj `json:"error"`
}

// writeSetupError 直写原生 JSON 错误体（不依赖 codec）：HTTP status 由调用方
// 给定（框架错误非 200；PathError 业务失败经 writePathError 恒 200，§13）。
func writeSetupError(c *gin.Context, status int, code, message string) {
	body, err := json.Marshal(setupErrorBody{
		Status: "error",
		Error: setupErrorObj{
			Code:      code,
			Message:   message,
			RequestID: c.GetString(middleware.RequestIDKey),
		},
	})
	if err != nil { // 全字符串字段的 Marshal，实际不可达
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Data(status, "application/json; charset=utf-8", body)
}

// Server 安装模式 HTTP 服务。
type Server struct {
	configPath string
	router     *gin.Engine
	exitOnce   sync.Once
	exited     chan struct{}
}

// NewServer 构造 setup server 并注册全部路由（仅 setup 模式使用）。
// 中间件链：recover 最外层 → requestid（所有响应回写 X-Request-Id 头，
// 过渡期错误信封亦携带 request_id）；不挂 origin——安装期无 rootOrigin
// 可配（首次部署可能经 IP 访问），§13 响应恒为 JSON。
func NewServer(configPath string) *Server {
	s := &Server{
		configPath: configPath,
		exited:     make(chan struct{}),
	}
	r := gin.New()
	r.Use(middleware.Recover(), middleware.RequestID())
	r.GET("/setup", s.handleSetupPage)
	api := r.Group("/api/setup")
	api.GET("/status", s.handleStatus)
	api.POST("/config", s.handleConfig)
	api.POST("/install", s.handleInstall)
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

// configRequest POST /api/setup/config 请求体（接口文档 §13.2）。
type configRequest struct {
	Config string `json:"config"`
}

// installRequest POST /api/setup/install 请求体（接口文档 §13.3）。
type installRequest struct {
	DBDSN         string `json:"db_dsn"`
	RedisAddr     string `json:"redis_addr"`
	RedisPassword string `json:"redis_password"`
	RedisDB       int    `json:"redis_db"`
	Root          string `json:"root"`
	RpID          string `json:"rp_id"`
	AdminUsername string `json:"admin_username"`
	AdminPassword string `json:"admin_password"`
}

// handleStatus GET /api/setup/status（§13.1）：模式判定 + 前端重启轮询锚点
//（连接被拒 / 404 = 已处于正常模式）。
func (s *Server) handleStatus(c *gin.Context) {
	writeSetupJSON(c, http.StatusOK, `{"status":"success","mode":"setup"}`)
}

// handleConfig POST /api/setup/config：路径 A 上传已有 config（§13.2）。
func (s *Server) handleConfig(c *gin.Context) {
	var req configRequest
	if !bindSetupJSON(c, &req) {
		return
	}
	if strings.TrimSpace(req.Config) == "" {
		writeSetupError(c, http.StatusBadRequest, setupCodeBadRequest, "config is required")
		return
	}
	if err := UploadConfig(c.Request.Context(), s.configPath, req.Config); err != nil {
		writePathError(c, err)
		return
	}
	writeRestarting(c)
	s.requestExit()
}

// handleInstall POST /api/setup/install：路径 B 全新安装（§13.3）。
func (s *Server) handleInstall(c *gin.Context) {
	var req installRequest
	if !bindSetupJSON(c, &req) {
		return
	}
	if req.DBDSN == "" || req.RedisAddr == "" || req.AdminUsername == "" || req.AdminPassword == "" {
		writeSetupError(c, http.StatusBadRequest, setupCodeBadRequest, "db_dsn, redis_addr, admin_username and admin_password are required")
		return
	}
	if req.RedisDB < 0 {
		writeSetupError(c, http.StatusBadRequest, setupCodeBadRequest, "redis_db must be >= 0")
		return
	}
	if c.Request.Host == "" {
		writeSetupError(c, http.StatusBadRequest, setupCodeBadRequest, "missing Host header")
		return
	}
	in := InstallInput{
		DBDSN:         req.DBDSN,
		RedisAddr:     req.RedisAddr,
		RedisPassword: req.RedisPassword,
		RedisDB:       req.RedisDB,
		Root:          req.Root,
		RpID:          req.RpID,
		AdminUsername: req.AdminUsername,
		AdminPassword: req.AdminPassword,
		Host:          c.Request.Host,
	}
	if err := FreshInstall(c.Request.Context(), s.configPath, in); err != nil {
		writePathError(c, err)
		return
	}
	writeRestarting(c)
	s.requestExit()
}

// writePathError 把安装路径错误写成原生 JSON 信封：*PathError（§13 域码）→
// HTTP 200 + status:"error" 业务信封（writeSetupError，不经 codec，
// Connect 化时改 connect.NewError + ErrorInfo detail）；其余（写盘失败
// 等服务端故障）→ 500 internal_error（§1.5 框架码）。日志侧经 redact 脱敏；
// Err 为 nil 的纯业务失败（如 admin_missing）只记 code。
func writePathError(c *gin.Context, err error) {
	var pe *PathError
	if !errors.As(err, &pe) {
		slog.Error("setup: unexpected failure", "err", redact(err.Error()))
		writeSetupError(c, http.StatusInternalServerError, setupCodeInternalError, "internal error")
		return
	}
	if pe.Err != nil {
		slog.Error("setup: step failed", "code", pe.Code, "err", redact(pe.Err.Error()))
	} else {
		slog.Error("setup: step failed", "code", pe.Code)
	}
	writeSetupError(c, http.StatusOK, pe.Code, pe.Message)
}

// writeRestarting 成功响应（§13.2 / §13.3）：{"status":"success","restarting":true}。
func writeRestarting(c *gin.Context) {
	writeSetupJSON(c, http.StatusOK, `{"status":"success","restarting":true}`)
}

// writeSetupJSON 写 setup 域的固定 JSON 响应（域内无 proto 消息——
// server/proto 未定义 setup 域，body 为固定常量，与 §1.0 信封字节一致）。
func writeSetupJSON(c *gin.Context, status int, body string) {
	c.Header("Content-Type", "application/json; charset=utf-8")
	c.String(status, body)
}

// bindSetupJSON 解码 JSON 请求体（§1.5 参数类错误）：Content-Type 非
// application/json → 415；空体 / 非法 JSON → 400。返回是否可继续。
func bindSetupJSON(c *gin.Context, req any) bool {
	ct := c.GetHeader("Content-Type")
	if mediaType, _, err := mime.ParseMediaType(ct); err != nil || mediaType != "application/json" {
		writeSetupError(c, http.StatusUnsupportedMediaType, setupCodeUnsupportedMediaType, "unsupported media type")
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxSetupBody))
	if err != nil {
		writeSetupError(c, http.StatusBadRequest, setupCodeBadRequest, "invalid request body")
		return false
	}
	if len(body) == 0 {
		writeSetupError(c, http.StatusBadRequest, setupCodeBadRequest, "empty request body")
		return false
	}
	if err := json.Unmarshal(body, req); err != nil {
		writeSetupError(c, http.StatusBadRequest, setupCodeBadRequest, "invalid request body")
		return false
	}
	return true
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
func (s *Server) handleSetupPage(c *gin.Context) {
	nonce, err := genNonce()
	if err != nil {
		slog.Error("setup: gen nonce", "err", err)
		writeSetupError(c, http.StatusInternalServerError, setupCodeInternalError, "internal error")
		return
	}
	init, err := json.Marshal(map[string]string{
		"al_root":     "https://" + c.Request.Host,
		"static_base": "/assets",
	})
	if err != nil {
		writeSetupError(c, http.StatusInternalServerError, setupCodeInternalError, "internal error")
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
