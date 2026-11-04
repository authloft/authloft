// bootstrap.go 按 docs/后端架构.md §3.1 行 237 的固定顺序装配启动链：
// config → DB → 迁移检查（migrate up，幂等）→ Redis → 密钥 → provider/factor
// 注册表 → settings 预热 → 队列 worker → cron → router。已落地 config /
// DB / migrate / Redis 四步，并接入五把密钥、settings 预热 + watcher、
// 队列 + 事件日志 sink 与优雅关闭；provider/factor 注册表与 cron 仍为 TODO。
//
// 启动分支（§3.1 行 253）：configs/config.yaml 不存在 → setup 模式
//——不加载 config、不初始化 DB / Redis、不起业务链路，只启动 internal/setup
//（§3.15）；存在 → 正常装配（保持既有结构）。
//
// 顶层分流与监听（§3.1 行 241-247）：标准库 http.ServeMux
// 顶层——Connect handler 按路径前缀挂 mux（requestid / logger / metrics /
// origin 等效链），其余全部交给 gin；监听由 server 段
// TLS 配置决定（Go 1.26 标准库原生 http.Server.Protocols：未配 cert+key
// → HTTP/1.1 + H2C；已配 → TLS 双协议 + min_tls_version），不引 x/net。

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"authloft/internal/asyncqueue"
	"authloft/internal/cache"
	"authloft/internal/config"
	"authloft/internal/connect"
	"authloft/internal/eventlog"
	"authloft/internal/middleware"
	"authloft/internal/migrate"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service"
	"authloft/internal/settings"
	"authloft/internal/setup"
)

// defaultReadMaxBytes Connect 域请求体上限默认值（docs/后端架构.md §1.6
// 行 86、§3.14 行 478：由装配层经 connect.NewServer 注入，包自身不读 config）。
const defaultReadMaxBytes = 1 << 20

// run 装配并阻塞运行 HTTP 服务（§3.1 行 248）。装配与运行错误原样上抛，
// 由 main 转 exit 非 0（fail-fast）；setup 模式下安装完成的退出走 Run 的
// nil 返回（exit 0，由部署环境拉起，§13.4）。
func run(configPath string) error {
	if setupMode(configPath) {
		return setup.NewServer(configPath).Run()
	}
	// 步骤 1 config：启动期一次读取 + env 覆盖 + Validate，任一失败即
	// fail-fast（§3.2 行 289）。sign_key 只在安装流程生成（§3.15），
	// 文件存在但缺项 / 非法一律 fail-fast，不自动补写（§3.2 约定 4）。
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	return serve(cfg)
}

// shutdownTimeout HTTP 优雅关闭上限（与队列 CloseTimeout 同口径 10s，§5.2
// 行 892：超时后不再等待在途请求 / 批次）。
const shutdownTimeout = 10 * time.Second

// assembled 正常模式装配产物（§3.1 行 237 启动链）：DB / Redis / 五把密钥编解码
// / settings 快照与热更新 watcher / 延迟写入队列与事件日志 sink。provider 注册表
// 与 cron 待对应包落地后补字段（§3.1 步骤 6 与 cron 仍为 TODO）。
type assembled struct {
	db       *gorm.DB
	rdb      *redis.Client
	codecs   *codecs
	settings *settings.Store
	watcher  *settings.Watcher
	queue    *asyncqueue.Queue
	sink     *service.LoginEventWriter
}

// codecs 五场景独立编解码器（§1.4 / §11.6.1）：session / login / ticket /
// cookie / sync_payload 各持一把密钥，互不复用。
type codecs struct {
	Session     *security.Codec
	Login       *security.Codec
	Ticket      *security.Codec
	Cookie      *security.Codec
	SyncPayload *security.Codec
}

// buildCodecs 把 cfg.SignKey 五把 KeyMaterial 逐把转成 security.Codec
// （§3.1 步骤 5、§1.4 / §11.6.1）。base64 解码与 kid 范围在任何一步非法即
// 返回错误，由 serve 转 fail-fast；密钥长度由 security.NewKeyStore 校验
// （AES-256 恰 32 字节）。每把独立构造 KeyStore，绝不共用。
func buildCodecs(cfg *config.Config) (*codecs, error) {
	build := func(field string, km config.KeyMaterial) (*security.Codec, error) {
		raw, err := base64.StdEncoding.DecodeString(km.Key)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: %s.key: decode base64: %w", field, err)
		}
		if km.Kid <= 0 || km.Kid > 255 {
			return nil, fmt.Errorf("bootstrap: %s.kid: must be in 1..255, got %d", field, km.Kid)
		}
		ks, err := security.NewKeyStore(security.KeyEntry{
			ID:  security.KeyID{Version: 1, Kid: byte(km.Kid)},
			Key: raw,
		})
		if err != nil {
			return nil, fmt.Errorf("bootstrap: %s: %w", field, err)
		}
		return security.NewCodec(ks), nil
	}

	var (
		c   codecs
		err error
	)
	if c.Session, err = build("sign_key.session", cfg.SignKey.Session); err != nil {
		return nil, err
	}
	if c.Login, err = build("sign_key.login", cfg.SignKey.Login); err != nil {
		return nil, err
	}
	if c.Ticket, err = build("sign_key.ticket", cfg.SignKey.Ticket); err != nil {
		return nil, err
	}
	if c.Cookie, err = build("sign_key.cookie", cfg.SignKey.Cookie); err != nil {
		return nil, err
	}
	if c.SyncPayload, err = build("sign_key.sync_payload", cfg.SignKey.SyncPayload); err != nil {
		return nil, err
	}
	return &c, nil
}

// eventLogExecutor 延迟写入队列的执行器（§5.2 行 886）：把攒批后的任务落到
// 已落地的 repo——model.EventLog 走 EventLogRepo.BatchInsert，last_login_at
// 走 UserRepo.UpdateLastLogin。执行失败只记日志（队列骨架不重试、不影响登录
// 主链路，§5.2 行 893）；真实重试策略归后续执行器卡。
type eventLogExecutor struct {
	logs  *repo.EventLogRepo
	users *repo.UserRepo
}

func (e *eventLogExecutor) Execute(ctx context.Context, tasks []asyncqueue.Task) {
	var rows []model.EventLog
	for _, task := range tasks {
		switch v := task.Value.(type) {
		case model.EventLog:
			rows = append(rows, v)
		case eventlog.LastLoginTask:
			if err := e.users.UpdateLastLogin(ctx, v.UserID, v.At); err != nil {
				slog.Warn("asyncqueue: update last_login_at failed", "user_id", v.UserID, "error", err)
			}
		}
	}
	if len(rows) == 0 {
		return
	}
	if err := e.logs.BatchInsert(ctx, rows); err != nil {
		slog.Warn("asyncqueue: batch insert event_log failed", "rows", len(rows), "error", err)
	}
}

// assemble 正常模式装配步骤 2-8（§3.1 行 237）：DB → 迁移检查（migrate up，
// 幂等——版本已最新时只读版本表秒过，§3.16 行 553-555：连上 DB 之后、
// settings 预热之前）→ Redis → 五把密钥 → settings 预热 + watcher → 队列
// worker 与事件日志 sink。provider/factor 注册表（步骤 6）与 cron 仍为 TODO。
// 任一步失败都先释放已建资源再原样上抛（serve 转 fail-fast）。
func assemble(ctx context.Context, cfg *config.Config) (*assembled, error) {
	db, err := repo.Open(cfg)
	if err != nil {
		return nil, err
	}
	if err := migrate.Up(ctx, cfg.DB.DSN); err != nil {
		closeSQLDB(db)
		return nil, err
	}
	rdb, err := cache.NewClient(ctx, cfg)
	if err != nil {
		closeSQLDB(db)
		return nil, err
	}

	deps := &assembled{db: db, rdb: rdb}

	// 步骤 5：五把 sign_key 逐把构造 KeyStore + Codec。
	if deps.codecs, err = buildCodecs(cfg); err != nil {
		deps.closeInfra()
		return nil, err
	}

	// 步骤 7：settings 全量预热（缺失键补齐，fail-fast）→ watcher 订阅热更新。
	store := settings.NewStore(repo.NewSettingsRepo(db), rdb)
	if err := store.Preload(ctx); err != nil {
		deps.closeInfra()
		return nil, err
	}
	watcher := settings.NewWatcher(rdb, store)
	if err := watcher.Start(ctx); err != nil {
		deps.closeInfra()
		return nil, err
	}
	deps.settings = store
	deps.watcher = watcher

	// 步骤 8：延迟写入队列（§5.2）与登录事件 sink（§4.6）。
	deps.queue = asyncqueue.New(&eventLogExecutor{
		logs:  repo.NewEventLogRepo(db),
		users: repo.NewUserRepo(db),
	}, asyncqueue.DefaultOptions())
	deps.sink = service.NewLoginEventWriter(eventlog.NewWriter(deps.queue))

	return deps, nil
}

// stopBackground 停止后台协程：先关 settings watcher，再优雅关闭队列
// （Queue.Close 内部先 flush 剩余任务、再等 worker 退出，§5.2 行 892）。
// 须在 http.Server.Shutdown 之前调用；重复调用安全。
func (a *assembled) stopBackground(ctx context.Context) {
	if a == nil {
		return
	}
	if a.watcher != nil {
		_ = a.watcher.Close()
		a.watcher = nil
	}
	if a.queue != nil {
		_ = a.queue.Close(ctx)
		a.queue = nil
	}
}

// closeInfra 关闭 DB / Redis 连接（后台协程须已由 stopBackground 停止）。
// nil 安全，供装配失败清理与优雅关闭复用。
func (a *assembled) closeInfra() {
	if a == nil {
		return
	}
	if a.db != nil {
		closeSQLDB(a.db)
		a.db = nil
	}
	if a.rdb != nil {
		_ = a.rdb.Close()
		a.rdb = nil
	}
}

// close 后台协程 + 基础设施的完整释放（装配失败清理与测试用）；HTTP
// Shutdown 需夹在两者之间，由 serve 直接分两步调用。
func (a *assembled) close(ctx context.Context) {
	a.stopBackground(ctx)
	a.closeInfra()
}

// closeSQLDB 关闭 GORM 底层 *sql.DB（取不到时静默跳过）。
func closeSQLDB(db *gorm.DB) {
	if db == nil {
		return
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// serve 正常模式装配链（§3.1 行 237）：config（run 已加载）→ DB → migrate
// up → Redis → 密钥 → provider/factor 注册表 → settings 预热 → 队列
// worker → cron → router → http.Server。启动期链路已由 assemble 完成；
// 本函数负责监听与优雅关闭：signal（SIGINT/SIGTERM）→ 停 watcher / 队列
// （先 flush 再停 worker）→ http.Server.Shutdown（超时 10s）→ 关 DB / Redis。
func serve(cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	deps, err := assemble(ctx, cfg)
	if err != nil {
		return err
	}

	// TODO(§3.1 行 237 步骤 6)：provider/factor 注册表——统一 `_ import`
	//   触发自注册（internal/provider / factor 子包尚未落地）。
	// TODO(cron)：定时清理任务包尚未落地（§3.12 行 457），随 cron 卡接入。

	handler, _ := buildRouter(cfg)
	srv, err := newHTTPServer(cfg, handler)
	if err != nil {
		deps.close(context.Background())
		return err
	}

	errCh := make(chan error, 1)
	go func() { errCh <- listenAndServe(cfg, srv) }()

	select {
	case err := <-errCh:
		// 监听自身出错（端口占用等）或外部已关闭：释放装配产物后原样上抛。
		deps.close(context.Background())
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		// 收到 SIGINT / SIGTERM：先停后台协程（watcher / 队列 worker，队列
		// Close 内部先 flush 剩余任务），再停止接收并等待在途请求，最后
		// 关 DB / Redis（§3.1 行 239 优雅关闭顺序）。
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		deps.stopBackground(shutdownCtx)
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("authloft: http shutdown incomplete", "error", err)
		}
		deps.closeInfra()
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// listenAndServe 按 server 段 TLS 配置选择监听模式（§3.1 行 244）：已配
// cert+key → 同端口 HTTP/1.1(TLS) + H2(TLS)（证书路径经 Validate 已校验
// 可读）；未配 → 明文 HTTP/1.1 + H2C。
func listenAndServe(cfg *config.Config, srv *http.Server) error {
	if cfg.Server.TLSEnabled() {
		return srv.ListenAndServeTLS(cfg.Server.CertFile, cfg.Server.KeyFile)
	}
	return srv.ListenAndServe()
}

// setupMode 判定首次启动（§3.1 行 253 / §3.15）：configs/config.yaml
// 不存在即 setup 模式。纯文件存在性判定，不含其他启发式。
func setupMode(configPath string) bool {
	_, err := os.Stat(configPath)
	return errors.Is(err, fs.ErrNotExist)
}

// buildRouter 从 *config.Config 构造生产顶层 handler（§3.2 约定 1：构造注入，
// 测试可传自造实例，§20）。rootOrigin 取 authloft.root（{al_root}，接口文档
// §1.1 行 76）；当前无 service 可挂，session/admin/
// rpc HMAC 拦截器随域 handler 注册时注入。setup 路由不在本链注册——仅
// setup 模式的独立链路（§3.15），正常模式下 /setup 与 /api.setup/** 一律
// 404（§13）。
func buildRouter(cfg *config.Config) (http.Handler, *gin.RouterGroup) {
	return buildHandler(cfg, connect.NewServer(defaultReadMaxBytes))
}

// buildHandler 顶层分流组装（§3.1 行 243：标准库 http.ServeMux）：
//   - Connect 各路由按路径前缀挂 mux——前缀链与 gin 全局链等效（§3.3
//     行 304 挂载顺序，recover 由 connect-go WithRecover 在 handler 内
//     等效、不进本链）：http 版 requestid（X-Request-Id 全响应回写）→
//     logger（访问日志）→ metrics（defer 累加，Connect 域流量同样计入
//     /metrics）→ origin（跨站 403）→ handler；中间件两版与 gin 版共用
//     同一实现（middleware/httpmw.go——requestid/origin 共用纯函数、
//     logger 共用 logAccess、metrics 共用同一组包级原子变量）；
//   - 其余全部 mux.Handle("/", ginEngine)：页面 / 静态 / OIDC / gateway /
//     未注册路径（含未注册的 connect 形态路径）→ gin 原生 404 兜底
//     （不再经 gin.NoRoute 桥，404 残留缺陷结构性消除）；
//   - 该分流链上禁挂 gzip / body-capture 类中间件（§3.1 行 246，破坏
//     h2c / 流式语义）。
func buildHandler(cfg *config.Config, csrv *connect.Server) (http.Handler, *gin.RouterGroup) {
	// TODO(appid)：Referer 白名单口径已定（docs/后端架构.md §13.0）= 已启用
	// mp provider 的 Ext.app_id 集合，由装配层注入 provider 查询函数并随
	// provider 变更热更新；internal/provider 尚未落地，接线归 provider
	// 实现，本次不接线。空表下小程序 Referer 校验恒不过，由 origin 中间件
	// 保守 403（既定口径）。
	refererAllowlist := []string{}
	ginEngine, apiGroup := newRouter(cfg.Authloft.Root, refererAllowlist)

	mux := http.NewServeMux()
	mux.Handle("/", ginEngine)
	for _, rt := range csrv.Routes() {
		mux.Handle(rt.Prefix, middleware.HTTPRequestID(
			middleware.HTTPLogger(
				middleware.HTTPMetrics(
					middleware.HTTPOrigin(cfg.Authloft.Root, refererAllowlist, rt.Handler),
				),
			),
		))
	}
	return mux, apiGroup
}

// newHTTPServer 从 *config.Config 构造 http.Server：监听地址与协议
// （Protocols / TLSConfig，Go 1.26 标准库原生 http.Server.Protocols——
// h2c 或 TLS 双模式，§3.1 行 244-245）取自 server 段，经
// ServerConfig.ConfigureHTTPServer 映射（与 setup 同口径，§3.15）；
// min_tls_version 非法取值在此 fail-fast（正常路径已在 config.Validate
// 拦截，防测试自造实例绕过）。
func newHTTPServer(cfg *config.Config, handler http.Handler) (*http.Server, error) {
	srv := &http.Server{Handler: handler}
	if err := cfg.Server.ConfigureHTTPServer(srv); err != nil {
		return nil, err
	}
	return srv, nil
}
