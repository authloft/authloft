// bootstrap.go 按 docs/后端架构.md §3.1 行 253 的固定顺序装配启动链：
// config → DB → 迁移检查（migrate up，幂等）→ Redis → 密钥 → provider/factor
// 注册表 → settings 预热 → 队列 worker → cron → router。已落地 config /
// DB / migrate / Redis 四步，密钥及其后步骤占位注释，随对应模块卡逐张接入。
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
	"errors"
	"io/fs"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"authloft/internal/cache"
	"authloft/internal/config"
	"authloft/internal/connect"
	"authloft/internal/middleware"
	"authloft/internal/migrate"
	"authloft/internal/repo"
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

// assembled 正常模式装配产物：DB / Redis 句柄。密钥、注册表、settings、
// worker、cron 落地后逐步补充字段（§3.1 行 253 步骤 5-9）。
type assembled struct {
	db  *gorm.DB
	rdb *redis.Client
}

// assemble 正常模式装配步骤 2-4（§3.1 行 253）：DB → 迁移检查（migrate up，
// 幂等——版本已最新时只读版本表秒过，§3.16 行 553-555：连上 DB 之后、
// settings 预热之前）→ Redis。任一步失败原样上抛（serve 转 fail-fast）。
func assemble(ctx context.Context, cfg *config.Config) (*assembled, error) {
	db, err := repo.Open(cfg)
	if err != nil {
		return nil, err
	}
	if err := migrate.Up(ctx, cfg.DB.DSN); err != nil {
		return nil, err
	}
	rdb, err := cache.NewClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &assembled{db: db, rdb: rdb}, nil
}

// serve 正常模式装配链（§3.1 行 253）：config（run 已加载）→ DB → migrate
// up → Redis → 密钥 → provider/factor 注册表 → settings 预热 → 队列
// worker → cron → router → http.Server。装配产物由本函数持有到进程退出，
// 优雅关闭（app.Run / Shutdown，§3.1 行 250）落地后接管释放。
func serve(cfg *config.Config) error {
	deps, err := assemble(context.Background(), cfg)
	if err != nil {
		return err
	}
	defer func() {
		if sqlDB, err := deps.db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		_ = deps.rdb.Close()
	}()

	// TODO(§3.1 行 253 步骤 5)：密钥预热——cfg.SignKey 五场景 AES-256-GCM
	//   密钥解码就绪（§3.2 约定 4）。
	// TODO(§3.1 行 253 步骤 6)：provider/factor 注册表——统一 `_ import`
	//   触发自注册。
	// TODO(§3.1 行 253 步骤 7)：settings 预热——运行期可变项载入（接口
	//   文档 §5.6，不进 config）。
	// TODO(§3.1 行 253 步骤 8)：队列 worker 与 cron 启动。

	// TODO(schema)：§3.2 无 max_body_bytes 字段，当前回落 connect 域默认
	// 1 MiB（§1.6 行 86，经 connect.NewServer 注入）；若需可配置须先改
	// §3.2 文档。

	handler, _ := buildRouter(cfg)
	srv, err := newHTTPServer(cfg, handler)
	if err != nil {
		return err
	}
	// 监听模式由 server 段 TLS 配置决定（§3.1 行 244）：已配 cert+key →
	// 同端口 HTTP/1.1(TLS) + H2(TLS)（ListenAndServeTLS，证书路径经
	// Validate 已校验可读）；未配 → 明文 HTTP/1.1 + H2C。
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
	// TODO(appid)：servicewechat appid Referer 白名单配置来源未定
	//（待定）；空表下小程序 Referer 校验恒不过，
	// 由 origin 中间件保守 403（既定口径）。
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
