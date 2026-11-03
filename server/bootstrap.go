// bootstrap.go 按 docs/后端架构.md §3.1 行 253 的固定顺序装配启动链：
// config → DB → 迁移检查（migrate up，幂等）→ Redis → 密钥 → provider/factor
// 注册表 → settings 预热 → 队列 worker → cron → router。已落地 config /
// DB / migrate / Redis 四步，密钥及其后步骤占位注释，随对应模块卡逐张接入。
//
// 启动分支（§3.1 行 253）：configs/config.yaml 不存在 → setup 模式
//——不加载 config、不初始化 DB / Redis、不起业务链路，只启动 internal/setup
//（§3.15）；存在 → 正常装配（保持既有结构）。

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
	"authloft/internal/migrate"
	"authloft/internal/repo"
	"authloft/internal/setup"
)

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

	// TODO(schema)：§3.2 无 max_body_bytes 字段，当前回落 codec 默认 1 MiB
	//（未调用 SetMaxBodyBytes 即回落默认，§3.14 行 492）；若需可配置
	// 须先改 §3.2 文档。

	router, _ := buildRouter(cfg)
	return newHTTPServer(cfg, router).ListenAndServe()
}

// setupMode 判定首次启动（§3.1 行 253 / §3.15）：configs/config.yaml
// 不存在即 setup 模式。纯文件存在性判定，不含其他启发式。
func setupMode(configPath string) bool {
	_, err := os.Stat(configPath)
	return errors.Is(err, fs.ErrNotExist)
}

// buildRouter 从 *config.Config 构造生产路由（§3.2 约定 1：构造注入，
// 测试可传自造实例，§20）。rootOrigin 取 authloft.root（{al_root}，
// 接口文档 §1.1 行 54）。setup 路由不在本链注册——仅 setup 模式的独立
// engine 挂载（§3.15），正常模式下 /setup 与 /api/setup/** 一律 404（§13）。
func buildRouter(cfg *config.Config) (*gin.Engine, *gin.RouterGroup) {
	// TODO(appid)：servicewechat appid Referer 白名单配置来源未定
	//（待定）；空表下小程序 Referer 校验恒不过，
	// 由 origin 中间件保守 403（既定口径）。
	return newRouter(cfg.Authloft.Root, []string{})
}

// newHTTPServer 从 *config.Config 构造 http.Server：监听地址与读写超时
// 均取自 server 段（§3.2 行 260-262）。
func newHTTPServer(cfg *config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:         cfg.Server.Listen,
		ReadTimeout:  cfg.Server.ReadTimeout.Duration,
		WriteTimeout: cfg.Server.WriteTimeout.Duration,
		Handler:      handler,
	}
}
