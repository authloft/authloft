// bootstrap.go 按 docs/后端架构.md §3.1 行 248 的固定顺序装配启动链：
// config → DB → Redis → 密钥 → provider/factor 注册表 → settings 预热
// → 队列 worker → cron → router。当前仅 config 与 router 两步落地，
// 其余步骤占位注释，随对应模块卡逐张接入。

package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"authloft/internal/config"
)

// run 装配并阻塞运行 HTTP 服务（§3.1 行 248）。装配与运行错误原样上抛，
// 由 main 转 exit 非 0（fail-fast）。
func run(configPath string) error {
	// 步骤 1 config：启动期一次读取 + env 覆盖 + Validate，任一失败即
	// fail-fast（§3.2 行 289；文件不存在且首次运行时自动生成 sign_key
	// 写回，见 §3.2 约定 4）。
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// TODO(§3.1 行 248 步骤 2)：DB——GORM 按 cfg.DB 打开 MariaDB 连接池。
	// TODO(§3.1 行 248 步骤 3)：Redis——按 cfg.Redis 建连接池。
	// TODO(§3.1 行 248 步骤 4)：密钥预热——cfg.SignKey 五场景 AES-256-GCM
	//   密钥解码就绪（§3.2 约定 4）。
	// TODO(§3.1 行 248 步骤 5)：provider/factor 注册表——统一 `_ import`
	//   触发自注册。
	// TODO(§3.1 行 248 步骤 6)：settings 预热——运行期可变项载入（接口
	//   文档 §5.6，不进 config）。
	// TODO(§3.1 行 248 步骤 7)：队列 worker 与 cron 启动。

	// TODO(schema)：§3.2 无 max_body_bytes 字段，当前回落 codec 默认 1 MiB
	//（未调用 SetMaxBodyBytes 即回落默认，§3.14 行 492）；若需可配置
	// 须先改 §3.2 文档。

	router, _ := buildRouter(cfg)
	return newHTTPServer(cfg, router).ListenAndServe()
}

// buildRouter 从 *config.Config 构造生产路由（§3.2 约定 1：构造注入，
// 测试可传自造实例，§20）。rootOrigin 取 authloft.root（{al_root}，
// 接口文档 §1.1 行 54）。
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
