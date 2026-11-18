// Package app 运行期进程级辅助（docs/后端架构.md §3.1 规划位）：当前仅健康
// 探针——依赖探活聚合与 HTTP 渲染。探活实现取装配层同一组基础设施句柄，
// 与优雅关闭链路（stopBackground → Shutdown → closeInfra）同生命周期：
// closeInfra 之后探活自然失败，探针状态随生命周期收敛，不另设状态位。
package app

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"authloft/internal/logx"
)

// probeTimeout 单依赖探活上限：SELECT 1 / PING 级连通检查毫秒级常态，超时
// 即判不健康，防依赖挂起拖死探针请求。各项并发探活，/health 总耗时上界约为
// probeTimeout；容器探针客户端超时须大于该值（docker/HEALTHCHECK 同源）。
// var 仅为测试可缩短，生产不改写。
var probeTimeout = 2 * time.Second

// Probe 具名单项探活：Name 供失败清单回显（仅组件名，不外泄基础设施细节），
// Check 返回 error 即判该项不健康。Check 须自持轻量（连通性检查，不带业务
// 查询），并遵守传入 ctx 的截止时间。
type Probe struct {
	Name  string
	Check func(ctx context.Context) error
}

// RedisPinger 健康探活所需的 Redis 连通性最小接口（装配层客户端适配器
// 实现），避免探针绑定具体客户端类型。
type RedisPinger interface {
	Ping(ctx context.Context) error
}

// StandardProbes 标准探活集：DB 经 sql.DB Ping（连通级，等价 SELECT 1）、
// Redis PING。句柄与优雅关闭链路同一组（assembled.db / assembled.rdb）。
// nil 句柄恒判失败——装配未完成即被探针命中属异常路径，如实报不健康。
func StandardProbes(db *gorm.DB, rdb RedisPinger) []Probe {
	return []Probe{
		{
			Name: "db",
			Check: func(ctx context.Context) error {
				if db == nil {
					return errors.New("db handle not wired")
				}
				sqlDB, err := db.DB()
				if err != nil {
					return err
				}
				return sqlDB.PingContext(ctx)
			},
		},
		{
			Name: "redis",
			Check: func(ctx context.Context) error {
				if rdb == nil {
					return errors.New("redis handle not wired")
				}
				return rdb.Ping(ctx)
			},
		},
	}
}

// NewHandler /health 处理器：并发逐项探活，全部通过 → 200；任一失败 → 503
// 并附失败项名单。响应体最小 JSON，不回传错误细节（端点无鉴权，防基础设施
// 报文经探针外泄）；原因只落服务端日志。每次现探不缓存——编排层按自身间隔
// 轮询，无高频路径。
func NewHandler(probes []Probe) gin.HandlerFunc {
	return func(c *gin.Context) {
		failed := make([]string, 0, len(probes))
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, p := range probes {
			wg.Add(1)
			go func(p Probe) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(c.Request.Context(), probeTimeout)
				defer cancel()
				err := p.Check(ctx)
				if err == nil {
					return
				}
				// 探针失败即依赖不可达， Warn 级留痕；错误文本经脱敏后落日志，
				// 不进响应体。
				logx.Warn(ctx, "app: health probe failed",
					"component", p.Name,
					"error", logx.RedactText(err.Error()),
				)
				mu.Lock()
				failed = append(failed, p.Name)
				mu.Unlock()
			}(p)
		}
		wg.Wait()

		if len(failed) > 0 {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unavailable",
				"failed": failed,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}
