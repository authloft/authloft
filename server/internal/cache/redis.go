// Package cache 提供 Redis 访问层基础设施（docs/后端架构.md §3.10）。
//
// 本文件只做客户端初始化；全部键空间的构造与读写封装（keys.go / code.go /
// captcha.go 等，TTL 严格按 §5.1）归后续实现。客户端选型：rueidis（RESP3，
// 单连接多路复用），经包内适配层（rueidis.go）翻译为自有结果类型后供各
// 键空间封装使用。
package cache

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/redis/rueidis"

	"authloft/internal/config"
	"authloft/internal/logx"
)

// degradeMaxRetries 单命令重试上限。rueidis 默认重试无次数上限（指数只压
// 延迟、封顶 1s）：无截止时间的业务命令在 Redis 故障期会无限重试挂死，错误
// 永远到不了上层回源逻辑，软降级的 fail-open 落空。上限取小值——延迟曲线
// 同默认指数抖动，总量毫秒级，故障期命令快速以错误收场转回源 DB；短暂抖动
// 仍被指数退避覆盖。有截止时间的命令（探活 / 启动 PING / 订阅确认）本就由
// deadline 兜底，不受此值影响。
const degradeMaxRetries = 10

// degradeRetryDelay 供 rueidis ClientOption.RetryDelay：超过上限返回负值
// （rueidis 约定负延迟 = 跳过重试，命令立即以错误收场），否则按默认指数
// 抖动延迟。
func degradeRetryDelay(attempts int, _ rueidis.Completed, _ error) time.Duration {
	if attempts > degradeMaxRetries {
		return -1
	}
	base := time.Duration(1) << uint(min(degradeMaxRetries, attempts))
	jitter := time.Duration(rand.IntN(int(base)))
	return min(time.Second, (base+jitter)*time.Microsecond)
}

// NewClient 按 cfg.Redis 初始化 rueidis 客户端（后端架构 §3.2：addr /
// password / db）。部署形态为单机 Redis（§3.2），ForceSingleClient 跳过
// 集群探测；rueidis 连接按需自动伸缩，无 go-redis PoolSize 对应项。
//
// 软降级口径（后端架构 §5.3）：构造后 PING 一次，失败不返回 error、不退出
// ——保留句柄等待 rueidis 后台自动重连，置降级状态并 Warn 留痕后继续装配；
// 核心链路读路径各自回源 DB，Redis-only 的一次性状态能力（验证码 / 扫码 /
// 授权码等）故障期不可用，由 /health 的 degraded 如实暴露、不伪装健康。
// 仅构造级错误（无法建立客户端）仍上抛：配置契约（addr 必填）与运行期连通
// 性解耦，不设降级开关。
func NewClient(ctx context.Context, cfg *config.Config) (*RedisClient, error) {
	client, err := rueidis.NewClient(rueidis.ClientOption{
		InitAddress:       []string{cfg.Redis.Addr},
		Password:          cfg.Redis.Password,
		SelectDB:          int(cfg.Redis.DB),
		ForceSingleClient: true,
		RetryDelay:        degradeRetryDelay,
	})
	if err != nil && client == nil {
		return nil, fmt.Errorf("redis: new client: %w", err)
	}
	// ForceSingleClient 下首连失败仍返回可用句柄（err 非空但 client 非空），
	// 连通性统一由下方 PING 判定——失败走软降级（见函数注释），句柄不回收。
	c := &RedisClient{c: client, state: &DegradeState{}}
	if err := c.Ping(ctx); err != nil {
		c.state.Set("redis unreachable at startup")
		logx.Warn(ctx, "cache: redis unreachable, serving degraded",
			"error", logx.RedactText(err.Error()))
	}
	return c, nil
}
