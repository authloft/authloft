// Package ipres factorpassword.IPResolver / factorotp.IPResolver 的生产实现
// （docs/后端架构.md §8.1、§10.3）：从 ctx 读取 http 挂载层
// 注入的请求侧来源 IP（orchestrator.WithRequestInfoHandler 对全部 connect
// 前缀统一注入，取值口径 = orchestrator.ClientIPFromRequest：settings 键
// client_ip_header 配置了采信头则取该头逗号首段并去空白，未配置仅取直连
// RemoteAddr host 段、不采信任何转发头）。
//
// 采信边界：与 event_log.ip 审计同款——配置的可信头由部署方在反代清洗入站
// 头，直连客户端可伪造、如实记录（接口文档 §1.1 明文部署风险自负的同款
// 口径）；本项目无「可信代理网段」配置项，故不复刻代理白名单逻辑，避免与
// 挂载层口径分叉（同一请求在审计与限流键里必须是同一个 IP）。
//
// 消费点：otp 单 IP 日限额键、密码失败计数的「IP+账号」user_ref、换绑发码
// 侧来源 IP。ctx 未注入（非 HTTP 链路 / 单测裸 ctx）返回空串，由各消费方
// 按既有兜底（unknown 桶）降级，不在本包二次兜底。
package ipres

import (
	"context"

	"authloft/internal/service/orchestrator"
)

// Resolver 空结构体实现两侧因子包的 IPResolver 窄接口，由装配方注入。
type Resolver struct{}

// ClientIP 返回 ctx 内挂载层注入的来源 IP；未注入返回空串。
func (Resolver) ClientIP(ctx context.Context) string {
	return ClientIP(ctx)
}

// ClientIP 包级取值：handler 层不经接口直接取同一来源（换绑审计链路）。
func ClientIP(ctx context.Context) string {
	return orchestrator.RequestInfoFromContext(ctx).IP
}
