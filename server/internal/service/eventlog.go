// eventlog.go 登录事件投递适配器（docs/后端架构.md §3.7 行 376、§4.6 行
// 806、§5.2 行 858-894）：实现 orchestrator.LoginEventSink（terminal.go
// 行 52-55），把一次成功登录映射为 login_success 事件 + user.last_login_at
// 更新，全部走 eventlog.Writer 的延迟队列，登录主链路零同步写库。
package service

import (
	"context"
	"strings"
	"time"

	"authloft/internal/eventlog"
	"authloft/internal/repo/model"
	"authloft/internal/service/orchestrator"
)

// LoginEventWriter 登录事件投递适配器。满足 orchestrator.LoginEventSink
// 签名（terminal.go 行 52-55）。
type LoginEventWriter struct {
	Logs *eventlog.Writer
}

// NewLoginEventWriter 注入事件投递器。
func NewLoginEventWriter(logs *eventlog.Writer) *LoginEventWriter {
	return &LoginEventWriter{Logs: logs}
}

// 编译期断言：接口签名漂移时构建失败，而不是留到装配期。
var _ orchestrator.LoginEventSink = (*LoginEventWriter)(nil)

// Record 投递 login_success 事件与 last_login_at 更新（§4.6 行 798、806）。
// 返回 error 只为满足接口签名；队列满/关闭等投递失败由 eventlog.Writer
// 静默降级（§5.2 行 893），绝不回滚登录（terminal.go 行 135-144）。
//
// 字段映射：actor_type=user、actor_id/user_id=UID、client_id 原样、amr
// 逗号连接（§4.6 行 774-775）；ip/ua 原样落列（§4.6 行 776-777，
// 未注入为空串）、session_id 进 detail（§4.6 行 798；device_hint 无数据源
// 维持空串，不自造）。
func (w *LoginEventWriter) Record(_ context.Context, ev orchestrator.LoginEvent) error {
	if w == nil || w.Logs == nil {
		return nil
	}

	at := time.Now()
	if ev.AuthTime > 0 {
		at = time.Unix(ev.AuthTime, 0)
	}

	factor, mfaFactor := loginFactors(ev.AMR)
	w.Logs.PushEvent(model.EventLog{
		Event:     eventlog.EventLoginSuccess,
		ActorType: eventlog.ActorTypeUser,
		ActorID:   ev.UID,
		UserID:    ev.UID,
		ClientID:  ev.ClientID,
		AMR:       strings.Join(ev.AMR, ","),
		IP:        ev.IP,
		UA:        ev.UA,
		Detail:    eventlog.DetailLoginSuccess(factor, mfaFactor, ev.SessionID, ""),
		CreatedAt: at,
	})
	w.Logs.PushLastLogin(ev.UID, at)
	return nil
}

// loginFactors 从 AMR 推导 detail 的 factor / mfa_factor。§4.6 行 798 只
// 定义键名、未定义取值语义，这里按认证方法通过顺序取第一个为主因子、
// 其余逗号连接为 MFA 因子；AMR 为空时两者均为空串。
func loginFactors(amr []string) (factor, mfaFactor string) {
	if len(amr) == 0 {
		return "", ""
	}
	factor = amr[0]
	if len(amr) > 1 {
		mfaFactor = strings.Join(amr[1:], ",")
	}
	return factor, mfaFactor
}
