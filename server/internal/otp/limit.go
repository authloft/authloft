package otp

import (
	"time"

	"authloft/internal/cache"
)

// Denial 发送侧限流判定结论（§10.3 行 1137-1151）：Allowed=true 表示发码
// 通过，可继续投递；否则 Status=too_many_requests 并附冷却 / 次日重置倒计时。
type Denial struct {
	Allowed    bool
	Status     string
	RetryAfter int64
}

// Judge 把 cache/code.go 的 SendResult 映射为登录流程信封结论（接口文档
// §1.6 行 242）。冷却 60s、单目标日限额、单 IP 日限额的键读写与判定都在
// cache/code.go 的原子 EVAL 内完成，本层只做结果分派，不重复实现键读写。
func Judge(result cache.SendResult, cfg Config, now time.Time) Denial {
	c := cfg.Effective()
	switch result {
	case cache.SendOK:
		return Denial{Allowed: true}
	case cache.SendCooldown:
		// 冷却中：按压冷却时长倒计时（精度到秒，秒级误差可接受）。
		return Denial{Status: StatusTooManyRequests, RetryAfter: seconds(c.Cooldown)}
	case cache.SendTargetDailyLimit, cache.SendIPDailyLimit:
		// 日限额到达：次日 00:00 重置，倒计时到服务器本地当天 24:00。
		return Denial{Status: StatusTooManyRequests, RetryAfter: secondsUntilMidnight(now)}
	default:
		// 未知结果按冷却处理：宁可不发，也不误放行。
		return Denial{Status: StatusTooManyRequests, RetryAfter: seconds(c.Cooldown)}
	}
}

// secondsUntilMidnight 返回距服务器本地当天 24:00 的秒数（至少 1s）。
func secondsUntilMidnight(now time.Time) int64 {
	next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
	n := int64(next.Sub(now) / time.Second)
	if n < 1 {
		n = 1
	}
	return n
}
