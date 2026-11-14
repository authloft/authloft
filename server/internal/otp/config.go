// config.go 验证码五参数启动期快照（docs/接口文档.md §5.6 行 1303-1311：
// 键名与默认值唯一定义处）。
package otp

import (
	"time"

	"authloft/internal/cache"
	"authloft/internal/settings"
)

// FromSettings 验证码五参数启动期快照（接口文档 §5.6 行 1303-1311
// 为键名与默认值的唯一定义处）。Config 供因子 Judge 与表单渲染，
// cache.CodeOptions 供 cache.CodeStore 限流判定；零值各自回落默认（两处
// 默认值同源 §10.3，一致）。
func FromSettings(st *settings.Store) (Config, cache.CodeOptions) {
	var cfg Config
	if st == nil {
		return cfg, cache.CodeOptions{}
	}
	if v, ok := st.GetInt64(settings.KeyOtpTtl); ok && v > 0 {
		cfg.TTL = time.Duration(v) * time.Second
	}
	if v, ok := st.GetInt64(settings.KeyOtpResendInterval); ok && v > 0 {
		cfg.Cooldown = time.Duration(v) * time.Second
	}
	if v, ok := st.GetInt64(settings.KeyOtpMaxAttempts); ok && v > 0 {
		cfg.MaxAttempts = int(v)
	}
	if v, ok := st.GetInt64(settings.KeyOtpDailyLimitTarget); ok && v > 0 {
		cfg.TargetDailyLimit = int(v)
	}
	if v, ok := st.GetInt64(settings.KeyOtpDailyLimitIP); ok && v > 0 {
		cfg.IPDailyLimit = int(v)
	}
	return cfg, cache.CodeOptions{
		TTL:              cfg.TTL,
		Cooldown:         cfg.Cooldown,
		TargetDailyLimit: cfg.TargetDailyLimit,
		IPDailyLimit:     cfg.IPDailyLimit,
		MaxAttempts:      cfg.MaxAttempts,
	}
}
