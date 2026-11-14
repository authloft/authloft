// config_test.go FromSettings 的键读取与回落口径（接口文档 §5.6 行 1303-1311）：
// 键缺失 / 非法（<=0）时保持零值，由 otp.Config.Effective 回落 §5.6 默认值；
// 键存在且合法时逐项投影，CodeOptions 与 Config 同值。
package otp

import (
	"testing"
	"time"

	"authloft/internal/cache"
	"authloft/internal/settings"
)

// TestFromSettingsNilStore 无配置源时返回零值（不 panic、不臆造默认）。
func TestFromSettingsNilStore(t *testing.T) {
	cfg, opts := FromSettings(nil)
	if cfg != (Config{}) {
		t.Fatalf("cfg = %+v, want zero", cfg)
	}
	if opts != (cache.CodeOptions{}) {
		t.Fatalf("opts = %+v, want zero", opts)
	}
	// 零值经 Effective 回落 §5.6 全默认（与 DefaultConfig 同源）。
	if cfg.Effective() != DefaultConfig() {
		t.Fatalf("Effective = %+v, want DefaultConfig %+v", cfg.Effective(), DefaultConfig())
	}
}

// TestFromSettingsDefaults 未预热 Store 快照为 §5.6 默认值：逐项投影到
// Config 与 CodeOptions。
func TestFromSettingsDefaults(t *testing.T) {
	st := settings.NewStore(nil, nil)
	cfg, opts := FromSettings(st)

	want := Config{
		TTL:              300 * time.Second,
		Cooldown:         60 * time.Second,
		MaxAttempts:      5,
		TargetDailyLimit: 10,
		IPDailyLimit:     50,
	}
	if cfg != want {
		t.Fatalf("cfg = %+v, want %+v", cfg, want)
	}
	wantOpts := cache.CodeOptions{
		TTL:              want.TTL,
		Cooldown:         want.Cooldown,
		TargetDailyLimit: want.TargetDailyLimit,
		IPDailyLimit:     want.IPDailyLimit,
		MaxAttempts:      want.MaxAttempts,
	}
	if opts != wantOpts {
		t.Fatalf("opts = %+v, want %+v", opts, wantOpts)
	}
}
