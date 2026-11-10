package logx

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// withDefault 临时接管全局 logger，测试结束恢复，避免污染其它包内用例。
func withDefault(t *testing.T, h slog.Handler) {
	t.Helper()
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(old) })
}

func decodeLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m); err != nil {
		t.Fatalf("decode log line %q: %v", buf.String(), err)
	}
	return m
}

func TestRequestIDContext(t *testing.T) {
	bg := context.Background()
	if got := RequestID(bg); got != "" {
		t.Errorf("RequestID(background) = %q, want empty", got)
	}
	if got := RequestID(nil); got != "" {
		t.Errorf("RequestID(nil) = %q, want empty", got)
	}
	// rand 失败留空串时不注入、不伪造值（§3.3 行 294）。
	if got := WithRequestID(bg, ""); got != bg {
		t.Error("WithRequestID with empty id must return the original ctx")
	}
	if got := WithRequestID(nil, "x"); got != nil {
		t.Error("WithRequestID(nil) must stay nil")
	}

	ctx := WithRequestID(bg, "abc-123")
	if got := RequestID(ctx); got != "abc-123" {
		t.Errorf("RequestID = %q, want abc-123", got)
	}
	// 内层覆盖，且父 ctx 不受影响。
	inner := WithRequestID(ctx, "inner-456")
	if got := RequestID(inner); got != "inner-456" {
		t.Errorf("RequestID(inner) = %q, want inner-456", got)
	}
	if got := RequestID(ctx); got != "abc-123" {
		t.Errorf("RequestID(parent) = %q, want abc-123", got)
	}
}

func TestHandlerInjectsRequestID(t *testing.T) {
	buf := &bytes.Buffer{}
	withDefault(t, NewHandler(buf, "debug", "json"))
	ctx := WithRequestID(context.Background(), "abc-123")

	// ① 便捷函数：结构化字段 + 自动补 request_id。
	Warn(ctx, "thirdparty: write ticket result failed", "ticket_id", "t-1", "error", "boom")
	m := decodeLine(t, buf)
	if m["request_id"] != "abc-123" || m["msg"] != "thirdparty: write ticket result failed" ||
		m["level"] != "WARN" || m["ticket_id"] != "t-1" || m["error"] != "boom" {
		t.Errorf("Warn output = %v, want request_id/msg/level/ticket_id/error", m)
	}

	// ② 现有代码直接调 slog.XxxContext 也自动带链路 ID，无需换函数。
	buf.Reset()
	slog.WarnContext(ctx, "direct slog call")
	m = decodeLine(t, buf)
	if m["request_id"] != "abc-123" || m["msg"] != "direct slog call" {
		t.Errorf("slog.WarnContext output = %v, want injected request_id", m)
	}

	// ③ logger.With / WithGroup 派生后包装不被丢掉。
	buf.Reset()
	slog.Default().With("component", "svc").WarnContext(ctx, "derived")
	m = decodeLine(t, buf)
	if m["request_id"] != "abc-123" || m["component"] != "svc" {
		t.Errorf("derived logger output = %v, want request_id + component", m)
	}

	// ④ 无链路 ID 的 ctx 不注入字段（访问日志 / panic 日志自行显式传值）。
	buf.Reset()
	Info(context.Background(), "no ctx id")
	m = decodeLine(t, buf)
	if _, ok := m["request_id"]; ok {
		t.Errorf("output = %v, want no request_id field", m)
	}
}

func TestLevelsAndFormats(t *testing.T) {
	for _, tc := range []struct {
		level     string
		wantDebug bool
		wantWarn  bool
	}{
		{"debug", true, true},
		{"info", false, true},
		{"warn", false, true},
		{"error", false, false},
		{"bogus", false, true}, // 未知值回退 info
		{"", false, true},      // setup 模式 / 加载失败用默认值
	} {
		buf := &bytes.Buffer{}
		l := slog.New(NewHandler(buf, tc.level, "json"))
		l.DebugContext(context.Background(), "debug-line")
		l.WarnContext(context.Background(), "warn-line")
		out := buf.String()
		if strings.Contains(out, "debug-line") != tc.wantDebug {
			t.Errorf("level %q: debug-line present = %v, want %v; output = %q",
				tc.level, strings.Contains(out, "debug-line"), tc.wantDebug, out)
		}
		if strings.Contains(out, "warn-line") != tc.wantWarn {
			t.Errorf("level %q: warn-line present = %v, want %v; output = %q",
				tc.level, strings.Contains(out, "warn-line"), tc.wantWarn, out)
		}
	}

	// text 格式：request_id 以 key=value 落地。
	buf := &bytes.Buffer{}
	ctx := WithRequestID(context.Background(), "abc-123")
	slog.New(NewHandler(buf, "debug", "text")).WarnContext(ctx, "text-line", "k", "v")
	out := buf.String()
	if !strings.Contains(out, "request_id=abc-123") || !strings.Contains(out, "msg=text-line") || !strings.Contains(out, "k=v") {
		t.Errorf("text output = %q, want request_id/msg/k", out)
	}
}

func TestSetupTakesEffect(t *testing.T) {
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })

	Setup("debug", "json")
	if !slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Setup(debug): Debug should be enabled")
	}
	Setup("error", "text")
	if slog.Default().Enabled(context.Background(), slog.LevelWarn) {
		t.Error("Setup(error): Warn should be disabled")
	}
	if !slog.Default().Enabled(context.Background(), slog.LevelError) {
		t.Error("Setup(error): Error should be enabled")
	}
	// 默认装配（setup 模式）为 info/json。
	Setup("", "")
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Setup(default): Debug should be disabled")
	}
}

// 测试里若用 slog.SetDefault 换成裸 handler，便捷函数仍须带 request_id
// （logger() 的显式 With 兜底，不依赖装配顺序）。
func TestConvenienceFuncsWithForeignHandler(t *testing.T) {
	buf := &bytes.Buffer{}
	withDefault(t, slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := WithRequestID(context.Background(), "abc-123")

	Debug(ctx, "dbg")
	Info(ctx, "inf")
	Warn(ctx, "wrn")
	Error(ctx, "err")
	out := buf.String()
	for _, msg := range []string{"dbg", "inf", "wrn", "err"} {
		if !strings.Contains(out, "msg="+msg) {
			t.Errorf("output missing %q: %s", msg, out)
		}
	}
	if got := strings.Count(out, "request_id=abc-123"); got != 4 {
		t.Errorf("request_id count = %d, want 4; output = %s", got, out)
	}
}
