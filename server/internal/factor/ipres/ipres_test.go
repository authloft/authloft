package ipres

import (
	"context"
	"testing"

	factorotp "authloft/internal/factor/otp"
	factorpassword "authloft/internal/factor/password"
	"authloft/internal/service/orchestrator"
)

// 两侧因子接口由同一实现满足（装配方单点注入的前提）。
var (
	_ factorpassword.IPResolver = Resolver{}
	_ factorotp.IPResolver      = Resolver{}
)

func TestClientIPFromRequestInfo(t *testing.T) {
	ctx := orchestrator.WithRequestInfo(context.Background(), orchestrator.RequestInfo{IP: "203.0.113.9"})
	if got := (Resolver{}).ClientIP(ctx); got != "203.0.113.9" {
		t.Fatalf("Resolver.ClientIP = %q, want 203.0.113.9", got)
	}
	if got := ClientIP(ctx); got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want 203.0.113.9", got)
	}
}

func TestClientIPWithoutRequestInfo(t *testing.T) {
	// 非 HTTP 链路 / 裸 ctx：返回空串，兜底（unknown 桶）归消费方。
	if got := (Resolver{}).ClientIP(context.Background()); got != "" {
		t.Fatalf("ClientIP = %q, want empty", got)
	}
	if got := (Resolver{}).ClientIP(nil); got != "" {
		t.Fatalf("ClientIP(nil) = %q, want empty", got)
	}
}
