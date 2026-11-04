package service

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/security"
)

// syncTestCodec 构造可签发 / 解析的编解码器（固定 32 字节 AES-256 密钥）。
func syncTestCodec(t *testing.T) *security.Codec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{
		ID:  security.KeyID{Version: 1, Kid: 1},
		Key: key,
	})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return security.NewCodec(ks)
}

func syncFixedNow() time.Time { return time.Unix(1700000000, 0) }

// splitSyncURL 拆出首跳 URL 与载荷（Build 约定 {首跳URL}?{payload}）。
func splitSyncURL(t *testing.T, raw string) (string, string) {
	t.Helper()
	u, payload, ok := strings.Cut(raw, "?")
	if !ok {
		t.Fatalf("url %q missing payload separator", raw)
	}
	return u, payload
}

func TestSyncCookieBuildEmptyDomains(t *testing.T) {
	b := NewSyncCookieURLBuilder(syncTestCodec(t))
	b.Now = syncFixedNow

	got, err := b.Build(context.Background(), "al_session", "v", "604800", nil, "https://final.example")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got != "" {
		t.Errorf("url = %q, want empty string", got)
	}
}

func TestSyncCookieBuildPayload(t *testing.T) {
	codec := syncTestCodec(t)
	b := NewSyncCookieURLBuilder(codec)
	b.Now = syncFixedNow

	// sso_domains 为裸域名 host[:port]（§3.2 行 251），实现方负责展开。
	domains := []string{"a.example", "b.example", "c.example"}
	const finalURL = "https://final.example/done"

	raw, err := b.Build(context.Background(), "al_session", "session-value", "604800", domains, finalURL)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	wantTargets := []string{
		"https://a.example/sso/sync_cookie",
		"https://b.example/sso/sync_cookie",
		"https://c.example/sso/sync_cookie",
	}
	first, payload := splitSyncURL(t, raw)
	if first != wantTargets[0] {
		t.Errorf("first hop = %q, want %q", first, wantTargets[0])
	}

	p, err := security.Open[token.SyncCookiePayload](codec, security.PurposeSyncPayload, payload)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if p.GetCookieName() != "al_session" {
		t.Errorf("cookie_name = %q, want al_session", p.GetCookieName())
	}
	if p.GetCookieValue() != "session-value" {
		t.Errorf("cookie_value = %q, want session-value", p.GetCookieValue())
	}
	if p.GetCookieTtl() != "604800" {
		t.Errorf("cookie_ttl = %q, want 604800", p.GetCookieTtl())
	}
	// 首跳不写进载荷：remaining 为展开后的 domains[1:]，顺序不变、不含首跳与 finalURL。
	if want := wantTargets[1:]; !reflect.DeepEqual(p.GetRemaining(), want) {
		t.Errorf("remaining = %v, want %v", p.GetRemaining(), want)
	}
	for _, addr := range p.GetRemaining() {
		if addr == wantTargets[0] {
			t.Errorf("remaining contains first hop %q (self-loop)", addr)
		}
		if addr == finalURL {
			t.Errorf("remaining contains final_url %q", addr)
		}
	}
	if p.GetFinalUrl() != finalURL {
		t.Errorf("final_url = %q, want %q", p.GetFinalUrl(), finalURL)
	}
	// exp = 签发时刻 + 30s × 地址总数（首跳 + remaining 个数 + final_url）。
	if want := syncFixedNow().Add(30 * time.Second * time.Duration(len(domains)+1)).Unix(); p.GetExp() != want {
		t.Errorf("exp = %d, want %d", p.GetExp(), want)
	}
}

func TestSyncCookieBuildSingleDomain(t *testing.T) {
	codec := syncTestCodec(t)
	b := NewSyncCookieURLBuilder(codec)
	b.Now = syncFixedNow

	const finalURL = "https://final.example"
	raw, err := b.Build(context.Background(), "al_session", "v", "0", []string{"a.example"}, finalURL)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	first, payload := splitSyncURL(t, raw)
	if want := "https://a.example/sso/sync_cookie"; first != want {
		t.Errorf("first hop = %q, want %q", first, want)
	}
	p, err := security.Open[token.SyncCookiePayload](codec, security.PurposeSyncPayload, payload)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(p.GetRemaining()) != 0 {
		t.Errorf("remaining = %v, want empty", p.GetRemaining())
	}
	if p.GetFinalUrl() != finalURL {
		t.Errorf("final_url = %q, want %q", p.GetFinalUrl(), finalURL)
	}
	if want := syncFixedNow().Add(60 * time.Second).Unix(); p.GetExp() != want {
		t.Errorf("exp = %d, want %d", p.GetExp(), want)
	}
}

func TestSyncCookieCrossPurposeOpenFails(t *testing.T) {
	codec := syncTestCodec(t)
	b := NewSyncCookieURLBuilder(codec)
	b.Now = syncFixedNow

	_, payload := splitSyncURL(t, mustBuild(t, b))

	if _, err := security.Open[token.SyncCookiePayload](codec, security.PurposeSession, payload); err == nil {
		t.Fatal("cross-purpose Open succeeded, want failure")
	}
}

func mustBuild(t *testing.T, b *SyncCookieURLBuilder) string {
	t.Helper()
	raw, err := b.Build(context.Background(), "al_session", "v", "604800", []string{"a.example"}, "https://final.example")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return raw
}
