// local_test.go local 实现磁盘行为：Put 写盘 + URL 拼接（含 path_prefix）、
// Get 回读、Delete 幂等、路径穿越防护、PresignPut 恒错误。目录用
// t.TempDir，不碰真实部署路径。
package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	providerpb "authloft/gen/go/provider"
)

func newLocal(t *testing.T, dir, prefix, domain string) *Local {
	t.Helper()
	l, err := NewLocal(&providerpb.Ext{Bucket: dir, PathPrefix: prefix, Domain: domain})
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}
	return l
}

// TestLocalPutGetURL 写盘 + 公开 URL + 回读三件一致。
func TestLocalPutGetURL(t *testing.T) {
	dir := t.TempDir()
	l := newLocal(t, dir, "qr", "https://cdn.example.com")

	url, err := l.Put(context.Background(), "q1.jpg", []byte("jpeg-bytes"), "image/jpeg")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if url != "https://cdn.example.com/qr/q1.jpg" {
		t.Fatalf("url = %q", url)
	}
	body, err := l.Get(context.Background(), "q1.jpg")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(body) != "jpeg-bytes" {
		t.Fatalf("body = %q", body)
	}
	if _, err := os.Stat(filepath.Join(dir, "qr", "q1.jpg")); err != nil {
		t.Fatalf("磁盘文件缺失: %v", err)
	}
}

// TestLocalPutWithoutPrefix path_prefix 为空时 URL 不出现空段。
func TestLocalPutWithoutPrefix(t *testing.T) {
	l := newLocal(t, t.TempDir(), "", "https://s.example.com")
	url, err := l.Put(context.Background(), "a.jpg", []byte("x"), "image/jpeg")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if url != "https://s.example.com/a.jpg" || strings.Contains(url, "//a") {
		t.Fatalf("url = %q", url)
	}
}

// TestLocalDeleteIdempotent 删除成功后重复删除不报错（§13.3 幂等）。
func TestLocalDeleteIdempotent(t *testing.T) {
	l := newLocal(t, t.TempDir(), "", "https://s.example.com")
	if _, err := l.Put(context.Background(), "k.jpg", []byte("x"), "image/jpeg"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := l.Delete(context.Background(), "k.jpg"); err != nil {
			t.Fatalf("Delete #%d: %v", i, err)
		}
	}
}

// TestLocalKeyGuard 穿越防护：空 / 绝对 / .. 段 / 反斜杠 / 盘符。
func TestLocalKeyGuard(t *testing.T) {
	l := newLocal(t, t.TempDir(), "", "https://s.example.com")
	for _, key := range []string{"", "/abs.jpg", "../escape.jpg", "a/../../b.jpg", `a\b.jpg`, "C:ev.jpg"} {
		if _, err := l.Put(context.Background(), key, []byte("x"), "image/jpeg"); err == nil {
			t.Errorf("Put(%q) 应被拒绝", key)
		}
		if err := l.Delete(context.Background(), key); err == nil {
			t.Errorf("Delete(%q) 应被拒绝", key)
		}
	}
}

// TestLocalPresignNotSupported local 无预签名能力（§15.1）。
func TestLocalPresignNotSupported(t *testing.T) {
	l := newLocal(t, t.TempDir(), "", "https://s.example.com")
	_, _, err := l.PresignPut(context.Background(), "k", "image/jpeg", 10)
	if !errors.Is(err, ErrPresignNotSupported) {
		t.Fatalf("err = %v, want ErrPresignNotSupported", err)
	}
}

// TestNewLocalNotConfigured bucket / domain 为空即未配置。
func TestNewLocalNotConfigured(t *testing.T) {
	for _, ext := range []*providerpb.Ext{
		nil,
		{Bucket: "/data"},
		{Domain: "https://cdn.example.com"},
	} {
		if _, err := NewLocal(ext); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("NewLocal(%+v) err = %v, want ErrNotConfigured", ext, err)
		}
	}
}
