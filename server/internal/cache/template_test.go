// 模板 content 缓存单测（§5.1）：键名 al:tpl:v:{key}、GET miss 返回
// ok=false、SET TTL 600s、Invalidate 单步 DEL（不 INCR、不 PUBLISH）。
// 用实现窄接口的 fake，本地可跑、不连 Redis。
package cache

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fakeTemplateRedis 实现 templateRedis 窄接口并记录操作。
type fakeTemplateRedis struct {
	mu     sync.Mutex
	ops    []string
	vals   map[string]string
	ttls   map[string]time.Duration
	getErr error
	delErr error
}

func newFakeTemplateRedis() *fakeTemplateRedis {
	return &fakeTemplateRedis{vals: map[string]string{}, ttls: map[string]time.Duration{}}
}

func (f *fakeTemplateRedis) Get(ctx context.Context, key string) *redis.StringCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, "GET "+key)
	cmd := redis.NewStringCmd(ctx)
	if f.getErr != nil {
		cmd.SetErr(f.getErr)
		return cmd
	}
	if v, ok := f.vals[key]; ok {
		cmd.SetVal(v)
	} else {
		cmd.SetErr(redis.Nil)
	}
	return cmd
}

func (f *fakeTemplateRedis) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, "SET "+key)
	f.vals[key] = fmt.Sprint(value)
	f.ttls[key] = expiration
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetVal("OK")
	return cmd
}

func (f *fakeTemplateRedis) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := redis.NewIntCmd(ctx)
	if f.delErr != nil {
		cmd.SetErr(f.delErr)
		return cmd
	}
	for _, k := range keys {
		f.ops = append(f.ops, "DEL "+k)
		delete(f.vals, k)
	}
	cmd.SetVal(int64(len(keys)))
	return cmd
}

// TestTemplateRowKey 键名唯一出处（§5.1）。
func TestTemplateRowKey(t *testing.T) {
	if got, want := TemplateRowKey("login"), "al:tpl:v:login"; got != want {
		t.Errorf("TemplateRowKey = %q, want %q", got, want)
	}
}

// TestTemplateCacheGetSetInvalidate 覆盖 miss / 命中 / TTL / 单步 DEL。
func TestTemplateCacheGetSetInvalidate(t *testing.T) {
	ctx := context.Background()
	f := newFakeTemplateRedis()
	c := NewTemplateCache(f)

	if _, ok, err := c.Get(ctx, "login"); err != nil || ok {
		t.Fatalf("miss: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	content := "<html>hi</html>"
	if err := c.SetRow(ctx, "login", content); err != nil {
		t.Fatalf("SetRow: %v", err)
	}
	if got := f.ttls[TemplateRowKey("login")]; got != 600*time.Second {
		t.Errorf("TTL = %v, want 600s", got)
	}
	if got, ok, err := c.Get(ctx, "login"); err != nil || !ok || got != content {
		t.Fatalf("hit: got=%q ok=%v err=%v, want %q true nil", got, ok, err, content)
	}

	if err := c.Invalidate(ctx, "login"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	if _, ok, _ := c.Get(ctx, "login"); ok {
		t.Error("Invalidate 后仍命中")
	}
	for _, op := range f.ops {
		if strings.HasPrefix(op, "INCR") || strings.HasPrefix(op, "PUBLISH") {
			t.Errorf("Invalidate 不应产生 %q", op)
		}
	}
}

// TestTemplateCacheErrors GET / DEL 错误原样包装，不吞错。
func TestTemplateCacheErrors(t *testing.T) {
	ctx := context.Background()
	f := newFakeTemplateRedis()
	c := NewTemplateCache(f)

	f.getErr = fmt.Errorf("boom")
	if _, ok, err := c.Get(ctx, "k"); err == nil || ok {
		t.Errorf("GET 错误: ok=%v err=%v, want ok=false err!=nil", ok, err)
	}
	f.delErr = fmt.Errorf("boom")
	if err := c.Invalidate(ctx, "k"); err == nil {
		t.Error("DEL 错误应返回非 nil")
	}
}
