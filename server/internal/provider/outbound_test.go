// 出站代理引用解析单测（后端架构 §15.4 / 接口文档 §5.3）：Loader 装配期解析
// 七场景——正常解析 / 引用未启用 / 引用缺失 / 类别不符 / 字段组合非法 / proxy
// 行自引防护 / 版本失效重解析换池，Pools 装配挂载，以及共享助手 ResolveOutbound
// 同语义（captcha 投影、admin TestProvider 等非 Loader 路径复用）。
package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/proxyclient"
	"authloft/internal/repo/model"
)

// proxyRow 构造 category=proxy 行。
func proxyRow(t *testing.T, key string, enabled int8, ext *providerpb.Ext) *model.Provider {
	t.Helper()
	return &model.Provider{ProviderKey: key, Type: "proxy", Category: "proxy", IsEnabled: enabled, Ext: mustExt(t, ext)}
}

// refRow 构造携带 proxy_provider_key 的引用方行（oauth 渠道形态）。
func refRow(t *testing.T, key, ref string) *model.Provider {
	t.Helper()
	return &model.Provider{ProviderKey: key, Type: "wechat_mp", Category: "oauth", IsEnabled: 1,
		Ext: mustExt(t, &providerpb.Ext{ProxyProviderKey: ref})}
}

// proxyExt 一个 socks5 代理行的 Ext（host 恒定，便于按 port / 凭据区分场景）。
func proxyExt(port int32, user, password string) *providerpb.Ext {
	return &providerpb.Ext{Scheme: "socks5", Host: "10.0.0.8", Port: port, User: user, Password: password}
}

func newTestLoaderWithPools(src *fakeSource, rowCache RowCache, clock *fakeClock) *Loader {
	return NewLoader(src, rowCache, proxyclient.NewPoolSet(), providerOptions(clock, 60*time.Second, 5*time.Second))
}

// TestLoaderResolveOutboundNormal 正常解析：Outbound 固化为按 proxy 行 key
// 键控的池（配置与被引行一致、同 key 命中同池），Pools 挂载为注入实例，
// LRU 命中路径池指针稳定。
func TestLoaderResolveOutboundNormal(t *testing.T) {
	src := newFakeSource(
		refRow(t, "app", "pxy"),
		proxyRow(t, "pxy", 1, proxyExt(1080, "u", "p")),
	)
	loader := newTestLoaderWithPools(src, nil, newFakeClock())

	p, err := loader.Get(context.Background(), "app")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.Pools == nil {
		t.Fatal("Pools 未挂载")
	}
	if p.Outbound == nil {
		t.Fatal("引用非空应解析出池")
	}
	wantCfg, err := proxyclient.NewConfig("socks5", "10.0.0.8", 1080, "u", "p")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Outbound.Config(); !got.Equal(wantCfg) {
		t.Fatalf("池配置 = %+v, want %+v", got, wantCfg)
	}
	if p.Outbound != p.Pools.Get("pxy", wantCfg) {
		t.Fatal("池应按 proxy 行 key 键控、全部引用方共享")
	}
	again, err := loader.Get(context.Background(), "app")
	if err != nil || again.Outbound != p.Outbound {
		t.Fatalf("LRU 命中应复用同池: (%v)", err)
	}
}

// TestLoaderResolveOutboundDisabled 引用未启用：fail-closed，包装哨兵。
func TestLoaderResolveOutboundDisabled(t *testing.T) {
	src := newFakeSource(
		refRow(t, "app", "pxy"),
		proxyRow(t, "pxy", 0, proxyExt(1080, "", "")),
	)
	loader := newTestLoaderWithPools(src, nil, newFakeClock())
	_, err := loader.Get(context.Background(), "app")
	if !errors.Is(err, ErrProxyRefUnresolvable) {
		t.Fatalf("err = %v, want ErrProxyRefUnresolvable", err)
	}
}

// TestLoaderResolveOutboundMissing 引用缺失：fail-closed，包装哨兵。
func TestLoaderResolveOutboundMissing(t *testing.T) {
	src := newFakeSource(refRow(t, "app", "ghost"))
	loader := newTestLoaderWithPools(src, nil, newFakeClock())
	_, err := loader.Get(context.Background(), "app")
	if !errors.Is(err, ErrProxyRefUnresolvable) {
		t.Fatalf("err = %v, want ErrProxyRefUnresolvable", err)
	}
}

// TestLoaderResolveOutboundCategoryMismatch 被引行类别不符（非 proxy）：
// fail-closed，包装哨兵。
func TestLoaderResolveOutboundCategoryMismatch(t *testing.T) {
	src := newFakeSource(
		refRow(t, "app", "pxy"),
		&model.Provider{ProviderKey: "pxy", Type: "qq", Category: "oauth", IsEnabled: 1,
			Ext: mustExt(t, proxyExt(1080, "", ""))},
	)
	loader := newTestLoaderWithPools(src, nil, newFakeClock())
	_, err := loader.Get(context.Background(), "app")
	if !errors.Is(err, ErrProxyRefUnresolvable) {
		t.Fatalf("err = %v, want ErrProxyRefUnresolvable", err)
	}
}

// TestLoaderResolveOutboundInvalidCombo 被引行字段组合非法（有 password 无
// user）：运行期与保存期同一规则源拦截，fail-closed 包装哨兵。
func TestLoaderResolveOutboundInvalidCombo(t *testing.T) {
	src := newFakeSource(
		refRow(t, "app", "pxy"),
		proxyRow(t, "pxy", 1, proxyExt(1080, "", "only-pass")),
	)
	loader := newTestLoaderWithPools(src, nil, newFakeClock())
	_, err := loader.Get(context.Background(), "app")
	if !errors.Is(err, ErrProxyRefUnresolvable) {
		t.Fatalf("err = %v, want ErrProxyRefUnresolvable", err)
	}
}

// TestLoaderResolveOutboundSelfRefSkipped proxy 行自身携带引用键：自引防护
// 跳过解析（防环），加载成功且 Outbound 保持 nil、Pools 已挂载。
func TestLoaderResolveOutboundSelfRefSkipped(t *testing.T) {
	self := proxyExt(1080, "", "")
	self.ProxyProviderKey = "pxy"
	src := newFakeSource(proxyRow(t, "pxy", 1, self))
	loader := newTestLoaderWithPools(src, nil, newFakeClock())

	p, err := loader.Get(context.Background(), "pxy")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.Outbound != nil {
		t.Fatal("proxy 行自身应跳过解析（自引防护），Outbound 保持 nil")
	}
	if p.Pools == nil {
		t.Fatal("Pools 仍应挂载")
	}
}

// TestLoaderResolveOutboundVersionInvalidates 代理行改动经版本失效链触发
// 重解析：新配置生效并换池（旧池排空归 PoolSet 语义，此处锁指针变更）。
func TestLoaderResolveOutboundVersionInvalidates(t *testing.T) {
	clock := newFakeClock()
	src := newFakeSource(
		refRow(t, "app", "pxy"),
		proxyRow(t, "pxy", 1, proxyExt(1080, "", "")),
	)
	rowCache := &fakeRowCache{version: 1}
	loader := newTestLoaderWithPools(src, rowCache, clock)

	ctx := context.Background()
	p1, err := loader.Get(ctx, "app")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p1.Outbound == nil || p1.Outbound.Config().Port != 1080 {
		t.Fatalf("首次解析池配置 = %+v, want port 1080", p1.Outbound.Config())
	}
	oldPool := p1.Outbound

	// 代理行改端口：写源 + DEL 行缓存 + INCR 版本（app 与 pxy 两行都经
	// Redis 整行缓存回源，均需失效），越过版本节流窗后重新加载。
	src.set(refRow(t, "app", "pxy"))
	src.set(proxyRow(t, "pxy", 1, proxyExt(1081, "", "")))
	rowCache.invalidate("app")
	rowCache.invalidate("pxy")
	clock.advance(6 * time.Second)

	p2, err := loader.Get(ctx, "app")
	if err != nil {
		t.Fatalf("Get after invalidation: %v", err)
	}
	if p2.Outbound == nil || p2.Outbound.Config().Port != 1081 {
		t.Fatalf("重解析后池配置 = %+v, want port 1081", p2.Outbound.Config())
	}
	if p2.Outbound == oldPool {
		t.Fatal("配置变更应换池（旧池排空、新池生效）")
	}
}

// TestResolveOutboundHelper 共享助手（非 Loader 路径）同语义：空 key 直连、
// 正常解析出键控池、引用未启用 fail-closed、proxy 行自引防护跳过、nil
// PoolSet fail-fast panic。
func TestResolveOutboundHelper(t *testing.T) {
	ctx := context.Background()
	src := newFakeSource(
		refRow(t, "app", "pxy"),
		proxyRow(t, "pxy", 1, proxyExt(1080, "", "")),
		proxyRow(t, "off", 0, proxyExt(1080, "", "")),
	)
	pools := proxyclient.NewPoolSet()
	appRow := refRow(t, "app", "pxy")
	pxyRow := proxyRow(t, "pxy", 1, proxyExt(1080, "", ""))

	pool, err := ResolveOutbound(ctx, pools, src, appRow, &providerpb.Ext{})
	if err != nil || pool != nil {
		t.Fatalf("空 key 应直连: (pool=%p, err=%v)", pool, err)
	}
	pool, err = ResolveOutbound(ctx, pools, src, appRow, &providerpb.Ext{ProxyProviderKey: "pxy"})
	if err != nil || pool == nil {
		t.Fatalf("正常引用应解析出池: (pool=%p, err=%v)", pool, err)
	}
	wantCfg, err := proxyclient.NewConfig("socks5", "10.0.0.8", 1080, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !pool.Config().Equal(wantCfg) {
		t.Fatalf("池配置 = %+v, want %+v", pool.Config(), wantCfg)
	}
	if pool != pools.Get("pxy", wantCfg) {
		t.Fatal("助手与 Loader 应共享同一键控池")
	}
	if _, err := ResolveOutbound(ctx, pools, src, appRow, &providerpb.Ext{ProxyProviderKey: "off"}); !errors.Is(err, ErrProxyRefUnresolvable) {
		t.Fatalf("err = %v, want ErrProxyRefUnresolvable", err)
	}
	pool, err = ResolveOutbound(ctx, pools, src, pxyRow, &providerpb.Ext{ProxyProviderKey: "pxy"})
	if err != nil || pool != nil {
		t.Fatalf("proxy 行自身应跳过解析: (pool=%p, err=%v)", pool, err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("nil PoolSet 应 panic fail-fast")
			}
		}()
		_, _ = ResolveOutbound(ctx, nil, src, appRow, &providerpb.Ext{ProxyProviderKey: "pxy"})
	}()
}
