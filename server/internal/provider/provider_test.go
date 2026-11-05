// Provider 加载 / 注册表 / 白名单单测：本地 LRU TTL、版本失效、
// singleflight 结果正确性、Redis 整行缓存可选路径、按 type 列表，以及
// Referer 白名单只含已启用且 app_id 非空的 mp 实例。
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// fakeClock 可推进的测试时钟。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeSource 内存 RowSource，记录回源次数。
type fakeSource struct {
	mu        sync.Mutex
	rows      map[string]*model.Provider
	findCalls int
	listCalls int
}

func newFakeSource(rows ...*model.Provider) *fakeSource {
	s := &fakeSource{rows: make(map[string]*model.Provider)}
	for _, r := range rows {
		s.rows[r.ProviderKey] = r
	}
	return s
}

func (s *fakeSource) FindByKey(_ context.Context, providerKey string) (*model.Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findCalls++
	row, ok := s.rows[providerKey]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	return row, nil
}

func (s *fakeSource) ListProviders(_ context.Context, q repo.ProviderListQuery) ([]model.Provider, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listCalls++
	var out []model.Provider
	for _, row := range s.rows {
		if q.Type != nil && row.Type != *q.Type {
			continue
		}
		if q.IsEnabled != nil && row.IsEnabled != *q.IsEnabled {
			continue
		}
		out = append(out, *row)
	}
	return out, int64(len(out)), nil
}

func (s *fakeSource) set(row *model.Provider) {
	s.mu.Lock()
	s.rows[row.ProviderKey] = row
	s.mu.Unlock()
}

func (s *fakeSource) counts() (find, list int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findCalls, s.listCalls
}

// fakeRowCache 内存 RowCache，实现版本号 + 整行缓存。
type fakeRowCache struct {
	mu      sync.Mutex
	rows    map[string][]byte
	version int64
	gets    int
	sets    int
	verGets int
	getErr  error
}

func (c *fakeRowCache) GetRow(_ context.Context, providerKey string) ([]byte, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets++
	if c.getErr != nil {
		return nil, false, c.getErr
	}
	raw, ok := c.rows[providerKey]
	return raw, ok, nil
}

func (c *fakeRowCache) SetRow(_ context.Context, providerKey string, raw []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sets++
	if c.rows == nil {
		c.rows = make(map[string][]byte)
	}
	c.rows[providerKey] = raw
	return nil
}

func (c *fakeRowCache) Version(_ context.Context) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verGets++
	if c.getErr != nil {
		return 0, c.getErr
	}
	return c.version, nil
}

// invalidate 模拟后台写 Provider 的三步（DEL 行 + INCR 版本）。
func (c *fakeRowCache) invalidate(providerKey string) {
	c.mu.Lock()
	delete(c.rows, providerKey)
	c.version++
	c.mu.Unlock()
}

func (c *fakeRowCache) cacheRow(providerKey string, row *model.Provider) {
	raw, err := json.Marshal(row)
	if err != nil {
		panic(err)
	}
	c.SetRow(context.Background(), providerKey, raw)
}

// mustExt 用项目唯一出口 repo.MarshalProviderExt 生成 ext 列字节。
func mustExt(t *testing.T, ext *providerpb.Ext) []byte {
	t.Helper()
	raw, err := repo.MarshalProviderExt(ext)
	if err != nil {
		t.Fatalf("MarshalProviderExt: %v", err)
	}
	return raw
}

// makeRow 构造一行测试 Provider。
func makeRow(t *testing.T, key, typ, appID, secret string, enabled int8) *model.Provider {
	t.Helper()
	return &model.Provider{
		ProviderKey: key,
		Type:        typ,
		Category:    "oauth",
		IsEnabled:   enabled,
		Ext:         mustExt(t, &providerpb.Ext{AppId: appID, ClientSecret: secret}),
	}
}

func providerOptions(clock *fakeClock, ttl, verRefresh time.Duration) LoaderOptions {
	return LoaderOptions{LocalTTL: ttl, VersionRefresh: verRefresh, Now: clock.now}
}

// TestLoaderGetLocalTTL：本地 LRU 命中不重复回源；TTL 到期后重新回源。
func TestLoaderGetLocalTTL(t *testing.T) {
	clock := newFakeClock()
	row := makeRow(t, "wx_a", "wechat_mp", "app-a", "secret-a", 1)
	src := newFakeSource(row)
	loader := NewLoader(src, nil, providerOptions(clock, 60*time.Second, 5*time.Second))

	ctx := context.Background()
	if p, err := loader.Get(ctx, "wx_a"); err != nil || p.Ext.GetAppId() != "app-a" {
		t.Fatalf("Get = (%v, %v), want app-a", p, err)
	}
	if find, _ := src.counts(); find != 1 {
		t.Fatalf("find calls = %d, want 1", find)
	}

	if _, err := loader.Get(ctx, "wx_a"); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if find, _ := src.counts(); find != 1 {
		t.Fatalf("find calls after cache hit = %d, want 1", find)
	}

	clock.advance(61 * time.Second)
	if _, err := loader.Get(ctx, "wx_a"); err != nil {
		t.Fatalf("Get after TTL: %v", err)
	}
	if find, _ := src.counts(); find != 2 {
		t.Fatalf("find calls after TTL = %d, want 2（TTL 60s 后重新回源）", find)
	}
}

// TestLoaderVersionInvalidates：版本号变化清空本地 LRU，下一次读取拿到新值。
func TestLoaderVersionInvalidates(t *testing.T) {
	clock := newFakeClock()
	oldRow := makeRow(t, "wx_a", "wechat_mp", "app-old", "secret-old", 1)
	src := newFakeSource(oldRow)
	rowCache := &fakeRowCache{version: 1}
	loader := NewLoader(src, rowCache, providerOptions(clock, 60*time.Second, 5*time.Second))

	ctx := context.Background()
	if _, err := loader.Get(ctx, "wx_a"); err != nil {
		t.Fatalf("Get: %v", err)
	}

	// 后台写 Provider：改数据 + DEL 行缓存 + INCR 版本。
	src.set(makeRow(t, "wx_a", "wechat_mp", "app-new", "secret-new", 1))
	rowCache.invalidate("wx_a")
	clock.advance(6 * time.Second) // 超过 VersionRefresh 节流窗口

	p, err := loader.Get(ctx, "wx_a")
	if err != nil {
		t.Fatalf("Get after version bump: %v", err)
	}
	if p.Ext.GetAppId() != "app-new" {
		t.Fatalf("app_id = %q, want app-new（版本失效后重新加载）", p.Ext.GetAppId())
	}
	if find, _ := src.counts(); find != 2 {
		t.Fatalf("find calls = %d, want 2", find)
	}
}

// TestLoaderRedisRowCache：本地 miss 时优先命中 Redis 整行缓存，不回源 repo。
func TestLoaderRedisRowCache(t *testing.T) {
	clock := newFakeClock()
	row := makeRow(t, "wx_a", "wechat_mp", "app-a", "secret-a", 1)
	src := newFakeSource(row)
	rowCache := &fakeRowCache{version: 1}
	rowCache.cacheRow("wx_a", row)

	loader := NewLoader(src, rowCache, providerOptions(clock, 60*time.Second, 5*time.Second))
	p, err := loader.Get(context.Background(), "wx_a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if p.Ext.GetAppId() != "app-a" {
		t.Fatalf("app_id = %q, want app-a", p.Ext.GetAppId())
	}
	if find, _ := src.counts(); find != 0 {
		t.Fatalf("find calls = %d, want 0（Redis 整行缓存命中）", find)
	}
}

// TestLoaderRedisFailureDegrades：Redis 读取故障时降级回源 repo。
func TestLoaderRedisFailureDegrades(t *testing.T) {
	clock := newFakeClock()
	row := makeRow(t, "wx_a", "wechat_mp", "app-a", "secret-a", 1)
	src := newFakeSource(row)
	rowCache := &fakeRowCache{getErr: errors.New("redis down")}
	loader := NewLoader(src, rowCache, providerOptions(clock, 60*time.Second, 5*time.Second))

	p, err := loader.Get(context.Background(), "wx_a")
	if err != nil || p.Ext.GetAppId() != "app-a" {
		t.Fatalf("Get = (%v, %v), want app-a（Redis 故障降级 repo）", p, err)
	}
}

// TestLoaderListByType：按 type 过滤、分页聚合、结果走本地缓存。
func TestLoaderListByType(t *testing.T) {
	clock := newFakeClock()
	a := makeRow(t, "wx_a", "wechat_mp", "app-a", "sa", 1)
	b := makeRow(t, "wx_b", "wechat_mp", "app-b", "sb", 0)
	other := makeRow(t, "wx_c", "wechat_mp_scan", "app-c", "sc", 1)
	src := newFakeSource(a, b, other)
	loader := NewLoader(src, nil, providerOptions(clock, 60*time.Second, 5*time.Second))

	ps, err := loader.ListByType(context.Background(), "wechat_mp")
	if err != nil {
		t.Fatalf("ListByType: %v", err)
	}
	if len(ps) != 2 || ps[0].Ext.GetAppId() == "" || ps[1].Ext.GetAppId() == "" {
		t.Fatalf("providers = %+v, want 2 wechat_mp rows", ps)
	}
	if _, err := loader.ListByType(context.Background(), "wechat_mp"); err != nil {
		t.Fatalf("ListByType second: %v", err)
	}
	if _, list := src.counts(); list != 1 {
		t.Fatalf("list calls = %d, want 1（本地缓存命中）", list)
	}
}

// TestWhitelistFiltersEnabledAndAppID：白名单只含已启用且 app_id 非空的
// wechat_mp / wechat_mp_scan 实例，去重排序。
func TestWhitelistFiltersEnabledAndAppID(t *testing.T) {
	clock := newFakeClock()
	rows := []*model.Provider{
		makeRow(t, "mp1", "wechat_mp", "wx1", "s1", 1),
		makeRow(t, "mp2", "wechat_mp_scan", "wx2", "s2", 1),
		makeRow(t, "mp3", "wechat_mp", "wx3", "s3", 0), // 未启用
		makeRow(t, "mp4", "wechat_mp", "", "s4", 1),    // app_id 空
		makeRow(t, "qq1", "qq", "wx5", "s5", 1),        // 非 mp 类型
		makeRow(t, "mp5", "wechat_mp_scan", "wx1", "s6", 1),
	}
	src := newFakeSource(rows...)
	loader := NewLoader(src, nil, providerOptions(clock, 60*time.Second, 5*time.Second))
	wl := newWhitelist(loader, 60*time.Second, clock.now)

	ids, err := wl.AppIDs(context.Background())
	if err != nil {
		t.Fatalf("AppIDs: %v", err)
	}
	want := []string{"wx1", "wx2"}
	if len(ids) != len(want) || ids[0] != want[0] || ids[1] != want[1] {
		t.Fatalf("AppIDs = %v, want %v", ids, want)
	}

	// 二次调用命中 60s 缓存，不重复 list。
	_, _ = wl.AppIDs(context.Background())
	if _, list := src.counts(); list != 2 {
		t.Fatalf("list calls = %d, want 2（两类各一次，白名单缓存命中）", list)
	}
}

// TestWhitelistVersionInvalidates：版本号变化立即重载，不等 60s TTL。
func TestWhitelistVersionInvalidates(t *testing.T) {
	clock := newFakeClock()
	row := makeRow(t, "mp1", "wechat_mp", "wx1", "s1", 1)
	src := newFakeSource(row)
	rowCache := &fakeRowCache{version: 1}
	loader := NewLoader(src, rowCache, providerOptions(clock, 60*time.Second, 5*time.Second))
	wl := newWhitelist(loader, 60*time.Second, clock.now)

	if ids, err := wl.AppIDs(context.Background()); err != nil || len(ids) != 1 || ids[0] != "wx1" {
		t.Fatalf("AppIDs = (%v, %v), want [wx1]", ids, err)
	}

	src.set(makeRow(t, "mp1", "wechat_mp", "wx9", "s9", 1))
	rowCache.invalidate("mp1")
	clock.advance(6 * time.Second)

	ids, err := wl.AppIDs(context.Background())
	if err != nil {
		t.Fatalf("AppIDs after version bump: %v", err)
	}
	if len(ids) != 1 || ids[0] != "wx9" {
		t.Fatalf("AppIDs = %v, want [wx9]（版本号变化立即失效）", ids)
	}
}

// TestWhitelistVersionErrorUsesCache：版本号读取失败但缓存未过期时降级使用。
func TestWhitelistVersionErrorUsesCache(t *testing.T) {
	clock := newFakeClock()
	row := makeRow(t, "mp1", "wechat_mp", "wx1", "s1", 1)
	src := newFakeSource(row)
	rowCache := &fakeRowCache{version: 1}
	loader := NewLoader(src, rowCache, providerOptions(clock, 60*time.Second, 5*time.Second))
	wl := newWhitelist(loader, 60*time.Second, clock.now)

	if _, err := wl.AppIDs(context.Background()); err != nil {
		t.Fatalf("AppIDs: %v", err)
	}
	rowCache.mu.Lock()
	rowCache.getErr = errors.New("redis down")
	rowCache.version = 2
	rowCache.mu.Unlock()
	clock.advance(6 * time.Second)

	ids, err := wl.AppIDs(context.Background())
	if err != nil || len(ids) != 1 || ids[0] != "wx1" {
		t.Fatalf("AppIDs = (%v, %v), want cached [wx1]（版本读取失败降级）", ids, err)
	}
}

// TestRegistryRegisterAndFactory：注册、查表（含 Fields 字段级声明透传）、
// 工厂调用与错误分支。
func TestRegistryRegisterAndFactory(t *testing.T) {
	const typ = "test_registry_ok"
	seen := ""
	fields := []FieldMeta{{Key: "client_id", Label: "AppID", Type: "text", Section: "credential", Required: true}}
	meta := Meta{Type: typ, DisplayName: "测试渠道", Category: "oauth", Channel: ChannelAPI, Fields: fields}
	if err := register(typ, meta, func(p *Provider) (AuthAdapter, error) {
		seen = p.Key + ":" + p.Ext.GetAppId()
		return ChannelAPIAdapter{}, nil
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := register(typ, meta, func(*Provider) (AuthAdapter, error) { return nil, nil }); !errors.Is(err, ErrAlreadyRegistered) {
		t.Fatalf("duplicate register err = %v, want ErrAlreadyRegistered", err)
	}

	got, ok := Lookup(typ)
	if !ok || got.DisplayName != "测试渠道" || got.Channel != ChannelAPI {
		t.Fatalf("Lookup = (%+v, %v)", got, ok)
	}
	if len(got.Fields) != 1 || got.Fields[0] != fields[0] {
		t.Fatalf("Lookup Fields = %+v, want %+v（字段级声明随 meta 透传）", got.Fields, fields)
	}

	p := &Provider{Key: "k1", Type: typ, Ext: &providerpb.Ext{AppId: "wx-k1"}}
	a, err := NewAdapter(p)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	if a.Channel() != ChannelAPI {
		t.Fatalf("Channel = %q, want api", a.Channel())
	}
	if seen != "k1:wx-k1" {
		t.Fatalf("factory saw %q, want k1:wx-k1", seen)
	}

	if _, err := NewAdapter(&Provider{Type: "test_registry_unknown"}); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("unknown type err = %v, want ErrUnknownType", err)
	}
	if _, err := NewAdapter(nil); !errors.Is(err, ErrNilProvider) {
		t.Fatalf("nil provider err = %v, want ErrNilProvider", err)
	}
}

// TestRegistryNilFactory 注册空工厂返回 ErrNilFactory。
func TestRegistryNilFactory(t *testing.T) {
	if err := register("test_registry_nilfactory", Meta{}, nil); !errors.Is(err, ErrNilFactory) {
		t.Fatalf("err = %v, want ErrNilFactory", err)
	}
}

// TestFlightGroupPanicThenRetry fn panic 时 do 必须重抛、且清理 calls 项
// 与 WaitGroup（否则同 key 的后续请求会在残留项上永久阻塞），重试同 key
// 应拿到新结果。
func TestFlightGroupPanicThenRetry(t *testing.T) {
	g := &flightGroup{}

	// 第一次调用 fn panic：重抛的 panic 在此捕获，不能打死测试进程。
	func() {
		defer func() {
			if r := recover(); r != "boom" {
				t.Fatalf("do 应重抛 panic, recover = %v", r)
			}
		}()
		g.do("k", func() (any, error) { panic("boom") })
	}()

	// 若 panic 路径未删表，此请求会永久等待；带超时兜底断言。
	done := make(chan struct{})
	go func() {
		defer close(done)
		v, err := g.do("k", func() (any, error) { return "ok", nil })
		if err != nil || v != "ok" {
			t.Errorf("panic 后同 key 重试 = (%v, %v), want (\"ok\", nil)", v, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("panic 后同 key 请求被永久阻塞：calls 项未清理")
	}
}

// TestFlightGroupPanicReleasesWaiters leader 的 fn panic 时，正在等待同
// key 的 follower 应被放行并拿到错误，而非永久阻塞。
func TestFlightGroupPanicReleasesWaiters(t *testing.T) {
	g := &flightGroup{}
	release := make(chan struct{})
	started := make(chan struct{})

	leaderDone := make(chan any, 1)
	go func() {
		defer func() { leaderDone <- recover() }()
		g.do("k", func() (any, error) {
			close(started)
			<-release
			panic("boom")
		})
	}()
	<-started

	followerDone := make(chan struct{})
	go func() {
		defer close(followerDone)
		v, err := g.do("k", func() (any, error) { return "new", nil })
		// leader 清理放行 → (nil, panic 错误)；若 follower 迟到成为
		// 新一轮 leader 则拿到 ("new", nil)。两者均合法，关键是
		// 不能阻塞，也不能拿到 (nil, nil)。
		if err == nil && v != "new" {
			t.Errorf("follower = (%v, %v)", v, err)
		}
	}()
	// 给 follower 时间进入 wg.Wait（此刻 leader 尚未返回，calls 项必在）。
	time.Sleep(100 * time.Millisecond)
	close(release)

	select {
	case <-followerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("leader panic 后 follower 被永久阻塞")
	}
	if r := <-leaderDone; r != "boom" {
		t.Fatalf("leader 应重抛 panic, got %v", r)
	}
}

// ChannelAPIAdapter 仅用于注册表测试的最小适配器。
type ChannelAPIAdapter struct{}

func (ChannelAPIAdapter) Channel() ThirdPartyChannel { return ChannelAPI }
func (ChannelAPIAdapter) BuildAuthURL(*AuthContext) (string, error) {
	return "", nil
}
func (ChannelAPIAdapter) Exchange(context.Context, ExchangeInput) (*Token, error) {
	return nil, nil
}
func (ChannelAPIAdapter) FetchUser(context.Context, *Token) (*ExternalIdentity, error) {
	return nil, nil
}
