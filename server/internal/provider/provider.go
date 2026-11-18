// Provider 实体加载与缓存（docs/后端架构.md §3.9、§15.3）：
// 本地 LRU + singleflight（TTL 60s），版本号 al:prov:ver 变化时整体失效；
// Redis al:prov:v:{key}（600s）作为可选的整行缓存，只在本地未命中时读取。
//
// 取舍（文档未明确两级缓存的关系，以 §15.3 为准）：
//   - 本地 LRU 是主缓存，TTL 60s；
//   - Redis 整行缓存是可选的回源加速层（TTL 600s），rowCache 为 nil 时退化为
//     直接读 repo；
//   - 版本检查按 VersionRefresh（默认 5s，§15.3「后台协程每 5s 比对
//     al:prov:ver」）节流，版本变化即清空本地 LRU；
//   - Redis / repo 故障不做负缓存，错误原样上抛（白名单等安全路径 fail-closed）。
package provider

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/logx"
	"authloft/internal/proxyclient"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// 默认参数（§3.9 / §15.3 / §5.1）。
const (
	defaultLocalTTL       = 60 * time.Second
	defaultLocalCapacity  = 1024
	defaultVersionRefresh = 5 * time.Second
	listPageSize          = 100
)

// RowSource Provider 行数据来源：*repo.ProviderRepo 天然满足（§3.9）。
type RowSource interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
	ListProviders(ctx context.Context, q repo.ProviderListQuery) ([]model.Provider, int64, error)
}

// RowCache Redis 整行缓存与版本号的可选读写接口（*cache.ProviderCache
// 天然满足）；为 nil 时 Provider 只用本地 LRU + repo。
type RowCache interface {
	GetRow(ctx context.Context, providerKey string) ([]byte, bool, error)
	SetRow(ctx context.Context, providerKey string, raw []byte) error
	Version(ctx context.Context) (int64, error)
}

// Provider 装配期使用的 Provider 实例：行数据 + 解析后的 Ext
// （§13.0：运行期从实例取 app_id / client_secret，不回读配置）。
type Provider struct {
	Key  string
	Type string
	Row  *model.Provider
	Ext  *providerpb.Ext

	// Pools 进程级出站连接池注册表（NewLoader 注入，后端架构 §15.4），工厂
	// 免改签名即可经 Get 取池；Outbound 引用解析出的连接池（proxy_provider_key
	// 指向的 proxy 行），nil = 直连，装配期固化、运行期不回读。
	Pools    *proxyclient.PoolSet
	Outbound *proxyclient.Pool
}

// Enabled 是否已启用（is_enabled=1，§13.0 白名单只取已启用实例）。
func (p *Provider) Enabled() bool {
	return p != nil && p.Row != nil && p.Row.IsEnabled == 1
}

// Loader Provider 加载器（本地 LRU + singleflight + 版本失效）。
type Loader struct {
	src   RowSource
	redis RowCache
	pools *proxyclient.PoolSet
	opts  LoaderOptions
	now   func() time.Time

	local   *lruCache
	flights flightGroup

	verMu     sync.Mutex
	ver       int64
	verAt     time.Time
	verLoaded bool
}

// LoaderOptions 加载器参数；零值字段回落默认值（便于测试注入短 TTL / 时钟）。
type LoaderOptions struct {
	LocalTTL       time.Duration
	LocalCapacity  int
	VersionRefresh time.Duration
	Now            func() time.Time
}

func (o LoaderOptions) withDefaults() LoaderOptions {
	if o.LocalTTL <= 0 {
		o.LocalTTL = defaultLocalTTL
	}
	if o.LocalCapacity <= 0 {
		o.LocalCapacity = defaultLocalCapacity
	}
	if o.VersionRefresh <= 0 {
		o.VersionRefresh = defaultVersionRefresh
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// NewLoader 构造 Provider 加载器。src 与 pools 必填；rowCache 可为 nil（不
// 使用 Redis 整行缓存）。pools 是进程级池注册表（bootstrap 构造一次显式注入，
// 后端架构 §15.4），挂载到每个加载出的实例供工厂取池，测试各传独立实例。
// opts 零值字段按文档默认值回落。
func NewLoader(src RowSource, rowCache RowCache, pools *proxyclient.PoolSet, opts LoaderOptions) *Loader {
	if src == nil {
		panic("provider: NewLoader: nil RowSource")
	}
	if pools == nil {
		panic("provider: NewLoader: nil PoolSet")
	}
	opts = opts.withDefaults()
	return &Loader{
		src:   src,
		redis: rowCache,
		pools: pools,
		opts:  opts,
		now:   opts.Now,
		local: newLRUCache(opts.LocalCapacity, opts.LocalTTL, opts.Now),
	}
}

// Get 按 provider_key 取 Provider 实例（§15.3）。读取顺序：本地 LRU →
// Redis 整行缓存（可选）→ repo；miss 合并并发请求（singleflight）。
func (l *Loader) Get(ctx context.Context, providerKey string) (*Provider, error) {
	if providerKey == "" {
		return nil, fmt.Errorf("provider: empty provider_key")
	}
	// 版本检查失败不阻断读取（Redis 故障降级；白名单路径另行 fail-closed）。
	_, _ = l.refreshVersion(ctx)

	// 本地 LRU key 与列表缓存（"l:"+type）命名空间隔离。
	localKey := "p:" + providerKey
	if v, ok := l.local.get(localKey); ok {
		if p, ok := v.(*Provider); ok {
			return p, nil
		}
	}

	v, err := l.flights.do(localKey, func() (any, error) {
		if v, ok := l.local.get(localKey); ok {
			if p, ok := v.(*Provider); ok {
				return p, nil
			}
		}
		row, err := l.loadRow(ctx, providerKey)
		if err != nil {
			return nil, err
		}
		p, err := toProvider(row)
		if err != nil {
			return nil, err
		}
		if err := l.resolveOutbound(ctx, p); err != nil {
			return nil, err
		}
		l.local.set(localKey, p)
		return p, nil
	})
	if err != nil {
		return nil, err
	}
	p, ok := v.(*Provider)
	if !ok {
		return nil, fmt.Errorf("provider: get %q: unexpected cached type", providerKey)
	}
	return p, nil
}

// GetDirect 不经本地 LRU 与 singleflight 的直读通道（§9.1 captcha catalog
// 「下发、拦截与错误体永远同源、配置改动立即生效」的落点）：行回源复用
// loadRow（Redis 整行缓存随写路径 DEL 失效、无 TTL 窗口，§15.3）+ toProvider
// + resolveOutbound，装配语义与 Get 完全同构，仅绕过 60s 缓存窗口；并发直读
// 不合并（correctness 不受影响，captcha 判定频率低）。普通读路径仍走
// Get（LRU + singleflight）。
func (l *Loader) GetDirect(ctx context.Context, providerKey string) (*Provider, error) {
	if providerKey == "" {
		return nil, fmt.Errorf("provider: empty provider_key")
	}
	row, err := l.loadRow(ctx, providerKey)
	if err != nil {
		return nil, err
	}
	p, err := toProvider(row)
	if err != nil {
		return nil, err
	}
	if err := l.resolveOutbound(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// ListByType 按 type 取全部 Provider（§3.9「按 type 列表」）：分页读完
// repo（pageSize 上限 100，§1.7），结果同样进本地 LRU（key = "l:"+type）。
// 是否启用由调用方按 Provider.Enabled() 过滤。
func (l *Loader) ListByType(ctx context.Context, providerType string) ([]*Provider, error) {
	if providerType == "" {
		return nil, fmt.Errorf("provider: empty type")
	}
	_, _ = l.refreshVersion(ctx)

	key := "l:" + providerType
	if v, ok := l.local.get(key); ok {
		if ps, ok := v.([]*Provider); ok {
			return copyProviders(ps), nil
		}
	}

	v, err := l.flights.do(key, func() (any, error) {
		if v, ok := l.local.get(key); ok {
			if ps, ok := v.([]*Provider); ok {
				return ps, nil
			}
		}
		ps, err := l.loadList(ctx, providerType)
		if err != nil {
			return nil, err
		}
		l.local.set(key, ps)
		return ps, nil
	})
	if err != nil {
		return nil, err
	}
	ps, ok := v.([]*Provider)
	if !ok {
		return nil, fmt.Errorf("provider: list %q: unexpected cached type", providerType)
	}
	return copyProviders(ps), nil
}

// Version 返回当前 Provider 版本号（al:prov:ver），按 VersionRefresh 节流；
// 未配置 RowCache 时恒为 0。供白名单等依赖版本失效的调用方使用。
func (l *Loader) Version(ctx context.Context) (int64, error) {
	l.verMu.Lock()
	defer l.verMu.Unlock()
	return l.refreshVersionLocked(ctx)
}

// refreshVersion 版本号节流读取；错误忽略（Provider 读取降级）。
func (l *Loader) refreshVersion(ctx context.Context) (int64, error) {
	l.verMu.Lock()
	defer l.verMu.Unlock()
	return l.refreshVersionLocked(ctx)
}

func (l *Loader) refreshVersionLocked(ctx context.Context) (int64, error) {
	if l.redis == nil {
		l.verLoaded = true
		return l.ver, nil
	}
	if l.verLoaded && l.now().Before(l.verAt.Add(l.opts.VersionRefresh)) {
		return l.ver, nil
	}
	cur, err := l.redis.Version(ctx)
	if err != nil {
		return l.ver, fmt.Errorf("provider: read version: %w", err)
	}
	if l.verLoaded && cur != l.ver {
		l.local.clear()
	}
	l.ver = cur
	l.verLoaded = true
	l.verAt = l.now()
	return l.ver, nil
}

// loadRow 回源单行：优先 Redis 整行缓存，未命中 / 故障时读 repo 并回写。
func (l *Loader) loadRow(ctx context.Context, providerKey string) (*model.Provider, error) {
	if l.redis != nil {
		if raw, ok, err := l.redis.GetRow(ctx, providerKey); err == nil && ok {
			var row model.Provider
			if err := json.Unmarshal(raw, &row); err == nil {
				return &row, nil
			}
			// 缓存值损坏：当作未命中，继续回源 repo。
		}
	}

	row, err := l.src.FindByKey(ctx, providerKey)
	if err != nil {
		return nil, fmt.Errorf("provider: find %q: %w", providerKey, err)
	}
	if l.redis != nil {
		// 编码 / 回写失败按设计不阻断本次读取，但 Redis 故障不能无痕；
		// logx.Warn(ctx, ...) 自动带 request_id。
		raw, err := json.Marshal(row)
		if err != nil {
			logx.Warn(ctx, "provider: cache row encode failed",
				"provider_key", providerKey,
				"error", logx.RedactText(err.Error()),
			)
		} else if err := l.redis.SetRow(ctx, providerKey, raw); err != nil {
			logx.Warn(ctx, "provider: cache row writeback failed",
				"provider_key", providerKey,
				"error", logx.RedactText(err.Error()),
			)
		}
	}
	return row, nil
}

// loadList 分页读 repo 直到取满 total（§1.7 分页上限 100）。
func (l *Loader) loadList(ctx context.Context, providerType string) ([]*Provider, error) {
	t := providerType
	var out []*Provider
	for page := 1; ; page++ {
		rows, total, err := l.src.ListProviders(ctx, repo.ProviderListQuery{
			Type:     &t,
			Page:     page,
			PageSize: listPageSize,
		})
		if err != nil {
			return nil, fmt.Errorf("provider: list type %q: %w", providerType, err)
		}
		for i := range rows {
			p, err := toProvider(&rows[i])
			if err != nil {
				return nil, err
			}
			if err := l.resolveOutbound(ctx, p); err != nil {
				return nil, err
			}
			out = append(out, p)
		}
		if len(rows) == 0 || int64(len(out)) >= total {
			break
		}
	}
	return out, nil
}

// toProvider 行 → 实例：Ext 的编解码唯一出口是 repo.ParseProviderExt
// （§3.9 / provider_repo.go），不另造第二套解析。
func toProvider(row *model.Provider) (*Provider, error) {
	if row == nil {
		return nil, fmt.Errorf("provider: nil row")
	}
	ext, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		return nil, fmt.Errorf("provider: parse ext %q: %w", row.ProviderKey, err)
	}
	return &Provider{Key: row.ProviderKey, Type: row.Type, Row: row, Ext: ext}, nil
}

func copyProviders(ps []*Provider) []*Provider {
	out := make([]*Provider, len(ps))
	copy(out, ps)
	return out
}

// lruCache 容量有界、条目按 TTL 失效的 LRU（container/list + map）。
type lruCache struct {
	mu      sync.Mutex
	cap     int
	ttl     time.Duration
	now     func() time.Time
	ll      *list.List
	entries map[string]*list.Element
}

type lruEntry struct {
	key     string
	value   any
	expires time.Time
}

func newLRUCache(capacity int, ttl time.Duration, now func() time.Time) *lruCache {
	return &lruCache{
		cap:     capacity,
		ttl:     ttl,
		now:     now,
		ll:      list.New(),
		entries: make(map[string]*list.Element, capacity),
	}
}

// get 命中且未过期时移到队首并返回；过期条目视同 miss 并删除。
func (c *lruCache) get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*lruEntry)
	if c.now().After(e.expires) {
		c.ll.Remove(el)
		delete(c.entries, key)
		return nil, false
	}
	c.ll.MoveToFront(el)
	return e.value, true
}

// set 写入 / 更新条目（过期时刻 = now + ttl），超容量淘汰队尾。
func (c *lruCache) set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	expires := c.now().Add(c.ttl)
	if el, ok := c.entries[key]; ok {
		el.Value.(*lruEntry).value = value
		el.Value.(*lruEntry).expires = expires
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&lruEntry{key: key, value: value, expires: expires})
	c.entries[key] = el
	for c.ll.Len() > c.cap {
		back := c.ll.Back()
		if back == nil {
			break
		}
		c.ll.Remove(back)
		delete(c.entries, back.Value.(*lruEntry).key)
	}
}

// clear 清空全部条目（版本号变化时整体失效，§15.3）。
func (c *lruCache) clear() {
	c.mu.Lock()
	c.ll.Init()
	c.entries = make(map[string]*list.Element, c.cap)
	c.mu.Unlock()
}

// flightGroup 最小 singleflight：同 key 的并发调用只执行一次，其余等待
// 同一结果（不引入 golang.org/x/sync 直接依赖，避免 go.mod 额外变动）。
type flightGroup struct {
	mu    sync.Mutex
	calls map[string]*flightCall
}

type flightCall struct {
	wg  sync.WaitGroup
	val any
	err error
}

func (g *flightGroup) do(key string, fn func() (any, error)) (any, error) {
	g.mu.Lock()
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := &flightCall{}
	c.wg.Add(1)
	if g.calls == nil {
		g.calls = make(map[string]*flightCall)
	}
	g.calls[key] = c
	g.mu.Unlock()

	// fn panic 时也必须完成清理（wg.Done + 删表）并给等待者留下错误，
	// 然后重抛 panic（对齐 golang.org/x/sync/singleflight 的行为语义）；
	// 否则 calls 项残留会让同 key 的后续请求永久阻塞。
	defer func() {
		if r := recover(); r != nil {
			c.err = fmt.Errorf("provider: singleflight panic: %v", r)
			g.mu.Lock()
			delete(g.calls, key)
			g.mu.Unlock()
			c.wg.Done()
			panic(r)
		}
	}()

	c.val, c.err = fn()

	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
	c.wg.Done()
	return c.val, c.err
}
