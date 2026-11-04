// Referer 白名单来源（docs/后端架构.md §13.0 行 1560、接口文档 §1.1 行 80）：
// 返回所有已启用 category=oauth、type ∈ {wechat_mp, wechat_mp_scan} 的
// Provider 中非空 Ext.app_id 集合（去重、排序）。装配层注入 origin
// 中间件；本文件不接线、不改 bootstrap / router / middleware。
//
// 缓存 60s；每次读取先经 Loader.Version 比对 al:prov:ver（节流 5s），版本
// 变化立即重载（§15.3 行 1716-1717）。版本号读取失败时若有未过期缓存则
// 降级使用旧值，否则返回错误（安全路径 fail-closed）。
package provider

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// wechatMPTypes 参与 Referer 白名单的 provider type（接口文档 §1.1 行 80）。
var wechatMPTypes = []string{"wechat_mp", "wechat_mp_scan"}

const defaultWhitelistTTL = 60 * time.Second

// Whitelist 已启用微信小程序 Provider 的 AppID 白名单来源。
type Whitelist struct {
	loader *Loader
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	ids     []string
	ver     int64
	expires time.Time
	loaded  bool
}

// NewWhitelist 构造白名单来源（TTL 60s）。
func NewWhitelist(loader *Loader) *Whitelist {
	return newWhitelist(loader, defaultWhitelistTTL, time.Now)
}

// newWhitelist 可注入 TTL / 时钟的内部构造（仅供本包测试）。
func newWhitelist(loader *Loader, ttl time.Duration, now func() time.Time) *Whitelist {
	if ttl <= 0 {
		ttl = defaultWhitelistTTL
	}
	if now == nil {
		now = time.Now
	}
	return &Whitelist{loader: loader, ttl: ttl, now: now}
}

// AppIDs 返回白名单快照（已排序、去重，调用方可直接构造集合）。只包含
// 已启用且 Ext.app_id 非空的实例（§13.0 优先级：空值视为未配置）。
func (w *Whitelist) AppIDs(ctx context.Context) ([]string, error) {
	ver, verErr := w.loader.Version(ctx)
	now := w.now()

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.loaded && now.Before(w.expires) {
		if verErr != nil {
			return append([]string(nil), w.ids...), nil // 版本读取失败：降级用未过期缓存
		}
		if ver == w.ver {
			return append([]string(nil), w.ids...), nil
		}
	}
	if verErr != nil {
		return nil, fmt.Errorf("provider: whitelist version: %w", verErr)
	}

	ids, err := w.reload(ctx)
	if err != nil {
		return nil, err
	}
	w.ids = ids
	w.ver = ver
	w.expires = now.Add(w.ttl)
	w.loaded = true
	return append([]string(nil), ids...), nil
}

// reload 从 Loader 读两类 Provider，过滤已启用 + app_id 非空并去重排序。
func (w *Whitelist) reload(ctx context.Context) ([]string, error) {
	set := make(map[string]struct{})
	for _, typ := range wechatMPTypes {
		ps, err := w.loader.ListByType(ctx, typ)
		if err != nil {
			return nil, fmt.Errorf("provider: whitelist list %q: %w", typ, err)
		}
		for _, p := range ps {
			if !p.Enabled() {
				continue
			}
			if appID := p.Ext.GetAppId(); appID != "" {
				set[appID] = struct{}{}
			}
		}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
