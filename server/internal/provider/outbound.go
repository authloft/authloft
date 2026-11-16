// 出站代理引用解析（docs/后端架构.md §15.4）：服务型 Provider 经
// proxy_provider_key 引用 category=proxy 行，装配期一跳解析为连接池并固化
// （Outbound），运行期不回读；引用失效 fail-closed，不降级直连。校验规则
// 单一来源是 proxyclient.NewConfig，本文件不做第二套字段校验。
package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	providerpb "authloft/gen/go/provider"
	"authloft/internal/proxyclient"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// ErrProxyRefUnresolvable 引用的 proxy 行不可解析（缺失 / 未启用 / 类别不符 /
// 字段组合非法）：渠道构造失败，走 provider_disabled 口径（与
// ErrChannelNotConfigured 同类），不降级直连（§15.4）。
var ErrProxyRefUnresolvable = errors.New("provider: proxy reference unresolvable")

// KeySource 引用解析的窄行源：只含按 key 取行。*repo.ProviderRepo 天然满足；
// admin 侧行仓库同形态。独立于 RowSource，避免把列表能力拖进签名。
type KeySource interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
}

// refUnresolvable 统一包装哨兵：错误串只含引用键（provider_key 非敏感，§12.1
// 读写约定），不含被引行字段值与凭据。
func refUnresolvable(refKey string) error {
	return fmt.Errorf("provider: %w (ref %q)", ErrProxyRefUnresolvable, refKey)
}

// resolveOutbound 装配期挂载池注册表并解析出站代理引用（§15.4）：Pools 挂到
// 实例（工厂免改签名即可取池）；引用 key 空（trim 后）→ 直连（Outbound
// nil）；proxy 行自身跳过解析（自引防护，防环）；被引行经 l.Get 取（嵌套走
// 同一 LRU + singleflight），未命中 / 未启用 / 类别不符 / NewConfig 失败 →
// 包装 ErrProxyRefUnresolvable；成功 → Outbound 固化为按 proxy 行 key 键控
// 的连接池。错误原样上抛（Loader 既有 fail 语义）。
func (l *Loader) resolveOutbound(ctx context.Context, p *Provider) error {
	p.Pools = l.pools
	if p.Row == nil || p.Row.Category == CategoryProxy {
		return nil // proxy 行自身不解析引用（自引防护，防环，接口文档 §5.3）
	}
	key := strings.TrimSpace(p.Ext.GetProxyProviderKey())
	if key == "" {
		return nil
	}
	ref, err := l.Get(ctx, key)
	if err != nil {
		return refUnresolvable(key)
	}
	pool, err := outboundPool(p.Pools, key, ref.Row, ref.Ext)
	if err != nil {
		return err
	}
	p.Outbound = pool
	return nil
}

// ResolveOutbound 非 Loader 路径的共享解析助手（§15.4：captcha 投影、admin
// TestProvider 直构等直持行源的场景复用同一语义）：key 空（trim 后）→ nil
// 直连；被引行未命中 / 未启用 / 类别不符 / ext 解析或 NewConfig 失败 → 包装
// ErrProxyRefUnresolvable，fail-closed 不降级直连；成功 → 按 proxy 行 key
// 键控的池（全部引用方共享）。row 为引用方行（category=proxy 时跳过解析，
// 自引防护），ext 为其已解析 Ext。pools 为 nil 属装配缺陷，与 NewLoader 同
// 风格 panic fail-fast。
func ResolveOutbound(ctx context.Context, pools *proxyclient.PoolSet, src KeySource, row *model.Provider, ext *providerpb.Ext) (*proxyclient.Pool, error) {
	if pools == nil {
		panic("provider: ResolveOutbound: nil PoolSet")
	}
	if row == nil || row.Category == CategoryProxy {
		return nil, nil
	}
	key := strings.TrimSpace(ext.GetProxyProviderKey())
	if key == "" {
		return nil, nil
	}
	refRow, err := src.FindByKey(ctx, key)
	if err != nil {
		return nil, refUnresolvable(key)
	}
	if refRow == nil {
		return nil, refUnresolvable(key)
	}
	refExt, err := repo.ParseProviderExt(refRow.Ext)
	if err != nil {
		return nil, refUnresolvable(key)
	}
	return outboundPool(pools, key, refRow, refExt)
}

// outboundPool 被引 proxy 行（含解析后 ext）→ 连接池：启用、类别、NewConfig
// 三道闸任一不过即包装 ErrProxyRefUnresolvable（fail-closed，§15.4）；成功
// 返回按 proxy 行 provider_key 键控的池（cfg 变更由 PoolSet 换池排空旧池）。
func outboundPool(pools *proxyclient.PoolSet, refKey string, refRow *model.Provider, refExt *providerpb.Ext) (*proxyclient.Pool, error) {
	if refRow == nil || refRow.IsEnabled != 1 {
		return nil, refUnresolvable(refKey)
	}
	if refRow.Category != CategoryProxy {
		return nil, refUnresolvable(refKey)
	}
	cfg, err := proxyclient.NewConfig(refExt.GetScheme(), refExt.GetHost(), refExt.GetPort(), refExt.GetUser(), refExt.GetPassword())
	if err != nil {
		return nil, refUnresolvable(refKey)
	}
	return pools.Get(refRow.ProviderKey, cfg), nil
}
