// Package ssoapp SSO 应用登录配置快照解析（docs/接口文档.md §2.2 首签口径、
// §2.1 交集口径；docs/后端架构.md §11.6.2 token.Sso）。首签时按 sso_client_id
// 读一次 sso_client 行 + 全局 settings，算好生效快照交给消费方写进流程载荷；
// 后续步骤与终点全部消费快照，不再回读配置（生效延迟被 login_token 有效期封顶）。
// 查无行 / 行不可用显式报错，调用方按 §2.2 转 invalid_request，不降级直登。
// orchestrator / thirdparty / qrcode 等消费方各自定义同形窄接口，装配层注入
// 同一实现（内部先例 UserRefResolver 同款）。
package ssoapp

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"authloft/gen/go/token"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/settings"
)

// 哨兵错误：调用方用 errors.Is 区分——查无行 / 行不可用属业务拒绝（§2.2 转
// invalid_request）；其余错误（列解码失败 / 存储故障）按内部故障处理。
var (
	// ErrClientNotFound sso_client 行不存在。
	ErrClientNotFound = errors.New("ssoapp: sso client not found")
	// ErrClientDisabled sso_client 行存在但 is_enabled≠1（行不可用）。
	ErrClientDisabled = errors.New("ssoapp: sso client disabled")
)

// thirdpartyMethod 全局 login_methods 内的三方整体开关取值（§2.1 交集口径）。
const thirdpartyMethod = "thirdparty"

// ClientRowSource sso_client 行查询窄接口（repo.ClientRepo 天然满足）。
type ClientRowSource interface {
	FindSsoClientByClientID(ctx context.Context, clientID string) (*model.SsoClient, error)
}

// SettingsSource 全局登录方式开关窄接口（settings.Store 满足）。
type SettingsSource interface {
	GetStringSlice(key string) ([]string, bool)
}

// Resolver 快照解析器：一处实现多方注入。
type Resolver struct {
	clients  ClientRowSource
	settings SettingsSource
}

// NewResolver 构造；clients / settings 由装配层注入（repo 与 settings.Store）。
func NewResolver(clients ClientRowSource, s SettingsSource) *Resolver {
	return &Resolver{clients: clients, settings: s}
}

// Snapshot 按 sso_client_id 解析应用登录快照：
//   - 空标识 = 直登 / OIDC 链路 → (nil, nil)，零查询；
//   - 查无行 / 行不可用 → ErrClientNotFound / ErrClientDisabled；
//   - 应用未配置任何登录配置（两列空且默认回跳空）→ (nil, nil)：空 = 跟随
//     全局（§2.1），放行与回跳均无应用级语义，无快照链路与现状完全一致；
//   - 其余组装 token.Sso：methods 为已与全局取过交集的生效集（冻结副本），
//     providers 为应用白名单（全局 thirdparty 关闭时为空集，行级可用性由
//     三方 / 扫码链路现查现判），default_redirect_uri 原样携带。
func (r *Resolver) Snapshot(ctx context.Context, ssoClientID string) (*token.Sso, error) {
	if ssoClientID == "" {
		return nil, nil
	}
	if r.clients == nil {
		return nil, errors.New("ssoapp: client row source not injected")
	}
	row, err := r.clients.FindSsoClientByClientID(ctx, ssoClientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrClientNotFound
		}
		return nil, fmt.Errorf("ssoapp: find sso client: %w", err)
	}
	if row.IsEnabled != 1 {
		return nil, ErrClientDisabled
	}

	methods, err := repo.ParseClientLoginMethods(row.LoginMethods)
	if err != nil {
		return nil, fmt.Errorf("ssoapp: parse login_methods: %w", err)
	}
	providers, err := repo.ParseClientOauthProviders(row.OauthProviders)
	if err != nil {
		return nil, fmt.Errorf("ssoapp: parse oauth_providers: %w", err)
	}
	appMethods := methods.GetMethods()
	appProviders := providers.GetProviders()
	defaultURI := row.DefaultRedirectURI
	if len(appMethods) == 0 && len(appProviders) == 0 && defaultURI == "" {
		return nil, nil
	}

	global := r.globalLoginMethods()
	return &token.Sso{
		ClientId:           row.ClientID,
		Methods:            effectiveMethods(global, appMethods),
		Providers:          effectiveProviders(sliceContains(global, thirdpartyMethod), appProviders),
		DefaultRedirectUri: defaultURI,
	}, nil
}

// globalLoginMethods 全局 login_methods：store 未命中回落默认表，与放行侧
// （orchestrator 对 settings 缺键的回落）同口径，保证快照冻结值与无快照
// 直登路径读的是同一来源。
func (r *Resolver) globalLoginMethods() []string {
	if r.settings != nil {
		if v, ok := r.settings.GetStringSlice(settings.KeyLoginMethods); ok {
			return v
		}
	}
	if def, ok := settings.Defaults()[settings.KeyLoginMethods].([]string); ok {
		return def
	}
	return nil
}

// effectiveMethods 生效方式集（§2.1 交集口径第一行）：应用未配置 → 全局冻结
// 副本（非 nil 快照的放行判定只看快照成员，必须携带完整生效集）；已配置 →
// 按全局顺序取交集，全局未启用 + 应用启用 = 关，应用声明的未知取值不扩集。
func effectiveMethods(global, app []string) []string {
	if len(app) == 0 {
		out := make([]string, len(global))
		copy(out, global)
		return out
	}
	allowed := make(map[string]bool, len(app))
	for _, m := range app {
		allowed[m] = true
	}
	out := make([]string, 0, len(app))
	for _, m := range global {
		if allowed[m] {
			out = append(out, m)
		}
	}
	return out
}

// effectiveProviders 生效三方 Provider 集（§2.1 交集口径）：应用未配置 → nil
// （跟随全局，无应用限制）；全局 thirdparty 关闭 → 空集（整体关即全部拒绝）；
// 其余原样携带应用白名单副本。
func effectiveProviders(globalThirdpartyOn bool, app []string) []string {
	if len(app) == 0 {
		return nil
	}
	if !globalThirdpartyOn {
		return []string{}
	}
	out := make([]string, len(app))
	copy(out, app)
	return out
}

func sliceContains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
