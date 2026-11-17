// authz_validate.go 授权参数校验工具（后端架构 §14.2 步骤 1/5/6、接口文档
// §4.2 参数错误档位、§3.10 同意 RPC 步骤 2-3）：client_id 存在且启用、
// redirect_uri 白名单（§12.3 整段匹配、* 通配）、scope 封闭集 + ⊆ 客户端
// 注册 scopes + 必含 openid。/auth/authorize 入口、Terminal 登录即同意与
// 同意 RPC 共用同一份（§14.2：不得各写一份）；oidc_client.scopes 逗号口径
// 与授权记录空格口径的解析统一走本包 consent.go 纯工具。错误分类到
// HTTP / Connect 错误形态的映射归调用方（§4.2 参数错误、§3.10 错误体）。
package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"authloft/internal/repo"
	"authloft/internal/repo/model"

	"gorm.io/gorm"
)

// 授权参数校验错误三分类（档位与调用方映射）：
//   - ErrAuthzClient / ErrAuthzRedirect：client_id 不存在 / 未启用、
//     redirect_uri 未命中白名单——authorize 为 HTTP 400 不跳转（防开放
//     重定向，§4.2 参数错误），同意 RPC 为 invalid_argument +
//     ErrorInfo.code=invalid_request（§3.10）；
//   - ErrAuthzScope：scope 含未支持值 / 超出注册 scopes / 缺 openid——
//     authorize 为 302 invalid_scope（redirect_uri 校验通过后，§4.2），
//     同意 RPC 为 invalid_argument + ErrorInfo.code=invalid_scope（§3.10）。
var (
	ErrAuthzClient   = errors.New("oidc: unknown or disabled client")
	ErrAuthzRedirect = errors.New("oidc: redirect_uri not allowed")
	ErrAuthzScope    = errors.New("oidc: invalid scope")
)

// errAuthzNotConfigured 依赖未注入（装配错误，调用方按 internal 处理）。
var errAuthzNotConfigured = errors.New("oidc: authz validator not configured (clients nil)")

// AuthzValidator 授权参数校验器：Clients 注入客户端读取窄接口（token.go
// 既有 ClientFinder，*repo.ClientRepo 天然满足，测试用 fake）。
type AuthzValidator struct {
	Clients ClientFinder
}

// Validate 授权参数全量校验，顺序循 §14.2 步骤 1：client_id →
// redirect_uri → scope，前一步不过不查后续（scope 的 302 档位以
// redirect_uri 校验通过为前提，§4.2）。通过返回客户端行，供调用方注入
// client_name / 后续签码复用。
//
//   - client 未注册 / 未启用 → ErrAuthzClient；查询故障（非
//     ErrRecordNotFound）包装原样上抛，不吞成参数错误（fail-closed）。
//   - redirect_uri 经该客户端白名单整段匹配 / * 通判命中（§12.3）。
//   - scope 经 ParseScopes 双口径解析后逐值校验：封闭集（SupportedScopes
//     同源）、子集（客户端注册 scopes，逗号口径，空 token 容错）、必含
//     openid；空串 / 纯分隔符 scope 因缺 openid 被拒（fail-closed，
//     不信任注入值口径 §14.2 步骤 5）——authorize 入口的缺省补值由调用方
//     先做（EffectiveScope），同意 RPC 与 Terminal 的契约入参即为有效
//     scope（§4.2 / §3.10）。
func (v *AuthzValidator) Validate(ctx context.Context, clientID, redirectURI, scope string) (*model.OidcClient, error) {
	if v == nil || v.Clients == nil {
		return nil, errAuthzNotConfigured
	}
	if clientID == "" {
		return nil, ErrAuthzClient
	}
	client, err := v.Clients.FindOidcClientByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAuthzClient
		}
		return nil, fmt.Errorf("oidc: authz client lookup: %w", err)
	}
	if client == nil || client.IsEnabled == 0 {
		return nil, ErrAuthzClient
	}
	whitelist, err := repo.ParseClientRedirectUris(client.RedirectURIs)
	if err != nil {
		return nil, fmt.Errorf("oidc: authz parse redirect whitelist: %w", err)
	}
	if !redirectURIHit(whitelist.Uris, redirectURI) {
		return nil, ErrAuthzRedirect
	}
	if err := validateScope(client.Scopes, scope); err != nil {
		return nil, err
	}
	return client, nil
}

// validateScope scope 三重校验（§14.2 步骤 1 / §3.10 步骤 3）：封闭集
// （复用 SupportedScopes，与 token 端点同源）、子集（注册 scopes 为上限，
// 不可放大——需求.md §4.5 / 接口文档 §4.2）、必含 openid。
// registeredScopes 为逗号口径原文（§4.5），空 token 容错由 ParseScopes
// 统一处理。
func validateScope(registeredScopes, scope string) error {
	requested := ParseScopes(scope)
	registered := ParseScopes(registeredScopes)
	for _, s := range requested {
		if !slices.Contains(SupportedScopes, s) {
			return fmt.Errorf("%w: unsupported scope %q", ErrAuthzScope, s)
		}
		if !slices.Contains(registered, s) {
			return fmt.Errorf("%w: scope %q exceeds client registered scopes", ErrAuthzScope, s)
		}
	}
	if !slices.Contains(requested, ScopeOpenID) {
		return fmt.Errorf("%w: openid is required", ErrAuthzScope)
	}
	return nil
}

// matchRedirectURI 回调白名单条目整段匹配（接口文档 §12.3：支持 * 通配、
// 整段匹配防子域名陷阱）：字面相等，或按 * 切段后前缀 / 中段 / 后缀依序
// 匹配。与 service/admin（matchRedirectURI）、internal/pages（uriMatches）
// 是同一规则的多处实现，改规则须同步。
func matchRedirectURI(pattern, target string) bool {
	if pattern == target {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(target, parts[0]) {
		return false
	}
	rest := target[len(parts[0]):]
	for i := 1; i < len(parts); i++ {
		if i == len(parts)-1 {
			if len(rest) < len(parts[i]) || !strings.HasSuffix(rest, parts[i]) {
				return false
			}
		} else {
			idx := strings.Index(rest, parts[i])
			if idx < 0 {
				return false
			}
			rest = rest[idx+len(parts[i]):]
		}
	}
	return true
}

// redirectURIHit target 是否命中白名单任一条目（白名单为空即全拒，
// fail-closed）。
func redirectURIHit(patterns []string, target string) bool {
	for _, p := range patterns {
		if matchRedirectURI(p, target) {
			return true
		}
	}
	return false
}
