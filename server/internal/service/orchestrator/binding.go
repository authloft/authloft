// binding.go 处理三方身份中间态（docs/后端架构.md §12.5、docs/接口文档.md
// §2.7.5 行 653-675）。每次三方认证成功都以本次结果整体覆盖 login_token.tp；
// 本层只做状态写入与信封组装，不提供“绑定已有账号”分支。
package orchestrator

import (
	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/gen/go/token"
)

// SetThirdParty 用本次成功的三方身份整体覆盖 payload.tp（不合并旧字段）。
func SetThirdParty(p *token.LoginTokenPayload, tp *token.ThirdParty) {
	if p == nil {
		return
	}
	if tp == nil {
		p.Tp = nil
		return
	}
	p.Tp = &token.ThirdParty{
		ProviderKey: tp.ProviderKey,
		OpenId:      tp.OpenId,
		UnionId:     tp.UnionId,
		Nickname:    tp.Nickname,
		AvatarUrl:   tp.AvatarUrl,
	}
}

// BindingEnvelope 组装 status=binding_required 时需要的 binding 对象。
// allowSignup 由装配方按 Provider 的 enable_signup 传入（§2.7.5）。
func BindingEnvelope(p *token.LoginTokenPayload, displayName string, allowSignup bool) *ssov1.Binding {
	b := &ssov1.Binding{DisplayName: displayName, AllowSignup: allowSignup}
	if p == nil || p.Tp == nil {
		return b
	}
	b.ProviderKey = p.Tp.ProviderKey
	b.Nickname = p.Tp.Nickname
	b.AvatarUrl = p.Tp.AvatarUrl
	return b
}
