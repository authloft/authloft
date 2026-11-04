// revoke.go 实现 `POST /api/oidc/revoke`（RFC 7009、docs/接口文档.md §4.4 行
// 1102-1104、《后端架构》§14.3 行 1653）：仅吊销该 Refresh Token，不影响
// SSO 会话；成功 / 未知 / 已吊销统一 HTTP 200 空响应体（不得返回 `{}`、
// 不得套 §1.0 信封）。查询按 token sha256 定位（与落库口径一致）。
//
// client 认证失败按 RFC 7009 §2.1 回到 RFC 6749 §5.2：HTTP 401
// `invalid_client`（文档 §4.4 未单独定义错误形态，按 RFC 实现）。
package oidc

import (
	"context"
	"time"
)

// RevokeStore 单令牌吊销窄接口；*repo.OidcTokenRepo 天然满足。
type RevokeStore interface {
	RevokeByTokenHash(ctx context.Context, tokenHash string, revokedAt time.Time) (bool, error)
}

// Revoker revoke 端点实现。
type Revoker struct {
	Clients ClientFinder
	Tokens  RevokeStore
	Now     func() time.Time
}

func (r *Revoker) now() time.Time {
	if r != nil && r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Revoke 校验客户端后按 refresh_token 哈希吊销；未知 / 已吊销同样成功
// （返回 nil）。token_type_hint 只接受 refresh_token，其他取值按 RFC 7009
// 忽略并继续按 refresh token 查找。
func (r *Revoker) Revoke(ctx context.Context, clientID, clientSecret, tokenValue, _ string) *OAuthError {
	if tokenValue == "" {
		return newOAuthError(400, ErrorInvalidRequest, "token is required")
	}
	if clientID == "" {
		return newOAuthError(401, ErrorInvalidClient, "client authentication failed")
	}
	c, err := r.Clients.FindOidcClientByClientID(ctx, clientID)
	if err != nil || c == nil || c.IsEnabled == 0 {
		return newOAuthError(401, ErrorInvalidClient, "unknown or disabled client")
	}
	if clientSecret == "" || !secretEqual(clientSecret, c.ClientSecret) {
		return newOAuthError(401, ErrorInvalidClient, "client authentication failed")
	}
	if _, err := r.Tokens.RevokeByTokenHash(ctx, hashToken(tokenValue), r.now()); err != nil {
		return newOAuthError(500, ErrorServerError, "cannot revoke token")
	}
	return nil
}
