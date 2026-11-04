// token.go 实现 `POST /api/oidc/token`（docs/接口文档.md §4.3 行 1091-1100、
// 《后端架构》§14.2 步骤 6/7、§14.3）：authorization_code 一次性消费授权码，
// 校验 client_id / redirect_uri / client_secret（或 PKCE S256）后签发
// ID Token（RS256）与 Access Token（RS256）及 opaque Refresh Token
// （sha256 落 oidc_refresh_token）；refresh_token grant 校验未吊销 / 未过期 /
// 同 client 后签发新 Access Token（按文档默认不轮换 Refresh Token）。
//
// 错误按 RFC 6749 §5.2 返回 `{error, error_description}`；本包只产出结构化
// OAuthError，HTTP 头（no-store / no-cache）由 handler 统一回写。
// 所有依赖（client / refresh token / epoch / 授权码消费）一律注入，本包
// 不连 DB / Redis、不读配置。
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"time"

	oidcapi "authloft/gen/go/api/oidc"
	"authloft/gen/go/token"
	"authloft/internal/repo/model"
)

// RFC 6749 §5.2 错误码。
const (
	ErrorInvalidRequest       = "invalid_request"
	ErrorInvalidClient        = "invalid_client"
	ErrorInvalidGrant         = "invalid_grant"
	ErrorUnsupportedGrantType = "unsupported_grant_type"
	ErrorServerError          = "server_error"
)

// OAuthError RFC 6749 / RFC 7009 / RFC 6750 错误体；Status 为 HTTP 状态码。
type OAuthError struct {
	Status      int
	Code        string
	Description string
}

func (e *OAuthError) Error() string {
	if e == nil {
		return ""
	}
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// newOAuthError 构造错误体。
func newOAuthError(status int, code, description string) *OAuthError {
	return &OAuthError{Status: status, Code: code, Description: description}
}

// ClientFinder OIDC 客户端读取窄接口；*repo.ClientRepo 天然满足。
type ClientFinder interface {
	FindOidcClientByClientID(ctx context.Context, clientID string) (*model.OidcClient, error)
}

// CodeConsumer 授权码一次性消费窄接口；*CodeIssuer 天然满足。
type CodeConsumer interface {
	Consume(ctx context.Context, code string) (*token.OidcCodePayload, error)
}

// RefreshTokenStore 刷新令牌读取 / 落库窄接口；*repo.OidcTokenRepo 天然满足。
type RefreshTokenStore interface {
	Create(ctx context.Context, t *model.OidcRefreshToken) error
	FindByTokenHash(ctx context.Context, tokenHash string) (*model.OidcRefreshToken, error)
}

// EpochReader user.epoch 读取窄接口；*cache.EpochStore 天然满足。
type EpochReader interface {
	Current(ctx context.Context, uid int64) (int64, error)
}

// TokenInput token 端点表单入参（两种 grant_type 字段并集，见 §4.3）。
type TokenInput struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
}

// TokenService token 端点实现。
type TokenService struct {
	JWT     *JWT
	Clients ClientFinder
	Codes   CodeConsumer
	Tokens  RefreshTokenStore
	Epoch   EpochReader
	Now     func() time.Time
	Rand    io.Reader
}

func (s *TokenService) now() time.Time {
	if s != nil && s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *TokenService) random() io.Reader {
	if s != nil && s.Rand != nil {
		return s.Rand
	}
	return rand.Reader
}

// Token 按 grant_type 分派（§4.3：固定支持两种，其余 unsupported_grant_type）。
func (s *TokenService) Token(ctx context.Context, in TokenInput) (*oidcapi.TokenResponse, *OAuthError) {
	switch in.GrantType {
	case "authorization_code":
		return s.authorizationCode(ctx, in)
	case "refresh_token":
		return s.refreshToken(ctx, in)
	case "":
		return nil, newOAuthError(400, ErrorInvalidRequest, "grant_type is required")
	default:
		return nil, newOAuthError(400, ErrorUnsupportedGrantType, "unsupported grant_type")
	}
}

// authorizationCode 授权码换取令牌（§14.2 步骤 6）。
func (s *TokenService) authorizationCode(ctx context.Context, in TokenInput) (*oidcapi.TokenResponse, *OAuthError) {
	if in.Code == "" || in.ClientID == "" || in.RedirectURI == "" {
		return nil, newOAuthError(400, ErrorInvalidRequest, "code, client_id and redirect_uri are required")
	}
	client, oe := s.findClient(ctx, in.ClientID)
	if oe != nil {
		return nil, oe
	}
	payload, err := s.Codes.Consume(ctx, in.Code)
	if err != nil {
		// 未命中 / 已消费 / 过期 / 篡改均为 invalid_grant（RFC 6749 §5.2）。
		return nil, newOAuthError(400, ErrorInvalidGrant, "authorization code is invalid or expired")
	}
	if payload.GetClientId() != in.ClientID {
		return nil, newOAuthError(400, ErrorInvalidGrant, "authorization code was issued to another client")
	}
	// redirect_uri 整段相等（§4.2：白名单匹配防子域名陷阱）。
	if payload.GetRedirectUri() != in.RedirectURI {
		return nil, newOAuthError(400, ErrorInvalidGrant, "redirect_uri mismatch")
	}
	if err := s.authenticate(client, payload, in); err != nil {
		return nil, err
	}
	scope := payload.GetScope()
	if scope == "" {
		scope = defaultScope
	}
	return s.issue(ctx, client, payload.GetUid(), scope, payload.GetAmr(), payload.GetNonce(), "")
}

// refreshToken 刷新令牌（§14.3：校验未吊销 / 未过期 / 同 client，默认不轮换）。
func (s *TokenService) refreshToken(ctx context.Context, in TokenInput) (*oidcapi.TokenResponse, *OAuthError) {
	if in.RefreshToken == "" || in.ClientID == "" {
		return nil, newOAuthError(400, ErrorInvalidRequest, "refresh_token and client_id are required")
	}
	client, oe := s.findClient(ctx, in.ClientID)
	if oe != nil {
		return nil, oe
	}
	if in.ClientSecret == "" || !secretEqual(in.ClientSecret, client.ClientSecret) {
		return nil, newOAuthError(400, ErrorInvalidClient, "client authentication failed")
	}
	row, err := s.Tokens.FindByTokenHash(ctx, hashToken(in.RefreshToken))
	if err != nil {
		return nil, newOAuthError(400, ErrorInvalidGrant, "refresh token is invalid")
	}
	if row.RevokedAt != nil || !row.ExpiresAt.After(s.now()) {
		return nil, newOAuthError(400, ErrorInvalidGrant, "refresh token is revoked or expired")
	}
	if row.ClientID != in.ClientID {
		return nil, newOAuthError(400, ErrorInvalidGrant, "refresh token belongs to another client")
	}
	scope := normalizeScope(row.Scopes)
	// 刷新令牌行未持久化 nonce / amr（DDL 无对应列），刷新签发的 ID Token
	// 只含可确定 claim（iss/sub/aud/exp/iat/epoch），不伪造 nonce / amr。
	return s.issue(ctx, client, row.UserID, scope, nil, "", in.RefreshToken)
}

// issue 同构签发两种 grant 的响应体（§4.3：响应同构）。
func (s *TokenService) issue(ctx context.Context, client *model.OidcClient, uid int64, scope string, amr []string, nonce, refresh string) (*oidcapi.TokenResponse, *OAuthError) {
	epoch, err := s.Epoch.Current(ctx, uid)
	if err != nil {
		return nil, newOAuthError(500, ErrorServerError, "cannot read user epoch")
	}
	accessTTL := secondsOrDefault(client.AccessTokenTTL, defaultAccessTokenTTL)
	refreshTTL := secondsOrDefault(client.RefreshTokenTTL, defaultRefreshTokenTTL)

	access, err := s.JWT.SignAccessToken(AccessTokenInput{
		UID: uid, ClientID: client.ClientID, Scope: scope, AMR: amr, Epoch: epoch, TTL: accessTTL,
	})
	if err != nil {
		return nil, newOAuthError(500, ErrorServerError, "cannot sign access token")
	}
	idToken, err := s.JWT.SignIDToken(IDTokenInput{
		UID: uid, ClientID: client.ClientID, Nonce: nonce, AMR: amr, Epoch: epoch, TTL: accessTTL,
	})
	if err != nil {
		return nil, newOAuthError(500, ErrorServerError, "cannot sign id token")
	}

	if refresh == "" {
		raw, err := randomToken(s.random())
		if err != nil {
			return nil, newOAuthError(500, ErrorServerError, "cannot generate refresh token")
		}
		refresh = raw
		now := s.now()
		if err := s.Tokens.Create(ctx, &model.OidcRefreshToken{
			TokenHash: hashToken(raw),
			ClientID:  client.ClientID,
			UserID:    uid,
			Scopes:    scope,
			ExpiresAt: now.Add(refreshTTL),
			CreatedAt: now,
		}); err != nil {
			return nil, newOAuthError(500, ErrorServerError, "cannot persist refresh token")
		}
	}

	return &oidcapi.TokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessTTL / time.Second),
		RefreshToken: refresh,
		IdToken:      idToken,
		Scope:        scope,
	}, nil
}

// findClient 按 client_id 取客户端并校验启用状态；不存在 / 未启用 / 读取
// 失败统一 invalid_client（不泄露内部细节）。
func (s *TokenService) findClient(ctx context.Context, clientID string) (*model.OidcClient, *OAuthError) {
	if clientID == "" {
		return nil, newOAuthError(400, ErrorInvalidRequest, "client_id is required")
	}
	c, err := s.Clients.FindOidcClientByClientID(ctx, clientID)
	if err != nil || c == nil || c.IsEnabled == 0 {
		return nil, newOAuthError(400, ErrorInvalidClient, "unknown or disabled client")
	}
	return c, nil
}

// authenticate 授权码 grant 的客户端认证：授权码带 code_challenge 时必须
// PKCE S256（§4.2 仅 S256）；否则要求 client_secret 与库内值相等。
func (s *TokenService) authenticate(client *model.OidcClient, payload *token.OidcCodePayload, in TokenInput) *OAuthError {
	if payload.GetCodeChallenge() != "" {
		if err := ValidatePKCE(payload.GetCodeChallenge(), payload.GetCodeChallengeMethod(), in.CodeVerifier); err != nil {
			return newOAuthError(400, ErrorInvalidGrant, err.Error())
		}
		return nil
	}
	if in.ClientSecret == "" || !secretEqual(in.ClientSecret, client.ClientSecret) {
		return newOAuthError(400, ErrorInvalidClient, "client authentication failed")
	}
	return nil
}

// secretEqual 常量时间比较客户端密钥。oidc_client.client_secret 为库内明文
// 列（§4.5 DDL），项目无第二个哈希出口，按既有 crypto/subtle 比较口径复用。
func secretEqual(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

const (
	defaultScope           = "openid profile email"
	defaultAccessTokenTTL  = 3600 * time.Second
	defaultRefreshTokenTTL = 2592000 * time.Second
	refreshTokenBytes      = 32
)

// secondsOrDefault 列值为 0 / 负数时回退 DDL 默认（§4.5 行 749-750）。
func secondsOrDefault(v int32, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return time.Duration(v) * time.Second
}

// normalizeScope 刷新令牌行以逗号分隔存储（§4.5 scopes 列），响应统一空格
// 分隔（§4.3）。
func normalizeScope(s string) string {
	if s == "" {
		return defaultScope
	}
	return strings.Join(strings.Fields(strings.ReplaceAll(s, ",", " ")), " ")
}

// hashToken refresh token 落库口径：sha256 小写十六进制（§4.7）。
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// randomToken opaque 刷新令牌：crypto/rand 32 字节 → base64url（无 padding）。
func randomToken(r io.Reader) (string, error) {
	buf := make([]byte, refreshTokenBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// 编译期断言：授权码消费方由既有 CodeIssuer 直接满足（装配层注入，
// 不新造适配层）。*repo.ClientRepo / *repo.OidcTokenRepo 满足其余窄接口，
// 由装配层接线时注入。
var _ CodeConsumer = (*CodeIssuer)(nil)
