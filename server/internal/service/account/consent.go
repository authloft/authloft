// consent.go 同意 RPC 的业务编排（接口文档 §3.10 步骤 2-6、方案 §5.2）：
// 授权参数校验 / 授权记录写回复用 internal/oidc 共享工具，签码与多域名同步
// 经注入窄接口完成。错误分类到 Connect 错误体的映射归 handler 层。
package account

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"authloft/internal/oidc"
	"authloft/internal/repo/model"
	"authloft/internal/service/orchestrator"
	"authloft/internal/settings"
)

// 同意编排错误分类（档位映射见 handler/account/consent.go）：
// scope 超集 / 缺 openid / 未支持值 → ErrConsentInvalidScope；
// client_id / redirect_uri 不合法 → ErrConsentInvalidRequest。
var (
	ErrConsentInvalidScope   = errors.New("account consent: invalid scope")
	ErrConsentInvalidRequest = errors.New("account consent: invalid authorization request")
)

// ConsentAuthz 授权参数校验窄接口；*oidc.AuthzValidator 天然满足。
type ConsentAuthz interface {
	Validate(ctx context.Context, clientID, redirectURI, scope string) (*model.OidcClient, error)
}

// ConsentGranter 授权记录写回窄接口；*oidc.ConsentService 天然满足。
type ConsentGranter interface {
	Grant(ctx context.Context, userID int64, clientID, scopes string) error
}

// ConsentCodeIssuer 授权码签发窄接口；*oidc.CodeIssuer 天然满足。
type ConsentCodeIssuer interface {
	Issue(ctx context.Context, in orchestrator.OIDCIssue) (code string, err error)
}

// ConsentSync 多域名同步首跳构造窄接口；*session.SyncCookieURLBuilder 天然满足。
type ConsentSync interface {
	Build(ctx context.Context, cookieName, cookieValue, cookieTTL string, domains []string, finalURL string) (string, error)
}

// ConsentSettings 同步链所需 settings 窄接口；*settings.Store 天然满足。
type ConsentSettings interface {
	GetString(key string) (string, bool)
	GetStringSlice(key string) ([]string, bool)
	GetInt64(key string) (int64, bool)
}

// ConsentDeps 同意编排依赖；各窄接口缺省时对应能力降级（同步缺失即跳过）。
type ConsentDeps struct {
	Authz    ConsentAuthz
	Consents ConsentGranter
	Codes    ConsentCodeIssuer
	Sync     ConsentSync
	Settings ConsentSettings
}

// ConsentService 同意 RPC 编排。
type ConsentService struct {
	deps ConsentDeps
}

// NewConsentService 构造同意编排 service。
func NewConsentService(d ConsentDeps) *ConsentService {
	return &ConsentService{deps: d}
}

// ApproveInput 同意提交输入；会话主体与签发时刻由 handler 注入，不接受请求体 uid。
type ApproveInput struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	SelectedScope       string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	UID                 int64
	AMR                 []string
	AuthTime            int64
	SessionToken        string
}

// ConsentOutput 两方法共用落点；SyncCookieURL 为空即无多域名同步（§2.9）。
type ConsentOutput struct {
	RedirectTo    string
	SyncCookieURL string
}

// Approve 校验 → 写记录 → 签码 → 拼落点 → 多域名同步首跳（§3.10 步骤 2-6）。
// 校验失败在写记录 / 签码之前返回；Grant / Issue 失败按整体失败上抛 internal。
func (s *ConsentService) Approve(ctx context.Context, in ApproveInput) (*ConsentOutput, error) {
	if _, err := s.deps.Authz.Validate(ctx, in.ClientID, in.RedirectURI, in.Scope); err != nil {
		return nil, mapConsentAuthzError(err)
	}
	// selected_scope 必含 openid、封闭集、且是请求 scope 的子集——前端勾选集
	// 不可信任，与 §4.2 / Terminal 签码前重校验同口径。
	if !oidc.ScopeSupported(in.SelectedScope) || !oidc.ScopeSubset(in.SelectedScope, in.Scope) ||
		!consentScopeHasOpenID(in.SelectedScope) {
		return nil, ErrConsentInvalidScope
	}
	selected := oidc.NormalizeScope(in.SelectedScope)
	if err := s.deps.Consents.Grant(ctx, in.UID, in.ClientID, selected); err != nil {
		return nil, fmt.Errorf("account consent: grant: %w", err)
	}
	code, err := s.deps.Codes.Issue(ctx, orchestrator.OIDCIssue{
		ClientID:            in.ClientID,
		RedirectURI:         in.RedirectURI,
		Scope:               selected,
		Nonce:               in.Nonce,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		State:               in.State,
		UID:                 in.UID,
		AMR:                 in.AMR,
		AuthTime:            in.AuthTime,
	})
	if err != nil {
		return nil, fmt.Errorf("account consent: issue code: %w", err)
	}
	redirectTo, err := consentAppendQuery(in.RedirectURI, url.Values{
		"code":  {code},
		"state": {in.State},
	})
	if err != nil {
		return nil, fmt.Errorf("account consent: redirect_uri: %w", err)
	}
	out := &ConsentOutput{RedirectTo: redirectTo}
	syncURL, err := s.syncCookieURL(ctx, in.SessionToken, redirectTo)
	if err != nil {
		return nil, err
	}
	out.SyncCookieURL = syncURL
	return out, nil
}

// Deny 不写授权记录：校验 client_id / redirect_uri 白名单后拼 access_denied（§3.10）。
// 以 openid 作 scope 入参复用同一校验工具——所有客户端注册 scopes 必含 openid，
// 该 scope 校验必然通过，实际只生效 client / redirect 两项（评审裁决②）。
func (s *ConsentService) Deny(ctx context.Context, clientID, redirectURI, state string) (*ConsentOutput, error) {
	if _, err := s.deps.Authz.Validate(ctx, clientID, redirectURI, oidc.ScopeOpenID); err != nil {
		return nil, mapConsentAuthzError(err)
	}
	redirectTo, err := consentAppendQuery(redirectURI, url.Values{
		"error": {"access_denied"},
		"state": {state},
	})
	if err != nil {
		return nil, fmt.Errorf("account consent: redirect_uri: %w", err)
	}
	return &ConsentOutput{RedirectTo: redirectTo}, nil
}

// syncCookieURL 多域名首跳：sso_domains 为空时省略；同步值取当前会话令牌串。
func (s *ConsentService) syncCookieURL(ctx context.Context, sessionToken, finalURL string) (string, error) {
	if s.deps.Sync == nil || s.deps.Settings == nil {
		return "", nil
	}
	domains, _ := s.deps.Settings.GetStringSlice(settings.KeySsoDomains)
	if len(domains) == 0 {
		return "", nil
	}
	cookieName, _ := s.deps.Settings.GetString(settings.KeyCookieName)
	if cookieName == "" {
		cookieName = "al_session"
	}
	ttl, _ := s.deps.Settings.GetInt64(settings.KeySessionTtl)
	if ttl <= 0 {
		ttl = 604800
	}
	syncURL, err := s.deps.Sync.Build(ctx, cookieName, sessionToken, strconv.FormatInt(ttl, 10), domains, finalURL)
	if err != nil {
		return "", fmt.Errorf("account consent: sync cookie url: %w", err)
	}
	return syncURL, nil
}

// mapConsentAuthzError 把 oidc 校验三分类映射到业务错误档位；其余（查询故障 /
// 装配缺失）原样上抛由上层消毒为 internal。
func mapConsentAuthzError(err error) error {
	switch {
	case errors.Is(err, oidc.ErrAuthzClient), errors.Is(err, oidc.ErrAuthzRedirect):
		return ErrConsentInvalidRequest
	case errors.Is(err, oidc.ErrAuthzScope):
		return ErrConsentInvalidScope
	default:
		return fmt.Errorf("account consent: authz validate: %w", err)
	}
}

func consentScopeHasOpenID(scope string) bool {
	for _, s := range oidc.ParseScopes(scope) {
		if s == oidc.ScopeOpenID {
			return true
		}
	}
	return false
}

// consentAppendQuery 往 redirect_uri 补 query（§4.2 appendQuery 同口径）：保留既有
// query 与 fragment，空值键（state 缺失）剔除。
func consentAppendQuery(base string, kv url.Values) (string, error) {
	for k, v := range kv {
		if len(v) == 1 && v[0] == "" {
			delete(kv, k)
		}
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, vs := range kv {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
