// terminal.go 是登录引擎第 6 步的终点（docs/后端架构.md §7.3 行 985-1004、
// docs/接口文档.md §2.2 行 430-437）：建会话（仅 1 次写）、OIDC 授权码、
// sync_cookie_url / redirect_to、日志与 last_login 投递。
// 所有落库/落 Redis 动作都经注入的窄接口完成，本层不直接连 DB/Redis。
package orchestrator

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/settings"
)

// SessionWriter 完成“建会话”的唯一一次写入；epoch 等存储细节由实现方负责。
type SessionWriter interface {
	Write(ctx context.Context, uid int64, amr []string) (sessionID, sessionToken string, err error)
}

// OIDCIssue 是生成授权码所需的 OIDC 载荷（§1.3、§4.2）。授权码的存储值与
// 加密格式属于 OIDC 域，由实现方负责，本层不臆造。
type OIDCIssue struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	UID                 int64
	AMR                 []string
	AuthTime            int64
}

// OIDCCodeIssuer 生成并写入一次性授权码，返回可拼进 redirect_to 的 code。
type OIDCCodeIssuer interface {
	Issue(ctx context.Context, in OIDCIssue) (code string, err error)
}

// LoginEvent 是同步日志 + 异步 last_login 投递的统一载荷。
type LoginEvent struct {
	UID      int64
	TID      string
	ClientID string
	AMR      []string
	AuthTime int64
	// IP / UA 请求侧信息：装配层 http 包装器在 connect 前缀链入口
	// 采集并注入 ctx，Complete 据此填充，eventlog 落 event_log.ip / ua
	//（§4.6 行 776-777）。缺省（未注入）为空串，与既有行为兼容。
	IP string
	UA string
	// SessionID 本次终点建会话的会话 ID（Complete 建会话后可得）。
	SessionID string
}

// RequestInfo 请求侧信息载体：来源 IP 与 User-Agent。唯一采集点
// 是 http 挂载层（connect 链 AnyRequest 只暴露 Header、拿不到 RemoteAddr，
// 先例同 session.RequestSignal 的 TLS 信号），经 ctx 注入后由 Terminal
// 读取填进 LoginEvent。
type RequestInfo struct {
	IP string
	UA string
}

// requestInfoKey ctx 注入键（私有类型，包外无法伪造同型键；sessionTokenSinkKey
// 同款先例）。
type requestInfoKey struct{}

// WithRequestInfo 把请求侧信息注入 ctx（装配层 http 包装器调用）。
func WithRequestInfo(ctx context.Context, info RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, info)
}

// RequestInfoFromContext 读取请求侧信息；未注入返回零值（ip/ua 落空串，
// 与旧行为一致）。
func RequestInfoFromContext(ctx context.Context) RequestInfo {
	if ctx == nil {
		return RequestInfo{}
	}
	info, _ := ctx.Value(requestInfoKey{}).(RequestInfo)
	return info
}

// LoginEventSink 投递登录日志与 last_login_at 更新（实现方走延迟队列）。
type LoginEventSink interface {
	Record(ctx context.Context, ev LoginEvent) error
}

// SyncCookieURLBuilder 拼多域名同步 URL（§11.2）；加密载荷与域名展开由实现方负责，
// 本层只传当前会话值与最终落地地址。domains 为空时必须返回空串。
type SyncCookieURLBuilder interface {
	Build(ctx context.Context, cookieName, cookieValue, cookieTTL string, domains []string, finalURL string) (string, error)
}

// Success 是终点产物，由引擎组装成 LoginFlowResponse。
type Success struct {
	UserID        int64
	SessionID     string
	SessionToken  string
	SyncCookieURL string
	RedirectTo    string
}

// Terminal 负责签发会话与收尾投递。
type Terminal struct {
	Sessions SessionWriter
	OIDC     OIDCCodeIssuer
	Events   LoginEventSink
	Sync     SyncCookieURLBuilder
	Settings SettingsReader
	Now      func() time.Time
}

// NewTerminal 注入依赖；Now 为空时使用 time.Now。
func NewTerminal(sessions SessionWriter, oidc OIDCCodeIssuer, events LoginEventSink, sync SyncCookieURLBuilder, s SettingsReader) *Terminal {
	return &Terminal{Sessions: sessions, OIDC: oidc, Events: events, Sync: sync, Settings: s}
}

// Complete 执行终点动作并返回成功信封所需字段。
func (t *Terminal) Complete(ctx context.Context, p *token.LoginTokenPayload) (*Success, error) {
	if p == nil || p.GetUid() == 0 {
		return nil, fmt.Errorf("orchestrator: terminal: no authenticated user")
	}
	if t.Sessions == nil {
		return nil, fmt.Errorf("orchestrator: terminal: session writer not configured")
	}
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	at := now().Unix()

	// 唯一一次会话写入（§7.3 第 6 步）。
	// 会话记录不参与登录_token 状态机，避免后续步骤再写。
	sid, stok, err := t.Sessions.Write(ctx, p.Uid, p.Amr)
	if err != nil {
		return nil, err
	}
	success := &Success{UserID: p.Uid, SessionID: sid, SessionToken: stok}

	clientID := p.GetOidc().GetClientId()
	if p.GetOidc() != nil {
		if t.OIDC == nil {
			return nil, fmt.Errorf("orchestrator: terminal: oidc code issuer not configured")
		}
		code, err := t.OIDC.Issue(ctx, OIDCIssue{
			ClientID:            p.Oidc.ClientId,
			RedirectURI:         p.Oidc.RedirectUri,
			Scope:               p.Oidc.Scope,
			Nonce:               p.Oidc.Nonce,
			CodeChallenge:       p.Oidc.CodeChallenge,
			CodeChallengeMethod: p.Oidc.CodeChallengeMethod,
			State:               p.Oidc.State,
			UID:                 p.Uid,
			AMR:                 p.Amr,
			AuthTime:            at,
		})
		if err != nil {
			return nil, err
		}
		success.RedirectTo, err = appendCode(p.Oidc.RedirectUri, code, p.Oidc.State)
		if err != nil {
			return nil, err
		}
	}

	// 日志 + last_login 走注入的投递接口；投递失败不回滚登录（主链路零同步写库）。
	// ip/ua 取 ctx 携带的请求侧信息（装配层 http 包装器注入）；session_id
	// 取刚建会话的 sid（session_id 与 device_hint 归 detail，§4.6 行 798）。
	if t.Events != nil {
		info := RequestInfoFromContext(ctx)
		_ = t.Events.Record(ctx, LoginEvent{
			UID:      p.Uid,
			TID:      p.Tid,
			ClientID: clientID,
			AMR:      append([]string(nil), p.Amr...),
			AuthTime: at,
			IP:       info.IP,
			UA:       info.UA,
			SessionID: sid,
		})
	}

	if t.Sync != nil {
		domains := t.stringSlice(settings.KeySsoDomains)
		if len(domains) > 0 {
			cookieName := t.stringSetting(settings.KeyCookieName, "al_session")
			ttl := t.intSetting(settings.KeySessionTtl, 604800)
			success.SyncCookieURL, err = t.Sync.Build(ctx,
				cookieName, stok, strconv.FormatInt(ttl, 10), domains, success.RedirectTo)
			if err != nil {
				return nil, err
			}
		}
	}
	return success, nil
}

// appendCode 在 redirect_uri 上补 code/state，保留原有 query（§4.2）。
func appendCode(rawURL, code, state string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("orchestrator: terminal: redirect_uri: %w", err)
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (t *Terminal) stringSetting(key, def string) string {
	if t.Settings != nil {
		if v, ok := t.Settings.GetString(key); ok && v != "" {
			return v
		}
	}
	return def
}

func (t *Terminal) intSetting(key string, def int64) int64 {
	if t.Settings != nil {
		if v, ok := t.Settings.GetInt64(key); ok && v > 0 {
			return v
		}
	}
	return def
}

func (t *Terminal) stringSlice(key string) []string {
	if t.Settings != nil {
		if v, ok := t.Settings.GetStringSlice(key); ok {
			return v
		}
	}
	if def, ok := settings.Defaults()[key].([]string); ok {
		return def
	}
	return nil
}
