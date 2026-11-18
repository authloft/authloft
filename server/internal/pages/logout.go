// logout.go GET /sso/logout（接口文档 §2.9、后端架构 §11.2）：
// 清本域 al_session（session 包 Cookie.Clear 经 Set-Cookie）→ 按 settings
// sso_domains 跳转式同步登出（复用 session 子包的同步跳转链载荷构造，
// 登出载荷 Cookie 值空、TTL="0"，接收端写入即等价清除）→ post_logout_
// redirect_uri 白名单。白名单来源 docs 未定义，默认两分支：
//   - 有 id_token_hint：oidcJWT 验签解析 aud=client_id → 该 OIDC 客户端
//     redirect_uris 白名单整段匹配（支持 * 通配，§12.3）；
//   - 无 hint：仅允许 al_root 同源（相对地址按 al_root 解析后同源）；
//   - hint 非法 / 不在白名单 / 无 post_logout → 落 al_root 默认页。
package pages

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/labstack/echo/v5"

	"authloft/internal/repo"
	"authloft/internal/session"
	"authloft/internal/settings"
	"authloft/internal/uriutil"
)

// defaultSessionTTL / defaultCookieName settings 键缺失回落值（§5.6：
// session_ttl 604800 秒、cookie_name al_session）。
const (
	defaultSessionTTL = int64(604800)
	defaultCookieName = "al_session"
)

// logout GET /sso/logout：清 Cookie + 多域同步 + 白名单回跳。
func (h *Handler) logout(c *echo.Context) error {
	// 1. 清本域会话 Cookie（session.Cookie.Clear：同名同 Path/Domain、
	// Max-Age=-1 浏览器立即删除；§2.9「清 Cookie」）。
	name := h.stringSetting(settings.KeyCookieName, defaultCookieName)
	ttl := h.intSetting(settings.KeySessionTtl, defaultSessionTTL)
	c.SetCookie(session.NewCookie(name, h.rootDomain, time.Duration(ttl)*time.Second).Clear())

	// 2. post_logout_redirect_uri 白名单 → 最终回跳地址（两分支见包注释）。
	final := h.logoutFinalURL(c)

	// 3. 多域同步（§11.2 发起端）：domains 非空时构造登出载荷首跳 URL 并
	// 302（Cookie 值空、TTL="0"）；空时直接 302 final。构造失败降级为
	// 直接回跳（本域 Cookie 已清，登出语义保全），记日志。
	if domains, ok := h.sliceSetting(settings.KeySsoDomains); ok && len(domains) > 0 && h.sync != nil {
		u, err := h.sync.Build(c.Request().Context(), name, "", "0", domains, final)
		if err != nil {
			slog.Error("pages: logout sync build", "err", err)
		} else if u != "" {
			return c.Redirect(http.StatusFound, u)
		}
	}
	return c.Redirect(http.StatusFound, final)
}

// logoutFinalURL 白名单判定（§2.9）：返回最终回跳地址（绝对 URL——
// 同步链末跳由别的根域发出，相对地址会落错主机）。
func (h *Handler) logoutFinalURL(c *echo.Context) string {
	target := c.QueryParam("post_logout_redirect_uri")
	if target == "" {
		return h.root // 无 post_logout → 落 al_root（同源默认页）
	}
	hint := c.QueryParam("id_token_hint")
	if hint != "" {
		if clientID, ok := h.hintClientID(c.Request().Context(), hint); ok {
			if h.matchClientRedirectURI(c.Request().Context(), clientID, target) {
				return target
			}
		}
		return h.root // hint 非法 / 客户端不可用 / 不在白名单 → 默认页
	}
	if resolved, ok := resolveSameOrigin(h.root, target); ok {
		return resolved // 无 hint：仅允许 al_root 同源路径（解析为绝对地址）
	}
	return h.root
}

// hintClientID 解析 id_token_hint：验签（iss / exp / RS256，§14.3）后取
// aud=client_id。aud 兼容 string 与数组两形态；验签失败即非法。
func (h *Handler) hintClientID(ctx context.Context, hint string) (string, bool) {
	if h.jwt == nil {
		return "", false
	}
	claims, err := h.jwt.Verify(hint)
	if err != nil {
		return "", false
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud != "" {
			return aud, true
		}
	case []any:
		for _, v := range aud {
			if s, ok := v.(string); ok && s != "" {
				return s, true
			}
		}
	}
	return "", false
}

// matchClientRedirectURI OIDC 客户端 redirect_uris 白名单整段匹配
// （repo.ClientRepo.FindOidcClientByClientID + repo.ParseClientRedirectUris
// 唯一编解码出口，§12.3）：客户端不存在 / 禁用 / 解码失败均不放行。
func (h *Handler) matchClientRedirectURI(ctx context.Context, clientID, target string) bool {
	if h.clients == nil {
		return false
	}
	cl, err := h.clients.FindOidcClientByClientID(ctx, clientID)
	if err != nil || cl == nil || cl.IsEnabled == 0 {
		return false
	}
	uris, err := repo.ParseClientRedirectUris(cl.RedirectURIs)
	if err != nil {
		return false
	}
	for _, pattern := range uris.GetUris() {
		if uriMatches(pattern, target) {
			return true
		}
	}
	return false
}

// uriMatches redirect_uris 条目整段匹配（接口文档 §4.2 / 后端架构 §14.2：
// 支持 * 通配、整段匹配防子域名陷阱）。规则唯一实现收敛于
// internal/uriutil.MatchWildcardURI，此处仅保留原名薄封装。
func uriMatches(pattern, target string) bool {
	return uriutil.MatchWildcardURI(pattern, target)
}

// resolveSameOrigin target 是否 al_root 同源：相对地址按 al_root 解析后
// 比较 scheme + host（含端口）；协议相对（//evil）与跨源绝对地址均不同源。
// 同源时返回解析后的绝对地址（同步链末跳跨根域发出，必须绝对）。
func resolveSameOrigin(root, target string) (string, bool) {
	rootURL, err := url.Parse(root)
	if err != nil || rootURL.Scheme == "" || rootURL.Host == "" {
		return "", false
	}
	t, err := url.Parse(target)
	if err != nil {
		return "", false
	}
	resolved := rootURL.ResolveReference(t)
	if resolved.Scheme != rootURL.Scheme || resolved.Host != rootURL.Host {
		return "", false
	}
	return resolved.String(), true
}

// ttlSeconds 载荷 TTL 字符串 → 秒；非数字 / 非正值 → 0（清除语义）。
func ttlSeconds(raw string) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}
