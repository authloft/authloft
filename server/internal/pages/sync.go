// sync.go GET /sso/sync_cookie 接收端（接口文档 §2.9 行 758、后端架构
// §11.2 行 1203-1210）：解密载荷 → 写入（覆盖）本域 Cookie → remaining
// 非空时重封载荷（exp 按剩余地址数重算）302 下一域 → 空时 302 final_url。
// 解密失败 / 过期 → 空体 200（不带 Location），链路就此中断。登出场景由
// 发起端把 cookie_value 置空、cookie_ttl 置 "0"，本端按同样逻辑写入即
// 等价于清除，不需要区分登录 / 登出。载荷是整个 query 串（{URL}?{payload}，
// §11.2 行 1200），非键值对。
package pages

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"authloft/gen/go/token"
	"authloft/internal/security"
	"authloft/internal/session"
)

// syncStepBudget 每地址过期预算（§11.2 行 1210：30s × 地址总数）。
const syncStepBudget = 30

// syncCookie GET /sso/sync_cookie：多域名同步中转（逐跳推进）。
func (h *Handler) syncCookie(c *gin.Context) {
	if h.codec == nil {
		slog.Error("pages: sync cookie codec not configured")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	raw := c.Request.URL.RawQuery
	if raw == "" {
		c.Status(http.StatusOK) // 空载荷：链路中断，空体不带 Location
		return
	}
	p, err := security.Open[token.SyncCookiePayload](h.codec, security.PurposeSyncPayload, raw)
	if err != nil {
		c.Status(http.StatusOK) // 解密失败：链路中断（§11.2 行 1205）
		return
	}
	now := h.now()
	if now.Unix() > p.GetExp() {
		c.Status(http.StatusOK) // 过期：不得再写 Cookie（§11.2 行 1210）
		return
	}

	// 一律写入（覆盖）本域 Cookie（§11.2 行 1206）：名 / 值 / TTL 全来自
	// 载荷；TTL "0"（登出）或非法 → Max-Age=0 清除语义。属性沿用 session
	// 包构造（HttpOnly; Secure; SameSite=None; Path=/，Domain=本部署根域）。
	var ck *http.Cookie
	if ttl := ttlSeconds(p.GetCookieTtl()); ttl > 0 {
		ck = session.NewCookie(p.GetCookieName(), h.rootDomain, time.Duration(ttl)*time.Second).Set(p.GetCookieValue())
	} else {
		ck = session.NewCookie(p.GetCookieName(), h.rootDomain, 0).Clear()
	}
	http.SetCookie(c.Writer, ck)

	// remaining 推进（§11.2 行 1207-1208）：非空 → 取下一个 URL、重封载荷
	// （exp = now + 30s × 剩余地址数：下一跳 + 新 remaining + final）并 302；
	// 空 → 302 final_url（不带载荷，不会再回本端点）。
	remaining := p.GetRemaining()
	if len(remaining) == 0 {
		c.Redirect(http.StatusFound, p.GetFinalUrl())
		return
	}
	next := remaining[0]
	p.Remaining = remaining[1:]
	p.Exp = now.Unix() + int64(len(remaining)+1)*syncStepBudget
	sealed, err := h.codec.Seal(security.PurposeSyncPayload, p)
	if err != nil {
		slog.Error("pages: sync cookie seal", "err", err)
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Redirect(http.StatusFound, next+"?"+sealed)
}
