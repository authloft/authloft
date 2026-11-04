// sync_cookie.go 多域名会话同步 URL 适配器（docs/后端架构.md §11.2 行 1177-1196，
// 接口文档 §1.9 行 290-296）：实现 orchestrator.SyncCookieURLBuilder，
// 由登录终点 / 登出共用同一段代码生成跳转链首跳 URL。链路状态全部装在
// security.Codec 加密的 SyncCookiePayload 里，不落存储；本文件不读写 DB / Redis。
package service

import (
	"context"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/security"
)

// syncStepBudget 跳转链每个地址的过期预算（§11.2 行 1196：30s × 地址总数）。
const syncStepBudget = 30 * time.Second

// syncCookiePath 各根域接收端路径（§3.2 行 251、§11.2 行 1189：GET /sso/sync_cookie）。
const syncCookiePath = "/sso/sync_cookie"

// expandSyncTarget 把 sso_domains 的裸域名 host[:port]（不含 scheme 与 path）
// 展开为接收端地址（§3.2 行 251、§11.2 行 1181-1186）。
func expandSyncTarget(domain string) string {
	return "https://" + domain + syncCookiePath
}

// SyncCookieURLBuilder 多域名同步 URL 适配器：拼首跳 URL 与加密载荷。
// 满足 orchestrator.SyncCookieURLBuilder 签名（terminal.go 行 57-61）。
type SyncCookieURLBuilder struct {
	Codec *security.Codec
	// Now 可注入时钟；为空时使用 time.Now。
	Now func() time.Time
}

// NewSyncCookieURLBuilder 注入编解码器；Now 为空时使用 time.Now。
func NewSyncCookieURLBuilder(codec *security.Codec) *SyncCookieURLBuilder {
	return &SyncCookieURLBuilder{Codec: codec}
}

// Build 生成多域名同步首跳 URL（§11.2 行 1183-1187）：
// 地址数组 = sso_domains 顺序（每个裸域名展开为 https://{domain}/sso/sync_cookie）
// + 末尾 finalURL；首跳取数组第一个且不写进载荷（避免自跳循环），remaining 为
// 展开后的 domains[1:]（不含首跳、不含 finalURL），exp = 签发时刻 + 30s × 地址总数。
// domains 为空时返回空串（不发起同步）。
func (b *SyncCookieURLBuilder) Build(_ context.Context, cookieName, cookieValue, cookieTTL string, domains []string, finalURL string) (string, error) {
	if len(domains) == 0 {
		return "", nil
	}

	// 地址总数 = 首跳 + remaining 个数 + finalURL（§11.2 行 1196）。
	total := len(domains) + 1

	// 裸域名 host[:port] 一律展开为接收端完整 URL；首跳不写进载荷（§11.2 行 1184）。
	targets := make([]string, len(domains))
	for i, domain := range domains {
		targets[i] = expandSyncTarget(domain)
	}

	now := time.Now
	if b.Now != nil {
		now = b.Now
	}

	payload := &token.SyncCookiePayload{
		CookieName:  cookieName,
		CookieValue: cookieValue,
		CookieTtl:   cookieTTL,
		Remaining:   append([]string(nil), targets[1:]...),
		FinalUrl:    finalURL,
		Exp:         now().Add(time.Duration(total) * syncStepBudget).Unix(),
	}
	sealed, err := b.Codec.Seal(security.PurposeSyncPayload, payload)
	if err != nil {
		return "", err
	}
	return targets[0] + "?" + sealed, nil
}
