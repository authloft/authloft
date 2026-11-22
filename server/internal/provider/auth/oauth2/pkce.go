// PKCE（RFC 7636）S256 工具：X 等强制 PKCE 的渠道经 oauth2 兜底 metadata
// 开关启用。适配器契约无跨请求存储、ExchangeInput 不携带 state，verifier
// 无处安全落地，故采用无状态派生：以 clientSecret 为 HMAC 密钥、
// providerKey 与 redirectURI（BuildAuthURL / Exchange 两侧由 service 层以
// 同一基准传入）为种子派生固定 verifier——兜底强制配置 client_secret，
// 无秘密不可预测；代价是 verifier 不随授权轮换，轮换 client_secret 即
// 轮换 verifier。渠道差异经配置承载，此处不含任何厂商专用逻辑。
package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// pkceSeedPrefix verifier 派生种子的域分隔前缀（防 HMAC 密钥被他途串用）。
const pkceSeedPrefix = "authloft.pkce.v1:"

// pkceVerifier 由共享秘密派生 code_verifier：HMAC-SHA256 32 字节 → base64url
// 43 字符，恰在 RFC 7636 §4.1 的 43-128 字符区间。redirectURI 两侧不同源
// （如 RootOrigin 中途变更）会导致令牌端点校验 challenge 失败，属可见的
// 配置错误。
func pkceVerifier(secret, providerKey, redirectURI string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(pkceSeedPrefix))
	mac.Write([]byte(providerKey))
	mac.Write([]byte{0})
	mac.Write([]byte(redirectURI))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// s256Challenge code_verifier → code_challenge（S256：SHA256 后 base64url
// 不带填充，RFC 7636 §4.2）。
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
