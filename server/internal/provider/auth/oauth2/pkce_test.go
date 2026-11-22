// PKCE 工具单测：S256 用 RFC 7636 Appendix B 官方向量锚定正确性；
// verifier 派生验证确定性、字符集 / 长度契约与输入敏感性（错秘密 / 错
// redirectURI 派生不同 verifier——令牌端点必拒，可证伪）。
package oauth2

import (
	"regexp"
	"testing"
)

// TestS256ChallengeRFCVector RFC 7636 Appendix B 测试向量：固定 verifier 的
// S256 challenge 为公开常量，实现偏差即失败。
func TestS256ChallengeRFCVector(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := s256Challenge(verifier); got != want {
		t.Fatalf("s256Challenge = %q, want %q", got, want)
	}
	// 同一 verifier 重复计算稳定；不同 verifier 不碰撞（抽查）。
	if s256Challenge(verifier) != want {
		t.Fatalf("s256Challenge 非确定性")
	}
	if s256Challenge(verifier+"x") == want {
		t.Fatalf("不同 verifier 不应产生相同 challenge")
	}
}

// TestPKCEVerifierDerivation 派生契约：确定性复现；43 字符 base64url
// （RFC 7636 §4.1 verifier 字符集）；秘密与 redirectURI 任一不同 → 不同
// verifier（错秘密派生的 verifier 送令牌端点必被 challenge 校验拒绝）。
func TestPKCEVerifierDerivation(t *testing.T) {
	const secret, key, redirect = "g-secret", "gen", "https://root/sso/oauth/callback/gen"
	got := pkceVerifier(secret, key, redirect)
	if again := pkceVerifier(secret, key, redirect); again != got {
		t.Fatalf("派生非确定性: %q vs %q", got, again)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9\-_]{43}$`).MatchString(got) {
		t.Fatalf("verifier = %q, want 43 字符 base64url", got)
	}
	if pkceVerifier(secret+"x", key, redirect) == got {
		t.Fatalf("不同秘密派生出相同 verifier")
	}
	if pkceVerifier(secret, key, redirect+"/x") == got {
		t.Fatalf("不同 redirectURI 派生出相同 verifier")
	}
	if s256Challenge(got) == "" {
		t.Fatalf("challenge 为空")
	}
}
