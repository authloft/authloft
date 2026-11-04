// pkce.go 实现 PKCE S256 校验（RFC 7636、docs/接口文档.md §4.2 行 1068 /
// §4.3）：BASE64URL(SHA256(code_verifier)) == code_challenge。
// 文档只支持 S256；`plain` 与仅给 code_challenge 不给 method 均按不支持处理。
// 授权码未携带 code_challenge 时不校验（公共客户端走 client_secret 校验）。
package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

var (
	// ErrPKCEMethodUnsupported code_challenge_method 非 S256（含 plain）。
	ErrPKCEMethodUnsupported = errors.New("oidc: unsupported code_challenge_method (only S256)")
	// ErrPKCEVerifierRequired 授权码带 code_challenge 但请求缺 code_verifier。
	ErrPKCEVerifierRequired = errors.New("oidc: code_verifier is required")
	// ErrPKCEVerifierMismatch code_verifier 与 code_challenge 不匹配。
	ErrPKCEVerifierMismatch = errors.New("oidc: code_verifier mismatch")
)

// ValidatePKCE 校验 S256：challenge 为空 → 不校验（返回 nil）。
func ValidatePKCE(challenge, method, verifier string) error {
	if challenge == "" {
		return nil
	}
	if method != "S256" {
		return ErrPKCEMethodUnsupported
	}
	if verifier == "" {
		return ErrPKCEVerifierRequired
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) != 1 {
		return ErrPKCEVerifierMismatch
	}
	return nil
}
