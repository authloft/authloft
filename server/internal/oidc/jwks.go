// jwks.go 从 config.oidc.jwt_keys 派生 JWKS（docs/后端架构.md §14.1 行 1627、
// RFC 7517）：发布列表内全部密钥的公钥，字段 kty=RSA / kid / n / e /
// alg=RS256 / use=sig；n、e 为 base64url（RawURLEncoding，无 padding）。
// 私钥不出现在响应（§3.2 约定 6）。
package oidc

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

// JWK 单个公钥（RFC 7517 §4 / §6.3.1）。
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSet 公钥集响应体（`/.well-known/jwks.json`）。
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKS 从全列表派生公钥集（首项签发、全列表发布，§14.3）。
func (j *JWT) JWKS() *JWKSet {
	set := &JWKSet{Keys: make([]JWK, 0, len(j.order))}
	for _, kid := range j.order {
		pub := j.verify[kid]
		set.Keys = append(set.Keys, JWK{
			Kty: "RSA",
			Kid: kid,
			Alg: "RS256",
			Use: "sig",
			N:   rsaModulus(pub),
			E:   rsaExponent(pub),
		})
	}
	return set
}

// rsaModulus n = base64url(RSA modulus)，无 padding（RFC 7517 §6.3.1.1）。
func rsaModulus(pub *rsa.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
}

// rsaExponent e = base64url(big-endian exponent)，常见值 65537 → "AQAB"
// （RFC 7517 §6.3.1.2）。
func rsaExponent(pub *rsa.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
}
