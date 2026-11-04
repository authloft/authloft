// jwt.go 实现 OIDC RS256 签发 / 验签（docs/后端架构.md §14.3 行 1645-1649、
// docs/接口文档.md §4.5/§4.7）：密钥集来自 config.oidc.jwt_keys，列表首项
// 签发、全列表验签（未知 kid 直接失败）；JWT header 固定 alg=RS256、kid 取
// 首项；iss = authloft.root 去末尾 "/"，与 discovery 逐字一致（§14.1）。
//
// 算法白名单只接受 RS256：none / HS* 等一律拒绝（§14.3 失败策略）。
// 私钥只在内存中用于签名，不出现在任何响应与日志（§3.2 约定 6）。
package oidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"authloft/internal/config"
)

var (
	// ErrUnknownKey kid 不在 oidc.jwt_keys 列表内。
	ErrUnknownKey = errors.New("oidc: unknown signing key id")
	// ErrInvalidToken JWT 结构 / 算法 / 签名 / iss / exp 任一不合法。
	ErrInvalidToken = errors.New("oidc: invalid token")
)

// JWT RS256 签发与验签器。Now 可注入（测试锁定 exp / iat）。
type JWT struct {
	issuer  string
	signKid string
	signKey *rsa.PrivateKey
	verify  map[string]*rsa.PublicKey
	order   []string
	Now     func() time.Time
}

// NewJWT 从 config.oidc.jwt_keys 解析密钥集：首项签发，全列表验签。
// 配置层已校验（§3.2 约定 6），此处仍按同一口径解析并返回错误，便于
// 单测与装配期 fail-fast。issuer 统一去末尾 "/"。
func NewJWT(keys []config.OIDCKey, issuer string) (*JWT, error) {
	if len(keys) == 0 {
		return nil, errors.New("oidc: jwt_keys is empty")
	}
	j := &JWT{
		issuer: strings.TrimSuffix(issuer, "/"),
		verify: make(map[string]*rsa.PublicKey, len(keys)),
		order:  make([]string, 0, len(keys)),
		Now:    time.Now,
	}
	for i, k := range keys {
		if k.Kid == "" {
			return nil, fmt.Errorf("oidc: jwt_keys[%d].kid is empty", i)
		}
		if _, dup := j.verify[k.Kid]; dup {
			return nil, fmt.Errorf("oidc: duplicate jwt key kid %q", k.Kid)
		}
		priv, err := parseRSAKey(k.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("oidc: parse jwt key %q: %w", k.Kid, err)
		}
		if i == 0 {
			j.signKid = k.Kid
			j.signKey = priv
		}
		j.verify[k.Kid] = &priv.PublicKey
		j.order = append(j.order, k.Kid)
	}
	return j, nil
}

// parseRSAKey base64(std) → PEM → PKCS#8 → *rsa.PrivateKey（§3.2 约定 6）。
func parseRSAKey(encoded string) (*rsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("base64 decode failed")
	}
	block, _ := pem.Decode(der)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New(`want PEM block "PRIVATE KEY"`)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("want PKCS#8 private key")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("must be an RSA private key")
	}
	return key, nil
}

func (j *JWT) now() time.Time {
	if j != nil && j.Now != nil {
		return j.Now()
	}
	return time.Now()
}

// Issuer 返回统一 issuer（§14.1：discovery 与 JWT iss 逐字相同）。
func (j *JWT) Issuer() string { return j.issuer }

// IDTokenInput ID Token 签发入参（claims 集合见接口文档 §4.7）。
type IDTokenInput struct {
	UID      int64
	ClientID string
	Nonce    string
	AMR      []string
	Epoch    int64
	TTL      time.Duration
}

// SignIDToken 签发 ID Token：iss/sub/aud/exp/iat/nonce/amr/epoch。
func (j *JWT) SignIDToken(in IDTokenInput) (string, error) {
	claims := jwt.MapClaims{
		"iss":   j.issuer,
		"sub":   int64String(in.UID),
		"aud":   in.ClientID,
		"iat":   j.now().Unix(),
		"exp":   j.now().Add(in.TTL).Unix(),
		"epoch": in.Epoch,
	}
	if in.Nonce != "" {
		claims["nonce"] = in.Nonce
	}
	if len(in.AMR) > 0 {
		claims["amr"] = in.AMR
	}
	return j.sign(claims)
}

// AccessTokenInput Access Token 签发入参（§4.7：RS256、含 epoch）。
type AccessTokenInput struct {
	UID      int64
	ClientID string
	Scope    string // 空格分隔；供 userinfo 判定 phone_plain / email_plain
	AMR      []string
	Epoch    int64
	TTL      time.Duration
}

// SignAccessToken 签发 Access Token。文档 §4.7 未逐列 Access Token claim，
// 但 §3.1 / §4.5 要求 userinfo 按 Access Token 的 scope 决定掩码，故按
// 实现需要写入 scope（与 ID Token 共用 iss/sub/aud/exp/iat/amr/epoch）。
func (j *JWT) SignAccessToken(in AccessTokenInput) (string, error) {
	claims := jwt.MapClaims{
		"iss":   j.issuer,
		"sub":   int64String(in.UID),
		"aud":   in.ClientID,
		"iat":   j.now().Unix(),
		"exp":   j.now().Add(in.TTL).Unix(),
		"scope": in.Scope,
		"epoch": in.Epoch,
	}
	if len(in.AMR) > 0 {
		claims["amr"] = in.AMR
	}
	return j.sign(claims)
}

// sign 统一 RS256 签发：header alg=RS256、kid = 首项（§14.3）。
func (j *JWT) sign(claims jwt.MapClaims) (string, error) {
	if j == nil || j.signKey == nil {
		return "", errors.New("oidc: signing key not configured")
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = j.signKid
	return tok.SignedString(j.signKey)
}

// AccessClaims 验签后要求的 Access Token claim 子集。
type AccessClaims struct {
	Sub   int64
	Scope string
	AMR   []string
	Epoch int64
}

// Verify 验签并校验 iss / exp；算法白名单仅 RS256，未知 kid 直接失败（§14.3）。
func (j *JWT) Verify(raw string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, ErrUnknownKey
		}
		pub, ok := j.verify[kid]
		if !ok {
			return nil, ErrUnknownKey
		}
		return pub, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		jwt.WithIssuer(j.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return j.now() }),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return claims, nil
}

// VerifyAccess 验签 Access Token 并提取掩码判定所需 claim。
func (j *JWT) VerifyAccess(raw string) (*AccessClaims, error) {
	claims, err := j.Verify(raw)
	if err != nil {
		return nil, err
	}
	return &AccessClaims{
		Sub:   int64Claim(claims, "sub"),
		Scope: stringClaim(claims, "scope"),
		AMR:   stringsClaim(claims, "amr"),
		Epoch: int64Claim(claims, "epoch"),
	}, nil
}

// stringClaim 取字符串型 claim（兼容 jwt 库把 MapClaims 解成 float64 的数值）。
func stringClaim(m jwt.MapClaims, key string) string {
	v, _ := m[key].(string)
	return v
}

// int64Claim 取数值型 claim；sub 按 §4.7 为 uid 字符串，兼容两种形态。
func int64Claim(m jwt.MapClaims, key string) int64 {
	switch v := m[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case string:
		if n, err := parseInt64(v); err == nil {
			return n
		}
	}
	return 0
}

// int64String uid → 十进制字符串（§4.5 / §4.7：sub 为字符串）。
func int64String(v int64) string { return strconv.FormatInt(v, 10) }

// parseInt64 解析十进制字符串。
func parseInt64(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }

// stringsClaim 取 []string 型 claim（JSON 反序列化为 []interface{}）。
func stringsClaim(m jwt.MapClaims, key string) []string {
	switch v := m[key].(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
