// jwt_test.go 覆盖 RS256 签发 / 验签、算法白名单、未知 kid、JWKS 字段与
// PKCE S256（docs/后端架构.md §14.1/§14.3、接口文档 §4.2/§4.7）。
package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"authloft/internal/config"
)

// newTestKey 生成一把测试 RS256 密钥（base64 PKCS#8 PEM，§3.2 约定 6）。
func newTestKey(t *testing.T, kid string) config.OIDCKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return config.OIDCKey{Kid: kid, PrivateKeyPEM: base64.StdEncoding.EncodeToString(block)}
}

func newTestJWT(t *testing.T, kids ...string) *JWT {
	t.Helper()
	keys := make([]config.OIDCKey, 0, len(kids))
	for _, kid := range kids {
		keys = append(keys, newTestKey(t, kid))
	}
	j, err := NewJWT(keys, "https://authloft.example.com/")
	if err != nil {
		t.Fatalf("NewJWT: %v", err)
	}
	return j
}

func fixedNow() time.Time {
	return time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
}

// TestSignVerifyIDToken ID Token claims 与 header kid / alg。
func TestSignVerifyIDToken(t *testing.T) {
	j := newTestJWT(t, "k1")
	j.Now = fixedNow
	raw, err := j.SignIDToken(IDTokenInput{
		UID: 42, ClientID: "web", Nonce: "n-1", AMR: []string{"pwd", "otp"},
		Epoch: 3, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	claims, err := j.Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := claims["iss"]; got != "https://authloft.example.com" {
		t.Errorf("iss = %v, want trim-suffix issuer", got)
	}
	if got := claims["sub"]; got != "42" {
		t.Errorf("sub = %v, want string \"42\"", got)
	}
	if got := claims["aud"]; got != "web" {
		t.Errorf("aud = %v, want web", got)
	}
	if got := claims["nonce"]; got != "n-1" {
		t.Errorf("nonce = %v, want n-1", got)
	}
	if got := claims["epoch"]; got != float64(3) {
		t.Errorf("epoch = %v, want 3", got)
	}
	if got := claims["iat"]; got != float64(fixedNow().Unix()) {
		t.Errorf("iat = %v, want %d", got, fixedNow().Unix())
	}
	if got := claims["exp"]; got != float64(fixedNow().Add(time.Hour).Unix()) {
		t.Errorf("exp = %v, want %d", got, fixedNow().Add(time.Hour).Unix())
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	if alg, _ := parsed.Header["alg"].(string); alg != "RS256" {
		t.Errorf("header alg = %v, want RS256", alg)
	}
	if kid, _ := parsed.Header["kid"].(string); kid != "k1" {
		t.Errorf("header kid = %v, want k1", kid)
	}
}

// TestVerifyRejectsUnknownKid 未知 kid 直接失败（§14.3）。
func TestVerifyRejectsUnknownKid(t *testing.T) {
	other := newTestJWT(t, "other")
	other.Now = fixedNow
	raw, err := other.SignIDToken(IDTokenInput{UID: 1, ClientID: "web", Epoch: 0, TTL: time.Hour})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	j := newTestJWT(t, "k1")
	j.Now = fixedNow
	if _, err := j.Verify(raw); err == nil {
		t.Fatal("Verify accepted token signed with unknown kid")
	}
}

// TestVerifyRejectsNonRS256 none / HS256 一律拒绝（§14.3 失败策略）。
func TestVerifyRejectsNonRS256(t *testing.T) {
	j := newTestJWT(t, "k1")
	j.Now = fixedNow
	claims := jwt.MapClaims{
		"iss": j.Issuer(), "sub": "1", "aud": "web",
		"iat": fixedNow().Unix(), "exp": fixedNow().Add(time.Hour).Unix(),
	}
	hs, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("sign HS256: %v", err)
	}
	if _, err := j.Verify(hs); err == nil {
		t.Fatal("Verify accepted HS256 token")
	}
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := j.Verify(none); err == nil {
		t.Fatal("Verify accepted none token")
	}
}

// TestVerifyRejectsExpired exp 过期失败（RFC 7519 / §4.7）。
func TestVerifyRejectsExpired(t *testing.T) {
	j := newTestJWT(t, "k1")
	j.Now = fixedNow
	raw, err := j.SignIDToken(IDTokenInput{UID: 1, ClientID: "web", Epoch: 0, TTL: time.Minute})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	j.Now = func() time.Time { return fixedNow().Add(2 * time.Hour) }
	if _, err := j.Verify(raw); err == nil {
		t.Fatal("Verify accepted expired token")
	}
}

// TestJWKSAllKids JWKS 含全部 kid、字段为 RFC 7517 口径（§14.1）。
func TestJWKSAllKids(t *testing.T) {
	j := newTestJWT(t, "k1", "k2")
	set := j.JWKS()
	if len(set.Keys) != 2 {
		t.Fatalf("JWKS keys = %d, want 2", len(set.Keys))
	}
	for i, kid := range []string{"k1", "k2"} {
		k := set.Keys[i]
		if k.Kid != kid || k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" {
			t.Errorf("key[%d] = %+v, want kid=%s kty=RSA alg=RS256 use=sig", i, k, kid)
		}
		pub := j.verify[kid]
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			t.Fatalf("decode n: %v", err)
		}
		if new(big.Int).SetBytes(n).Cmp(pub.N) != 0 {
			t.Errorf("key[%d] n mismatch", i)
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			t.Fatalf("decode e: %v", err)
		}
		if len(e) == 0 || int(new(big.Int).SetBytes(e).Int64()) != pub.E {
			t.Errorf("key[%d] e mismatch", i)
		}
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("empty jwks")
	}
}

// TestValidatePKCE S256 通过 / 失败 / plain / 缺失（§4.2 仅 S256）。
func TestValidatePKCE(t *testing.T) {
	verifier := "test-verifier-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if err := ValidatePKCE("", "", ""); err != nil {
		t.Fatalf("no challenge should skip validation: %v", err)
	}
	if err := ValidatePKCE(challenge, "S256", verifier); err != nil {
		t.Fatalf("valid S256 rejected: %v", err)
	}
	if err := ValidatePKCE(challenge, "S256", "wrong-verifier"); err == nil {
		t.Fatal("wrong verifier accepted")
	}
	if err := ValidatePKCE(challenge, "plain", verifier); err == nil {
		t.Fatal("plain method accepted")
	}
	if err := ValidatePKCE(challenge, "S256", ""); err == nil {
		t.Fatal("missing verifier accepted")
	}
}
