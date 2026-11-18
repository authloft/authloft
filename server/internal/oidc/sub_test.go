// sub_test.go 覆盖 OIDC sub 的确定性派生 / 还原与四处对外泄露面
// （后端架构 §11.6.8、接口文档 §4.5 / §4.7）。
package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"authloft/internal/security"
)

// newTestSubCodec 用固定测试密钥构造确定性 codec：不同实例对同一
// (client_id, uid) 的派生结果恒定，便于跨 helper 对期望值。
func newTestSubCodec(t *testing.T) *SubCodec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x40 + i)
	}
	ks, err := security.NewKeyStore(security.KeyEntry{
		ID: security.KeyID{Version: 1, Kid: 1}, Key: key,
	})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	c, err := security.NewDeterministicCodec(ks)
	if err != nil {
		t.Fatalf("NewDeterministicCodec: %v", err)
	}
	return NewSubCodec(c)
}

// testSub 是测试主体 (web, 42) 的密文 sub。
func testSub(t *testing.T) string {
	t.Helper()
	sub, err := newTestSubCodec(t).DeriveSub("web", 42)
	if err != nil {
		t.Fatalf("DeriveSub: %v", err)
	}
	return sub
}

// TestDeriveSubDeterministic 同一 (client_id, uid) 重复签发逐字节恒定、
// 跨客户端互异；还原出的 uid / client_id 与明文一致（§11.6.8）。
func TestDeriveSubDeterministic(t *testing.T) {
	sc := newTestSubCodec(t)
	first, err := sc.DeriveSub("web", 42)
	if err != nil {
		t.Fatalf("DeriveSub first: %v", err)
	}
	second, err := sc.DeriveSub("web", 42)
	if err != nil {
		t.Fatalf("DeriveSub second: %v", err)
	}
	if first != second {
		t.Fatalf("same (client_id, uid) produced different sub: %q vs %q", first, second)
	}
	other, err := sc.DeriveSub("other-client", 42)
	if err != nil {
		t.Fatalf("DeriveSub other: %v", err)
	}
	if first == other {
		t.Fatal("different clients produced identical sub")
	}
	uid, clientID, err := sc.DecodeSub(first)
	if err != nil {
		t.Fatalf("DecodeSub: %v", err)
	}
	if uid != 42 || clientID != "web" {
		t.Errorf("decoded = (%d, %q), want (42, web)", uid, clientID)
	}
	// 篡改密文必须被 GCM 认证与 nonce 规范校验拒绝。
	tampered := first[:len(first)-2] + "AA"
	if _, _, err := sc.DecodeSub(tampered); err == nil {
		t.Fatal("DecodeSub accepted tampered sub")
	}
}

// decodeJWTPayload 不经验签直接解码 JWT payload（RP 侧可读视角）。
func decodeJWTPayload(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d, want 3", len(parts))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

// TestFourSurfacesCarryCipherSub ID Token / Access Token / userinfo /
// get_user_info 四处的 sub 均为密文，RP 侧直接解码 payload 读不到真实 uid。
func TestFourSurfacesCarryCipherSub(t *testing.T) {
	sub := testSub(t)
	if sub == "42" {
		t.Fatal("derived sub must not be the plain uid")
	}
	j := newTestJWT(t, "k1")
	j.Now = func() time.Time { return fixedNow() }

	idRaw, err := j.SignIDToken(IDTokenInput{Sub: sub, ClientID: "web", Epoch: 3, TTL: time.Hour})
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}
	accessRaw, err := j.SignAccessToken(AccessTokenInput{
		Sub: sub, ClientID: "web", Scope: "openid", Epoch: 3, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	for name, raw := range map[string]string{"id_token": idRaw, "access_token": accessRaw} {
		claims := decodeJWTPayload(t, raw)
		if got := claims["sub"]; got != sub {
			t.Errorf("%s sub = %v, want cipher sub %q", name, got, sub)
		}
	}

	svc := &UserInfoService{
		JWT: j, Subs: newTestSubCodec(t), Users: fakeUsers{42: testUser()},
		Profiles: fakeProfiles{}, Epoch: fakeEpoch{v: 3},
	}
	uResp, oe := svc.Userinfo(context.Background(), accessRaw)
	if oe != nil {
		t.Fatalf("Userinfo: %v", oe)
	}
	if uResp.GetSub() != sub {
		t.Errorf("userinfo sub = %q, want %q", uResp.GetSub(), sub)
	}
	gResp, oe := svc.GetUserInfo(context.Background(), accessRaw)
	if oe != nil {
		t.Fatalf("GetUserInfo: %v", oe)
	}
	if gResp.GetSub() != sub {
		t.Errorf("get_user_info sub = %q, want %q", gResp.GetSub(), sub)
	}
	uid, clientID, err := newTestSubCodec(t).DecodeSub(gResp.GetSub())
	if err != nil || uid != 42 || clientID != "web" {
		t.Errorf("解码对外 sub 还原 = (%d, %q, %v), want (42, web, nil)", uid, clientID, err)
	}
}
