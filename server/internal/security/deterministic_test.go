package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"google.golang.org/protobuf/proto"

	"authloft/gen/go/token"
)

// newTestDeterministic 用单字节填充密钥构造确定性 codec。
func newTestDeterministic(t *testing.T, b byte) *DeterministicCodec {
	t.Helper()
	ks, err := NewKeyStore(KeyEntry{ID: KeyID{Version: 1, Kid: 1}, Key: testKey(b)})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	c, err := NewDeterministicCodec(ks)
	if err != nil {
		t.Fatalf("NewDeterministicCodec: %v", err)
	}
	return c
}

// subNonce 取出 sub 中随令牌传输的 nonce 字节。
func subNonce(t *testing.T, sub string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(sub)
	if err != nil {
		t.Fatalf("decode sub: %v", err)
	}
	if len(raw) < tokenMinLen {
		t.Fatalf("sub too short: %d", len(raw))
	}
	return append([]byte(nil), raw[tokenPrefixLen:tokenPrefixLen+tokenNonceLen]...)
}

// TestDeterministicSubKeyDerivation k_enc / k_mac 由原始密钥分别派生，
// 彼此独立、且都不等于原密钥（§11.6.8）。
func TestDeterministicSubKeyDerivation(t *testing.T) {
	key := testKey(0xA1)
	kEnc, kMac := deriveSubKeys(key)
	wantEnc := sha256.Sum256(append(append([]byte(nil), key...), []byte("enc")...))
	wantMac := sha256.Sum256(append(append([]byte(nil), key...), []byte("mac")...))
	if !bytes.Equal(kEnc, wantEnc[:]) {
		t.Fatal("k_enc must be SHA256(key||\"enc\")")
	}
	if !bytes.Equal(kMac, wantMac[:]) {
		t.Fatal("k_mac must be SHA256(key||\"mac\")")
	}
	if bytes.Equal(kEnc, kMac) || bytes.Equal(kEnc, key) || bytes.Equal(kMac, key) {
		t.Fatal("derived sub keys must differ from each other and from the raw key")
	}
}

// TestDeterministicSamePlaintextStable 同一 (client_id, uid) 双次 Seal
// 逐字节一致；不同明文 nonce 恒不同、sub 互异（pairwise，§11.6.8）。
func TestDeterministicSamePlaintextStable(t *testing.T) {
	c := newTestDeterministic(t, 0xA1)
	msg := &token.OidcSubPayload{ClientId: "client-1", Uid: 42}
	s1, err := c.Seal(PurposeOidcSub, msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	s2, err := c.Seal(PurposeOidcSub, msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if s1 != s2 {
		t.Fatal("same plaintext must seal byte-identically")
	}

	others := []*token.OidcSubPayload{
		{ClientId: "client-1", Uid: 43},
		{ClientId: "client-2", Uid: 42},
	}
	n1 := subNonce(t, s1)
	for _, other := range others {
		so, err := c.Seal(PurposeOidcSub, other)
		if err != nil {
			t.Fatalf("Seal(other): %v", err)
		}
		if so == s1 {
			t.Fatalf("different plaintext must yield different sub: %v", other)
		}
		if bytes.Equal(subNonce(t, so), n1) {
			t.Fatalf("different plaintext must yield different nonce: %v", other)
		}
	}
}

// TestDeterministicRoundTrip OidcSubPayload 全字段 Seal→OpenDeterministic
// 往返一致。
func TestDeterministicRoundTrip(t *testing.T) {
	c := newTestDeterministic(t, 0xA1)
	want := &token.OidcSubPayload{ClientId: "client-1", Uid: 9223372036854775807}
	sub, err := c.Seal(PurposeOidcSub, want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := OpenDeterministic[token.OidcSubPayload](c, PurposeOidcSub, sub)
	if err != nil {
		t.Fatalf("OpenDeterministic: %v", err)
	}
	if !proto.Equal(want, got) {
		t.Fatalf("round trip mismatch:\n got %v\nwant %v", got, want)
	}
}

// sealWithChosenNonce 用攻击者自选 nonce 但仍以正确 k_enc / AAD 封装相同
// 明文——GCM 认证可通过，借此单独验证 Open 端的 HMAC nonce 重算比对。
func sealWithChosenNonce(t *testing.T, c *DeterministicCodec, nonce []byte, msg proto.Message) string {
	t.Helper()
	plain, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	gcm, err := newGCM(c.kEnc)
	if err != nil {
		t.Fatalf("newGCM: %v", err)
	}
	prefix := [...]byte{1, 1}
	sealed := gcm.Seal(nil, nonce, plain, tokenAAD(prefix[:], PurposeOidcSub))
	out := make([]byte, 0, tokenPrefixLen+tokenNonceLen+len(sealed))
	out = append(out, prefix[:]...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return base64.RawURLEncoding.EncodeToString(out)
}

// TestDeterministicNonceMustBeDerived 替换 nonce 解密失败：直接翻转 nonce
// 字节失败于 GCM；用自选 nonce 但合法 GCM 密文也失败于 HMAC 重算比对。
func TestDeterministicNonceMustBeDerived(t *testing.T) {
	c := newTestDeterministic(t, 0xA1)
	msg := &token.OidcSubPayload{ClientId: "client-1", Uid: 42}
	sub, err := c.Seal(PurposeOidcSub, msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	tampered := tamperByte(t, sub, tokenPrefixLen, 0x01)
	if _, err := OpenDeterministic[token.OidcSubPayload](c, PurposeOidcSub, tampered); err == nil {
		t.Fatal("flipped nonce must fail")
	}

	forgedNonce := bytes.Repeat([]byte{0x5A}, tokenNonceLen)
	forged := sealWithChosenNonce(t, c, forgedNonce, msg)
	if _, err := OpenDeterministic[token.OidcSubPayload](c, PurposeOidcSub, forged); err == nil {
		t.Fatal("nonce that is not derived from plaintext must be rejected")
	}
}

// TestDeterministicCrossPurpose 跨 purpose 拒绝：确定性 codec 只处理
// oidc_sub；普通随机 nonce codec 以别的 purpose 也解不开该 sub（AAD 隔离）。
func TestDeterministicCrossPurpose(t *testing.T) {
	c := newTestDeterministic(t, 0xA1)
	msg := &token.OidcSubPayload{ClientId: "client-1", Uid: 42}
	if _, err := c.Seal(PurposeSession, msg); err == nil {
		t.Fatal("Seal with non-oidc_sub purpose must fail")
	}
	sub, err := c.Seal(PurposeOidcSub, msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := OpenDeterministic[token.OidcSubPayload](c, PurposeOidcCode, sub); err == nil {
		t.Fatal("OpenDeterministic with non-oidc_sub purpose must fail")
	}
	plain := NewCodec(c.ks)
	for _, purpose := range []string{PurposeSession, PurposeLogin, PurposeOidcCode} {
		if _, err := Open[token.OidcSubPayload](plain, purpose, sub); err == nil {
			t.Fatalf("cross purpose %q must fail (AAD isolation)", purpose)
		}
	}
	// 随机 nonce 变体签发的 oidc_sub 载荷也不能被确定性变体接受。
	randomNonceSub, err := plain.Seal(PurposeOidcSub, msg)
	if err != nil {
		t.Fatalf("random Seal: %v", err)
	}
	if _, err := OpenDeterministic[token.OidcSubPayload](c, PurposeOidcSub, randomNonceSub); err == nil {
		t.Fatal("random-nonce token must fail the deterministic nonce check")
	}
}

// TestDeterministicUnknownKid 未知 kid / 异密钥拒绝。
func TestDeterministicUnknownKid(t *testing.T) {
	c := newTestDeterministic(t, 0xA1)
	sub, err := c.Seal(PurposeOidcSub, &token.OidcSubPayload{ClientId: "client-1", Uid: 42})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	other := newTestDeterministic(t, 0xB2)
	if _, err := OpenDeterministic[token.OidcSubPayload](other, PurposeOidcSub, sub); err == nil {
		t.Fatal("sub sealed by another key must fail")
	}

	raw, err := base64.RawURLEncoding.DecodeString(sub)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[1] = 0x7F
	unknownKid := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := OpenDeterministic[token.OidcSubPayload](c, PurposeOidcSub, unknownKid); err == nil {
		t.Fatal("unknown kid must fail")
	}
}

// TestDeterministicTampered 篡改 ciphertext / tag / prefix 与畸形输入一律失败。
func TestDeterministicTampered(t *testing.T) {
	c := newTestDeterministic(t, 0xA1)
	sub, err := c.Seal(PurposeOidcSub, &token.OidcSubPayload{ClientId: "client-1", Uid: 42})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sub)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for name, bad := range map[string]string{
		"ciphertext": tamperByte(t, sub, tokenPrefixLen+tokenNonceLen, 0x01),
		"tag":        tamperByte(t, sub, len(raw)-tokenTagLen, 0x01),
		"version":    tamperByte(t, sub, 0, 0xFF),
		"kid":        tamperByte(t, sub, 1, 0xFF),
		"malformed":  "!!!!",
		"short":      "AAAA",
		"empty":      "",
	} {
		if _, err := OpenDeterministic[token.OidcSubPayload](c, PurposeOidcSub, bad); err == nil {
			t.Fatalf("tampered %s must fail", name)
		}
	}
}

// TestNewDeterministicCodecNilKeystore 空 keystore 构造失败。
func TestNewDeterministicCodecNilKeystore(t *testing.T) {
	if _, err := NewDeterministicCodec(nil); err == nil {
		t.Fatal("nil keystore must fail")
	}
}

// TestOpenDeterministicErrorPath 失败时泛型 OpenDeterministic 返回零值消息。
func TestOpenDeterministicErrorPath(t *testing.T) {
	c := newTestDeterministic(t, 0xA1)
	msg, err := OpenDeterministic[token.OidcSubPayload](c, PurposeOidcSub, "!!!!")
	if err == nil {
		t.Fatal("malformed sub must fail")
	}
	if msg != nil {
		t.Fatal("failed OpenDeterministic must return nil message")
	}
}
