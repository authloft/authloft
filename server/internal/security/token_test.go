package security

import (
	"encoding/base64"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"authloft/gen/go/token"
)

// testKey 生成 32B 填充测试密钥。
func testKey(b byte) []byte {
	key := make([]byte, aesKeyLen)
	for i := range key {
		key[i] = b
	}
	return key
}

// newTestCodec 构造 Codec：sign=(version,kid,key)，legacy 为历史密钥。
func newTestCodec(t *testing.T, version, kid byte, key []byte, legacy ...KeyEntry) *Codec {
	t.Helper()
	ks, err := NewKeyStore(KeyEntry{ID: KeyID{Version: version, Kid: kid}, Key: key}, legacy...)
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	return NewCodec(ks)
}

// sealOK Seal 成功否则 Fatal。
func sealOK(t *testing.T, c *Codec, purpose string, msg string) string {
	t.Helper()
	tok, err := c.Seal(purpose, wrapperspb.String(msg))
	if err != nil {
		t.Fatalf("Seal(%s): %v", purpose, err)
	}
	return tok
}

func openString(t *testing.T, c *Codec, purpose, tok string) (string, error) {
	t.Helper()
	msg, err := Open[wrapperspb.StringValue](c, purpose, tok)
	if err != nil {
		return "", err
	}
	return msg.GetValue(), nil
}

// TestSealOpenAllPurposes 八个 purpose 各自往返（§11.6.1 封闭集合）。
func TestSealOpenAllPurposes(t *testing.T) {
	c := newTestCodec(t, 1, 1, testKey(0xA1))
	for _, purpose := range []string{
		PurposeSession, PurposeLogin, PurposeTicket, PurposeBind,
		PurposeWebAuthn, PurposeCookie, PurposeSyncPayload, PurposeOidcCode,
	} {
		tok := sealOK(t, c, purpose, "payload-"+purpose)
		got, err := openString(t, c, purpose, tok)
		if err != nil {
			t.Fatalf("Open(%s): %v", purpose, err)
		}
		if want := "payload-" + purpose; got != want {
			t.Fatalf("Open(%s) = %q, want %q", purpose, got, want)
		}
	}
}

// TestOidcCodePayloadRoundTrip OidcCodePayload 全字段 Seal→Open 往返一致，
// 且跨 purpose 解同一令牌失败（§11.6.6、接口文档 §4.2）。
func TestOidcCodePayloadRoundTrip(t *testing.T) {
	c := newTestCodec(t, 1, 1, testKey(0xA1))
	want := &token.OidcCodePayload{
		ClientId:            "client-1",
		RedirectUri:         "https://app.example/callback",
		Uid:                 42,
		Scope:               "openid profile email",
		Nonce:               "n-0S6_WzA2Mj",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Amr:                 []string{"pwd", "otp"},
		AuthTime:            1700000000,
		Iat:                 1700000001,
		Exp:                 1700000121,
	}
	tok, err := c.Seal(PurposeOidcCode, want)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Open[token.OidcCodePayload](c, PurposeOidcCode, tok)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !proto.Equal(want, got) {
		t.Fatalf("round trip mismatch:\n got %v\nwant %v", got, want)
	}
	for _, purpose := range []string{
		PurposeSession, PurposeLogin, PurposeTicket, PurposeSyncPayload,
	} {
		if _, err := Open[token.OidcCodePayload](c, purpose, tok); err == nil {
			t.Fatalf("cross purpose %q must fail", purpose)
		}
	}
}

// TestSealUnknownPurpose 表外 purpose 拒绝（封闭集合）。
func TestSealUnknownPurpose(t *testing.T) {
	c := newTestCodec(t, 1, 1, testKey(0xA1))
	if _, err := c.Seal("bogus", wrapperspb.String("x")); err == nil {
		t.Fatal("Seal with unknown purpose must fail")
	}
	if _, err := Open[wrapperspb.StringValue](c, "bogus", "whatever"); err == nil {
		t.Fatal("Open with unknown purpose must fail")
	}
}

// TestSealUniqueNonce 两次 Seal 令牌不同（随机 nonce）。
func TestSealUniqueNonce(t *testing.T) {
	c := newTestCodec(t, 1, 1, testKey(0xA1))
	t1 := sealOK(t, c, PurposeLogin, "same")
	t2 := sealOK(t, c, PurposeLogin, "same")
	if t1 == t2 {
		t.Fatal("two seals must differ (random nonce)")
	}
}

// TestOpenCrossPurpose 跨 purpose 解令牌一律失败（AAD 隔离）。
func TestOpenCrossPurpose(t *testing.T) {
	c := newTestCodec(t, 1, 1, testKey(0xA1))
	tok := sealOK(t, c, PurposeLogin, "state")
	for _, purpose := range []string{
		PurposeSession, PurposeTicket, PurposeBind,
		PurposeWebAuthn, PurposeCookie, PurposeSyncPayload, PurposeOidcCode,
	} {
		if _, err := openString(t, c, purpose, tok); err == nil {
			t.Fatalf("cross purpose %q must fail", purpose)
		}
	}
	// 同 purpose 仍可解。
	if got, err := openString(t, c, PurposeLogin, tok); err != nil || got != "state" {
		t.Fatalf("same purpose must open: got %q, err %v", got, err)
	}
}

// tamperByte 篡改令牌解码后的第 i 字节再重新编码。
func tamperByte(t *testing.T, tok string, i int, xor byte) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if i >= len(raw) {
		t.Fatalf("index %d out of range (%d)", i, len(raw))
	}
	raw[i] ^= xor
	return base64.RawURLEncoding.EncodeToString(raw)
}

// TestOpenTampered 篡改 ciphertext / tag / nonce / prefix 一律失败。
func TestOpenTampered(t *testing.T) {
	c := newTestCodec(t, 1, 1, testKey(0xA1))
	tok := sealOK(t, c, PurposeSession, "secret")
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw) < tokenMinLen {
		t.Fatalf("token too short: %d", len(raw))
	}
	ciphertextAt := tokenPrefixLen + tokenNonceLen
	tagAt := len(raw) - tokenTagLen
	for name, tampered := range map[string]string{
		"ciphertext": tamperByte(t, tok, ciphertextAt, 0x01),
		"tag":        tamperByte(t, tok, tagAt, 0x01),
		"nonce":      tamperByte(t, tok, tokenNonceLen, 0x01),
		"version":    tamperByte(t, tok, 0, 0xFF),
		"kid":        tamperByte(t, tok, 1, 0xFF),
	} {
		if _, err := openString(t, c, PurposeSession, tampered); err == nil {
			t.Fatalf("tampered %s must fail", name)
		}
	}
}

// TestOpenMalformed 坏 base64 / 过短 / 空串失败。
func TestOpenMalformed(t *testing.T) {
	c := newTestCodec(t, 1, 1, testKey(0xA1))
	for _, tok := range []string{"", "!!!!", "AAAA", "QUJD"} {
		if _, err := openString(t, c, PurposeSession, tok); err == nil {
			t.Fatalf("malformed token %q must fail", tok)
		}
	}
}

// TestOpenUnknownKid 未知 kid / 未知密钥（不同 keystore）失败。
func TestOpenUnknownKid(t *testing.T) {
	a := newTestCodec(t, 1, 1, testKey(0xA1))
	b := newTestCodec(t, 1, 2, testKey(0xB2))
	tok := sealOK(t, a, PurposeBind, "x")
	if _, err := openString(t, b, PurposeBind, tok); err == nil {
		t.Fatal("token sealed by keystore A must not open in keystore B")
	}
}

// TestOpenVersionMismatch 同 kid 同 key、不同 version 也解不开
//（version 进 AAD → 防降级）。
func TestOpenVersionMismatch(t *testing.T) {
	v1 := newTestCodec(t, 1, 1, testKey(0xA1))
	v2 := newTestCodec(t, 2, 1, testKey(0xA1)) // 同 key、版本升到 2
	tok := sealOK(t, v1, PurposeTicket, "x")
	if _, err := openString(t, v2, PurposeTicket, tok); err == nil {
		t.Fatal("same key but different version must fail (version in AAD)")
	}
	tok2 := sealOK(t, v2, PurposeTicket, "x")
	if _, err := openString(t, v1, PurposeTicket, tok2); err == nil {
		t.Fatal("downgrade open must fail")
	}
	if _, err := openString(t, v2, PurposeTicket, tok2); err != nil {
		t.Fatalf("self version must open: %v", err)
	}
}

// TestKeyRotation 轮换：旧令牌可解、新令牌用新 kid 签。
func TestKeyRotation(t *testing.T) {
	oldCodec := newTestCodec(t, 1, 1, testKey(0xA1))
	newCodec := newTestCodec(t, 1, 2, testKey(0xB2), KeyEntry{ID: KeyID{Version: 1, Kid: 1}, Key: testKey(0xA1)})

	oldTok := sealOK(t, oldCodec, PurposeLogin, "old")
	newTok := sealOK(t, newCodec, PurposeLogin, "new")

	// 新 store：旧令牌（legacy kid）可解、新令牌可解。
	if got, err := openString(t, newCodec, PurposeLogin, oldTok); err != nil || got != "old" {
		t.Fatalf("legacy kid must decode: got %q, err %v", got, err)
	}
	if got, err := openString(t, newCodec, PurposeLogin, newTok); err != nil || got != "new" {
		t.Fatalf("new kid must decode: got %q, err %v", got, err)
	}
	// 旧 store：新 kid 未知，解不开。
	if _, err := openString(t, oldCodec, PurposeLogin, newTok); err == nil {
		t.Fatal("unknown new kid must fail in old keystore")
	}
	// 新令牌前缀必须携带新 kid（签发路径用 SignKid）。
	raw, err := base64.RawURLEncoding.DecodeString(newTok)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if raw[1] != 2 {
		t.Fatalf("new token kid = %d, want 2", raw[1])
	}
}

// TestNewKeyStoreErrors 构造校验：key 长度、ID 重复。
func TestNewKeyStoreErrors(t *testing.T) {
	if _, err := NewKeyStore(KeyEntry{ID: KeyID{1, 1}, Key: testKey(0xA1)[:31]}); err == nil {
		t.Fatal("31-byte sign key must fail")
	}
	if _, err := NewKeyStore(
		KeyEntry{ID: KeyID{1, 1}, Key: testKey(0xA1)},
		KeyEntry{ID: KeyID{1, 1}, Key: testKey(0xB2)}, // 与 sign 重复
	); err == nil {
		t.Fatal("duplicate sign id must fail")
	}
	if _, err := NewKeyStore(
		KeyEntry{ID: KeyID{1, 1}, Key: testKey(0xA1)},
		KeyEntry{ID: KeyID{1, 2}, Key: append(testKey(0xB2), 0)},
	); err == nil {
		t.Fatal("33-byte legacy key must fail")
	}
	ks, err := NewKeyStore(KeyEntry{ID: KeyID{1, 1}, Key: testKey(0xA1)})
	if err != nil {
		t.Fatalf("valid store: %v", err)
	}
	if _, ok := ks.Lookup(KeyID{9, 9}); ok {
		t.Fatal("lookup missing id must miss")
	}
	key, ok := ks.Lookup(ks.SigningID())
	if !ok || len(key) != aesKeyLen {
		t.Fatalf("lookup sign id: ok=%v len=%d", ok, len(key))
	}
}

// TestKeyStoreDefensiveCopy 构造后改原切片不影响 store 内密钥。
func TestKeyStoreDefensiveCopy(t *testing.T) {
	key := testKey(0xA1)
	ks, err := NewKeyStore(KeyEntry{ID: KeyID{1, 1}, Key: key})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	key[0] = 0xFF
	got, ok := ks.Lookup(KeyID{1, 1})
	if !ok || got[0] != 0xA1 {
		t.Fatal("store must hold an independent copy of the key")
	}
	got[0] = 0xFF
	got2, _ := ks.Lookup(KeyID{1, 1})
	if got2[0] != 0xA1 {
		t.Fatal("Lookup must return a copy")
	}
}

// TestOpenErrorPath 失败时泛型 Open 返回零值消息（调用方无空指针歧义）。
func TestOpenErrorPath(t *testing.T) {
	c := newTestCodec(t, 1, 1, testKey(0xA1))
	tok := sealOK(t, c, PurposeCookie, "x")
	msg, err := Open[wrapperspb.StringValue](c, PurposeSession, tok)
	if err == nil {
		t.Fatal("cross purpose must fail")
	}
	if msg != nil {
		t.Fatal("failed Open must return nil message")
	}
}
