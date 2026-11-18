package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"google.golang.org/protobuf/proto"
)

// DeterministicCodec 是 §11.6.8 的确定性封装变体：复用 §11.6.1 的
// prefix / tag / AAD 结构，但 nonce 不取随机，而由明文经 HMAC 确定性派生。
// 它把 OidcSubPayload 稳定映射为对外 sub：同一 (client_id, uid) 重复签发
// 逐字节一致，不同客户端对同一用户天然互异；GCM 仍负责认证与机密性。
//
// 与随机 nonce 变体的关键差别：nonce 是明文的函数、必须随令牌传输，
// Open 端解密后重算 HMAC 比对。不可改成字面固定 nonce 或引入映射表——
// 固定 nonce 会触发 GCM forbidden attack（同 key/nonce 两条密文即可恢复
// 认证子密钥、离线伪造任意 sub），映射表则与新表约束冲突。
type DeterministicCodec struct {
	ks *KeyStore
	// k_enc / k_mac 构造期由签发密钥派生（§11.6.8），原密钥不直接进 GCM。
	kEnc []byte
	kMac []byte
}

// NewDeterministicCodec 用第 8 把 sign_key.oidc_sub 构造确定性 codec。
// 构造期即派生两把子密钥；keystore 仍保留以支持 prefix/kid 的 AAD 绑定
// 与轮换期历史密钥解码。
func NewDeterministicCodec(ks *KeyStore) (*DeterministicCodec, error) {
	if ks == nil {
		return nil, fmt.Errorf("security: deterministic codec: nil keystore")
	}
	kEnc, kMac := deriveSubKeys(ks.signingKey())
	return &DeterministicCodec{ks: ks, kEnc: kEnc, kMac: kMac}, nil
}

// deriveSubKeys §11.6.8：k_enc = SHA256(key‖"enc")、k_mac = SHA256(key‖"mac")。
// 两把子密钥与原始密钥、彼此之间均无直接关系，原密钥不直接用做 AES 密钥。
func deriveSubKeys(key []byte) (kEnc, kMac []byte) {
	encIn := append(append([]byte(nil), key...), []byte("enc")...)
	macIn := append(append([]byte(nil), key...), []byte("mac")...)
	enc := sha256.Sum256(encIn)
	mac := sha256.Sum256(macIn)
	return enc[:], mac[:]
}

// deriveNonce §11.6.8：nonce = HMAC-SHA256(k_mac, 明文序列化)[:12]。
// 明文相等则 nonce 相等——这正是 pairwise sub 需要的语义；不同明文碰撞
// 概率约 2^-96，无 keystream 重用，XOR / forbidden attack 均不成立。
func deriveNonce(kMac, plain []byte) []byte {
	mac := hmac.New(sha256.New, kMac)
	mac.Write(plain)
	return mac.Sum(nil)[:tokenNonceLen]
}

// Seal 将 msg 按 §11.6.8 确定性封装为 sub 串。purpose 必须为 oidc_sub。
// 同一明文、同一密钥、同一 kid 的两次 Seal 逐字节一致。
func (c *DeterministicCodec) Seal(purpose string, msg proto.Message) (string, error) {
	if purpose != PurposeOidcSub {
		return "", fmt.Errorf("security: deterministic codec only seals %q, got %q", PurposeOidcSub, purpose)
	}
	plain, err := proto.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("security: marshal payload: %w", err)
	}
	id := c.ks.SigningID()
	prefix := [...]byte{id.Version, id.Kid}
	nonce := deriveNonce(c.kMac, plain)
	gcm, err := newGCM(c.kEnc)
	if err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, plain, tokenAAD(prefix[:], purpose))
	out := make([]byte, 0, tokenPrefixLen+tokenNonceLen+len(sealed))
	out = append(out, prefix[:]...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// OpenDeterministic 解开 sub 并反序列化为 M，用法与 token.go 的 Open 一致：
//
//	msg, err := security.OpenDeterministic[token.OidcSubPayload](codec, security.PurposeOidcSub, sub)
//
// purpose 必须为 oidc_sub；跨 purpose、篡改、替换 nonce、未知 kid 一律失败。
func OpenDeterministic[T any, M interface {
	proto.Message
	*T
}](c *DeterministicCodec, purpose, token string) (M, error) {
	plain, err := c.open(purpose, token)
	if err != nil {
		var zero M
		return zero, err
	}
	var msg M = new(T)
	if err := proto.Unmarshal(plain, msg); err != nil {
		var zero M
		return zero, fmt.Errorf("security: unmarshal payload: %w", err)
	}
	return msg, nil
}

// open 解出明文字节：GCM 认证通过后再重算 HMAC 比对 nonce（§11.6.8
// 的规范 nonce 校验），防任何非派生 nonce 的用法。
func (c *DeterministicCodec) open(purpose, token string) ([]byte, error) {
	if purpose != PurposeOidcSub {
		return nil, fmt.Errorf("security: deterministic codec only opens %q, got %q", PurposeOidcSub, purpose)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("security: token base64: %w", err)
	}
	if len(raw) < tokenMinLen {
		return nil, fmt.Errorf("security: token too short (%d bytes)", len(raw))
	}
	prefix := raw[:tokenPrefixLen]
	key, ok := c.ks.Lookup(KeyID{Version: prefix[0], Kid: prefix[1]})
	if !ok {
		return nil, fmt.Errorf("security: unknown key id (version=%d kid=%d)", prefix[0], prefix[1])
	}
	// 轮换期历史 kid 用它自己的 key 派生子密钥；当前 kid 与构造期结果一致。
	kEnc, kMac := deriveSubKeys(key)
	gcm, err := newGCM(kEnc)
	if err != nil {
		return nil, err
	}
	nonce := raw[tokenPrefixLen : tokenPrefixLen+tokenNonceLen]
	plain, err := gcm.Open(nil, nonce, raw[tokenPrefixLen+tokenNonceLen:], tokenAAD(prefix, purpose))
	if err != nil {
		return nil, fmt.Errorf("security: decrypt token: %w", err)
	}
	want := deriveNonce(kMac, plain)
	if subtle.ConstantTimeCompare(nonce, want) != 1 {
		return nil, fmt.Errorf("security: nonce not derived from plaintext")
	}
	return plain, nil
}
