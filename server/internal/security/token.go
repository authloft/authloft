package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

// 通用封装（后端架构 §11.6.1，§1.4：本文件是唯一编解码实现，多类令牌
// 与内部载荷共用）：
//
//	token = base64url( prefix || nonce || ciphertext || tag )
//	prefix      2B   [version:1][kid:1]
//	nonce      12B   crypto/rand
//	ciphertext  nB   AES-256-GCM(protobuf_payload)
//	tag        16B   （GCM Seal 输出即 ciphertext||tag 拼接）
//
//	AAD = "al/" || prefix || purpose
//
// version+kid 与 purpose 均进 AAD → 防降级、防跨类型串用（同 key 不同
// version/kid/purpose 一律解不开）；purpose 取值封闭见 purpose.go。
// base64url 取 Raw（无 padding），令牌可安全进 URL / Cookie / JSON。
const (
	tokenPrefixLen = 2
	tokenNonceLen  = 12
	tokenTagLen    = 16
	tokenMinLen    = tokenPrefixLen + tokenNonceLen + tokenTagLen
	tokenAADPrefix = "al/"
)

// Codec 令牌编解码器：Seal 用 keystore 当前签发密钥，Open 按令牌前缀取钥。
type Codec struct {
	ks *KeyStore
}

// NewCodec 构造编解码器（keystore 由装配方构造注入，本包不读配置）。
func NewCodec(ks *KeyStore) *Codec { return &Codec{ks: ks} }

// Seal 将 msg（protobuf 序列化）按 purpose 加密封装为令牌串。purpose
// 必须属于 purpose.go 的封闭集合；密钥取 keystore 签发路径（轮换后
// 自动用新 kid 签，旧令牌仍可 Open）。
func (c *Codec) Seal(purpose string, msg proto.Message) (string, error) {
	if !validPurpose(purpose) {
		return "", fmt.Errorf("security: unknown purpose %q", purpose)
	}
	id := c.ks.SigningID()
	key := c.ks.signingKey()
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	plain, err := proto.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("security: marshal payload: %w", err)
	}
	nonce := make([]byte, tokenNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("security: read nonce: %w", err)
	}
	prefix := [...]byte{id.Version, id.Kid}
	sealed := gcm.Seal(nil, nonce, plain, tokenAAD(prefix[:], purpose))
	out := make([]byte, 0, tokenPrefixLen+tokenNonceLen+len(sealed))
	out = append(out, prefix[:]...)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Open 用 purpose 解开令牌并反序列化为 M（M 由 *T 推导）。调用方式：
//
//	msg, err := security.Open[pb.LoginTokenPayload](codec, security.PurposeLogin, tok)
//
// purpose 必须与 Seal 时一致；跨 purpose、篡改、未知 kid 一律失败。
func Open[T any, M interface {
	proto.Message
	*T
}](c *Codec, purpose, token string) (M, error) {
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

// open 解出明文字节。GCM 认证通过即证明密文、tag、AAD（含 prefix 的
// version/kid 与 purpose）与密钥全部匹配，任何一处不符都会失败。
func (c *Codec) open(purpose, token string) ([]byte, error) {
	if !validPurpose(purpose) {
		return nil, fmt.Errorf("security: unknown purpose %q", purpose)
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
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil,
		raw[tokenPrefixLen:tokenPrefixLen+tokenNonceLen],
		raw[tokenPrefixLen+tokenNonceLen:],
		tokenAAD(prefix, purpose))
	if err != nil {
		return nil, fmt.Errorf("security: decrypt token: %w", err)
	}
	return plain, nil
}

// tokenAAD §11.6.1：AAD = "al/" || prefix || purpose（prefix 为 2 原始字节）。
func tokenAAD(prefix []byte, purpose string) []byte {
	aad := make([]byte, 0, len(tokenAADPrefix)+len(prefix)+len(purpose))
	aad = append(aad, tokenAADPrefix...)
	aad = append(aad, prefix...)
	aad = append(aad, purpose...)
	return aad
}

// newGCM 每次按 key 构造（key 为副本，用后即弃；无状态，无算法协商）。
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("security: init aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("security: init gcm: %w", err)
	}
	return gcm, nil
}
