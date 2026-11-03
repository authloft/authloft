package security

import "fmt"

// aesKeyLen AES-256 密钥字节数（§11.6.1：算法固定 AES-256-GCM，不做协商）。
const aesKeyLen = 32

// KeyID 令牌前缀携带的密钥标识（§11.6.1 prefix = [version:1][kid:1]）。
type KeyID struct {
	Version byte
	Kid     byte
}

// KeyEntry 一把 AES-256 密钥及其标识。Key 构造时拷贝，调用方事后修改
// 原切片不影响 store。
type KeyEntry struct {
	ID  KeyID
	Key []byte
}

// KeyStore version+kid → key 映射（§1.4 / §3.11）。两条使用路径：
//   - 签发（token.go Seal）：固定用当前签发密钥；
//   - 解密（token.go Open）：按令牌前缀 Lookup，签发密钥与历史密钥都在表内。
//
// 轮换 = 新 KeyEntry 作 sign、旧 KeyEntry 降级进 legacy（轮换期新旧并存）：
// 旧 kid 可解、新 kid 可签。密钥由构造方注入（叶子包约束，不读配置）。
type KeyStore struct {
	sign   KeyEntry
	decode map[KeyID][]byte
}

// NewKeyStore sign 为当前签发密钥；legacy 为仍需可解密的历史密钥。
func NewKeyStore(sign KeyEntry, legacy ...KeyEntry) (*KeyStore, error) {
	if len(sign.Key) != aesKeyLen {
		return nil, fmt.Errorf("security: sign key must be %d bytes, got %d", aesKeyLen, len(sign.Key))
	}
	ks := &KeyStore{
		sign:   KeyEntry{ID: sign.ID, Key: append([]byte(nil), sign.Key...)},
		decode: make(map[KeyID][]byte, len(legacy)+1),
	}
	ks.decode[ks.sign.ID] = ks.sign.Key
	for _, e := range legacy {
		if len(e.Key) != aesKeyLen {
			return nil, fmt.Errorf("security: legacy key %d/%d must be %d bytes, got %d", e.ID.Version, e.ID.Kid, aesKeyLen, len(e.Key))
		}
		if _, dup := ks.decode[e.ID]; dup {
			return nil, fmt.Errorf("security: duplicate key id (version=%d kid=%d)", e.ID.Version, e.ID.Kid)
		}
		ks.decode[e.ID] = append([]byte(nil), e.Key...)
	}
	return ks, nil
}

// SigningID 当前签发密钥标识（进令牌 prefix 与 AAD）。
func (ks *KeyStore) SigningID() KeyID { return ks.sign.ID }

// signingKey 当前签发密钥（仅本包使用；返回副本，不暴露内部切片）。
func (ks *KeyStore) signingKey() []byte { return append([]byte(nil), ks.sign.Key...) }

// Lookup 按令牌前缀查解密密钥（含签发密钥）。返回副本，调用方改动不影响 store。
func (ks *KeyStore) Lookup(id KeyID) ([]byte, bool) {
	key, ok := ks.decode[id]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), key...), true
}
