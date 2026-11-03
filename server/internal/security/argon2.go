package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id 参数（OWASP 推荐档位，与 §3.2 默认、setup 安装路径一致）：
// m=64MiB、t=3、p=4、keyLen=32、saltLen=16。
const (
	argon2Time     = 3
	argon2MemoryKiB = 64 * 1024
	argon2Parallel = 4
	argon2KeyLen    = 32
	argon2SaltLen   = 16

	// argon2MaxMemoryKiB 串内参数防滥用上限（1 GiB）：哈希串来自
	// user_credential.secret（可信写入），上限仅防手工导入数据触发
	// 超大内存分配拖垮校验路径。
	argon2MaxMemoryKiB = 1 << 20
)

// ErrInvalidHash 哈希串格式损坏（不可解析），与口令对错无关。
var ErrInvalidHash = errors.New("security: invalid argon2id hash")

// ErrPasswordMismatch 口令不匹配。
var ErrPasswordMismatch = errors.New("security: password mismatch")

// HashPassword 生成自包含 PHC 串（盐与参数随哈希一起存储，校验时按串内
// 参数重算，无外部状态）：
//
//	$argon2id$v=19$m=65536,t=3,p=4$<salt>$<key>
//
// salt/key 为 Raw base64（与 setup 安装路径同口径）。
func HashPassword(password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("security: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2MemoryKiB, argon2Parallel, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2MemoryKiB, argon2Time, argon2Parallel,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword 按串内自包含参数校验口令：损坏串 → ErrInvalidHash，
// 口令不符 → ErrPasswordMismatch。两分支文案均不泄露哈希细节。
func VerifyPassword(password, encoded string) error {
	salt, want, prm, err := parseArgon2Hash(encoded)
	if err != nil {
		return err
	}
	got := argon2.IDKey([]byte(password), salt, prm.time, prm.memory, prm.parallel, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

type argon2Params struct {
	time     uint32
	memory   uint32
	parallel uint8
}

// parseArgon2Hash 解析 $argon2id$v=N$m=...,t=...,p=...$<salt>$<key>。
func parseArgon2Hash(encoded string) (salt, key []byte, prm argon2Params, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, nil, prm, ErrInvalidHash
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[2], "v="))
	if err != nil || version != argon2.Version {
		return nil, nil, prm, ErrInvalidHash
	}
	kv := strings.Split(parts[3], ",")
	if len(kv) != 3 || !strings.HasPrefix(kv[0], "m=") || !strings.HasPrefix(kv[1], "t=") || !strings.HasPrefix(kv[2], "p=") {
		return nil, nil, prm, ErrInvalidHash
	}
	memory, err := strconv.ParseUint(kv[0][2:], 10, 32)
	if err != nil {
		return nil, nil, prm, ErrInvalidHash
	}
	timeCost, err := strconv.ParseUint(kv[1][2:], 10, 32)
	if err != nil {
		return nil, nil, prm, ErrInvalidHash
	}
	parallel, err := strconv.ParseUint(kv[2][2:], 10, 8)
	if err != nil || memory == 0 || memory > argon2MaxMemoryKiB || timeCost == 0 || parallel == 0 {
		return nil, nil, prm, ErrInvalidHash
	}
	prm = argon2Params{time: uint32(timeCost), memory: uint32(memory), parallel: uint8(parallel)}
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return nil, nil, prm, ErrInvalidHash
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return nil, nil, prm, ErrInvalidHash
	}
	return salt, key, prm, nil
}
