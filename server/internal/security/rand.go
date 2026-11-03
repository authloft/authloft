package security

import (
	"crypto/rand"
	"fmt"
	"io"
)

// urlSafeAlphabet URL-safe 随机字符集（base64url 字母表，无 padding）。
const urlSafeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// RandomBytes 返回 n 个 crypto/rand 随机字节（§3.11：禁 math/rand）。
func RandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("security: negative length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, fmt.Errorf("security: read random bytes: %w", err)
	}
	return buf, nil
}

// RandomString 返回 n 个 URL-safe 随机字符（crypto/rand）。字母表恰
// 64 个字符占 6 位，取 b&63 无模偏差，无需拒绝采样。
func RandomString(n int) (string, error) {
	if n < 0 {
		return "", fmt.Errorf("security: negative length %d", n)
	}
	out := make([]byte, n)
	buf := make([]byte, n)
	for off := 0; off < n; {
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return "", fmt.Errorf("security: read random bytes: %w", err)
		}
		for _, b := range buf {
			out[off] = urlSafeAlphabet[b&63]
			off++
			if off == n {
				break
			}
		}
	}
	return string(out), nil
}
