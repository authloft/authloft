package security

import (
	"errors"
	"strings"
	"testing"
)

// TestHashPasswordFormat PHC 格式：头 + 参数（OWASP 档位 m=65536 t=3 p=4）
// + Raw base64 盐 / 摘要；两次哈希不同（随机盐）。
func TestHashPasswordFormat(t *testing.T) {
	h1, err := HashPassword("Str0ngPassw0rd")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	prefix := "$argon2id$v=19$m=65536,t=3,p=4$"
	if !strings.HasPrefix(h1, prefix) {
		t.Fatalf("hash prefix wrong: %q", h1)
	}
	if parts := strings.Split(h1, "$"); len(parts) != 6 {
		t.Fatalf("hash has %d parts, want 6: %q", len(parts), h1)
	}
	h2, _ := HashPassword("Str0ngPassw0rd")
	if h1 == h2 {
		t.Fatal("two hashes must differ (random salt)")
	}
}

// TestVerifyPasswordRoundTrip 正确口令通过；错误口令 → ErrPasswordMismatch。
func TestVerifyPasswordRoundTrip(t *testing.T) {
	encoded, err := HashPassword("Str0ngPassw0rd")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := VerifyPassword("Str0ngPassw0rd", encoded); err != nil {
		t.Fatalf("correct password must verify: %v", err)
	}
	err = VerifyPassword("Str0ngPassw0rD", encoded)
	if !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("wrong password = %v, want ErrPasswordMismatch", err)
	}
}

// TestVerifyPasswordInvalidHash 损坏哈希串 → ErrInvalidHash（不 panic、
// 不误报 mismatch）。
func TestVerifyPasswordInvalidHash(t *testing.T) {
	encoded, err := HashPassword("Str0ngPassw0rd")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	parts := strings.Split(encoded, "$")
	bad := map[string]string{
		"empty":          "",
		"not argon2":     strings.Replace(encoded, "argon2id", "bcrypt", 1),
		"bad version":    "$argon2id$v=99$" + parts[3] + "$" + parts[4] + "$" + parts[5],
		"missing tail":   strings.TrimSuffix(encoded, "$"+parts[5]),
		"bad params":     "$argon2id$v=19$m=65536,t=0,p=4$" + parts[4] + "$" + parts[5],
		"oversize memory": "$argon2id$v=19$m=99999999,t=3,p=4$" + parts[4] + "$" + parts[5],
		"bad salt b64":   "$argon2id$v=19$m=65536,t=3,p=4$!!!!$" + parts[5],
		"bad key b64":    "$argon2id$v=19$m=65536,t=3,p=4$" + parts[4] + "$??",
		"zero parallel":  "$argon2id$v=19$m=65536,t=3,p=0$" + parts[4] + "$" + parts[5],
	}
	for name, s := range bad {
		err := VerifyPassword("Str0ngPassw0rd", s)
		if !errors.Is(err, ErrInvalidHash) {
			t.Errorf("%s: err = %v, want ErrInvalidHash", name, err)
		}
	}
}

// TestVerifyPasswordParamsHonor 串内参数必须被尊重（手工构造 t=1 短参
// 串，同一口令按参数重算仍通过）。
func TestVerifyPasswordParamsHonor(t *testing.T) {
	encoded, err := HashPassword("Abcdef12")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := VerifyPassword("Abcdef12", encoded); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
