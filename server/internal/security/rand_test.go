package security

import (
	"strings"
	"testing"
)

// TestRandomBytes 长度、n=0、负数报错、两次不同。
func TestRandomBytes(t *testing.T) {
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("len = %d, want 32", len(b))
	}
	if b2, _ := RandomBytes(32); string(b) == string(b2) {
		t.Fatal("two RandomBytes must differ")
	}
	if b, err := RandomBytes(0); err != nil || len(b) != 0 {
		t.Fatalf("n=0: b=%v err=%v", b, err)
	}
	if _, err := RandomBytes(-1); err == nil {
		t.Fatal("negative n must fail")
	}
}

// TestRandomString 长度、字符集 ⊆ URL-safe 字母表、n=0、负数报错。
func TestRandomString(t *testing.T) {
	s, err := RandomString(64)
	if err != nil {
		t.Fatalf("RandomString: %v", err)
	}
	if len(s) != 64 {
		t.Fatalf("len = %d, want 64", len(s))
	}
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(urlSafeAlphabet, rune(s[i])) {
			t.Fatalf("char %q at %d outside URL-safe alphabet", s[i], i)
		}
	}
	if s2, _ := RandomString(64); s == s2 {
		t.Fatal("two RandomString must differ")
	}
	if s, err := RandomString(0); err != nil || s != "" {
		t.Fatalf("n=0: s=%q err=%v", s, err)
	}
	if _, err := RandomString(-1); err == nil {
		t.Fatal("negative n must fail")
	}
}

// TestRandomStringCharset 分布冒烟：64 字符字母表在长串中应全部出现
//（概率意义上，64*30 字符期望每字符出现 ~30 次，缺失概率可忽略）。
func TestRandomStringCharset(t *testing.T) {
	s, err := RandomString(64 * 30)
	if err != nil {
		t.Fatalf("RandomString: %v", err)
	}
	for _, c := range urlSafeAlphabet {
		if !strings.ContainsRune(s, rune(c)) {
			t.Fatalf("alphabet char %q missing from sample", c)
		}
	}
}
