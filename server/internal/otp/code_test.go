package otp

import (
	"context"
	"errors"
	"testing"
	"time"

	"authloft/internal/cache"
)

// fakeStore 记录 Send / Verify 入参并返回预设结果，不连 Redis。
type fakeStore struct {
	sendResult   cache.SendResult
	sendErr      error
	verifyResult cache.VerifyResult
	attemptsLeft int64
	verifyErr    error

	gotTarget  string
	gotPurpose string
	gotOwner   string
	gotIP      string
	gotCode    string
}

func (s *fakeStore) Send(_ context.Context, target, purpose, owner, ip, code string) (cache.SendResult, error) {
	s.gotTarget, s.gotPurpose, s.gotOwner, s.gotIP, s.gotCode = target, purpose, owner, ip, code
	return s.sendResult, s.sendErr
}

func (s *fakeStore) Verify(_ context.Context, target, purpose, owner, code string) (cache.CodeVerifyResult, error) {
	s.gotTarget, s.gotPurpose, s.gotOwner, s.gotCode = target, purpose, owner, code
	return cache.CodeVerifyResult{Result: s.verifyResult, AttemptsLeft: s.attemptsLeft}, s.verifyErr
}

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.TTL != 300*time.Second || c.Cooldown != 60*time.Second {
		t.Fatalf("TTL/Cooldown = %v/%v, want 300s/60s", c.TTL, c.Cooldown)
	}
	if c.MaxAttempts != 5 || c.TargetDailyLimit != 10 || c.IPDailyLimit != 50 {
		t.Fatalf("limits = %d/%d/%d, want 5/10/50", c.MaxAttempts, c.TargetDailyLimit, c.IPDailyLimit)
	}
}

func TestConfigEffectiveFallsBackToDefaults(t *testing.T) {
	c := (Config{Cooldown: 30 * time.Second}).Effective()
	if c.TTL != 300*time.Second || c.Cooldown != 30*time.Second {
		t.Fatalf("effective = %v/%v", c.TTL, c.Cooldown)
	}
	if c.MaxAttempts != 5 || c.TargetDailyLimit != 10 || c.IPDailyLimit != 50 {
		t.Fatalf("limits = %d/%d/%d", c.MaxAttempts, c.TargetDailyLimit, c.IPDailyLimit)
	}
	if got := (Config{}).TTLSeconds(); got != 300 {
		t.Fatalf("TTLSeconds = %d, want 300", got)
	}
	if got := (Config{}).CooldownSeconds(); got != 60 {
		t.Fatalf("CooldownSeconds = %d, want 60", got)
	}
}

func TestGenerateIsSixDigits(t *testing.T) {
	seen := make(map[string]bool, 64)
	for i := 0; i < 64; i++ {
		code, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !WellFormed(code) {
			t.Fatalf("Generate = %q, want 6 digits", code)
		}
		seen[code] = true
	}
	// 64 次生成全撞的概率可忽略；只确认不是常量。
	if len(seen) < 2 {
		t.Fatal("Generate returned the same code 64 times")
	}
}

func TestWellFormed(t *testing.T) {
	for _, code := range []string{"001234", "999999"} {
		if !WellFormed(code) {
			t.Fatalf("WellFormed(%q) = false, want true", code)
		}
	}
	for _, code := range []string{"", "12345", "1234567", "12a456", " 12345"} {
		if WellFormed(code) {
			t.Fatalf("WellFormed(%q) = true, want false", code)
		}
	}
}

func TestIssueGeneratesAndDelegates(t *testing.T) {
	st := &fakeStore{sendResult: cache.SendOK}
	svc := NewService(st, DefaultConfig())

	code, res, err := svc.Issue(context.Background(), "13800000000", "login", "tid-1", "10.0.0.1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if res != cache.SendOK {
		t.Fatalf("res = %v, want SendOK", res)
	}
	if !WellFormed(code) {
		t.Fatalf("code = %q, want 6 digits", code)
	}
	if st.gotCode != code || st.gotTarget != "13800000000" || st.gotPurpose != "login" || st.gotOwner != "tid-1" || st.gotIP != "10.0.0.1" {
		t.Fatalf("delegated args = %q/%q/%q/%q, want code/target/purpose/owner/ip", st.gotTarget, st.gotPurpose, st.gotOwner, st.gotIP)
	}
}

func TestIssueRejectsMissingBinding(t *testing.T) {
	svc := NewService(&fakeStore{sendResult: cache.SendOK}, DefaultConfig())
	if _, _, err := svc.Issue(context.Background(), "", "login", "tid-1", ""); err == nil {
		t.Fatal("Issue with empty target must fail")
	}
	if _, _, err := svc.Issue(context.Background(), "13800000000", "", "tid-1", ""); err == nil {
		t.Fatal("Issue with empty purpose must fail")
	}
	// 空 owner 会写出无法校验的码（§10.1 行 1121），必须拒绝。
	if _, _, err := svc.Issue(context.Background(), "13800000000", "login", "", ""); err == nil {
		t.Fatal("Issue with empty owner must fail")
	}
}

func TestIssuePropagatesStoreError(t *testing.T) {
	wantErr := errors.New("redis down")
	svc := NewService(&fakeStore{sendErr: wantErr}, DefaultConfig())
	if _, _, err := svc.Issue(context.Background(), "13800000000", "login", "tid-1", "10.0.0.1"); !errors.Is(err, wantErr) {
		t.Fatalf("Issue err = %v, want %v", err, wantErr)
	}
}

func TestCheckMapsVerifyResults(t *testing.T) {
	cases := []struct {
		in   cache.VerifyResult
		want CheckOutcome
	}{
		{cache.VerifyOK, CheckOK},
		{cache.VerifyMismatch, CheckMismatch},
		{cache.VerifyExhausted, CheckExhausted},
		{cache.VerifyMissing, CheckMissing},
	}
	for _, tc := range cases {
		st := &fakeStore{verifyResult: tc.in}
		svc := NewService(st, DefaultConfig())
		got, err := svc.Check(context.Background(), "13800000000", "login", "tid-1", "123456")
		if err != nil {
			t.Fatalf("Check(%v): %v", tc.in, err)
		}
		if got.Outcome != tc.want {
			t.Fatalf("Check(%v) = %v, want %v", tc.in, got.Outcome, tc.want)
		}
		if st.gotTarget != "13800000000" || st.gotPurpose != "login" || st.gotOwner != "tid-1" || st.gotCode != "123456" {
			t.Fatalf("delegated args = %q/%q/%q/%q", st.gotTarget, st.gotPurpose, st.gotOwner, st.gotCode)
		}
	}
}

// TestCheckCarriesAttemptsLeft 错码且键保留时必须透出剩余尝试次数
// （接口文档 §2.6 行 553；§1.3 行 151 attempts_left 可选但具体条款优先）。
func TestCheckCarriesAttemptsLeft(t *testing.T) {
	st := &fakeStore{verifyResult: cache.VerifyMismatch, attemptsLeft: 3}
	svc := NewService(st, DefaultConfig())
	got, err := svc.Check(context.Background(), "13800000000", "login", "tid-1", "123456")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Outcome != CheckMismatch || got.AttemptsLeft != 3 {
		t.Fatalf("Check = %+v, want mismatch with attemptsLeft 3", got)
	}
}

func TestCheckPropagatesStoreError(t *testing.T) {
	wantErr := errors.New("redis down")
	svc := NewService(&fakeStore{verifyErr: wantErr}, DefaultConfig())
	if _, err := svc.Check(context.Background(), "13800000000", "login", "tid-1", "123456"); !errors.Is(err, wantErr) {
		t.Fatalf("Check err = %v, want %v", err, wantErr)
	}
}

func TestJudgeMapsSendResults(t *testing.T) {
	now := time.Date(2026, 11, 4, 23, 0, 0, 0, time.Local)

	if d := Judge(cache.SendOK, DefaultConfig(), now); !d.Allowed {
		t.Fatalf("SendOK = %+v, want allowed", d)
	}
	if d := Judge(cache.SendCooldown, DefaultConfig(), now); d.Allowed || d.Status != StatusTooManyRequests || d.RetryAfter != 60 {
		t.Fatalf("SendCooldown = %+v, want too_many_requests/60", d)
	}
	if d := Judge(cache.SendTargetDailyLimit, DefaultConfig(), now); d.Allowed || d.Status != StatusTooManyRequests {
		t.Fatalf("SendTargetDailyLimit = %+v", d)
	}
	if d := Judge(cache.SendIPDailyLimit, DefaultConfig(), now); d.Allowed || d.Status != StatusTooManyRequests {
		t.Fatalf("SendIPDailyLimit = %+v", d)
	}
	// 23:00 → 距当天 24:00 恰好 3600s。
	if d := Judge(cache.SendTargetDailyLimit, DefaultConfig(), now); d.RetryAfter != 3600 {
		t.Fatalf("daily RetryAfter = %d, want 3600", d.RetryAfter)
	}
}
