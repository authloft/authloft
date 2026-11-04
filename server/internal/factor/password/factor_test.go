package password

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/internal/factor"
	"authloft/internal/repo/model"
	"authloft/internal/security"
)

// fakeUsers 三个查找方法返回同一结果，模拟仓储；不连 DB。
type fakeUsers struct {
	user *model.User
	err  error
}

func (f fakeUsers) FindByID(_ context.Context, _ int64) (*model.User, error) {
	return f.user, f.err
}

func (f fakeUsers) FindByUsername(_ context.Context, _ string) (*model.User, error) {
	return f.user, f.err
}

func (f fakeUsers) FindByPhone(_ context.Context, _ string) (*model.User, error) {
	return f.user, f.err
}

func (f fakeUsers) FindByEmail(_ context.Context, _ string) (*model.User, error) {
	return f.user, f.err
}

type fakeCredentials struct {
	cred *model.UserCredential
	err  error
}

func (f fakeCredentials) FindByUserAndKind(_ context.Context, _ int64, _ string) (*model.UserCredential, error) {
	return f.cred, f.err
}

// fakeFails 记录调用入参，返回预设计数 / 封禁状态。
type fakeFails struct {
	count      int64
	ban        bool
	remaining  time.Duration
	captureErr error

	captured []string
	banned   []string
}

func (f *fakeFails) Capture(_ context.Context, userRef string) (int64, error) {
	f.captured = append(f.captured, userRef)
	return f.count, f.captureErr
}

func (f *fakeFails) IsBanned(_ context.Context, _ string) (bool, error) { return f.ban, nil }

func (f *fakeFails) Ban(_ context.Context, userRef string) (bool, error) {
	f.banned = append(f.banned, userRef)
	return true, nil
}

func (f *fakeFails) BanRemaining(_ context.Context, _ string) (time.Duration, error) {
	return f.remaining, nil
}

type fakeReset struct {
	refs [][]string
}

func (f *fakeReset) ResetPasswordFailures(_ context.Context, userRefs ...string) error {
	f.refs = append(f.refs, userRefs)
	return nil
}

type fakeIP struct{ ip string }

func (f fakeIP) ClientIP(context.Context) string { return f.ip }

func newCtx(user *model.User, cred *model.UserCredential, username, password string) *factor.FactorContext {
	return &factor.FactorContext{
		Context:     context.Background(),
		Payload:     &factor.Payload{Username: username, Password: password},
		Users:       fakeUsers{user: user},
		Credentials: fakeCredentials{cred: cred},
	}
}

func TestFactorShape(t *testing.T) {
	f := New(fakeUsers{}, &fakeFails{}, &fakeReset{}, fakeIP{ip: "10.0.0.1"}, DefaultOptions())
	if f.Kind() != factor.FactorPassword {
		t.Fatalf("Kind = %v, want password", f.Kind())
	}
	if usages := f.Usages(); len(usages) != 1 || usages[0] != factor.UsagePrimary {
		t.Fatalf("Usages = %v, want [primary]", usages)
	}
	if steps := f.Steps(); len(steps) != 1 || steps[0] != factor.StepForm {
		t.Fatalf("Steps = %v, want [form]", steps)
	}
}

func TestVerifySuccessResetsFailures(t *testing.T) {
	hash, err := security.HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	user := &model.User{ID: 42, Username: "alice", UserStatus: 1}
	cred := &model.UserCredential{UserID: 42, Kind: "password", Secret: []byte(hash), IsEnabled: 1}
	reset := &fakeReset{}
	f := New(fakeUsers{user: user}, &fakeFails{}, reset, fakeIP{ip: "10.0.0.1"}, DefaultOptions())

	res, err := f.Verify(newCtx(user, cred, "alice", "correct-password"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed || res.UID != 42 {
		t.Fatalf("Verify = %+v, want passed uid=42", res)
	}
	if len(reset.refs) != 1 || len(reset.refs[0]) != 1 || reset.refs[0][0] != "42" {
		t.Fatalf("reset refs = %v, want[[42]]", reset.refs)
	}
}

func TestVerifyWrongPasswordCaptures(t *testing.T) {
	hash, err := security.HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	user := &model.User{ID: 42, Username: "alice", UserStatus: 1}
	cred := &model.UserCredential{UserID: 42, Kind: "password", Secret: []byte(hash), IsEnabled: 1}
	fails := &fakeFails{count: 1}
	reset := &fakeReset{}
	f := New(fakeUsers{user: user}, fails, reset, fakeIP{ip: "10.0.0.1"}, DefaultOptions())

	res, err := f.Verify(newCtx(user, cred, "alice", "wrong-password"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Passed || res.Status != StatusInvalidCredentials {
		t.Fatalf("Verify = %+v, want invalid_credentials", res)
	}
	if len(fails.captured) != 1 || fails.captured[0] != "42" {
		t.Fatalf("captured = %v, want [42]", fails.captured)
	}
	if len(reset.refs) != 0 {
		t.Fatalf("success queue must not be called on failure: %v", reset.refs)
	}
}

func TestVerifyBanAtThreshold(t *testing.T) {
	hash, _ := security.HashPassword("correct-password")
	user := &model.User{ID: 42, Username: "alice", UserStatus: 1}
	cred := &model.UserCredential{UserID: 42, Kind: "password", Secret: []byte(hash), IsEnabled: 1}
	fails := &fakeFails{count: defaultFailBan, remaining: 10 * time.Minute}
	f := New(fakeUsers{user: user}, fails, &fakeReset{}, fakeIP{ip: "10.0.0.1"}, DefaultOptions())

	res, err := f.Verify(newCtx(user, cred, "alice", "wrong-password"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != StatusLocked || res.RetryAfter != 600 {
		t.Fatalf("Verify = %+v, want locked/600", res)
	}
	if len(fails.banned) != 1 || fails.banned[0] != "42" {
		t.Fatalf("banned = %v, want [42]", fails.banned)
	}
}

func TestVerifyAlreadyBannedSkipsCredential(t *testing.T) {
	user := &model.User{ID: 42, Username: "alice", UserStatus: 1}
	fails := &fakeFails{ban: true, remaining: 5 * time.Minute}
	cred := &model.UserCredential{UserID: 42, Kind: "password", Secret: []byte("hash"), IsEnabled: 1}
	f := New(fakeUsers{user: user}, fails, &fakeReset{}, fakeIP{ip: "10.0.0.1"}, DefaultOptions())

	res, err := f.Verify(newCtx(user, cred, "alice", "whatever"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != StatusLocked || res.RetryAfter != 300 {
		t.Fatalf("Verify = %+v, want locked/300", res)
	}
	if len(fails.captured) != 0 {
		t.Fatalf("banned request must not capture: %v", fails.captured)
	}
}

func TestVerifyUnknownUserUsesIPHashRef(t *testing.T) {
	fails := &fakeFails{count: 1}
	f := New(fakeUsers{err: gorm.ErrRecordNotFound}, fails, &fakeReset{}, fakeIP{ip: "10.0.0.1"}, DefaultOptions())

	res, err := f.Verify(newCtx(nil, nil, "ghost", "whatever"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != StatusInvalidCredentials {
		t.Fatalf("Verify = %+v, want invalid_credentials", res)
	}
	if len(fails.captured) != 1 || !strings.HasPrefix(fails.captured[0], "10.0.0.1|") {
		t.Fatalf("captured = %v, want ip|hash prefix", fails.captured)
	}
}

func TestVerifyDisabledUser(t *testing.T) {
	user := &model.User{ID: 42, Username: "alice", UserStatus: 0}
	fails := &fakeFails{}
	f := New(fakeUsers{user: user}, fails, &fakeReset{}, fakeIP{ip: "10.0.0.1"}, DefaultOptions())

	res, err := f.Verify(newCtx(user, nil, "alice", "whatever"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != StatusUserDisabled {
		t.Fatalf("Verify = %+v, want user_disabled", res)
	}
	if len(fails.captured) != 0 {
		t.Fatalf("disabled user must not capture: %v", fails.captured)
	}
}

func TestVerifyMissingCredentialCountsAsFailure(t *testing.T) {
	user := &model.User{ID: 42, Username: "alice", UserStatus: 1}
	fails := &fakeFails{count: 1}
	f := New(fakeUsers{user: user}, fails, &fakeReset{}, fakeIP{ip: "10.0.0.1"}, DefaultOptions())
	ctx := &factor.FactorContext{
		Context:     context.Background(),
		Payload:     &factor.Payload{Username: "alice", Password: "whatever"},
		Users:       fakeUsers{user: user},
		Credentials: fakeCredentials{err: gorm.ErrRecordNotFound},
	}
	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Status != StatusInvalidCredentials {
		t.Fatalf("Verify = %+v, want invalid_credentials", res)
	}
	if len(fails.captured) != 1 {
		t.Fatalf("captured = %v, want one capture", fails.captured)
	}
}

func TestVerifyInvalidRequest(t *testing.T) {
	f := New(fakeUsers{}, &fakeFails{}, &fakeReset{}, fakeIP{ip: "10.0.0.1"}, DefaultOptions())

	for _, ctx := range []*factor.FactorContext{
		nil,
		&factor.FactorContext{Context: context.Background()},
		&factor.FactorContext{Context: context.Background(), Payload: &factor.Payload{Username: ""}},
		&factor.FactorContext{Context: context.Background(), Payload: &factor.Payload{Username: "alice"}},
	} {
		res, err := f.Verify(ctx)
		if err != nil {
			t.Fatalf("Verify(invalid): %v", err)
		}
		if res.Status != StatusInvalidRequest {
			t.Fatalf("Verify(invalid) = %+v, want invalid_request", res)
		}
	}
}

func TestVerifyPropagatesRepositoryError(t *testing.T) {
	wantErr := errors.New("db down")
	f := New(fakeUsers{err: wantErr}, &fakeFails{}, &fakeReset{}, fakeIP{ip: "10.0.0.1"}, DefaultOptions())
	if _, err := f.Verify(newCtx(nil, nil, "alice", "whatever")); !errors.Is(err, wantErr) {
		t.Fatalf("Verify err = %v, want %v", err, wantErr)
	}
}
