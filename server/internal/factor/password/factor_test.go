package password

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"database/sql"

	"authloft/internal/factor"
	"authloft/internal/factor/ipres"
	"authloft/internal/repo/model"
	"authloft/internal/security"
	"authloft/internal/service/orchestrator"
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
	f := New(fakeUsers{err: sql.ErrNoRows}, fails, &fakeReset{}, fakeIP{ip: "10.0.0.1"}, DefaultOptions())

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
		Credentials: fakeCredentials{err: sql.ErrNoRows},
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

// statefulFails 内存版失败计数 / 封禁（cache.PwFailStore 语义同构）：
// Capture 累加、Factor 达阈值调 Ban、reset 删除单 ref 的计数与封禁。
type statefulFails struct {
	counts map[string]int64
	bans   map[string]bool
}

func newStatefulFails() *statefulFails {
	return &statefulFails{counts: map[string]int64{}, bans: map[string]bool{}}
}

func (f *statefulFails) Capture(_ context.Context, ref string) (int64, error) {
	f.counts[ref]++
	return f.counts[ref], nil
}

func (f *statefulFails) IsBanned(_ context.Context, ref string) (bool, error) {
	return f.bans[ref], nil
}

func (f *statefulFails) Ban(_ context.Context, ref string) (bool, error) {
	f.bans[ref] = true
	return true, nil
}

func (f *statefulFails) BanRemaining(_ context.Context, ref string) (time.Duration, error) {
	if f.bans[ref] {
		return 10 * time.Minute, nil
	}
	return 0, nil
}

func (f *statefulFails) reset(_ context.Context, ref string) error {
	delete(f.counts, ref)
	delete(f.bans, ref)
	return nil
}

// TestVerifySuccessClearsAccumulatedFailures 失败 N 次 → 成功登录 → 计数归零，
// 证伪「成功后仍误锁」（生产装配 = ResetFunc 包存储清零，bootstrap 同款闭包）。
func TestVerifySuccessClearsAccumulatedFailures(t *testing.T) {
	hash, err := security.HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	user := &model.User{ID: 42, Username: "alice", UserStatus: 1}
	cred := &model.UserCredential{UserID: 42, Kind: "password", Secret: []byte(hash), IsEnabled: 1}
	fails := newStatefulFails()
	reset := ResetFunc(func(ctx context.Context, refs ...string) error {
		for _, ref := range refs {
			if err := fails.reset(ctx, ref); err != nil {
				return err
			}
		}
		return nil
	})
	f := New(fakeUsers{user: user}, fails, reset, fakeIP{ip: "10.0.0.1"}, DefaultOptions())

	// 成功前累计 2 次失败（低于封禁阈值）。
	for i := 0; i < 2; i++ {
		res, err := f.Verify(newCtx(user, cred, "alice", "wrong-password"))
		if err != nil {
			t.Fatalf("Verify(fail %d): %v", i+1, err)
		}
		if res.Status != StatusInvalidCredentials {
			t.Fatalf("Verify(fail %d) = %+v, want invalid_credentials", i+1, res)
		}
	}
	if fails.counts["42"] != 2 {
		t.Fatalf("counts = %v, want 2", fails.counts)
	}

	res, err := f.Verify(newCtx(user, cred, "alice", "correct-password"))
	if err != nil {
		t.Fatalf("Verify(success): %v", err)
	}
	if !res.Passed || res.UID != 42 {
		t.Fatalf("Verify(success) = %+v, want passed uid=42", res)
	}
	if _, ok := fails.counts["42"]; ok {
		t.Fatalf("成功登录后计数未清零: %v", fails.counts)
	}

	// 清零后再失败 4 次：若无清零则 2+4 达阈值必 locked，实际应重新计数。
	for i := 0; i < 4; i++ {
		res, err := f.Verify(newCtx(user, cred, "alice", "wrong-password"))
		if err != nil {
			t.Fatalf("Verify(post-reset %d): %v", i+1, err)
		}
		if res.Status == StatusLocked {
			t.Fatalf("成功清零后第 %d 次失败误锁（计数未归零）: %+v", i+1, res)
		}
		if res.Status != StatusInvalidCredentials {
			t.Fatalf("Verify(post-reset %d) = %+v, want invalid_credentials", i+1, res)
		}
	}
	if fails.counts["42"] != 4 {
		t.Fatalf("counts = %v, want 4（从 0 重新累计）", fails.counts)
	}

	// 对照：reset 为 nil（跳过清零）时同一序列在累计第 6 次失败即 locked。
	fails2 := newStatefulFails()
	f2 := New(fakeUsers{user: user}, fails2, nil, fakeIP{ip: "10.0.0.1"}, DefaultOptions())
	for i := 0; i < 2; i++ {
		if _, err := f2.Verify(newCtx(user, cred, "alice", "wrong-password")); err != nil {
			t.Fatalf("Verify(no-reset fail %d): %v", i+1, err)
		}
	}
	if _, err := f2.Verify(newCtx(user, cred, "alice", "correct-password")); err != nil {
		t.Fatalf("Verify(no-reset success): %v", err)
	}
	var res2 *factor.VerifyResult
	for i := 0; i < 4; i++ {
		res2, err = f2.Verify(newCtx(user, cred, "alice", "wrong-password"))
		if err != nil {
			t.Fatalf("Verify(no-reset post %d): %v", i+1, err)
		}
	}
	if res2 == nil || res2.Status != StatusLocked {
		t.Fatalf("no-reset 对照序列应因计数未清零而 locked: %+v", res2)
	}
}

// TestUserRefResolverUsesRequestIP 引擎读计数侧与生产 resolver 组合：
// ctx 注入请求来源 IP 时 user_ref 用真实 IP（不得一律 unknown），
// 未注入维持 unknown 桶兜底（后端架构 §8.1）。
func TestUserRefResolverUsesRequestIP(t *testing.T) {
	sum := sha256.Sum256([]byte("ghost"))
	wantHash := hex.EncodeToString(sum[:])
	r := UserRefResolver{Users: fakeUsers{err: sql.ErrNoRows}, IP: ipres.Resolver{}}

	ctx := orchestrator.WithRequestInfo(context.Background(), orchestrator.RequestInfo{IP: "198.51.100.7"})
	ref, err := r.UserRef(ctx, "ghost")
	if err != nil {
		t.Fatalf("UserRef: %v", err)
	}
	if ref != "198.51.100.7|"+wantHash {
		t.Fatalf("UserRef = %q, want 198.51.100.7|%s（不得回退 unknown）", ref, wantHash)
	}

	ref, err = r.UserRef(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("UserRef(no request info): %v", err)
	}
	if ref != "unknown|"+wantHash {
		t.Fatalf("UserRef(no request info) = %q, want unknown|%s", ref, wantHash)
	}
}
