package recovery

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"authloft/gen/go/credential"
	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// fakeCredentials 满足 recovery.CredentialStore（读 + 写回），仅内存操作，
// 不连真实 DB；Update 模拟落库，使二次提交能读回消费后的行。
type fakeCredentials struct {
	cred      *model.UserCredential
	findErr   error
	updateErr error
	updates   int
	lastSaved *model.UserCredential
}

func (f *fakeCredentials) FindByUserAndKind(_ context.Context, _ int64, _ string) (*model.UserCredential, error) {
	return f.cred, f.findErr
}

func (f *fakeCredentials) Update(_ context.Context, c *model.UserCredential) error {
	f.updates++
	if f.updateErr != nil {
		return f.updateErr
	}
	f.lastSaved = c
	f.cred = c
	return nil
}

var testCodes = []string{
	"abcd0000", "abcd0001", "abcd0002", "abcd0003", "abcd0004",
	"abcd0005", "abcd0006", "abcd0007", "abcd0008", "abcd0009",
}

func mustCred(t *testing.T, codes []string) *model.UserCredential {
	t.Helper()
	meta, err := repo.MarshalCredentialMeta(&credential.CredentialMeta{RecoveryCodes: codes})
	if err != nil {
		t.Fatalf("Marshal recovery meta: %v", err)
	}
	return &model.UserCredential{
		ID: 42, UserID: 7, Kind: "recovery_code", Secret: []byte{}, Meta: meta,
		IsEnabled: 1, UpdatedAt: time.Now(),
	}
}

func newCtx(uid int64, code string, creds *fakeCredentials) *factor.FactorContext {
	ctx := &factor.FactorContext{
		Context:     context.Background(),
		Payload:     &factor.Payload{Code: code},
		Credentials: creds,
	}
	if uid != 0 {
		ctx.Login = &token.LoginTokenPayload{Uid: uid, Passed: []string{"password"}}
	}
	return ctx
}

func savedCodes(t *testing.T, c *model.UserCredential) []string {
	t.Helper()
	meta, err := repo.UnmarshalCredentialMeta(c.Meta)
	if err != nil {
		t.Fatalf("Unmarshal saved meta: %v", err)
	}
	return meta.GetRecoveryCodes()
}

// TestFactorShape 接口形态与 §1.10 / §8.4 一致：仅二次因子、单步 form。
func TestFactorShape(t *testing.T) {
	f := New()
	if f.Kind() != factor.FactorRecovery {
		t.Fatalf("Kind = %v, want recovery_code", f.Kind())
	}
	if usages := f.Usages(); len(usages) != 1 || usages[0] != factor.UsageSecondary {
		t.Fatalf("Usages = %v, want [secondary]", usages)
	}
	if steps := f.Steps(); len(steps) != 1 || steps[0] != factor.StepForm {
		t.Fatalf("Steps = %v, want [form]", steps)
	}
	start, err := f.Start(nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if start.Kind != factor.StepForm || start.Method != factor.FactorRecovery ||
		len(start.Fields) != 1 || start.Fields[0].Name != "code" {
		t.Fatalf("Start = %+v, want 单步 form code 字段", start)
	}
}

// TestVerifyConsumesMatchedCode 命中后同步写回、该条被删除，同码再次提交失败
// （一次性消费，§4.2 行 686）；展示形 xxxx-xxxx 可直接提交（接口文档 §2.6 行 550）。
func TestVerifyConsumesMatchedCode(t *testing.T) {
	f := New()
	creds := &fakeCredentials{cred: mustCred(t, testCodes)}
	ctx := newCtx(7, "abcd-0003", creds)

	res, err := f.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed || res.UID != 7 {
		t.Fatalf("Verify = %+v, want passed uid=7", res)
	}
	// 返回值不得回显存量明文。
	if strings.Contains(fmt.Sprintf("%+v", res), "abcd") {
		t.Fatalf("Verify 结果回显了恢复码明文: %+v", res)
	}

	if creds.updates != 1 {
		t.Fatalf("Update 次数 = %d, want 1（命中即同步写回）", creds.updates)
	}
	got := savedCodes(t, creds.lastSaved)
	if len(got) != len(testCodes)-1 {
		t.Fatalf("写回后剩余 = %d 条, want %d", len(got), len(testCodes)-1)
	}
	for _, c := range got {
		if c == "abcd0003" {
			t.Fatal("命中的恢复码未从写回结果删除")
		}
	}

	// 同一条码再次提交：已消费，必然失败且不再写回。
	res, err = f.Verify(newCtx(7, "abcd-0003", creds))
	if err != nil {
		t.Fatalf("Verify(重复使用): %v", err)
	}
	if res.Passed || res.Status != StatusInvalidCode {
		t.Fatalf("Verify(重复使用) = %+v, want invalid_code", res)
	}
	if creds.updates != 1 {
		t.Fatalf("重复使用不应写回，Update 次数 = %d", creds.updates)
	}
}

// TestVerifyAcceptsStorageForm 存储形 xxxxxxxx（无连字符）同样可提交。
func TestVerifyAcceptsStorageForm(t *testing.T) {
	f := New()
	creds := &fakeCredentials{cred: mustCred(t, testCodes)}
	res, err := f.Verify(newCtx(7, "abcd0007", creds))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed || creds.updates != 1 {
		t.Fatalf("Verify(存储形) = %+v, updates=%d, want passed + 1 次写回", res, creds.updates)
	}
}

// TestVerifyEmptyCodes 数组为空（含 nil meta）→ code_expired（删空即失效）。
func TestVerifyEmptyCodes(t *testing.T) {
	f := New()
	for _, codes := range [][]string{nil, {}} {
		creds := &fakeCredentials{cred: mustCred(t, codes)}
		res, err := f.Verify(newCtx(7, "abcd0000", creds))
		if err != nil {
			t.Fatalf("Verify(empty): %v", err)
		}
		if res.Passed || res.Status != StatusCodeExpired {
			t.Fatalf("Verify(empty) = %+v, want code_expired", res)
		}
		if creds.updates != 0 {
			t.Fatalf("空数组不应写回，Update 次数 = %d", creds.updates)
		}
	}
}

// TestVerifyMissingCredentialRow 无该 kind 行 → code_expired（因子不可用）。
func TestVerifyMissingCredentialRow(t *testing.T) {
	f := New()
	creds := &fakeCredentials{findErr: gorm.ErrRecordNotFound}
	res, err := f.Verify(newCtx(7, "abcd0000", creds))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Passed || res.Status != StatusCodeExpired {
		t.Fatalf("Verify(no row) = %+v, want code_expired", res)
	}
}

// TestVerifyMismatch 码不匹配 → invalid_code，且不写回。
func TestVerifyMismatch(t *testing.T) {
	f := New()
	creds := &fakeCredentials{cred: mustCred(t, testCodes)}
	res, err := f.Verify(newCtx(7, "abcd9999", creds))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Passed || res.Status != StatusInvalidCode {
		t.Fatalf("Verify(mismatch) = %+v, want invalid_code", res)
	}
	if creds.updates != 0 {
		t.Fatalf("不匹配不应写回，Update 次数 = %d", creds.updates)
	}
}

// TestVerifyMalformedCode 格式不合法 → invalid_request（§1.6 行 245）。
func TestVerifyMalformedCode(t *testing.T) {
	f := New()
	for _, code := range []string{"", "abcd-000", "abcd0003x", "abcd_0003", "abcd 0003", "ilou0000"} {
		creds := &fakeCredentials{cred: mustCred(t, testCodes)}
		res, err := f.Verify(newCtx(7, code, creds))
		if err != nil {
			t.Fatalf("Verify(%q): %v", code, err)
		}
		if res.Passed || res.Status != StatusInvalidRequest {
			t.Fatalf("Verify(%q) = %+v, want invalid_request", code, res)
		}
		if creds.updates != 0 {
			t.Fatalf("Verify(%q) 不应写回，Update 次数 = %d", code, creds.updates)
		}
	}
}

// TestVerifyRequiresSecondaryStage 非二次因子阶段（无 login_token / uid=0）
// → step_invalid，杜绝绕过主因子。
func TestVerifyRequiresSecondaryStage(t *testing.T) {
	f := New()
	creds := &fakeCredentials{cred: mustCred(t, testCodes)}
	res, err := f.Verify(newCtx(0, "abcd0000", creds))
	if err != nil {
		t.Fatalf("Verify(uid=0): %v", err)
	}
	if res.Passed || res.Status != StatusStepInvalid {
		t.Fatalf("Verify(uid=0) = %+v, want step_invalid", res)
	}
}

// TestVerifyComparesAllCodesConstantTime 比对走 crypto/subtle 常量时间路径，
// 且循环不因命中提前退出：命中第 1 条时仍与全部码逐条比对。
func TestVerifyComparesAllCodesConstantTime(t *testing.T) {
	f := New()
	calls := 0
	f.compare = func(a, b []byte) int {
		calls++
		return subtle.ConstantTimeCompare(a, b)
	}
	creds := &fakeCredentials{cred: mustCred(t, testCodes)}
	res, err := f.Verify(newCtx(7, "abcd-0000", creds))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Passed {
		t.Fatalf("Verify = %+v, want passed", res)
	}
	if calls != len(testCodes) {
		t.Fatalf("常量时间比较次数 = %d, want %d（命中不提前退出）", calls, len(testCodes))
	}
}
