// Package recovery 恢复码因子（docs/后端架构.md §3.8 行 394、§8.4 行 1053-1057、
// §4.2 行 686）。单步 form、仅二次因子：user_credential(kind='recovery_code')
// 一行 meta 存 10 条明文恢复码（8 位 Crockford Base32 小写，展示形如
// xxxx-xxxx，接口文档 §12.2 行 1732-1733）；命中一个即同步删除该条并写回
// （一次性消费、不可复用、删空即失效），不在日志 / 错误文案 / 返回值里回显
// 存量明文。本包不生成码、不重生成（归账号域 service 卡）。
package recovery

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"authloft/internal/factor"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

const (
	// credentialKind user_credential.kind 取值（§4.2 行 686）。
	credentialKind = "recovery_code"
	// codeLength 存储形 8 位（§4.2 行 686）。
	codeLength = 8
	// crockfordBase32 无 i/l/o/u 的 Crockford Base32 小写字符集（§4.2 行 686）。
	crockfordBase32 = "0123456789abcdefghjkmnpqrstvwxyz"
)

// 登录流程域 status（接口文档 §1.6 行 228-273 封闭集合子集）。
const (
	StatusInvalidRequest = "invalid_request" // 行 245：参数缺失 / 格式错误
	StatusInvalidCode    = "invalid_code"    // 行 247：码不匹配
	StatusCodeExpired    = "code_expired"    // 行 248：该因子无码 / 已全部消费，等同作废
	StatusStepInvalid    = "step_invalid"    // 行 250：非二次因子阶段
)

// CredentialStore 本因子所需仓储窄接口（§3.8 行 386-387 窄接口原则）：
// 读取 recovery_code 行 + 命中后同步写回（§4.2 行 686：一次性消费必须同步，
// 不走 §5.2 延迟队列）。公共 factor.CredentialRepo 只暴露读接口，
// 本包按需声明完整子集，装配方注入的真实 repo.CredentialRepo 天然满足。
type CredentialStore interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
	Update(ctx context.Context, c *model.UserCredential) error
}

// Factor 恢复码因子。
type Factor struct {
	now func() time.Time
	// compare 默认 crypto/subtle.ConstantTimeCompare，测试可替换以断言
	// 逐条比对本路径（禁止用 == 直接比字符串）。
	compare func([]byte, []byte) int
}

// New 构造恢复码因子；时钟与常量时间比较默认取标准库实现（测试可替换）。
func New() *Factor { return &Factor{now: time.Now, compare: subtle.ConstantTimeCompare} }

// Kind 固定 recovery_code。
func (f *Factor) Kind() factor.FactorKind { return factor.FactorRecovery }

// Usages 仅二次因子（§8.4 行 1057）。
func (f *Factor) Usages() []factor.Usage { return []factor.Usage{factor.UsageSecondary} }

// Steps 单步 form（接口文档 §2.6 行 550）。
func (f *Factor) Steps() []factor.StepKind { return []factor.StepKind{factor.StepForm} }

// Start 单步因子没有 challenge 步，派发器不会调用；仍返回 form 描述以保持
// 与 Steps 一致（字段名与接口文档 §1.3 行 126 / §2.6 行 550 一致）。
func (f *Factor) Start(*factor.FactorContext) (*factor.StepResult, error) {
	return &factor.StepResult{
		Kind:   factor.StepForm,
		Method: factor.FactorRecovery,
		Fields: []factor.Field{{Name: "code", Label: "login.field.recoveryCode", Type: "text", Required: true}},
	}, nil
}

// Verify 校验提交的恢复码：uid 只能取自 login_token（仅二次因子阶段
// `uid != 0 且 passed 非空`，§7.3 行 1000），不接受请求侧注入。命中后同步
// 删除该条并写回，本次通过；同一条码再次提交必然失败。
func (f *Factor) Verify(ctx *factor.FactorContext) (*factor.VerifyResult, error) {
	if ctx == nil {
		return &factor.VerifyResult{Status: StatusStepInvalid}, nil
	}
	var uid int64
	if ctx.Login != nil {
		uid = ctx.Login.GetUid()
	}
	if uid == 0 {
		// 非二次因子阶段一律拒绝，杜绝绕过主因子。
		return &factor.VerifyResult{Status: StatusStepInvalid}, nil
	}

	submitted := ""
	if ctx.Payload != nil {
		submitted = normalizeCode(ctx.Payload.Code)
	}
	if !validCode(submitted) {
		return &factor.VerifyResult{Status: StatusInvalidRequest}, nil
	}

	if ctx.Credentials == nil {
		return nil, fmt.Errorf("recovery: credentials not configured")
	}
	store, ok := ctx.Credentials.(CredentialStore)
	if !ok {
		return nil, fmt.Errorf("recovery: credential store does not support update")
	}

	cred, err := store.FindByUserAndKind(ctx.Context, uid, credentialKind)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 未签发 / 已全部消费：该因子不可用，等同作废（§1.6 行 248）。
			return &factor.VerifyResult{Status: StatusCodeExpired}, nil
		}
		return nil, err
	}
	if cred == nil || cred.IsEnabled != 1 {
		return &factor.VerifyResult{Status: StatusCodeExpired}, nil
	}

	meta, err := repo.UnmarshalCredentialMeta(cred.Meta)
	if err != nil {
		return nil, err
	}
	codes := meta.GetRecoveryCodes()
	if len(codes) == 0 {
		// 删空即失效（§8.4 行 1056）。
		return &factor.VerifyResult{Status: StatusCodeExpired}, nil
	}

	idx := f.matchIndex(codes, submitted)
	if idx < 0 {
		return &factor.VerifyResult{Status: StatusInvalidCode}, nil
	}

	// 命中即同步删除该条并写回（§4.2 行 686：不走延迟队列）。
	remaining := make([]string, 0, len(codes)-1)
	remaining = append(remaining, codes[:idx]...)
	remaining = append(remaining, codes[idx+1:]...)
	meta.RecoveryCodes = remaining
	encoded, err := repo.MarshalCredentialMeta(meta)
	if err != nil {
		return nil, err
	}
	cred.Meta = encoded
	cred.UpdatedAt = f.clock()
	if err := store.Update(ctx.Context, cred); err != nil {
		return nil, err
	}

	// 不回显存量明文：只返回结论与 uid。
	return &factor.VerifyResult{Passed: true, UID: uid}, nil
}

// matchIndex 逐条常量时间比对，返回命中下标（未命中 -1）。循环不因命中
// 提前退出：比对次数只取决于码数量，与命中位置无关。
func (f *Factor) matchIndex(codes []string, submitted string) int {
	idx := -1
	for i, stored := range codes {
		if f.constantTimeCompare([]byte(normalizeCode(stored)), []byte(submitted)) == 1 {
			idx = i
		}
	}
	return idx
}

func (f *Factor) constantTimeCompare(a, b []byte) int {
	if f == nil || f.compare == nil {
		return subtle.ConstantTimeCompare(a, b)
	}
	return f.compare(a, b)
}

func (f *Factor) clock() time.Time {
	if f == nil || f.now == nil {
		return time.Now()
	}
	return f.now()
}

// normalizeCode 展示形 xxxx-xxxx → 存储形 xxxxxxxx：去首尾空白、去连字符、
// 转小写（§4.2 行 686、接口文档 §2.6 行 550）。
func normalizeCode(raw string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(raw)), "-", "")
}

// validCode 是否为 8 位 Crockford Base32 小写字符（无 i/l/o/u，§4.2 行 686）。
func validCode(code string) bool {
	if len(code) != codeLength {
		return false
	}
	for _, r := range code {
		if !strings.ContainsRune(crockfordBase32, r) {
			return false
		}
	}
	return true
}
