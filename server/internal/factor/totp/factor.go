// Package totp 动态口令因子（docs/后端架构.md §3.8 行 391、§8.4 行 1052-1056）。
// 单步 form、仅二次因子；按 RFC 6238 校验，允许 ±1 个时间步。密钥按文档
// 保持明文 Base32（§3.11 行 430「TOTP 密钥不加密，明文（Base32）存
// user_credential.secret，故不设对称加密模块」）。
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"authloft/internal/factor"
)

const (
	// credentialKind user_credential.kind 取值（§4.2 行 680-684）。
	credentialKind = "totp"
	// stepSeconds RFC 6238 默认时间步（30s）。
	stepSeconds = 30
	// skewSteps 允许前后各 1 个时间步（§8.4 行 1054）。
	skewSteps = 1
	// codeLength 六位动态码（接口文档 §1.10 行 308）。
	codeLength = 6
	// modulus 6 位截断模数。
	modulus = 1_000_000
)

// 登录流程域 status（接口文档 §1.6 行 228-273 封闭集合子集）。
const (
	StatusInvalidCode    = "invalid_code"
	StatusInvalidRequest = "invalid_request"
	StatusStepInvalid    = "step_invalid"
)

// Factor totp 因子。
type Factor struct {
	now func() time.Time
}

// New 构造 totp 因子；时钟默认 time.Now（测试可替换）。
func New() *Factor { return &Factor{now: time.Now} }

// Kind 固定 totp。
func (f *Factor) Kind() factor.FactorKind { return factor.FactorTOTP }

// Usages 仅二次因子（§1.10 行 308、§8.4 行 1056）。
func (f *Factor) Usages() []factor.Usage { return []factor.Usage{factor.UsageSecondary} }

// Steps 单步 form（§1.10 行 308）。
func (f *Factor) Steps() []factor.StepKind { return []factor.StepKind{factor.StepForm} }

// Start 单步因子没有 challenge 步，派发器不会调用；仍返回 form 描述以保持
// 与 Steps 一致。
func (f *Factor) Start(*factor.FactorContext) (*factor.StepResult, error) {
	return &factor.StepResult{
		Kind:   factor.StepForm,
		Method: factor.FactorTOTP,
		Fields: []factor.Field{{Name: "code", Label: "login.field.totpCode", Type: "totp", Required: true, Length: codeLength}},
	}, nil
}

// Verify 校验六位动态码。uid 只能取自 login_token（二次因子阶段
// `uid != 0 且 passed 非空`，§7.3 行 1000），不接受请求侧注入。
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

	code := ""
	if ctx.Payload != nil {
		code = strings.TrimSpace(ctx.Payload.Code)
	}
	if len(code) != codeLength || !digits(code) {
		return &factor.VerifyResult{Status: StatusInvalidRequest}, nil
	}

	if ctx.Credentials == nil {
		return nil, fmt.Errorf("totp: credentials not configured")
	}
	cred, err := ctx.Credentials.FindByUserAndKind(ctx.Context, uid, credentialKind)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &factor.VerifyResult{Status: StatusInvalidCode}, nil
		}
		return nil, err
	}
	if cred == nil || cred.IsEnabled != 1 {
		return &factor.VerifyResult{Status: StatusInvalidCode}, nil
	}

	secret, err := decodeSecret(string(cred.Secret))
	if err != nil {
		// 密钥损坏等同于该因子不可用，按错码处理，不暴露内部细节。
		return &factor.VerifyResult{Status: StatusInvalidCode}, nil
	}
	if !valid(secret, code, f.clock()) {
		return &factor.VerifyResult{Status: StatusInvalidCode}, nil
	}
	return &factor.VerifyResult{Passed: true, UID: uid}, nil
}

func (f *Factor) clock() time.Time {
	if f == nil || f.now == nil {
		return time.Now()
	}
	return f.now()
}

// valid 校验 code 是否为 now 前后 ±1 个时间步内的有效值（RFC 6238）。
func valid(secret []byte, code string, now time.Time) bool {
	base := now.Unix() / stepSeconds
	for off := -int64(skewSteps); off <= int64(skewSteps); off++ {
		counter := base + off
		if counter < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(secret, uint64(counter))), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// hotp RFC 4226 Hotp（HMAC-SHA1 + 动态截断 + 6 位取模）。
func hotp(secret []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", bin%modulus)
}

// decodeSecret 解码明文 Base32 密钥（容忍大小写、空格与填充符差异）。
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, fmt.Errorf("totp: empty secret")
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.DecodeString(s)
}

func digits(code string) bool {
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
