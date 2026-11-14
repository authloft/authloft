// adapters.go step-up 适配器（docs/后端架构.md §3.6 logincompleter 规划项、
// §3.8）：把因子注册表与会话资料读取适配为 verification 的窄接口。
package verification

import (
	"context"
	"errors"
	"strconv"

	"gorm.io/gorm"

	"authloft/gen/go/token"
	"authloft/internal/factor"
	"authloft/internal/repo"
)

// boundFactorReader 按主体读已绑定 / 已启用因子，供策略表取交集
// （§1.10.2 约束 1）；tid 主体（扫码）无绑定资料，返回候选全量。
type boundFactorReader struct {
	users *repo.UserRepo
	creds *repo.CredentialRepo
}

func (r boundFactorReader) Bound(ctx context.Context, subject Subject, candidates []string) ([]string, error) {
	if subject.Kind != SubjectKindUID {
		return candidates, nil
	}
	uid, err := strconv.ParseInt(subject.ID, 10, 64)
	if err != nil || uid <= 0 {
		return nil, nil
	}
	enabled, err := r.enabledFactors(ctx, uid)
	if err != nil {
		return nil, err
	}
	u, err := r.users.FindByID(ctx, uid)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		u = nil
	}
	// 策略强制（user.mfa_required=1）但用户未显式 SetMfa、无 mfa_setting 行时，
	// 以全部已绑定因子为可用集合。
	if len(enabled) == 0 && u != nil && u.MfaRequired == 1 {
		for _, m := range candidates {
			enabled[m] = true
		}
	}

	out := make([]string, 0, len(candidates))
	for _, m := range candidates {
		if !enabled[m] {
			continue
		}
		switch m {
		case "totp", "recovery_code":
			row, err := r.creds.FindByUserAndKind(ctx, uid, m)
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					continue
				}
				return nil, err
			}
			if row != nil && row.IsEnabled == 1 {
				out = append(out, m)
			}
		case "webauthn":
			rows, err := r.creds.ListByUser(ctx, uid)
			if err != nil {
				return nil, err
			}
			for i := range rows {
				if rows[i].Kind == "webauthn" && rows[i].IsEnabled == 1 {
					out = append(out, m)
					break
				}
			}
		case "otp_sms", "otp_email":
			if u == nil {
				continue
			}
			if (m == "otp_sms" && u.Phone != nil && *u.Phone != "") ||
				(m == "otp_email" && u.Email != nil && *u.Email != "") {
				out = append(out, m)
			}
		}
	}
	return out, nil
}

// enabledFactors 读 user_credential(kind=mfa_setting) 的 mfa_methods（§3.2：
// 行存在即 enabled=true，is_enabled=0 按未启用兼容；recovery_code 随 totp
// 投影，不单列）。
func (r boundFactorReader) enabledFactors(ctx context.Context, uid int64) (map[string]bool, error) {
	out := map[string]bool{}
	row, err := r.creds.FindByUserAndKind(ctx, uid, "mfa_setting")
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return out, nil
		}
		return nil, err
	}
	if row == nil || row.IsEnabled != 1 {
		return out, nil
	}
	meta, err := repo.UnmarshalCredentialMeta(row.Meta)
	if err != nil {
		return nil, err
	}
	for _, m := range meta.GetMfaMethods() {
		out[m] = true
		if m == "totp" {
			out["recovery_code"] = true
		}
	}
	return out, nil
}

// StepUpVerifier 把 step-up 的下发与提交适配到因子注册表（§6.3）：以挑战
// 令牌的三元组构造 FactorContext，复用各因子的 Start / Verify 实现。
type StepUpVerifier struct {
	registry *factor.Registry
	users    *repo.UserRepo
	creds    *repo.CredentialRepo
}

// Start 适配因子下发：OTP 发码、WebAuthn 生成 options，其余单步因子返回
// 渲染描述。返回的 nonce 取因子 Start 写入的值（WebAuthn 自生成 challenge），
// 保证 options.challenge 与挑战令牌、断言校验同源。
func (v StepUpVerifier) Start(ctx context.Context, in FactorStartInput) (FactorStartResult, error) {
	f, err := v.registry.Get(factor.FactorKind(in.Method))
	if err != nil {
		return FactorStartResult{Code: "method_disabled"}, nil
	}
	uid, _ := strconv.ParseInt(in.Subject.ID, 10, 64)
	login := &token.LoginTokenPayload{
		Tid:    Owner(in.BizPurpose, in.Subject.ID, in.Nonce),
		Uid:    uid,
		Flow:   "mfa",
		Passed: []string{"primary"},
		Ch:     &token.Challenge{Purpose: "mfa", Nonce: in.Nonce},
	}
	step, err := f.Start(&factor.FactorContext{
		Context:     ctx,
		Login:       login,
		Payload:     &factor.Payload{},
		BizPurpose:  string(in.BizPurpose),
		Subject:     in.Subject.ID,
		ChallengeID: in.Nonce,
		Users:       v.users,
		Credentials: v.creds,
	})
	if err != nil {
		return FactorStartResult{}, err
	}
	out := FactorStartResult{Nonce: login.GetCh().GetNonce()}
	if out.Nonce == "" {
		out.Nonce = in.Nonce
	}
	if step == nil {
		return out, nil
	}
	if step.Status != "" {
		out.Code = step.Status
		out.RetryAfter = step.RetryAfter
		return out, nil
	}
	out.Kind = string(step.Kind)
	out.ChallengeData = step.ChallengeData
	return out, nil
}

func (v StepUpVerifier) Verify(ctx context.Context, in FactorVerifyInput) (FactorVerifyResult, error) {
	f, err := v.registry.Get(factor.FactorKind(in.Method))
	if err != nil {
		return FactorVerifyResult{Code: "method_disabled"}, nil
	}
	p := &factor.Payload{}
	if in.Payload != nil {
		get := func(k string) string {
			fv, ok := in.Payload.Fields[k]
			if !ok || fv == nil {
				return ""
			}
			return fv.GetStringValue()
		}
		p.Code = get("code")
		p.Phone = get("phone")
		p.Email = get("email")
		if cv, ok := in.Payload.Fields["credential"]; ok && cv != nil {
			p.Credential = cv.GetStructValue()
		}
	}
	uid, _ := strconv.ParseInt(in.Subject.ID, 10, 64)
	login := &token.LoginTokenPayload{
		Tid:    Owner(in.BizPurpose, in.Subject.ID, in.ChallengeID),
		Uid:    uid,
		Flow:   "mfa",
		Passed: []string{"primary"},
		Ch:     &token.Challenge{Purpose: "mfa", Nonce: in.ChallengeID},
	}
	res, err := f.Verify(&factor.FactorContext{
		Context:     ctx,
		Login:       login,
		Payload:     p,
		BizPurpose:  string(in.BizPurpose),
		Subject:     in.Subject.ID,
		ChallengeID: in.ChallengeID,
		Users:       v.users,
		Credentials: v.creds,
	})
	if err != nil {
		return FactorVerifyResult{}, err
	}
	if res.Passed {
		return FactorVerifyResult{Passed: true}, nil
	}
	code := res.Status
	switch code {
	case "invalid_code", "code_expired", "too_many_attempts", "method_disabled", "invalid_request":
	default:
		code = "invalid_code"
	}
	return FactorVerifyResult{Code: code, AttemptsLeft: res.AttemptsLeft}, nil
}

// NewBoundFactorReader 注入用户 / 凭据仓储（装配层构造）。
func NewBoundFactorReader(users *repo.UserRepo, creds *repo.CredentialRepo) BoundFactorReader {
	return boundFactorReader{users: users, creds: creds}
}

// NewStepUpVerifier 注入因子注册表与用户 / 凭据仓储（装配层构造）。
func NewStepUpVerifier(registry *factor.Registry, users *repo.UserRepo, creds *repo.CredentialRepo) *StepUpVerifier {
	return &StepUpVerifier{registry: registry, users: users, creds: creds}
}
