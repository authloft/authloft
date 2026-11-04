package webauthn

// token.go 账号域注册场景的独立原子 token（接口文档 §3.6 行 931、§8.3
// 行 1052）：复用 LoginTokenPayload 结构与 security.Codec 加解密实现，
// AAD purpose 取 PurposeWebAuthn，与 login_token（PurposeLogin）不互解。
// 载荷只使用 uid 与 ch.nonce，前端不感知结构、仅透传 token 字段。

import (
	"time"

	"authloft/gen/go/token"
	"authloft/internal/security"
)

// registrationPurpose 载荷内 challenge.purpose 的本场景取值；与 AAD 的
// PurposeWebAuthn 是两套概念（§11.6.2 行 1290）。
const registrationPurpose = "webauthn"

// issueRegistrationToken 签发独立原子 token：purpose=webauthn、uid=当前会话
// uid、ch.nonce 承载 challenge、exp 与挑战有效期一致（默认 120s）。
func issueRegistrationToken(codec *security.Codec, uid int64, challenge string, now time.Time, ttl time.Duration) (string, error) {
	payload := &token.LoginTokenPayload{
		Uid:  uid,
		Ch:   &token.Challenge{Purpose: registrationPurpose, Nonce: challenge},
		Iat:  now.Unix(),
		Exp:  now.Add(ttl).Unix(),
	}
	return codec.Seal(security.PurposeWebAuthn, payload)
}

// parseRegistrationToken 由服务端解析校验独立原子 token：篡改 / 无效 →
// invalid_request，过期 → code_expired（§3.6 行 931、§8.3 行 1052）。
// 返回 (uid, challenge, status)；status 非空即失败结论。
func parseRegistrationToken(codec *security.Codec, tok string, now time.Time) (int64, string, string) {
	if tok == "" || codec == nil {
		return 0, "", StatusInvalidRequest
	}
	payload, err := security.Open[token.LoginTokenPayload](codec, security.PurposeWebAuthn, tok)
	if err != nil {
		// 篡改、无效、跨 purpose、未知 kid 均在 GCM 认证处失败。
		return 0, "", StatusInvalidRequest
	}
	if payload.GetCh().GetPurpose() != registrationPurpose ||
		payload.GetUid() == 0 || payload.GetCh().GetNonce() == "" {
		return 0, "", StatusInvalidRequest
	}
	if payload.GetExp() <= now.Unix() {
		return 0, "", StatusCodeExpired
	}
	return payload.GetUid(), payload.GetCh().GetNonce(), ""
}
