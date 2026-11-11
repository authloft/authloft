package webauthn

// token.go 账号域注册场景的独立挑战令牌（接口文档 §3.6、后端架构 §8.3 /
// §11.6.7）：载荷用 ChallengeTokenPayload，复用 security.Codec 加解密实现，
// AAD purpose 取 PurposeChallenge、密钥用 sign_key.challenge，与 login_token
// （PurposeLogin / sign_key.login）互不解。前端不感知结构、仅透传 token 字段。

import (
	"strconv"
	"time"

	"authloft/gen/go/token"
	"authloft/internal/security"
)

// 注册场景载荷字段取值（后端架构 §8.3 末条 / §11.6.7）：消费方按
// biz_purpose + operation 双重校验；subject_kind=uid、subject=当前会话 uid。
// AAD purpose（challenge）不进载荷，与 biz_purpose 是两套封闭命名空间。
const (
	enrollBizPurpose  = "webauthn_enroll"
	registerOperation = "webauthn_register"
	subjectKindUID    = "uid"
)

// issueRegistrationToken 签发一次性挑战令牌：biz_purpose=webauthn_enroll、
// operation=webauthn_register、subject_kind=uid、subject=当前会话 uid、
// nonce=本次 challenge、exp 与挑战有效期一致（默认 120s，随响应 expires_in
// 下发）；methods 为空（webauthn 注册无 step-up 因子快照）。一次性由
// challenge 匹配、断言签名校验与凭据去重共同保证，不额外增加消费键。
func issueRegistrationToken(codec *security.Codec, uid int64, challenge string, now time.Time, ttl time.Duration) (string, error) {
	payload := &token.ChallengeTokenPayload{
		BizPurpose:  enrollBizPurpose,
		SubjectKind: subjectKindUID,
		Subject:     strconv.FormatInt(uid, 10),
		Nonce:       challenge,
		Operation:   registerOperation,
		Iat:         now.Unix(),
		Exp:         now.Add(ttl).Unix(),
	}
	return codec.Seal(security.PurposeChallenge, payload)
}

// parseRegistrationToken 由服务端解析校验挑战令牌：篡改 / 无效 →
// invalid_request，过期 → code_expired（接口文档 §3.6、后端架构 §8.3）。
// 返回 (uid, challenge, status)；status 非空即失败结论。
func parseRegistrationToken(codec *security.Codec, tok string, now time.Time) (int64, string, string) {
	if tok == "" || codec == nil {
		return 0, "", StatusInvalidRequest
	}
	payload, err := security.Open[token.ChallengeTokenPayload](codec, security.PurposeChallenge, tok)
	if err != nil {
		// 篡改、无效、跨 purpose、未知 kid 均在 GCM 认证处失败。
		return 0, "", StatusInvalidRequest
	}
	if payload.GetBizPurpose() != enrollBizPurpose ||
		payload.GetOperation() != registerOperation ||
		payload.GetSubjectKind() != subjectKindUID ||
		payload.GetNonce() == "" {
		return 0, "", StatusInvalidRequest
	}
	uid, err := strconv.ParseInt(payload.GetSubject(), 10, 64)
	if err != nil || uid <= 0 {
		return 0, "", StatusInvalidRequest
	}
	if payload.GetExp() <= now.Unix() {
		return 0, "", StatusCodeExpired
	}
	return uid, payload.GetNonce(), ""
}
