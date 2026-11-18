// sub.go 实现 OIDC 对外 sub 的确定性派生与还原（后端架构 §11.6.8、
// 接口文档 §4.5 / §4.7）：签发链把 (client_id, uid) 封成 pairwise 密文，
// 消费链还原 uid / client_id，两端共用同一把确定性 codec，保证同一主体
// 重复签发（授权码 / 刷新两路径）逐字节一致。真实 uid 只经此还原，
// rpc 域 DecodeOidcSub 另须比对 client_id 归属（接口文档 §7.3）。
package oidc

import (
	"errors"

	"authloft/gen/go/token"
	"authloft/internal/security"
)

// SubCodec 封装 OIDC sub 的派生与还原，无状态、不触存储；由装配层注入
// 第 8 把 sign_key.oidc_sub 构造的确定性 codec。
type SubCodec struct {
	codec *security.DeterministicCodec
}

// NewSubCodec 用注入的确定性 codec 构造 sub 编解码器。
func NewSubCodec(codec *security.DeterministicCodec) *SubCodec {
	return &SubCodec{codec: codec}
}

// errSubCodecMissing 装配遗漏确定性 codec 时的内部错误（显式失败而非 panic）。
var errSubCodecMissing = errors.New("oidc: sub codec not configured")

// DeriveSub 按 §11.6.8 将 OidcSubPayload 确定性封装为密文 sub：
// 同一 (client_id, uid) 恒等、不同客户端对同一用户互异；JWT payload 与
// userinfo 对外只见密文，真实 uid 仅在 DecodeSub 还原。
func (s *SubCodec) DeriveSub(clientID string, uid int64) (string, error) {
	if s == nil || s.codec == nil {
		return "", errSubCodecMissing
	}
	return s.codec.Seal(security.PurposeOidcSub, &token.OidcSubPayload{
		ClientId: clientID,
		Uid:      uid,
	})
}

// DecodeSub 解开密文 sub 还原 uid / client_id。篡改、跨 purpose、未知 kid
// 由 codec 的认证与 nonce 规范校验拒绝；调用方须自行按业务口径比对
// client_id 归属，本方法只负责还原。
func (s *SubCodec) DecodeSub(sub string) (int64, string, error) {
	if s == nil || s.codec == nil {
		return 0, "", errSubCodecMissing
	}
	p, err := security.OpenDeterministic[token.OidcSubPayload](s.codec, security.PurposeOidcSub, sub)
	if err != nil {
		return 0, "", err
	}
	return p.GetUid(), p.GetClientId(), nil
}
