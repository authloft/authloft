// token.go 实现 TokenService/DecodeSession（docs/接口文档.md §7.1 行 1392-1408、
// docs/后端架构.md §17 行 1737）：会话校验通过 → 每次均重签 session_token →
// 以报文视图 SessionResponse 平铺载荷 + renewed_token。
// 校验失败不重签、零存储写入；错误语义（未登录 / 会话失效）由 session 包
// 原样上抛，HTTP 401 映射归 handler 批，本层不引 connect 包。
package service

import (
	"context"

	rpcv1 "authloft/gen/go/api/rpc/v1"
	"authloft/internal/session"
)

// TokenService 是 rpc 域会话解码 service 的实现（接口文档 §7.1）。
// Verifier / Renewer 由装配方注入：Verifier 含 epoch 校验（session/verify.go），
// Renewer 的 TTL 由装配方注入、纯计算（session/renew.go）。
type TokenService struct {
	Verifier *session.Verifier
	Renewer  *session.Renewer
}

// NewTokenService 注入会话校验器与重签器（装配方负责构造与 TTL 取值）。
func NewTokenService(verifier *session.Verifier, renewer *session.Renewer) *TokenService {
	return &TokenService{Verifier: verifier, Renewer: renewer}
}

// DecodeSession 解码会话令牌并续期重签（接口文档 §7.1 行 1405-1407）：
//  1. Verifier.Verify 校验四步，失败原样上抛 ErrNotAuthenticated /
//     ErrSessionStale（不重签、不写任何存储）；
//  2. Renewer.Renew 重签：iat / exp 刷新，id / epoch / amr / sid 不变；
//  3. 组装响应：载荷字段用**新载荷**，renewed_token = 新令牌串。
func (s *TokenService) DecodeSession(ctx context.Context, req *rpcv1.DecodeSessionRequest) (*rpcv1.SessionResponse, error) {
	payload, err := s.Verifier.Verify(ctx, req.GetSessionToken())
	if err != nil {
		return nil, err
	}
	fresh, renewed, err := s.Renewer.Renew(payload)
	if err != nil {
		return nil, err
	}
	return &rpcv1.SessionResponse{
		Id:           fresh.GetId(),
		Epoch:        fresh.GetEpoch(),
		Amr:          fresh.GetAmr(),
		Sid:          fresh.GetSid(),
		Iat:          fresh.GetIat(),
		Exp:          fresh.GetExp(),
		RenewedToken: renewed,
	}, nil
}
