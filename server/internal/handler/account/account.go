// Package account 实现 api.account.v1.AccountService 的 Connect handler
//（docs/后端架构.md §3.4 行 332：account 域方法族，全部需会话）。本实现
// 仅落地 GetProfile，其余方法一律由生成的
// UnimplementedAccountServiceHandler 返回 unimplemented（不自造错误信封）。
//
// GetConfig 缺口（TODO，依赖齐备后实现）：avatarUpload 需头像 Storage
// Provider 适配器（后端架构 §15.1，未落地）、captcha 需 captcha Provider
// 选择链（§9.1，未落地）、mfaPolicy 需用户 MFA 绑定明细查询（接口文档
// §3.5）——三者均待后续卡接线；hasPassword 虽可查 credential（kind=password
// 且 is_enabled=1），单字段不足以成实现，整方法留桩。
package account

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"gorm.io/gorm"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/gen/go/api/account/v1/accountv1connect"
	"authloft/internal/dto"
	"authloft/internal/repo/model"
	"authloft/internal/session"
)

// UserReader account 域用户读取窄接口（§20 依赖注入）：生产注入
// *repo.UserRepo（FindByID / GetProfile 均已有，不扩公共接口），测试可传 fake。
type UserReader interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	GetProfile(ctx context.Context, userID int64) (*model.UserProfile, error)
}

// 线上错误文案：connect.Error 文本直达客户端，一律不携带内部信息
//（口径同 internal/connect interceptors.go）。
var (
	errAuthRequired = errors.New("authentication required")
	errNotFound     = errors.New("not found")
)

// Handler AccountService 服务实现。内嵌生成的 unimplemented 基类：本卡未
// 实现的方法（含 GetConfig 桩，见包注释缺口说明）统一返回 Connect
// CodeUnimplemented。
type Handler struct {
	accountv1connect.UnimplementedAccountServiceHandler
	users UserReader
}

// New 构造 AccountService handler。
func New(users UserReader) *Handler {
	return &Handler{users: users}
}

// GetProfile（接口文档 §3.1 行 774-813 / §3.2 行 820）：从会话取 uid → 读
// user + user_profile → 按 §3.1 统一结构与服务端掩码输出（组装在
// dto.AccountProfile）。会话要求（§1.2 行 96）：本域全接口需 al_session；
// session 拦截器对无 / 无效令牌放行匿名（既定语义），故 ctx 无 uid
// 即 unauthenticated（HTTP 401）。user_profile 行缺失输出零值 profile
// 消息，不视为错误；用户不存在返回 not_found。
func (h *Handler) GetProfile(ctx context.Context, req *connect.Request[accountv1.GetProfileRequest]) (*connect.Response[accountv1.ProfileResponse], error) {
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	user, err := h.users.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, errNotFound)
		}
		return nil, fmt.Errorf("account handler: load user: %w", err)
	}
	profile, err := h.users.GetProfile(ctx, uid)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("account handler: load profile: %w", err)
	}
	return connect.NewResponse(dto.AccountProfile(user, profile)), nil
}
