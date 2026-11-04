// Package rpc 实现 api.rpc.v1 两个 service 的 Connect handler（docs/接口文档.md
// §7 行 1366-1393）：UserService（GetUserProfile / UpdateUserProfile，资料读写）
// 与 TokenService（DecodeSession，会话解码 + 续期重签）。鉴权（HMAC 三头 +
// 写接口 nonce 去重 + 五项签名）为 Connect interceptor，由装配层挂载
//（bootstrap registerRPC → connect.NewRPCHMACInterceptor，必须经
// connect.Server.RegisterRPC 强制包 CaptureRawBody）；session 步归端点自身
//（§7 行 1387 校验顺序：读接口签名 → session、写接口 nonce 去重 → 签名 →
// session），故本包不依赖会话拦截器注入的 ctx 身份，用户目标一律取请求体
// uid、会话令牌一律取请求体 sessionToken。
//
// 错误口径（§1.5 / §1.6）：user 不存在 → 404 not_found + ErrorInfo(rpc,
// user_not_found)（§1.6 封闭集合；HTTP 语义对齐 account GetProfile 的 404
// 先例）；birthday 格式非法 → 400 invalid_argument + ErrorInfo(rpc,
// invalid_request)（§1.6；先例 admin GetProviderSchema 的入参拒绝）；会话
// 无效 / 过期 / epoch 不一致 → 401 unauthenticated（§7.1 行 1410）；epoch
// 读取链故障 → internal（verify.go 行 27-29：基础设施错误不得与未登录混同）。
package rpc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"gorm.io/gorm"

	accountv1 "authloft/gen/go/api/account/v1"
	rpcv1 "authloft/gen/go/api/rpc/v1"
	"authloft/gen/go/api/rpc/v1/rpcv1connect"
	internalconnect "authloft/internal/connect"
	"authloft/internal/dto"
	"authloft/internal/repo/model"
	"authloft/internal/session"
)

// UserStore rpc 域用户数据面窄接口（§20 依赖注入）：生产注入 *repo.UserRepo
//（FindByID / GetProfile / SaveProfile / UpdateProfileColumns 均为 UserRepo
// 既有方法，不扩公共接口），测试注入 fake。
type UserStore interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	GetProfile(ctx context.Context, userID int64) (*model.UserProfile, error)
	SaveProfile(ctx context.Context, p *model.UserProfile) error
	UpdateProfileColumns(ctx context.Context, id int64, nickname, avatarURL *string) error
}

// 线上错误文案：connect.Error 文本直达客户端，一律不携带内部信息
//（口径同 internal/connect interceptors.go、handler/account）。
var (
	errAuthRequired = errors.New("authentication required")
	errNotFound     = errors.New("not found")
	errInternal     = errors.New("internal error")
	errBadBirthday  = errors.New("invalid birthday")
)

// UserHandler 实现 api.rpc.v1.UserService。内嵌生成的 unimplemented 基类：
// 后续新增方法在显式实现前统一返回 Connect CodeUnimplemented。
type UserHandler struct {
	rpcv1connect.UnimplementedUserServiceHandler
	users UserStore
}

// NewUserHandler 构造 UserService handler。
func NewUserHandler(users UserStore) *UserHandler {
	return &UserHandler{users: users}
}

// GetUserProfile（§7 行 1391）：{uid} → FindByID + GetProfile → §3.1 Authloft
// 结构（rpc 域 phone / email 明文，§3.1 行 809，组装在 dto.RPCProfile）。
// user_profile 行缺失输出零值 profile 消息，不视为错误；用户不存在 →
// 404 + ErrorInfo(rpc, user_not_found)。
func (h *UserHandler) GetUserProfile(ctx context.Context, req *connect.Request[rpcv1.GetUserProfileRequest]) (*connect.Response[rpcv1.ProfileResponse], error) {
	uid := req.Msg.GetUid()
	user, err := h.users.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, userNotFound()
		}
		return nil, fmt.Errorf("rpc handler: load user: %w", err)
	}
	profile, err := h.users.GetProfile(ctx, uid)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("rpc handler: load profile: %w", err)
	}
	return connect.NewResponse(dto.RPCProfile(user, profile)), nil
}

// UpdateUserProfile（§7 行 1392，入参同 §3.2 行 821 的
// AccountService/UpdateProfile）：部分更新——未传字段不覆盖。proto3 标量无
// presence，未传与零值不可区分，按「零值 = 未传」约定落地（nickname /
// avatar_url / profile 各子字段均如此）；嵌套 profile 消息本身有 presence
//（nil = 未传，不触碰 user_profile 行）。
//
// 用户名 / 手机号 / 邮箱不可由此修改（§3.2 行 821）：proto
// UpdateUserProfileRequest 不含这三项字段，契约结构上即不可改，本实现亦
// 不提供任何绕过入口；user 表仅更新 nickname / avatar_url 两列（经
// UpdateProfileColumns），user_profile 行按 SaveProfile 行 224 注释的合并
// 语义「先读后拼整行」——读现行（缺失从零值行起）→ 逐字段合并 → 整行
// UPSERT。全字段未传时为纯 no-op，不触碰任何存储（连 updated_at 也不刷）。
func (h *UserHandler) UpdateUserProfile(ctx context.Context, req *connect.Request[rpcv1.UpdateUserProfileRequest]) (*connect.Response[rpcv1.OkResponse], error) {
	uid := req.Msg.GetUid()
	// 先判存在（行不存在 → 404，不落入 UPSERT 的隐式建行）。
	if _, err := h.users.FindByID(ctx, uid); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, userNotFound()
		}
		return nil, fmt.Errorf("rpc handler: load user: %w", err)
	}

	// user 表资料列：nickname / avatar_url（§3.2 行 821），nil = 该列未传不写。
	var nickname, avatarURL *string
	if v := req.Msg.GetNickname(); v != "" {
		nickname = &v
	}
	if v := req.Msg.GetAvatarUrl(); v != "" {
		avatarURL = &v
	}
	if nickname != nil || avatarURL != nil {
		if err := h.users.UpdateProfileColumns(ctx, uid, nickname, avatarURL); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, userNotFound()
			}
			return nil, fmt.Errorf("rpc handler: update user columns: %w", err)
		}
	}

	// user_profile 行：部分合并（SaveProfile 行 224 注释口径）。
	if in := req.Msg.GetProfile(); in != nil {
		merged, changed, err := h.mergeProfile(ctx, uid, in)
		if err != nil {
			return nil, err
		}
		if changed {
			if err := h.users.SaveProfile(ctx, merged); err != nil {
				return nil, fmt.Errorf("rpc handler: save profile: %w", err)
			}
		}
	}
	return connect.NewResponse(&rpcv1.OkResponse{}), nil
}

// mergeProfile 读现行并合并 UpdateUserProfile 入参的 profile 子字段
//（§3.2 行 821：gender?/birthday?/locale?/timezone?/extra?）。「零值 = 未传」
// 逐字段判定（gender 0 / 空串 / nil extra 均保留现行值）；现行行缺失从
// 零值行起（UserID 补 uid）。changed = 是否存在任一已传子字段（全未传则
// 调用方跳过写库）。birthday 格式非法 → 400 invalid_argument +
// ErrorInfo(rpc, invalid_request)（§1.6；先例 admin GetProviderSchema）。
func (h *UserHandler) mergeProfile(ctx context.Context, uid int64, in *accountv1.UserProfile) (*model.UserProfile, bool, error) {
	merged := &model.UserProfile{UserID: uid}
	if existing, err := h.users.GetProfile(ctx, uid); err == nil && existing != nil {
		merged = existing
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, fmt.Errorf("rpc handler: load profile: %w", err)
	}
	changed := false
	if in.GetGender() != 0 {
		merged.Gender = int8(in.GetGender())
		changed = true
	}
	if raw := in.GetBirthday(); raw != "" {
		t, err := dto.ParseRPCProfileBirthday(raw)
		if err != nil {
			return nil, false, internalconnect.WithErrorInfo(
				connect.NewError(connect.CodeInvalidArgument, errBadBirthday),
				internalconnect.NewErrorInfo("rpc", "invalid_request", "birthday must be YYYY-MM-DD"))
		}
		merged.Birthday = &t
		changed = true
	}
	if v := in.GetLocale(); v != "" {
		merged.Locale = v
		changed = true
	}
	if v := in.GetTimezone(); v != "" {
		merged.Timezone = v
		changed = true
	}
	if extra := in.GetExtra(); extra != nil {
		raw, err := dto.EncodeRPCProfileExtra(extra)
		if err != nil {
			return nil, false, fmt.Errorf("rpc handler: encode profile extra: %w", err)
		}
		merged.Extra = raw
		changed = true
	}
	if changed {
		merged.UpdatedAt = time.Now()
	}
	return merged, changed, nil
}

// TokenHandler 实现 api.rpc.v1.TokenService。内嵌 unimplemented 基类同
// UserHandler。
type TokenHandler struct {
	rpcv1connect.UnimplementedTokenServiceHandler
	verify *session.Verifier
	renew  *session.Renewer
}

// NewTokenHandler 构造 TokenService handler（Verifier / Renewer 复用装配层
// 共享单例，不新造第二套校验 / 重签链）。
func NewTokenHandler(verify *session.Verifier, renew *session.Renewer) *TokenHandler {
	return &TokenHandler{verify: verify, renew: renew}
}

// DecodeSession（§7.1 行 1395-1411）：请求体 sessionToken → Verifier 四步
// 校验（含 epoch 比对，§11.1）→ 通过即每次重签（Renewer.Renew 纯计算、
// 零存储写入，§7.1 行 1408）→ 响应 SessionResponse（平铺载荷取重签后的
// 新载荷，与 renewedToken 自洽）。
//
// 失败语义（§7.1 行 1410）：session 无效 / 过期 / epoch 不一致 → 401
// unauthenticated，错误只由 Connect 错误体表达，不重签、无 renewedToken，
// 不得以 200 + 空 renewedToken 与错误语义混用。epoch 读取链基础设施故障
// → internal（verify.go 行 27-29 口径，不与未登录混同；与 gateway
// 的 500 出口同源）。重签失败（Seal 为内存操作，实际不可达）按 internal
// 拒绝：保持「校验通过 ⇒ renewedToken 非空」的 §7.1 不变量（与会话拦截器
// 「不拒绝已验证请求」的差异：本端点的核心产出即重签令牌，缺它无法兑现
// 契约）。
//
// 本端点不写 Set-Cookie、不设 X-Authloft-Token 响应头（§7.1 行 1408：
// renewedToken 只经响应体字段下发，按原渠道落盘归调用方）。
func (h *TokenHandler) DecodeSession(ctx context.Context, req *connect.Request[rpcv1.DecodeSessionRequest]) (*connect.Response[rpcv1.SessionResponse], error) {
	p, err := h.verify.Verify(ctx, req.Msg.GetSessionToken())
	if err != nil {
		if errors.Is(err, session.ErrNotAuthenticated) || errors.Is(err, session.ErrSessionStale) {
			return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
		}
		return nil, connect.NewError(connect.CodeInternal, errInternal)
	}
	fresh, renewed, rerr := h.renew.Renew(p)
	if rerr != nil {
		return nil, connect.NewError(connect.CodeInternal, errInternal)
	}
	return connect.NewResponse(dto.RPCSession(fresh, renewed)), nil
}

// userNotFound 构造「用户不存在」错误（§1.6 user_not_found，封闭集合）：
// Connect 标准码 not_found（HTTP 404，语义对齐 account GetProfile 先例）+
// ErrorInfo detail（domain=rpc，供 SDK / SSO 应用后端按 §1.6 词汇表归一）。
func userNotFound() error {
	return internalconnect.WithErrorInfo(
		connect.NewError(connect.CodeNotFound, errNotFound),
		internalconnect.NewErrorInfo("rpc", "user_not_found", "user not found"))
}
