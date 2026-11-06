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
//（FindByID / GetProfile / SaveProfile / UpdateProfileColumns /
// ListByIDs 均为 UserRepo 既有方法，不扩公共接口），测试注入 fake。
type UserStore interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	GetProfile(ctx context.Context, userID int64) (*model.UserProfile, error)
	SaveProfile(ctx context.Context, p *model.UserProfile) error
	UpdateProfileColumns(ctx context.Context, id int64, nickname, avatarURL *string) error
	ListByIDs(ctx context.Context, ids []int64) ([]model.User, []model.UserProfile, error)
}

// maxBatchProfileIDs GetUserProfiles 单次批量上限（§7.2 批量语义①行 1462）：
// 按入参列表长度计、去重前；超出整单失败、无部分返回、不许截断。
const maxBatchProfileIDs = 100

// 线上错误文案：connect.Error 文本直达客户端，一律不携带内部信息
//（口径同 internal/connect interceptors.go、handler/account）。
var (
	errAuthRequired = errors.New("authentication required")
	errNotFound     = errors.New("not found")
	errInternal     = errors.New("internal error")
	errBadBirthday  = errors.New("invalid birthday")
	errTooManyIDs   = errors.New("too many ids")
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

// GetUserProfiles（§7.2 行 1436）：GetUserProfile 的批量版，批量语义四项口径
//（行 1462-1465）逐条落地：
//   - 上限①：ids 按入参列表长度计、**去重前** > 100 → 整单失败 400
//     invalid_argument + ErrorInfo(rpc, invalid_request)（§1.6 既有码，
//     不新增词汇），无部分返回、不许截断；
//   - 去重④：重复 id 按首次出现位置去重，同一 id 至多返回一条；
//   - 顺序③：响应 profiles 顺序 = 入参去重后的顺序（缺失项跳过后相对
//     顺序保持）——ListByIDs 返回行序不保证（IN 无序），本处以去重后
//     ids 为定位主序回填，不依赖也不改写存储层排序；
//   - 缺失②：实际不存在的 id 跳过、不占位、不报错、不终止整单；
//     user_profile 行缺失输出零值 profile 消息（同 GetUserProfile 口径，
//     行缺失不视为错误）。
//
// 一次批量读取：对 UserStore 仅一次 ListByIDs 调用（N+1 禁止，
// §7.2 行 1462 理由——严禁按 id 循环单查）。ids 缺省 / 空 → 空 profiles、
// 不报错、零查询（空批量是合法的空集语义，行 1467）。读接口不校验
// nonce（方法名 Get 前缀，拦截器按 §7 前言「命名决定校验」天然放行，
// nonce 仅参与签名）。
func (h *UserHandler) GetUserProfiles(ctx context.Context, req *connect.Request[rpcv1.GetUserProfilesRequest]) (*connect.Response[rpcv1.GetUserProfilesResponse], error) {
	ids := req.Msg.GetIds()
	if len(ids) > maxBatchProfileIDs {
		return nil, internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, errTooManyIDs),
			internalconnect.NewErrorInfo("rpc", "invalid_request", "ids must not exceed 100"),
		)
	}
	// 去重④：按首次出现位置保留（顺序③的主序即此去重后序列）。
	seen := make(map[int64]struct{}, len(ids))
	uniq := make([]int64, 0, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		uniq = append(uniq, id)
	}
	if len(uniq) == 0 {
		return connect.NewResponse(&rpcv1.GetUserProfilesResponse{}), nil
	}
	users, profiles, err := h.users.ListByIDs(ctx, uniq)
	if err != nil {
		return nil, fmt.Errorf("rpc handler: list users: %w", err)
	}
	userByID := make(map[int64]*model.User, len(users))
	for i := range users {
		userByID[users[i].ID] = &users[i]
	}
	profileByUID := make(map[int64]*model.UserProfile, len(profiles))
	for i := range profiles {
		profileByUID[profiles[i].UserID] = &profiles[i]
	}
	// 顺序③ + 缺失②：以去重后 ids 为主序回填，缺失 id 跳过不占位；
	// 投影复用 dto.RPCProfile（与 GetUserProfile 响应同构，§7.2 行 1438）。
	out := make([]*rpcv1.ProfileResponse, 0, len(uniq))
	for _, id := range uniq {
		u, ok := userByID[id]
		if !ok {
			continue
		}
		out = append(out, dto.RPCProfile(u, profileByUID[id]))
	}
	return connect.NewResponse(&rpcv1.GetUserProfilesResponse{Profiles: out}), nil
}

// UpdateUserProfile（§7 行 1423，入参同 §3.2 行 837 的
// AccountService/UpdateProfile）：proto3 optional 部分更新（2026-11-06
// 定稿）——has 位区分「未设置 = 不修改」与「显式设值 = 覆盖」：nickname /
// avatar_url 显式空串 = 清空，profile 各子字段（gender / birthday / locale /
// timezone / extra）显式零值均可表达（gender 可改回 0=保密、birthday 显式
// 空串 = 清空），禁止按零值猜「未传」（后端架构 §17 行 1789）；嵌套
// profile 消息自带 presence（nil = 未传，不触碰 user_profile 行）。
//
// 用户名 / 手机号 / 邮箱不可由此修改（§3.2 行 837）：proto
// UpdateUserProfileRequest 不含这三项字段，契约结构上即不可改，本实现亦
// 不提供任何绕过入口；user 表仅更新 nickname / avatar_url 两列（经
// UpdateProfileColumns），user_profile 行按 SaveProfile 行 224 注释的合并
// 语义「先读后拼整行」——读现行（缺失从零值行起）→ 逐字段合并（共享
// dto.MergeUserProfile）→ 整行 UPSERT。全字段未设置时为纯 no-op，不触碰
// 任何存储（连 updated_at 也不刷）。
func (h *UserHandler) UpdateUserProfile(ctx context.Context, req *connect.Request[rpcv1.UpdateUserProfileRequest]) (*connect.Response[rpcv1.OkResponse], error) {
	uid := req.Msg.GetUid()
	// 先判存在（行不存在 → 404，不落入 UPSERT 的隐式建行）。
	if _, err := h.users.FindByID(ctx, uid); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, userNotFound()
		}
		return nil, fmt.Errorf("rpc handler: load user: %w", err)
	}

	// user 表资料列：nickname / avatar_url（§3.2 行 837 optional 口径），
	// has 位判定（指针非 nil = 显式设置，含空串 = 显式清空）。
	var nickname, avatarURL *string
	if req.Msg.Nickname != nil {
		nickname = req.Msg.Nickname
	}
	if req.Msg.AvatarUrl != nil {
		avatarURL = req.Msg.AvatarUrl
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

// mergeProfile 读现行并按 has 位合并 UpdateUserProfile 入参的 profile
// 子字段（§3.2 行 837：gender?/birthday?/locale?/timezone?/extra?），
// 合并本体共享 dto.MergeUserProfile（account 域 UpdateProfile 同一出口，
// §12.9 行 1748「同一结构只定义一次」先例）：未设置 = 不修改，显式设值
//（含 0 / 空串）= 覆盖——gender 可显式改回 0、birthday / locale / timezone
// 可显式清空；现行行缺失从零值行起（UserID 补 uid）。changed = 是否存在
// 任一 has 子字段（全未设置则调用方跳过写库）。birthday 格式非法 →
// 400 invalid_argument + ErrorInfo(rpc, invalid_request)（§1.6；先例
// admin GetProviderSchema）。
func (h *UserHandler) mergeProfile(ctx context.Context, uid int64, in *accountv1.UserProfile) (*model.UserProfile, bool, error) {
	existing, err := h.users.GetProfile(ctx, uid)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, fmt.Errorf("rpc handler: load profile: %w", err)
	}
	merged, changed, err := dto.MergeUserProfile(uid, existing, in)
	if err != nil {
		return nil, false, internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, errBadBirthday),
			internalconnect.NewErrorInfo("rpc", "invalid_request", "birthday must be YYYY-MM-DD"))
	}
	if changed {
		merged.UpdatedAt = time.Now()
	}
	return merged, changed, nil
}

// TokenHandler 实现 api.rpc.v1.TokenService。内嵌 unimplemented 基类同
// UserHandler。users 为 rpc 域用户数据面窄接口（include_user_info=true 的
// 用户资料读取；§7.1 行 1434——false / 缺省零额外查询，不注入读取路径）。
type TokenHandler struct {
	rpcv1connect.UnimplementedTokenServiceHandler
	verify *session.Verifier
	renew  *session.Renewer
	users  UserStore
}

// NewTokenHandler 构造 TokenService handler（Verifier / Renewer 复用装配层
// 共享单例，不新造第二套校验 / 重签链；users 与 UserService 共享同一
// UserRepo 实例，批量 / 单条读取走同一数据面）。
func NewTokenHandler(verify *session.Verifier, renew *session.Renewer, users UserStore) *TokenHandler {
	return &TokenHandler{verify: verify, renew: renew, users: users}
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
//
// include_user_info（§7.1 行 1434）：true 且会话校验通过 → 响应
// user_info 填充——与 UserService/GetUserProfile 响应**同构**，投影复用
// dto.RPCProfile（不复制造第二份投影）；false / 缺省 → 不触 users、零额外
// 查询（响应与现行完全一致）；session 无效 / 过期 / epoch 不一致 → 401
// 不变（校验先于用户读取，include_user_info 不改变失败分支，失败路径
// 亦零用户查询）。校验已通过而 FindByID 落 NotFound 的防御分支（真实链
// epoch 比对已触达 user 行，理论不可达）按 internal 拒绝：不与未登录
//（401）/ 用户不存在（404）混同，口径同 verify.go 行 27-29 基础设施错误。
// GetProfile 行缺失输出零值 profile 消息，不视为错误（同 GetUserProfile）。
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
	resp := dto.RPCSession(fresh, renewed)
	if req.Msg.GetIncludeUserInfo() {
		user, err := h.users.FindByID(ctx, fresh.GetId())
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, connect.NewError(connect.CodeInternal, errInternal)
			}
			return nil, fmt.Errorf("rpc handler: load user: %w", err)
		}
		profile, err := h.users.GetProfile(ctx, fresh.GetId())
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("rpc handler: load profile: %w", err)
		}
		resp.UserInfo = dto.RPCProfile(user, profile)
	}
	return connect.NewResponse(resp), nil
}

// userNotFound 构造「用户不存在」错误（§1.6 user_not_found，封闭集合）：
// Connect 标准码 not_found（HTTP 404，语义对齐 account GetProfile 先例）+
// ErrorInfo detail（domain=rpc，供 SDK / SSO 应用后端按 §1.6 词汇表归一）。
func userNotFound() error {
	return internalconnect.WithErrorInfo(
		connect.NewError(connect.CodeNotFound, errNotFound),
		internalconnect.NewErrorInfo("rpc", "user_not_found", "user not found"))
}
