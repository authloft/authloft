// profile.go account 域资料更新业务层（docs/接口文档.md §3.2 行
// 837、《后端架构》§17 行 1789）。
//
// 职责：AccountService/UpdateProfile 的更新编排——proto3 optional 口径
//（2026-11-06 定稿）：has 位区分「未设置 = 不修改」与「显式设值 = 覆盖」
//（含 0 / 空串，gender 可显式改回 0=保密、字符串字段可显式清空），禁止
// 按零值猜「未传」。仅本人（会话 uid 由 handler 注入，service 不解析会话）；
// nickname / avatar_url 走 user 表列级更新（UpdateProfileColumns），profile
// 子字段先读现行 → dto.MergeUserProfile 按 has 合并 → SaveProfile 整行
// UPSERT（行 224 注释口径）；用户名 / 手机号 / 邮箱不可由此修改
//（proto 不含该三项，契约结构上即不可改）。全字段未设置 = 合法空操作，
// 零写库直接成功。无审计（§4.6 事件枚举无 profile_update，不自造）。
package account

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/internal/dto"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
)

// ProfileStore 用户资料读写窄接口（§20 依赖注入）：*repo.UserRepo 天然满足
//（FindByID / GetProfile / SaveProfile / UpdateProfileColumns 均为既有方法，
// 不扩公共接口），测试可传 fake。
type ProfileStore interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	GetProfile(ctx context.Context, userID int64) (*model.UserProfile, error)
	SaveProfile(ctx context.Context, p *model.UserProfile) error
	UpdateProfileColumns(ctx context.Context, id int64, nickname, avatarURL *string) error
}

// ErrProfileInvalidRequest birthday 格式非法（handler 转 invalid_argument +
// ErrorInfo(account, invalid_request)，§1.6 封闭集成员）。
var ErrProfileInvalidRequest = errors.New("account profile: invalid request")

// ProfileService account 域资料更新业务层。
type ProfileService struct {
	users ProfileStore
	now   func() time.Time
}

// NewProfileService 构造。
func NewProfileService(users ProfileStore) *ProfileService {
	return &ProfileService{users: users, now: time.Now}
}

// UpdateProfile（§3.2 行 837）：当前用户资料部分更新，编排链——
//  1. 存在性先判（user 行不存在 → gorm.ErrRecordNotFound 透传，handler 转
//     not_found，口径同 GetProfile；先于任何写操作，空 body 同样适用）；
//  2. user 表资料列：nickname / avatar_url has 位判定（指针非 nil = 显式
//     设置，含空串 = 显式清空），仅 has 时列级 UPDATE（未传列不覆盖）；
//  3. user_profile 行：profile 消息在场（自带 presence）→ 读现行 →
//     dto.MergeUserProfile 按 has 合并（显式 gender 0 / 空串 birthday /
//     locale / timezone 均可表达；birthday 显式空串 = 清空）→ changed 时
//     整行 UPSERT（含 updated_at 刷新；全未设置零写库）。
func (s *ProfileService) UpdateProfile(ctx context.Context, uid int64, in *accountv1.UpdateProfileRequest) error {
	// 存在性先判（account GetProfile 口径：不存在 → not_found）。
	if _, err := s.users.FindByID(ctx, uid); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		return fmt.Errorf("account profile: load user: %w", err)
	}

	// user 表资料列（§3.2 行 837）：has 位判定，仅 has 时列级 UPDATE。
	var nickname, avatarURL *string
	if in.Nickname != nil {
		nickname = in.Nickname
	}
	if in.AvatarUrl != nil {
		avatarURL = in.AvatarUrl
	}
	if nickname != nil || avatarURL != nil {
		if err := s.users.UpdateProfileColumns(ctx, uid, nickname, avatarURL); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			return fmt.Errorf("account profile: update columns: %w", err)
		}
	}

	// user_profile 行：has 位合并（profile 消息 nil = 未传，不触碰该行）。
	if p := in.GetProfile(); p != nil {
		existing, err := s.users.GetProfile(ctx, uid)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("account profile: load profile: %w", err)
		}
		merged, changed, err := dto.MergeUserProfile(uid, existing, p)
		if err != nil {
			return ErrProfileInvalidRequest
		}
		if changed {
			merged.UpdatedAt = s.now()
			if err := s.users.SaveProfile(ctx, merged); err != nil {
				return fmt.Errorf("account profile: save profile: %w", err)
			}
		}
	}
	return nil
}

// compile 时断言生产实现满足窄接口（webauthn.go 同款）。
var _ ProfileStore = (*repo.UserRepo)(nil)
