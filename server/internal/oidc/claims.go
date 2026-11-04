// claims.go 组装 `GET /api/oidc/userinfo` 标准 claims 与
// `GET /api/oidc/get_user_info` 的 Authloft 用户信息结构
// （docs/接口文档.md §3.1 行 774-813 / §4.5 行 1106-1124 / §4.6 行 1126-1128、
// 《后端架构》§14.4 行 1656-1671）：phone / email 默认掩码，Access Token 的
// scope 含 phone_plain / email_plain 时对应字段明文；标准 phone / email
// scope 决定该 claim / 字段是否存在（§4.2 行 1065）；*_verified 布尔不受
// 掩码影响。Access Token 必须验签 + exp + epoch（改密后旧令牌失效）。
package oidc

import (
	"context"
	"strings"

	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/types/known/structpb"

	accountv1 "authloft/gen/go/api/account/v1"
	oidcapi "authloft/gen/go/api/oidc"
	rpcv1 "authloft/gen/go/api/rpc/v1"
	"authloft/internal/repo/model"
)

// UserFinder user 行读取窄接口；*repo.UserRepo 天然满足。
type UserFinder interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
}

// ProfileFinder user_profile 行读取窄接口；*repo.UserRepo 天然满足。
type ProfileFinder interface {
	GetProfile(ctx context.Context, userID int64) (*model.UserProfile, error)
}

// UserInfoService userinfo / get_user_info 端点实现。
type UserInfoService struct {
	JWT      *JWT
	Users    UserFinder
	Profiles ProfileFinder
	Epoch    EpochReader
}

// Userinfo 返回 OIDC 标准 claims（§4.5）。
func (s *UserInfoService) Userinfo(ctx context.Context, accessToken string) (*oidcapi.UserinfoResponse, *OAuthError) {
	user, claims, oe := s.load(ctx, accessToken)
	if oe != nil {
		return nil, oe
	}
	scope := claims.Scope
	resp := &oidcapi.UserinfoResponse{
		Sub:     user.ID,
		Name:    user.Nickname,
		Picture: user.AvatarURL,
		Amr:     claims.AMR,
	}
	if scopeHas(scope, "email") && user.Email != nil && *user.Email != "" {
		if scopeHas(scope, "email_plain") {
			resp.Email = *user.Email
		} else {
			resp.Email = maskEmail(*user.Email)
		}
		resp.EmailVerified = user.EmailVerified != 0
	}
	if scopeHas(scope, "phone") && user.Phone != nil && *user.Phone != "" {
		if scopeHas(scope, "phone_plain") {
			resp.PhoneNumber = *user.Phone
		} else {
			resp.PhoneNumber = maskPhone(*user.Phone)
		}
		resp.PhoneNumberVerified = user.PhoneVerified != 0
	}
	return resp, nil
}

// GetUserInfo 返回 §3.1 Authloft 用户信息结构（无信封包裹，§4.6）。
func (s *UserInfoService) GetUserInfo(ctx context.Context, accessToken string) (*rpcv1.ProfileResponse, *OAuthError) {
	user, claims, oe := s.load(ctx, accessToken)
	if oe != nil {
		return nil, oe
	}
	scope := claims.Scope
	resp := &rpcv1.ProfileResponse{
		Id:          user.ID,
		Username:    user.Username,
		Nickname:    user.Nickname,
		AvatarUrl:   user.AvatarURL,
		UserStatus:  int64(user.UserStatus),
		MfaRequired: int64(user.MfaRequired),
		Epoch:       int64(user.Epoch),
		CreatedAt:   user.CreatedAt.Unix(),
		UpdatedAt:   user.UpdatedAt.Unix(),
	}
	if user.LastLoginAt != nil {
		resp.LastLoginAt = user.LastLoginAt.Unix()
	}
	if scopeHas(scope, "phone") && user.Phone != nil && *user.Phone != "" {
		if scopeHas(scope, "phone_plain") {
			resp.Phone = *user.Phone
		} else {
			resp.Phone = maskPhone(*user.Phone)
		}
	}
	resp.PhoneVerified = int64(user.PhoneVerified)
	if scopeHas(scope, "email") && user.Email != nil && *user.Email != "" {
		if scopeHas(scope, "email_plain") {
			resp.Email = *user.Email
		} else {
			resp.Email = maskEmail(*user.Email)
		}
	}
	resp.EmailVerified = int64(user.EmailVerified)

	if p, err := s.Profiles.GetProfile(ctx, user.ID); err == nil && p != nil {
		resp.Profile = &accountv1.UserProfile{
			Gender:   int64(p.Gender),
			Locale:   p.Locale,
			Timezone: p.Timezone,
			Extra:    decodeExtra(p.Extra),
		}
		if p.Birthday != nil {
			resp.Profile.Birthday = p.Birthday.Format("2006-01-02")
		}
	}
	return resp, nil
}

// load 验签 Access Token、比对 epoch、读取用户；任一失败按 RFC 6750
// 401 invalid_token（handler 负责回写 WWW-Authenticate）。
func (s *UserInfoService) load(ctx context.Context, accessToken string) (*model.User, *AccessClaims, *OAuthError) {
	if accessToken == "" {
		return nil, nil, newOAuthError(401, "invalid_token", "access token is required")
	}
	claims, err := s.JWT.VerifyAccess(accessToken)
	if err != nil {
		return nil, nil, newOAuthError(401, "invalid_token", "access token is invalid or expired")
	}
	epoch, err := s.Epoch.Current(ctx, claims.Sub)
	if err != nil || epoch != claims.Epoch {
		// epoch 不一致 = 改密 / 重置 / 禁用后旧令牌失效（§4.7）。
		return nil, nil, newOAuthError(401, "invalid_token", "access token epoch is stale")
	}
	user, err := s.Users.FindByID(ctx, claims.Sub)
	if err != nil || user == nil {
		return nil, nil, newOAuthError(401, "invalid_token", "user not found")
	}
	return user, claims, nil
}

// scopeHas 判断空格分隔 scope 是否含指定值。
func scopeHas(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// maskPhone 固定掩码格式：前 3 + "****" + 后 4（接口文档 §3.1 行 813）。
func maskPhone(phone string) string {
	if len(phone) <= 7 {
		return "****"
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}

// maskEmail 固定掩码格式：本地部分首字符 + "***"，域名保留（§3.1 行 813）。
func maskEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		return "***"
	}
	local := []rune(email[:at])
	if len(local) == 0 {
		return "***" + email[at:]
	}
	return string(local[0]) + "***" + email[at:]
}

// decodeExtra user_profile.extra（msgpack）→ JSON 对象（§3.1 行 796）；
// 解码失败按空值处理（附加资料缺失不能影响主信息返回）。
func decodeExtra(raw []byte) *structpb.Struct {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := msgpack.Unmarshal(raw, &m); err != nil {
		return nil
	}
	out, err := structpb.NewStruct(m)
	if err != nil {
		return nil
	}
	return out
}
