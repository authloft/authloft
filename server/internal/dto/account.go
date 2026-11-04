// account 域的内部模型 → proto 报文转换（docs/接口文档.md §3.1 行
// 774-813）：AccountService/GetProfile 响应的字段映射、phone / email
// 服务端掩码与 user_profile.extra 的 msgpack 解码均以本文件为唯一出口
//（docs/后端架构.md §3.5：本层只做转换与裁剪，不定义新的跨端结构）。
package dto

import (
	"strings"

	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/types/known/structpb"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/internal/repo/model"
)

// AccountProfile 把 user + user_profile 行组装为 §3.1 的 ProfileResponse
//（行 775：各端点响应即下列字段、无信封包裹）。掩码在服务端完成（行 802：
// 前端不二次处理），account 域自助接口默认掩码（行 806）。profile 行缺失
//（p == nil）时输出零值 profile 消息，不视为错误；u == nil 时返回空响应
//（调用方契约下不可达的防御分支，口径同 internal/oidc 的 user 判空）。
func AccountProfile(u *model.User, p *model.UserProfile) *accountv1.ProfileResponse {
	if u == nil {
		return &accountv1.ProfileResponse{}
	}
	resp := &accountv1.ProfileResponse{
		Id:            u.ID,
		Username:      u.Username,
		Nickname:      u.Nickname,
		AvatarUrl:     u.AvatarURL,
		PhoneVerified: int64(u.PhoneVerified),
		EmailVerified: int64(u.EmailVerified),
		UserStatus:    int64(u.UserStatus),
		MfaRequired:   int64(u.MfaRequired),
		Epoch:         int64(u.Epoch),
		CreatedAt:     u.CreatedAt.Unix(),
		UpdatedAt:     u.UpdatedAt.Unix(),
		Profile:       accountUserProfile(p),
	}
	// phone / email：绑定（非空）才掩码输出，未绑定保持零值由 protojson
	// 省略（§1.1 空值口径）；*_verified 原样输出、不受掩码影响（行 813）。
	if u.Phone != nil && *u.Phone != "" {
		resp.Phone = maskPhone(*u.Phone)
	}
	if u.Email != nil && *u.Email != "" {
		resp.Email = maskEmail(*u.Email)
	}
	if u.LastLoginAt != nil {
		resp.LastLoginAt = u.LastLoginAt.Unix()
	}
	return resp
}

// accountUserProfile user_profile 行 → §3.1 行 793-797 的 profile 结构：
// birthday DATE → YYYY-MM-DD 字符串；extra（msgpack 字节）→ JSON 对象。
func accountUserProfile(p *model.UserProfile) *accountv1.UserProfile {
	profile := &accountv1.UserProfile{}
	if p == nil {
		return profile
	}
	profile.Gender = int64(p.Gender)
	if p.Birthday != nil {
		profile.Birthday = p.Birthday.Format("2006-01-02")
	}
	profile.Locale = p.Locale
	profile.Timezone = p.Timezone
	profile.Extra = decodeProfileExtra(p.Extra)
	return profile
}

// decodeProfileExtra user_profile.extra（msgpack）→ JSON 对象（§3.1 行 796）；
// 解码失败按空值处理（附加资料缺失不能影响主信息返回）。口径与
// internal/oidc/claims.go 的 decodeExtra 一致（该函数包内私有，无法跨包
// 复用，掩码 / 解码助手在 dto 层按 §3.1 各落一份并配同款测试）。
func decodeProfileExtra(raw []byte) *structpb.Struct {
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

// maskPhone 固定掩码格式：前 3 + "****" + 后 4（§3.1 行 813）；不足 8 位
//（掩码后无意义）整体 "****"。
func maskPhone(phone string) string {
	if len(phone) <= 7 {
		return "****"
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}

// maskEmail 固定掩码格式：本地部分首字符 + "***"，域名保留（§3.1 行 813）；
// 无 "@" 或空本地部分时仅 "***"。
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
