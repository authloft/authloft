package dto

import (
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"authloft/internal/repo/model"
)

// wantUser §3.1 行 779-793 的全字段样例（phone=13800008000 → 掩码
// 138****8000；email=alice@example.com → 掩码 a***@example.com）。
func wantUser() *model.User {
	phone := "13800008000"
	email := "alice@example.com"
	lastLogin := time.Unix(1761800000, 0).UTC()
	return &model.User{
		ID:            10086,
		Username:      "zhang_san",
		Phone:         &phone,
		Email:         &email,
		PhoneVerified: 1,
		EmailVerified: 1,
		Nickname:      "张三",
		AvatarURL:     "https://cdn.example.com/a.jpg",
		UserStatus:    1,
		MfaRequired:   0,
		Epoch:         3,
		LastLoginAt:   &lastLogin,
		CreatedAt:     time.Unix(1761700000, 0).UTC(),
		UpdatedAt:     time.Unix(1761800000, 0).UTC(),
	}
}

// wantProfile §3.1 行 793-797 的 profile 样例，extra = {"company":"Acme"}。
func wantProfile(t *testing.T) *model.UserProfile {
	t.Helper()
	extra, err := msgpack.Marshal(map[string]interface{}{"company": "Acme"})
	if err != nil {
		t.Fatalf("marshal extra: %v", err)
	}
	birthday := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	return &model.UserProfile{
		UserID:   10086,
		Gender:   1,
		Birthday: &birthday,
		Locale:   "zh-CN",
		Timezone: "Asia/Shanghai",
		Extra:    extra,
	}
}

// TestAccountProfileMapsAllFields 逐项断言 §3.1 统一结构（对 proto 字段与
// 文档行 779-797 逐字一致）：标量字段、verified 原样、profile 五字段、
// extra 的 msgpack → JSON 对象。
func TestAccountProfileMapsAllFields(t *testing.T) {
	got := AccountProfile(wantUser(), wantProfile(t))

	if got.GetId() != 10086 {
		t.Errorf("id = %d, want 10086", got.GetId())
	}
	if got.GetUsername() != "zhang_san" {
		t.Errorf("username = %q", got.GetUsername())
	}
	if got.GetNickname() != "张三" {
		t.Errorf("nickname = %q", got.GetNickname())
	}
	if got.GetAvatarUrl() != "https://cdn.example.com/a.jpg" {
		t.Errorf("avatarUrl = %q", got.GetAvatarUrl())
	}
	if got.GetPhoneVerified() != 1 {
		t.Errorf("phoneVerified = %d, want 1（原样，不受掩码影响）", got.GetPhoneVerified())
	}
	if got.GetEmailVerified() != 1 {
		t.Errorf("emailVerified = %d, want 1（原样，不受掩码影响）", got.GetEmailVerified())
	}
	if got.GetUserStatus() != 1 {
		t.Errorf("userStatus = %d, want 1", got.GetUserStatus())
	}
	if got.GetMfaRequired() != 0 {
		t.Errorf("mfaRequired = %d, want 0", got.GetMfaRequired())
	}
	if got.GetEpoch() != 3 {
		t.Errorf("epoch = %d, want 3", got.GetEpoch())
	}
	if got.GetLastLoginAt() != 1761800000 {
		t.Errorf("lastLoginAt = %d, want 1761800000", got.GetLastLoginAt())
	}
	if got.GetCreatedAt() != 1761700000 {
		t.Errorf("createdAt = %d, want 1761700000", got.GetCreatedAt())
	}
	if got.GetUpdatedAt() != 1761800000 {
		t.Errorf("updatedAt = %d, want 1761800000", got.GetUpdatedAt())
	}

	p := got.GetProfile()
	if p == nil {
		t.Fatal("profile = nil, want 零值消息（未绑定资料的形状稳定）")
	}
	if p.GetGender() != 1 {
		t.Errorf("profile.gender = %d, want 1", p.GetGender())
	}
	if p.GetBirthday() != "1990-01-01" {
		t.Errorf("profile.birthday = %q, want 1990-01-01（YYYY-MM-DD）", p.GetBirthday())
	}
	if p.GetLocale() != "zh-CN" {
		t.Errorf("profile.locale = %q", p.GetLocale())
	}
	if p.GetTimezone() != "Asia/Shanghai" {
		t.Errorf("profile.timezone = %q", p.GetTimezone())
	}
	if v := p.GetExtra().GetFields()["company"].GetStringValue(); v != "Acme" {
		t.Errorf("profile.extra.company = %q, want Acme（msgpack → JSON 对象）", v)
	}
}

// TestAccountProfileMasksPhoneAndEmail 断言 §3.1 行 813 的固定掩码格式：
// 手机号前 3 + "****" + 后 4；邮箱本地部分首字符 + "***"、域名保留。
func TestAccountProfileMasksPhoneAndEmail(t *testing.T) {
	masked := func(phone, email string) (maskedPhone, maskedEmail string) {
		u := wantUser()
		u.Phone, u.Email = &phone, &email
		r := AccountProfile(u, nil)
		return r.GetPhone(), r.GetEmail()
	}

	if gotPhone, gotEmail := masked("13800008000", "alice@example.com"); gotPhone != "138****8000" || gotEmail != "a***@example.com" {
		t.Errorf("mask = (%q, %q), want (138****8000, a***@example.com)", gotPhone, gotEmail)
	}
	// 手机号不足 8 位：掩码后无意义，整体 "****"。
	if got, _ := masked("1234567", "alice@example.com"); got != "****" {
		t.Errorf("short phone mask = %q, want ****", got)
	}
	// 邮箱无 @：整体 "***"，不透出任何本地部分。
	if _, got := masked("13800008000", "not-an-email"); got != "***" {
		t.Errorf("no-at email mask = %q, want ***", got)
	}
	// 多字节本地部分按 rune 取首字符，域名原样保留。
	if _, got := masked("13800008000", "张三@example.com"); got != "张***@example.com" {
		t.Errorf("unicode local mask = %q, want 张***@example.com", got)
	}
}

// TestAccountProfileUnboundContact 未绑定（指针 nil / 空串）不掩码、保持
// 零值（protojson 省略，§1.1 空值口径），verified 照常输出。
func TestAccountProfileUnboundContact(t *testing.T) {
	empty := ""
	u := wantUser()
	u.Phone, u.Email = nil, &empty
	got := AccountProfile(u, nil)
	if got.GetPhone() != "" || got.GetEmail() != "" {
		t.Errorf("unbound = (%q, %q), want 空串（省略）", got.GetPhone(), got.GetEmail())
	}
	if got.GetPhoneVerified() != 1 || got.GetEmailVerified() != 1 {
		t.Errorf("verified = (%d, %d), want (1, 1)", got.GetPhoneVerified(), got.GetEmailVerified())
	}
}

// TestAccountProfileNilInputs 防御分支：nil user → 空响应；nil profile →
// 零值 profile 消息（birthday / locale / timezone / extra 零值）。
func TestAccountProfileNilInputs(t *testing.T) {
	if got := AccountProfile(nil, wantProfile(t)); got.GetId() != 0 || got.GetProfile() != nil {
		t.Errorf("nil user → %+v, want 空响应", got)
	}
	got := AccountProfile(wantUser(), nil)
	p := got.GetProfile()
	if p == nil || p.GetGender() != 0 || p.GetBirthday() != "" || p.GetLocale() != "" ||
		p.GetTimezone() != "" || p.GetExtra() != nil {
		t.Errorf("nil profile → %+v, want 零值 profile 消息", p)
	}
	if got.GetId() != 10086 {
		t.Errorf("主信息字段不受 profile 缺失影响: id = %d", got.GetId())
	}
}

// TestAccountProfileBadExtra extra 非法 msgpack 字节 → 空值处理（附加资料
// 缺失不能影响主信息返回），主字段照常输出。
func TestAccountProfileBadExtra(t *testing.T) {
	p := wantProfile(t)
	p.Extra = []byte{0xc1} // 非法 msgpack 填充字节
	got := AccountProfile(wantUser(), p)
	if got.GetProfile().GetExtra() != nil {
		t.Errorf("bad extra = %+v, want nil", got.GetProfile().GetExtra())
	}
	if got.GetId() != 10086 || got.GetUsername() != "zhang_san" {
		t.Errorf("主信息受 extra 解码失败影响: id=%d username=%q", got.GetId(), got.GetUsername())
	}
}
