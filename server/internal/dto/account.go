// account 域的内部模型 → proto 报文转换（docs/接口文档.md §3.1 行
// 774-813）：AccountService/GetProfile 响应的字段映射、phone / email
// 服务端掩码与 user_profile.extra 的 msgpack 解码均以本文件为唯一出口
//（docs/后端架构.md §3.5：本层只做转换与裁剪，不定义新的跨端结构）。
// GetConfig 的 avatarUpload / mfaPolicy 投影（§3.2 行 818-847）同此。
package dto

import (
	"strings"

	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/types/known/structpb"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/gen/go/provider"
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

// avatarUploadDefaultMaxSize storage Ext.max_size 未配置（proto 零值 0）
// 的读端兜底默认 2MB（接口文档 §12.1 行 1704 字段默认值语义）。
const avatarUploadDefaultMaxSize = 2 << 20

// AccountAvatarUpload 把 storage Provider 行投影为 §3.2 行 818 的
// AvatarUploadConfig。providerType 为该行 type（s3/local）；providerType
// 空串 = 未配置 → 零值投影 {mode:"proxy", maxSize:0, allowedTypes:[]}
//（接口文档行 826：mode 值域保持 proxy/direct 闭合，不新增
// 枚举，前端据零值隐藏上传入口）。local 配置 direct 回退 proxy（行 825、
// 后端架构 §15.1：local 无预签名能力）；maxSize / allowedTypes 取
// Ext.max_size / Ext.allowed_types（§12.1 行 1704-1705），maxSize 零值
// 兜底 2MB，allowedTypes 逗号分隔 → 列表、空串 → 空列表。
func AccountAvatarUpload(providerType string, ext *provider.Ext) *accountv1.AvatarUploadConfig {
	if providerType == "" {
		return &accountv1.AvatarUploadConfig{Mode: "proxy"}
	}
	mode := "proxy"
	if ext.GetUploadMode() == "direct" && providerType != "local" {
		mode = "direct"
	}
	maxSize := ext.GetMaxSize()
	if maxSize <= 0 {
		maxSize = avatarUploadDefaultMaxSize
	}
	return &accountv1.AvatarUploadConfig{
		Mode:         mode,
		MaxSize:      maxSize,
		AllowedTypes: splitAllowedTypes(ext.GetAllowedTypes()),
	}
}

// splitAllowedTypes 逗号分隔 MIME 白名单（§12.1 行 1705）→ 列表；
// 空串返回空列表（零值投影，行 826），逐项去空白、丢空段。
func splitAllowedTypes(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// MfaBound MFA 各因子绑定态（§3.2 行 836-840 bound 投影的输入）：
// totp / webauthn / recovery_code 由 user_credential 行判定（is_enabled=1，
// recovery_code 需余量非空），otp_sms / otp_email 由 user.phone / email
// 判定；明细字段归 GetMfa（§3.5），此处仅布尔投影（行 845）。
type MfaBound struct {
	Totp         bool
	OtpSms       bool
	OtpEmail     bool
	Webauthn     bool
	RecoveryCode bool
}

// mfaFactorOrder 五因子序（§3.2 行 834-840：totp/otp_sms/otp_email/
// webauthn/recovery_code，顺序即前端渲染顺序，行 845）。
var mfaFactorOrder = [...]string{"totp", "otp_sms", "otp_email", "webauthn", "recovery_code"}

// AccountMfaPolicy 组装 §3.2 行 827-847 的 mfaPolicy 摘要：
// enabled=已开启（mfa_setting 行存在，行 846）；methods[].enabled =
// factor ∈ enabledMethods（mfa_setting 行 CredentialMeta.mfa_methods，
// 行 846）；recovery_code 随 totp 投影（行 846、§5.6：随 totp 生效
// 不单列）；bound=绑定态投影；trustedDeviceDays 恒 0（行 847 预留字段，
// 本期不提供「信任此设备」）。
func AccountMfaPolicy(enabled bool, enabledMethods []string, required bool, bound MfaBound) *accountv1.MfaPolicy {
	enabledSet := make(map[string]bool, len(enabledMethods))
	for _, m := range enabledMethods {
		enabledSet[m] = true
	}
	policy := &accountv1.MfaPolicy{
		Enabled:           enabled,
		Required:          required,
		TrustedDeviceDays: 0,
		Methods:           make([]*accountv1.MfaPolicyMethod, 0, len(mfaFactorOrder)),
	}
	for _, factor := range mfaFactorOrder {
		m := &accountv1.MfaPolicyMethod{Factor: factor, Enabled: enabledSet[factor]}
		if factor == "recovery_code" {
			m.Enabled = enabledSet["totp"]
		}
		switch factor {
		case "totp":
			m.Bound = bound.Totp
		case "otp_sms":
			m.Bound = bound.OtpSms
		case "otp_email":
			m.Bound = bound.OtpEmail
		case "webauthn":
			m.Bound = bound.Webauthn
		case "recovery_code":
			m.Bound = bound.RecoveryCode
		}
		policy.Methods = append(policy.Methods, m)
	}
	return policy
}
