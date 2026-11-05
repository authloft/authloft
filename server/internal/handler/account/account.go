// Package account 实现 api.account.v1.AccountService 的 Connect handler
//（docs/后端架构.md §3.4 行 332：account 域方法族，全部需会话）。已落地
// GetProfile 与 GetConfig（四件全量下发：avatarUpload / mfaPolicy /
// captcha / hasPassword，接口文档 §3.2 行 818-847）；其余方法一律由生成的
// UnimplementedAccountServiceHandler 返回 unimplemented（不自造错误信封）。
package account

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"gorm.io/gorm"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/gen/go/api/account/v1/accountv1connect"
	commonv1 "authloft/gen/go/api/common/v1"
	"authloft/internal/captcha"
	"authloft/internal/dto"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/session"
	"authloft/internal/settings"
)

// UserReader account 域用户读取窄接口（§20 依赖注入）：生产注入
// *repo.UserRepo（FindByID / GetProfile 均已有，不扩公共接口），测试可传 fake。
type UserReader interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	GetProfile(ctx context.Context, userID int64) (*model.UserProfile, error)
}

// CredentialReader account 域凭证读取窄接口（§20）：生产注入
// *repo.CredentialRepo（FindByUserAndKind 已有，不扩公共接口），
// hasPassword / mfaPolicy / mfa 绑定态共用。
type CredentialReader interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
}

// SettingsReader account 域 settings 读取窄接口（§20）：生产注入
// *settings.Store（GetBool / GetString 已有）。
type SettingsReader interface {
	GetBool(key string) (bool, bool)
	GetString(key string) (string, bool)
}

// ProviderReader account 域 provider 行读取窄接口（§20）：生产注入
// *repo.ProviderRepo（FindByKey 已有），avatarUpload 的 storage 行查询。
type ProviderReader interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
}

// CaptchaConfiger captcha 当前生效配置出口（后端架构 §9.1 行 1094：
// 注入快照 / GetConfig / 触发响应三处共用同一出口，每次现算不缓存）：
// 生产注入 *captcha.Gate（nil Gate 的 Config 走 builtin 降级）。
type CaptchaConfiger interface {
	Config(ctx context.Context) captcha.Config
}

// 线上错误文案：connect.Error 文本直达客户端，一律不携带内部信息
//（口径同 internal/connect interceptors.go）。
var (
	errAuthRequired = errors.New("authentication required")
	errNotFound     = errors.New("not found")
)

// Handler AccountService 服务实现。内嵌生成的 unimplemented 基类：本包未
// 实现的方法统一返回 Connect CodeUnimplemented。
type Handler struct {
	accountv1connect.UnimplementedAccountServiceHandler
	users     UserReader
	creds     CredentialReader
	settings  SettingsReader
	providers ProviderReader
	captcha   CaptchaConfiger
}

// New 构造 AccountService handler。
func New(users UserReader, creds CredentialReader, settings SettingsReader, providers ProviderReader, captcha CaptchaConfiger) *Handler {
	return &Handler{users: users, creds: creds, settings: settings, providers: providers, captcha: captcha}
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

// GetConfig（接口文档 §3.2 行 818-847）：account entry 的配置读取处，
// 四件全量下发——avatarUpload（settings avatar_storage_provider →
// provider 表 storage 生效行 Ext 投影）、mfaPolicy（mfa_setting 行摘要）、
// captcha（Gate 现算公开视图，无凭证）、hasPassword（kind=password 且
// is_enabled=1）。鉴权同 GetProfile：session 拦截器放行匿名（既定语义），
// ctx 无 uid 即 unauthenticated。
func (h *Handler) GetConfig(ctx context.Context, req *connect.Request[accountv1.GetConfigRequest]) (*connect.Response[accountv1.AccountConfigResponse], error) {
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

	avatar, err := h.avatarUpload(ctx)
	if err != nil {
		return nil, err
	}
	mfa, err := h.mfaPolicy(ctx, uid, user)
	if err != nil {
		return nil, err
	}
	hasPassword, err := h.hasPassword(ctx, uid)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accountv1.AccountConfigResponse{
		AvatarUpload: avatar,
		MfaPolicy:    mfa,
		Captcha:      h.captchaConfig(ctx),
		HasPassword:  hasPassword,
	}), nil
}

// avatarUpload 组装 avatarUpload 投影：settings 键 avatar_storage_provider
//（§5.6 行 1337）→ provider 表 category=storage 生效行 → Ext{mode,maxSize,
// allowedTypes}（§5.3 storage 扩展字段，行 1237）。未配置（空串 / 查无该行 /
// is_enabled=0 / category≠storage）→ 零值投影（行 826），投影逻辑在
// dto.AccountAvatarUpload；local 配置 direct 回退 proxy（行 825、§15.1）。
// 基础设施错误（含 ext 解析失败）上抛，按未知异常映射 internal（行 826）。
func (h *Handler) avatarUpload(ctx context.Context) (*accountv1.AvatarUploadConfig, error) {
	key := ""
	if h.settings != nil {
		key, _ = h.settings.GetString(settings.KeyAvatarStorageProvider)
	}
	if key == "" {
		return dto.AccountAvatarUpload("", nil), nil
	}
	row, err := h.providers.FindByKey(ctx, key)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return dto.AccountAvatarUpload("", nil), nil
		}
		return nil, fmt.Errorf("account handler: load avatar storage provider: %w", err)
	}
	if row.Category != providerCategoryStorage || row.IsEnabled != 1 {
		return dto.AccountAvatarUpload("", nil), nil
	}
	ext, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		return nil, fmt.Errorf("account handler: parse avatar storage provider ext: %w", err)
	}
	return dto.AccountAvatarUpload(row.Type, ext), nil
}

// providerCategoryStorage provider 表 category=storage（§5.3 行 1237
// storage 类；avatarUpload 只认 storage 行）。
const providerCategoryStorage = "storage"

// credential kind 取值（后端架构 §4.2 行 667 kind 枚举：password|totp|
// webauthn|recovery_code|mfa_setting）。
const (
	kindPassword      = "password"
	kindTotp          = "totp"
	kindWebauthn      = "webauthn"
	kindRecoveryCode  = "recovery_code"
	kindMfaSetting    = "mfa_setting"
)

// mfaPolicy 组装 mfaPolicy 摘要（§3.2 行 827-847）：enabled=uid 有
// kind=mfa_setting 行（行 846：行存在即顶层 enabled=true，每用户至多
// 一行；is_enabled 语义归写入端 SetMfa，本实现只读）；required=
// settings.mfa_enabled && user.mfa_required==1（mfa_enabled 缺失回落默认
// true，§5.6 行 1322）；trustedDeviceDays 恒 0；methods[] 五因子序投影
// （dto.AccountMfaPolicy）。mfa_setting 行读取 = FindByUserAndKind +
// UnmarshalCredentialMeta 反序列化取 MfaMethods（repo 现有能力，不扩接口）。
func (h *Handler) mfaPolicy(ctx context.Context, uid int64, user *model.User) (*accountv1.MfaPolicy, error) {
	mfaEnabled := true
	if h.settings != nil {
		if v, ok := h.settings.GetBool(settings.KeyMfaEnabled); ok {
			mfaEnabled = v
		}
	}
	required := mfaEnabled && user.MfaRequired == 1

	var (
		enabled        bool
		enabledMethods []string
	)
	row, err := h.creds.FindByUserAndKind(ctx, uid, kindMfaSetting)
	switch {
	case err == nil:
		enabled = true
		meta, err := repo.UnmarshalCredentialMeta(row.Meta)
		if err != nil {
			return nil, fmt.Errorf("account handler: decode mfa_setting meta: %w", err)
		}
		enabledMethods = meta.GetMfaMethods()
	case errors.Is(err, gorm.ErrRecordNotFound):
		// 行不存在 = 未开启两步验证（行 846）。
	default:
		return nil, fmt.Errorf("account handler: load mfa_setting: %w", err)
	}

	bound, err := h.mfaBound(ctx, uid, user)
	if err != nil {
		return nil, err
	}
	return dto.AccountMfaPolicy(enabled, enabledMethods, required, bound), nil
}

// mfaBound 各因子绑定态（§3.2 行 836-840 bound 仅布尔投影，明细归 §3.5
// GetMfa）：totp / webauthn / recovery_code 走 user_credential 行（存在且
// is_enabled=1；recovery_code 需 meta 余量非空——删空写回空数组等价该 kind
// 不可用，后端架构 §4.2 行 697）；otp_sms / otp_email 走 user.phone /
// email 非空（OTP 因子无凭证行，目标即绑定）。
func (h *Handler) mfaBound(ctx context.Context, uid int64, user *model.User) (dto.MfaBound, error) {
	var bound dto.MfaBound

	totp, err := h.creds.FindByUserAndKind(ctx, uid, kindTotp)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return bound, fmt.Errorf("account handler: load totp credential: %w", err)
	}
	bound.Totp = err == nil && totp.IsEnabled == 1

	webauthn, err := h.creds.FindByUserAndKind(ctx, uid, kindWebauthn)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return bound, fmt.Errorf("account handler: load webauthn credential: %w", err)
	}
	bound.Webauthn = err == nil && webauthn.IsEnabled == 1

	recovery, err := h.creds.FindByUserAndKind(ctx, uid, kindRecoveryCode)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return bound, fmt.Errorf("account handler: load recovery_code credential: %w", err)
	}
	if err == nil && recovery.IsEnabled == 1 {
		meta, err := repo.UnmarshalCredentialMeta(recovery.Meta)
		if err != nil {
			return bound, fmt.Errorf("account handler: decode recovery_code meta: %w", err)
		}
		bound.RecoveryCode = len(meta.GetRecoveryCodes()) > 0
	}

	bound.OtpSms = user.Phone != nil && *user.Phone != ""
	bound.OtpEmail = user.Email != nil && *user.Email != ""
	return bound, nil
}

// hasPassword 当前用户是否存在 kind=password 且 is_enabled=1 的凭证
//（§3.2 行 818：供安全中心判断改密入口与第三方解绑是否可用，§3.7 判定
// 口径）。行不存在 / 已停用均返回 false，不视为错误。
func (h *Handler) hasPassword(ctx context.Context, uid int64) (bool, error) {
	row, err := h.creds.FindByUserAndKind(ctx, uid, kindPassword)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("account handler: load password credential: %w", err)
	}
	return row.IsEnabled == 1, nil
}

// captchaConfig captcha 公开视图（§3.2 行 818：经公开视图消息输出，不含
// 凭证）：Gate 现算保降级一致（§9.1 行 1094 三处共用出口）；未注入时按
// (*captcha.Gate).Config 的 nil 分支降级内置图形码。
func (h *Handler) captchaConfig(ctx context.Context) *commonv1.CaptchaConfig {
	if h.captcha == nil {
		return &commonv1.CaptchaConfig{
			ProviderKey: captcha.BuiltinProviderKey,
			Type:        captcha.TypeImage,
		}
	}
	cfg := h.captcha.Config(ctx)
	return &commonv1.CaptchaConfig{
		ProviderKey: cfg.ProviderKey,
		Type:        cfg.Type,
		SiteKey:     cfg.SiteKey,
	}
}
