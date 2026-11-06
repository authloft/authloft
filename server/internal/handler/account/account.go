// Package account 实现 api.account.v1.AccountService 的 Connect handler
// （docs/后端架构.md §3.4 行 332：account 域方法族，全部需会话）。已落地
// GetProfile 与 GetConfig（四件全量下发：avatarUpload / mfaPolicy /
// captcha / hasPassword，接口文档 §3.2 行 818-847）及三方绑定族四
// 方法（GetThirdpartyBindings / UnbindThirdparty / ThirdpartyOauth /
// GetThirdpartyTicket，§3.7 / §3.7.1）；UpdateProfile 落地（§3.2 行
// 837，proto3 optional 口径——编排全部在 service/account.ProfileService，
// 本层只做会话判定与错误映射）；落地剩余十一桩（PresignAvatar /
// CommitAvatar §3.2 行 839-840、ChangePassword §3.3、BindPhone / BindEmail
// §3.4、GetMfa / SetMfa / BindTotp / GetRecoveryCodes /
// RegenerateRecoveryCodes §3.5、GetEvents §3.7 行 1057——五族 service
// 已交付，本层做会话判定、proto ↔ 领域结构转换与错误映射），
// 22 方法全部实装；未装配 service 的方法仍由生成的
// UnimplementedAccountServiceHandler 语义返回 unimplemented（不自造错误信封）。
package account

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"
	"gorm.io/gorm"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/gen/go/api/account/v1/accountv1connect"
	commonv1 "authloft/gen/go/api/common/v1"
	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/internal/captcha"
	internalconnect "authloft/internal/connect"
	"authloft/internal/dto"
	"authloft/internal/factor/webauthn"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	"authloft/internal/service"
	accountsvc "authloft/internal/service/account"
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

// Thirdparty 三方绑定族 service 窄接口（§20 依赖注入）：生产注入
// *accountsvc.ThirdpartyService，测试可传 fake；nil（未装配）时四个方法
// 返回 unimplemented。
type Thirdparty interface {
	GetThirdpartyBindings(ctx context.Context, uid int64) (*accountsvc.BindingsResult, error)
	UnbindThirdparty(ctx context.Context, uid int64, providerKey string) error
	ThirdpartyOauth(ctx context.Context, in accountsvc.OauthInput) (*accountsvc.BindOutcome, error)
	GetThirdpartyTicket(ctx context.Context, in accountsvc.TicketInput) *ssov1.LoginFlowResponse
}

// Webauthn 通行密钥族 service 窄接口（§20 依赖注入；Delete 为补充
// 实装）：生产注入 *accountsvc.WebauthnService，测试可传 fake；nil（未装配）
// 时对应方法返回 unimplemented。
type Webauthn interface {
	ListCredentials(ctx context.Context, uid int64) ([]accountsvc.WebauthnItem, error)
	BeginRegister(ctx context.Context, uid int64) (*webauthn.RegistrationChallenge, error)
	FinishRegister(ctx context.Context, uid int64, tok string, credential *structpb.Struct, label string) error
	RenameCredential(ctx context.Context, uid int64, id int64, label string) error
	DeleteCredential(ctx context.Context, uid int64, id int64) error
}

// ProfileUpdater 资料更新 service 窄接口（§20 依赖注入）：生产注入
// *accountsvc.ProfileService，测试可传 fake；nil（未装配）时 UpdateProfile
// 返回 unimplemented。
type ProfileUpdater interface {
	UpdateProfile(ctx context.Context, uid int64, in *accountv1.UpdateProfileRequest) error
}

// AvatarDirector 头像直传两桩 service 窄接口（§20 依赖注入）：生产
// 注入 *accountsvc.AvatarService，测试可传 fake；nil（未装配）时对应方法
// 返回 unimplemented。service 直接消费 / 产出 proto 消息（avatar.go 签名），
// 本层不做二次转换。
type AvatarDirector interface {
	PresignAvatar(ctx context.Context, uid int64, in *accountv1.PresignAvatarRequest) (*accountv1.AvatarPresignResponse, error)
	CommitAvatar(ctx context.Context, uid int64, in *accountv1.CommitAvatarRequest) (*accountv1.AvatarResponse, error)
}

// PasswordChanger 改密 service 窄接口（§20 依赖注入）：生产注入
// *accountsvc.PasswordService，测试可传 fake；nil（未装配）时 ChangePassword
// 返回 unimplemented。
type PasswordChanger interface {
	ChangePassword(ctx context.Context, uid int64, currentPassword, newPassword string) error
}

// ContactBinder 换绑 service 窄接口（§20 依赖注入）：生产注入
// *accountsvc.BindContactService，测试可传 fake；nil（未装配）时对应方法
// 返回 unimplemented。
type ContactBinder interface {
	BindPhone(ctx context.Context, uid int64, in accountsvc.BindPhoneInput) error
	BindEmail(ctx context.Context, uid int64, in accountsvc.BindEmailInput) error
}

// MfaManager 两步验证族 service 窄接口（§20 依赖注入）：生产注入
// *accountsvc.MfaService，测试可传 fake；nil（未装配）时对应方法返回
// unimplemented。
type MfaManager interface {
	GetMfa(ctx context.Context, uid int64) (*accountsvc.MfaDetail, error)
	SetMfa(ctx context.Context, uid int64, methods []string) error
	BindTotpChallenge(ctx context.Context, uid int64) (*accountsvc.TotpChallenge, error)
	BindTotpVerify(ctx context.Context, uid int64, secret, code string) ([]string, error)
	GetRecoveryCodes(ctx context.Context, uid int64) (*accountsvc.RecoveryCodesResult, error)
	RegenerateRecoveryCodes(ctx context.Context, uid int64, action string) (*accountsvc.RecoveryCodesResult, error)
}

// EventReader 本人事件日志 service 窄接口（§20 依赖注入）：生产注入
// *accountsvc.EventsService，测试可传 fake；nil（未装配）时 GetEvents 返回
// unimplemented。
type EventReader interface {
	GetEvents(ctx context.Context, uid int64, event string, page, pageSize int) ([]model.EventLog, int64, error)
}

// 线上错误文案：connect.Error 文本直达客户端，一律不携带内部信息
// （口径同 internal/connect interceptors.go）。
var (
	errAuthRequired = errors.New("authentication required")
	errNotFound     = errors.New("not found")
	// errThirdpartyNotConfigured 未装配三方绑定 service（测试桩）。
	errThirdpartyNotConfigured = errors.New("thirdparty service not configured")
	// errThirdpartyInternal 未知异常的固定文案（§1.5：不暴露内部信息；
	// §1.6 行 273 internal 无 ErrorInfo）。
	errThirdpartyInternal = errors.New("internal error")
	// errWebauthnNotConfigured 未装配通行密钥 service（测试桩）。
	errWebauthnNotConfigured = errors.New("webauthn service not configured")
	// errWebauthnInternal 未知异常的固定文案（同 errThirdpartyInternal 口径）。
	errWebauthnInternal = errors.New("internal error")
	// errWebauthnDuplicate 重复注册的固定文案（§1.5 行 191「重复绑定」）。
	errWebauthnDuplicate = errors.New("credential already exists")
	// errWebauthnInvalidStep step 取值非法。
	errWebauthnInvalidStep = errors.New("invalid step")
	// errProfileNotConfigured 未装配资料更新 service（测试桩）。
	errProfileNotConfigured = errors.New("profile service not configured")
	// errAvatarNotConfigured 未装配头像直传 service（测试桩）。
	errAvatarNotConfigured = errors.New("avatar service not configured")
	// errAvatarInternal 头像直传未知异常的固定文案（§1.6 行 273 internal 无
	// ErrorInfo；行 842 未配置 / 非 direct 模式同口径）。
	errAvatarInternal = errors.New("internal error")
	// errPasswordNotConfigured 未装配改密 service（测试桩）。
	errPasswordNotConfigured = errors.New("password service not configured")
	// errBindNotConfigured 未装配换绑 service（测试桩）。
	errBindNotConfigured = errors.New("bind contact service not configured")
	// errMfaNotConfigured 未装配两步验证 service（测试桩）。
	errMfaNotConfigured = errors.New("mfa service not configured")
	// errMfaInternal 两步验证族未知异常的固定文案（ErrMfaInternal 映射，
	// §1.6 行 273 internal 无 ErrorInfo）。
	errMfaInternal = errors.New("internal error")
	// errMfaInvalidStep BindTotp step 取值非法。
	errMfaInvalidStep = errors.New("invalid step")
	// errEventsNotConfigured 未装配事件日志 service（测试桩）。
	errEventsNotConfigured = errors.New("events service not configured")
)

// Handler AccountService 服务实现。内嵌生成的 unimplemented 基类：本包未
// 实现的方法统一返回 Connect CodeUnimplemented。
type Handler struct {
	accountv1connect.UnimplementedAccountServiceHandler
	users       UserReader
	creds       CredentialReader
	settings    SettingsReader
	providers   ProviderReader
	captcha     CaptchaConfiger
	thirdparty  Thirdparty
	webauthn    Webauthn
	profile     ProfileUpdater
	avatar      AvatarDirector
	password    PasswordChanger
	bindcontact ContactBinder
	mfa         MfaManager
	events      EventReader
	// cookies 会话 Cookie 属性构造器（ChangePassword 成功后清除
	// al_session——service 层 IncEpoch 已令全部旧令牌失效，浏览器侧清
	// Cookie 属 handler 收尾；sso handler 同款注入）。
	cookies *session.Cookie
}

// NewWithServices 全依赖构造：八基础依赖 + 五族 service
//（avatar / password / bindcontact / mfa / events）与会话 Cookie
// 构造器（ChangePassword 清除 al_session 用；
// session.Cookie 属性构造器与拦截器同源，sso handler cookies 同款注入）。
// 各 service 可为 nil（对应方法返回 unimplemented，测试 / 降级装配用）；
// cookies 为 nil 时跳过 Cookie 清除。
func NewWithServices(users UserReader, creds CredentialReader, settings SettingsReader, providers ProviderReader, captcha CaptchaConfiger, thirdparty Thirdparty, webauthn Webauthn, profile ProfileUpdater, avatar AvatarDirector, password PasswordChanger, bindcontact ContactBinder, mfa MfaManager, events EventReader, cookies *session.Cookie) *Handler {
	return &Handler{
		users: users, creds: creds, settings: settings, providers: providers,
		captcha: captcha, thirdparty: thirdparty, webauthn: webauthn, profile: profile,
		avatar: avatar, password: password, bindcontact: bindcontact, mfa: mfa,
		events: events, cookies: cookies,
	}
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

// UpdateProfile（接口文档 §3.2 行 837）：当前用户资料的部分更新——proto3
// optional has 位语义（2026-11-06 定稿）：未设置 = 不修改、显式设值（含
// 0 / 空串）= 覆盖（gender 可改回 0=保密、字符串字段可显式清空）；
// nickname / avatarUrl / profile 子字段分别按 has 处理；用户名 / 手机号 /
// 邮箱不可由此修改（proto 不含该三项，契约结构上即不可改）。仅本人
//（会话 uid，不接受任何入参目标）；全字段未设置 = 合法空操作（零写库
// 直接成功，§3.2 无明确口径时由实现裁量）。会话要求同 GetProfile：session
// 拦截器放行匿名（既定语义），ctx 无 uid 即 unauthenticated（401）；
// 编排在 service/account.ProfileService，本层做会话判定与错误映射。
func (h *Handler) UpdateProfile(ctx context.Context, req *connect.Request[accountv1.UpdateProfileRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.profile == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errProfileNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.profile.UpdateProfile(ctx, uid, req.Msg); err != nil {
		return nil, mapProfileError("update profile", err)
	}
	// 成功为空响应（§3.2 行 837）：零值消息 protojson 输出 {}。
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// mapProfileError 资料更新 service 错误 → Connect 形态（§1.5 行 182-195
// 统一口径）：birthday 格式非法 → invalid_argument + ErrorInfo(account,
// invalid_request)（§1.6 封闭集；文案同 rpc 域先例）；用户不存在 →
// not_found（口径同 GetProfile）；其余原样上抛由错误包装拦截器消毒。
func mapProfileError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrProfileInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_request", "birthday must be YYYY-MM-DD"),
		)
	case errors.Is(err, gorm.ErrRecordNotFound):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
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
// （§5.6 行 1337）→ provider 表 category=storage 生效行 → Ext{mode,maxSize,
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
	kindPassword     = "password"
	kindTotp         = "totp"
	kindWebauthn     = "webauthn"
	kindRecoveryCode = "recovery_code"
	kindMfaSetting   = "mfa_setting"
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
// （§3.2 行 818：供安全中心判断改密入口与第三方解绑是否可用，§3.7 判定
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

// —— 三方绑定族四方法（接口文档 §3.7 / §3.7.1）——
// 请求绑定、Cookie 头解析与信封透传归本层，绑定编排全部在
// service/account.ThirdpartyService（§12.6 BindToCurrentUser 内核两通道共用）。
// GetThirdpartyBindings / UnbindThirdparty / ThirdpartyOauth 的业务失败走
// 可判别哨兵错误 → Connect 错误体 + ErrorInfo（§1.5 行 198-211）；GetThirdpartyTicket
// 的轮询结论走 HTTP 200 信封域（§1.3 / §1.6），透传 service 产物。四接口
// 均需 al_session（§1.2 行 96；session 拦截器放行匿名，ctx 无 uid 即 401）。

// GetThirdpartyBindings 双列表（§3.7 行 953-959）：items 已绑定 + available
// 可绑定，投影在 handler（service 返回领域结构体）。
func (h *Handler) GetThirdpartyBindings(ctx context.Context, req *connect.Request[accountv1.GetThirdpartyBindingsRequest]) (*connect.Response[accountv1.ThirdpartyBindingsResponse], error) {
	if h.thirdparty == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errThirdpartyNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	res, err := h.thirdparty.GetThirdpartyBindings(ctx, uid)
	if err != nil {
		return nil, mapThirdpartyError("get thirdparty bindings", err)
	}
	items := make([]*accountv1.ThirdpartyBinding, len(res.Items))
	for i := range res.Items {
		it := &res.Items[i]
		items[i] = &accountv1.ThirdpartyBinding{
			ProviderKey: it.ProviderKey,
			DisplayName: it.DisplayName,
			Type:        it.Type,
			Channel:     it.Channel,
			Icon:        it.Icon,
			CreatedAt:   it.CreatedAt,
		}
	}
	available := make([]*accountv1.ThirdpartyOption, len(res.Available))
	for i := range res.Available {
		op := &res.Available[i]
		available[i] = &accountv1.ThirdpartyOption{
			ProviderKey: op.ProviderKey,
			DisplayName: op.DisplayName,
			Type:        op.Type,
			Channel:     op.Channel,
			Icon:        op.Icon,
			UiGroup:     op.UiGroup,
			SortOrder:   op.SortOrder,
		}
	}
	return connect.NewResponse(&accountv1.ThirdpartyBindingsResponse{
		Items:     items,
		Available: available,
	}), nil
}

// UnbindThirdparty 解绑（§3.7 行 954）：成功为空响应（OkResponse）。
func (h *Handler) UnbindThirdparty(ctx context.Context, req *connect.Request[accountv1.UnbindThirdpartyRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.thirdparty == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errThirdpartyNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.thirdparty.UnbindThirdparty(ctx, uid, req.Msg.GetProviderKey()); err != nil {
		return nil, mapThirdpartyError("unbind thirdparty", err)
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// ThirdpartyOauth redirect 绑定回调落地（§3.7.1 A 行 969-1003）：请求 Cookie
// 头解出 al_login_state 交 service 载体校验；成功 {providerKey, displayName}。
// 本接口不返回登录信封、不签发 login_token、不 Set-Cookie、不重建会话
// （行 1000——绑定不改变登录态）。
func (h *Handler) ThirdpartyOauth(ctx context.Context, req *connect.Request[accountv1.ThirdpartyOauthRequest]) (*connect.Response[accountv1.ThirdpartyOauthResponse], error) {
	if h.thirdparty == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errThirdpartyNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	out, err := h.thirdparty.ThirdpartyOauth(ctx, accountsvc.OauthInput{
		ProviderKey: req.Msg.GetProviderKey(),
		Code:        req.Msg.GetCode(),
		State:       req.Msg.GetState(),
		StateCookie: loginStateCookie(req),
		UID:         uid,
	})
	if err != nil {
		return nil, mapThirdpartyError("thirdparty oauth", err)
	}
	return connect.NewResponse(&accountv1.ThirdpartyOauthResponse{
		ProviderKey: out.ProviderKey,
		DisplayName: out.DisplayName,
	}), nil
}

// GetThirdpartyTicket 扫码绑定长轮询（§3.7.1 B 行 1012-1026）：响应复用
// 登录流程信封（§1.3 行 152-155），轮询结论（pending / scanned / expired /
// success / 失败类）走 HTTP 200 信封域原样透传。不签发 login_token、不
// Set-Cookie、不重建会话（行 1049）。
func (h *Handler) GetThirdpartyTicket(ctx context.Context, req *connect.Request[accountv1.GetThirdpartyTicketRequest]) (*connect.Response[ssov1.LoginFlowResponse], error) {
	if h.thirdparty == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errThirdpartyNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	resp := h.thirdparty.GetThirdpartyTicket(ctx, accountsvc.TicketInput{
		Ticket: req.Msg.GetTicket(),
		Poll:   req.Msg.GetPoll(),
		UID:    uid,
	})
	return connect.NewResponse(resp), nil
}

// loginStateCookie 从请求 Cookie 头解析 al_login_state（§3.7.1 A redirect
// 绑定通道的载体校验源；与 handler/sso 同款私有助手——跨包复用需导出 sso
// 层，按既有分工各落一份）；未携带返回空串。
func loginStateCookie(req *connect.Request[accountv1.ThirdpartyOauthRequest]) string {
	cookies, err := http.ParseCookie(req.Header().Get("Cookie"))
	if err != nil {
		return ""
	}
	for _, ck := range cookies {
		if ck.Name == service.LoginStateCookieName {
			return ck.Value
		}
	}
	return ""
}

// mapThirdpartyError 三方绑定族 service 错误 → Connect 形态（§1.5 行 182-195
// 统一口径）：参数 / 校验类 → invalid_argument + ErrorInfo domain=account
// （code 取 §1.6 封闭集）；target_taken → already_exists（409，§1.5 行 191
// 「重复绑定」）；资源不存在 → not_found；上游 / 内部故障 → internal 固定文案
// （§1.6 行 273：internal 不挂 ErrorInfo）；其余原样上抛由错误包装拦截器消毒。
func mapThirdpartyError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, accountsvc.ErrInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid request"),
		)
	case errors.Is(err, accountsvc.ErrStateMismatch):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "state_mismatch", "state mismatch"),
		)
	case errors.Is(err, accountsvc.ErrProviderDisabled):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "provider_disabled", "provider not available for binding"),
		)
	case errors.Is(err, accountsvc.ErrTargetTaken):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeAlreadyExists, err),
			internalconnect.NewErrorInfo("account", "target_taken", "该账号已被其他账号绑定"),
		)
	case errors.Is(err, accountsvc.ErrFailed):
		return connect.NewError(connect.CodeInternal, errThirdpartyInternal)
	case errors.Is(err, gorm.ErrRecordNotFound):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}

// —— 通行密钥族（接口文档 §3.6 行 927-947 / 后端架构 §8.3 行
// 1071-1075；Delete 为补充实装）——
//
// 请求绑定与投影归本层，挑战 / 断言校验编排全部在
// service/account.WebauthnService（内核复用 factor/webauthn）。
// 业务失败走可判别哨兵错误 → Connect 错误体 + ErrorInfo（§1.5 行 198-211）。
// 降级窗口 fail-closed：ErrWebauthnDegraded → invalid_argument +
// ErrorInfo{method_disabled, 「通行密钥暂不可用，请联系管理员」}（§1.6
// 行 250、§8.3 行 1071-1075——service 层已逐次 WARN）。五接口均需
// al_session（§1.2 行 96）。

// GetWebauthnCredentials 通行密钥列表（§3.6 行 931）：{items:[{id, label,
// createdAt, lastUsedAt, transports, aaguid}]}。
func (h *Handler) GetWebauthnCredentials(ctx context.Context, req *connect.Request[accountv1.GetWebauthnCredentialsRequest]) (*connect.Response[accountv1.WebauthnListResponse], error) {
	if h.webauthn == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errWebauthnNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	items, err := h.webauthn.ListCredentials(ctx, uid)
	if err != nil {
		return nil, mapWebauthnError("get webauthn credentials", err)
	}
	out := make([]*accountv1.WebauthnCredential, len(items))
	for i := range items {
		it := &items[i]
		out[i] = &accountv1.WebauthnCredential{
			Id:         it.ID,
			Label:      it.Label,
			CreatedAt:  it.CreatedAt,
			LastUsedAt: it.LastUsedAt,
			Transports: it.Transports,
			Aaguid:     it.AAGUID,
		}
	}
	return connect.NewResponse(&accountv1.WebauthnListResponse{Items: out}), nil
}

// RegisterWebauthn 绑定通行密钥两态（§3.6 行 932-933）：step=challenge →
// {token, challengeData, expiresIn}（token 为独立原子 token，前端不感知
// 结构仅透传）；step=verify → {token, credential, label} 注册成功空响应。
// step 非法 → invalid_request。
func (h *Handler) RegisterWebauthn(ctx context.Context, req *connect.Request[accountv1.RegisterWebauthnRequest]) (*connect.Response[accountv1.RegisterWebauthnResponse], error) {
	if h.webauthn == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errWebauthnNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	switch req.Msg.GetStep() {
	case "challenge":
		ch, err := h.webauthn.BeginRegister(ctx, uid)
		if err != nil {
			return nil, mapWebauthnError("register webauthn challenge", err)
		}
		return connect.NewResponse(&accountv1.RegisterWebauthnResponse{
			Token:         ch.Token,
			ChallengeData: ch.ChallengeData,
			ExpiresIn:     ch.ExpiresIn,
		}), nil
	case "verify":
		if err := h.webauthn.FinishRegister(ctx, uid, req.Msg.GetToken(), req.Msg.GetCredential(), req.Msg.GetLabel()); err != nil {
			return nil, mapWebauthnError("register webauthn verify", err)
		}
		// 注册成功为空响应：零值消息 protojson 输出 {}（webauthn.proto
		// RegisterWebauthnResponse 注释，§12.9 行 1752）。
		return connect.NewResponse(&accountv1.RegisterWebauthnResponse{}), nil
	default:
		return nil, internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, errWebauthnInvalidStep),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid step"),
		)
	}
}

// RenameWebauthnCredential 重命名（§3.6 行 934）：{id, label} 仅本人；成功
// 空响应（OkResponse）。
func (h *Handler) RenameWebauthnCredential(ctx context.Context, req *connect.Request[accountv1.RenameWebauthnCredentialRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.webauthn == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errWebauthnNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.webauthn.RenameCredential(ctx, uid, req.Msg.GetId(), req.Msg.GetLabel()); err != nil {
		return nil, mapWebauthnError("rename webauthn credential", err)
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// DeleteWebauthnCredential 删除（§3.6 行 935）：{id} 仅本人；
// 成功空响应（OkResponse）。
func (h *Handler) DeleteWebauthnCredential(ctx context.Context, req *connect.Request[accountv1.DeleteWebauthnCredentialRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.webauthn == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errWebauthnNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.webauthn.DeleteCredential(ctx, uid, req.Msg.GetId()); err != nil {
		return nil, mapWebauthnError("delete webauthn credential", err)
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// mapWebauthnError 通行密钥族 service 错误 → Connect 形态（§1.5 行 181-195
// 统一口径）：降级窗口 → invalid_argument + ErrorInfo{method_disabled,
// 固定文案}（§1.6 行 250）；参数 / 校验类 → invalid_argument + ErrorInfo
// （code 取 §1.6 封闭集）；重复注册 → already_exists（§1.5 行 191「重复
// 绑定」，admin ErrDuplicateKey 先例——裸 Connect code）；资源不存在 →
// not_found；内部故障 → internal 固定文案（§1.6 行 273 internal 无
// ErrorInfo）；其余原样上抛由错误包装拦截器消毒。
func mapWebauthnError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrWebauthnUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, accountsvc.ErrWebauthnDegraded):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "method_disabled", accountsvc.WebauthnDegradedMessage),
		)
	case errors.Is(err, accountsvc.ErrWebauthnInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid request"),
		)
	case errors.Is(err, accountsvc.ErrWebauthnCodeExpired):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "code_expired", "challenge expired, restart with step=challenge"),
		)
	case errors.Is(err, accountsvc.ErrWebauthnDuplicate):
		return connect.NewError(connect.CodeAlreadyExists, errWebauthnDuplicate)
	case errors.Is(err, accountsvc.ErrWebauthnInternal):
		return connect.NewError(connect.CodeInternal, errWebauthnInternal)
	case errors.Is(err, gorm.ErrRecordNotFound):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}

// —— 头像直传两桩（接口文档 §3.2 行 839-840、
// §10.8 /《后端架构》§15.1）——
//
// 请求绑定与错误映射归本层，direct 三步编排（数据源链复判、key 服务端
// 生成、presign 签发、URL 回显）在 service/account.AvatarService。
// avatarUpload 未配置 / 非 direct 模式被直调按未知异常映射 internal
//（行 842，不新增错误码）。两接口均需 al_session（§1.2 行 96）。

// PresignAvatar（§3.2 行 839、§10.8 direct 第一步）：direct 模式签发有时效
// PUT URL，{filename, contentType, size} → {key, uploadUrl, headers,
// expiresIn}；service 直接消费 proto 请求，本层透传。
func (h *Handler) PresignAvatar(ctx context.Context, req *connect.Request[accountv1.PresignAvatarRequest]) (*connect.Response[accountv1.AvatarPresignResponse], error) {
	if h.avatar == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errAvatarNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	res, err := h.avatar.PresignAvatar(ctx, uid, req.Msg)
	if err != nil {
		return nil, mapAvatarError("presign avatar", err)
	}
	return connect.NewResponse(res), nil
}

// CommitAvatar（§3.2 行 840、§10.8 direct 第三步）：仅记录已上传并回显
// 地址，不回读校验（行 868 禁止 Get/HEAD）；{key} → {url}。
func (h *Handler) CommitAvatar(ctx context.Context, req *connect.Request[accountv1.CommitAvatarRequest]) (*connect.Response[accountv1.AvatarResponse], error) {
	if h.avatar == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errAvatarNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	res, err := h.avatar.CommitAvatar(ctx, uid, req.Msg)
	if err != nil {
		return nil, mapAvatarError("commit avatar", err)
	}
	return connect.NewResponse(res), nil
}

// mapAvatarError 头像直传 service 错误 → Connect 形态（§1.5 行 181-195
// 统一口径）：未配置 / 非 direct 模式 → internal 固定文案（行 842 + §1.6
// 行 273 internal 无 ErrorInfo）；MIME / size 校验类 → invalid_argument +
// ErrorInfo{file_type_not_allowed / file_too_large}（§1.6 行 261，文案与
// 前端预校验一致）；文档未覆盖边界的非法入参 → invalid_request；用户不
// 存在 → not_found（profile.go 口径同源）；其余原样上抛由错误包装拦截器
// 消毒。
func mapAvatarError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrAvatarNotConfigured), errors.Is(err, accountsvc.ErrAvatarPresignUnavailable):
		return connect.NewError(connect.CodeInternal, errAvatarInternal)
	case errors.Is(err, accountsvc.ErrAvatarFileTypeNotAllowed):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "file_type_not_allowed", "file type not allowed"),
		)
	case errors.Is(err, accountsvc.ErrAvatarFileTooLarge):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "file_too_large", "file too large"),
		)
	case errors.Is(err, accountsvc.ErrAvatarInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid request"),
		)
	case errors.Is(err, gorm.ErrRecordNotFound):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}

// —— 改密（接口文档 §3.3 行 870-879）——

// ChangePassword（§3.3 行 872）：当前用户改密 / 无密码账号设密，编排全部在
// service/account.PasswordService（策略校验、旧密码校验、credential 更新、
// IncEpoch + al:pwdep 同步、审计）；成功为空响应。改密成功后旧会话与全部
// 已颁发令牌经 epoch 失效链失效（行 879），浏览器侧清除 al_session 收尾
//（Cookie 构造器 Clear，与 session 拦截器同一写出出口 AddSessionCookie；
// 未注入时跳过——测试装配用）。
func (h *Handler) ChangePassword(ctx context.Context, req *connect.Request[accountv1.ChangePasswordRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.password == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errPasswordNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.password.ChangePassword(ctx, uid, req.Msg.GetCurrentPassword(), req.Msg.GetNewPassword()); err != nil {
		return nil, mapPasswordError("change password", err)
	}
	if h.cookies != nil {
		internalconnect.AddSessionCookie(ctx, h.cookies.Clear(session.RequestSignalFromContext(ctx)))
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// mapPasswordError 改密 service 错误 → Connect 形态（§1.5 行 181-195 统一
// 口径）：newPassword 不满足策略 → invalid_argument + ErrorInfo{password_weak}
//（§3.3 行 879）；旧密码校验失败 → invalid_credentials（§1.6 行 247/269
// 默认口径——password_incorrect 系笔误，不另设码）；参数类 →
// invalid_request；用户不存在 → not_found；其余原样上抛由错误包装拦截器
// 消毒。
func mapPasswordError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrPasswordWeak):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "password_weak", "password does not meet policy"),
		)
	case errors.Is(err, accountsvc.ErrPasswordInvalidCredentials):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_credentials", "invalid credentials"),
		)
	case errors.Is(err, accountsvc.ErrPasswordInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid request"),
		)
	case errors.Is(err, gorm.ErrRecordNotFound):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}

// —— 手机 / 邮箱换绑族（接口文档 §3.4 行 881-898）——
//
// 请求绑定（step / payload 拆解、CaptchaPayload → captcha.Submission）与
// 错误映射归本层，两步编排（captcha 必检、占用判定、发码、GETDEL 核销、
// 列级落库、审计）在 service/account.BindContactService。两接口均需
// al_session（§1.2 行 96）。IP 维度：Connect 链仅暴露请求头、生产侧
// IPResolver 尚未落地（bootstrap.go TODO §8.1，OTP 因子同走 "unknown"
// 兜底），本层传空串由 service bindSourceIP 兜底，不自造 Header 解析。

// BindPhone（§3.4 行 887）：手机号绑定 / 换绑两步同端点，由 step 区分
//（challenge {phone, captcha} / verify {phone, code}）；成功为空响应。
func (h *Handler) BindPhone(ctx context.Context, req *connect.Request[accountv1.BindPhoneRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.bindcontact == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errBindNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	in := accountsvc.BindPhoneInput{Step: req.Msg.GetStep()}
	if p := req.Msg.GetPayload(); p != nil {
		in.Target = p.GetPhone()
		in.Code = p.GetCode()
		in.Captcha = captchaSubmission(p.GetCaptcha())
	}
	if err := h.bindcontact.BindPhone(ctx, uid, in); err != nil {
		return nil, mapBindError("bind phone", err)
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// BindEmail（§3.4 行 889）：邮箱绑定 / 换绑两步同端点，由 step 区分；成功
// 为空响应。
func (h *Handler) BindEmail(ctx context.Context, req *connect.Request[accountv1.BindEmailRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.bindcontact == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errBindNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	in := accountsvc.BindEmailInput{Step: req.Msg.GetStep()}
	if p := req.Msg.GetPayload(); p != nil {
		in.Target = p.GetEmail()
		in.Code = p.GetCode()
		in.Captcha = captchaSubmission(p.GetCaptcha())
	}
	if err := h.bindcontact.BindEmail(ctx, uid, in); err != nil {
		return nil, mapBindError("bind email", err)
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// captchaSubmission CaptchaPayload → captcha.Submission（§2.5 行 478-486
// 统一提交格式）：与 dto/sso.go captchaSubmission 同名字段直映（跨包私有
// 按既有分工各落一份——本包不为此扩大 dto 导出面）；nil payload 返回 nil
// 交由 service 按 challenge 步判定缺失。
func captchaSubmission(c *ssov1.CaptchaPayload) *captcha.Submission {
	if c == nil {
		return nil
	}
	return &captcha.Submission{
		ProviderKey: c.GetProviderKey(),
		Token:       c.GetToken(),
		ID:          c.GetId(),
		Answer:      c.GetAnswer(),
	}
}

// mapBindError 换绑 service 错误 → Connect 形态（§1.5 行 181-195 统一口径，
// 十哨兵与 §1.6 行 229-273 封闭集一一对应）：参数 / 校验类 →
// invalid_argument + ErrorInfo；target_taken → already_exists（409，§1.5
// 行 191 占用）；user_not_found → not_found（404，行 190 资源不存在）；
// 限流 / 冷却 / 日限额 → resource_exhausted（429，行 192）；invalid_code
// 经 errors.As 取 BindInvalidCodeError.AttemptsLeft 挂 ErrorInfo.attemptsLeft
//（§1.5 行 222「剩余尝试次数」）；其余原样上抛由错误包装拦截器消毒。
func mapBindError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrBindInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid request"),
		)
	case errors.Is(err, accountsvc.ErrBindCaptchaRequired):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "captcha_required", "captcha required"),
		)
	case errors.Is(err, accountsvc.ErrBindCaptchaInvalid):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "captcha_invalid", "captcha invalid"),
		)
	case errors.Is(err, accountsvc.ErrBindTargetTaken):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeAlreadyExists, err),
			internalconnect.NewErrorInfo("account", "target_taken", "该账号已被其他账号绑定"),
		)
	case errors.Is(err, accountsvc.ErrBindUserNotFound):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeNotFound, err),
			internalconnect.NewErrorInfo("account", "user_not_found", "user not found"),
		)
	case errors.Is(err, accountsvc.ErrBindTooManyRequests):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeResourceExhausted, err),
			internalconnect.NewErrorInfo("account", "too_many_requests", "too many requests"),
		)
	case errors.Is(err, accountsvc.ErrBindProviderDisabled):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "provider_disabled", "provider not available"),
		)
	case errors.Is(err, accountsvc.ErrBindTooManyAttempts):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "too_many_attempts", "too many attempts"),
		)
	case errors.Is(err, accountsvc.ErrBindCodeExpired):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "code_expired", "code expired"),
		)
	case errors.Is(err, accountsvc.ErrBindInvalidCode):
		info := internalconnect.NewErrorInfo("account", "invalid_code", "invalid code")
		var ic *accountsvc.BindInvalidCodeError
		if errors.As(err, &ic) {
			info.AttemptsLeft = ic.AttemptsLeft
		}
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			info,
		)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}

// —— 两步验证族五方法（接口文档 §3.5 行 900-925）——
//
// 请求绑定（step 分派、MfaDetail → proto 投影）与错误映射归本层，明细
// 聚合 / mfa_setting 写入 / TOTP 绑定 / 恢复码生成在
// service/account.MfaService。五接口均需 al_session（§1.2 行 96）。

// GetMfa（§3.5 行 920）：五因子绑定明细 + recoveryIssuedAt（摘要走 §3.2
// mfaPolicy，本接口只出明细不重复）。
func (h *Handler) GetMfa(ctx context.Context, req *connect.Request[accountv1.GetMfaRequest]) (*connect.Response[accountv1.MfaResponse], error) {
	if h.mfa == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errMfaNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	d, err := h.mfa.GetMfa(ctx, uid)
	if err != nil {
		return nil, mapMfaError("get mfa", err)
	}
	factors := make([]*accountv1.MfaFactor, len(d.Factors))
	for i := range d.Factors {
		f := &d.Factors[i]
		factors[i] = &accountv1.MfaFactor{
			Factor:      f.Factor,
			Bound:       f.Bound,
			BoundAt:     f.BoundAt,
			LastUsedAt:  f.LastUsedAt,
			Target:      f.Target,
			Credentials: f.Credentials,
			Remaining:   f.Remaining,
		}
	}
	return connect.NewResponse(&accountv1.MfaResponse{
		Factors:          factors,
		RecoveryIssuedAt: d.RecoveryIssuedAt,
	}), nil
}

// SetMfa（§3.5 行 921）：勾选启用因子集合；空数组 = 关闭（受 §3.2
// mfaPolicy.required 约束）；成功为空响应。
func (h *Handler) SetMfa(ctx context.Context, req *connect.Request[accountv1.SetMfaRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.mfa == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errMfaNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.mfa.SetMfa(ctx, uid, req.Msg.GetMethods()); err != nil {
		return nil, mapMfaError("set mfa", err)
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// BindTotp 绑定两步（§3.5 行 922-923，step 分派同 RegisterWebauthn 惯例）：
// challenge → {secret, otpauthUrl, qrcodeContent} 前端绘制二维码；verify
//（{secret, code}）→ {recoveryCodes} 验证一次后生效并同一响应下发 10 个
// 恢复码；step 非法 → invalid_request。
func (h *Handler) BindTotp(ctx context.Context, req *connect.Request[accountv1.BindTotpRequest]) (*connect.Response[accountv1.BindTotpResponse], error) {
	if h.mfa == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errMfaNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	switch req.Msg.GetStep() {
	case "challenge":
		ch, err := h.mfa.BindTotpChallenge(ctx, uid)
		if err != nil {
			return nil, mapMfaError("bind totp challenge", err)
		}
		return connect.NewResponse(&accountv1.BindTotpResponse{
			Secret:         ch.Secret,
			OtpauthUrl:     ch.OtpauthUrl,
			QrcodeContent:  ch.QrcodeContent,
		}), nil
	case "verify":
		codes, err := h.mfa.BindTotpVerify(ctx, uid, req.Msg.GetSecret(), req.Msg.GetCode())
		if err != nil {
			return nil, mapMfaError("bind totp verify", err)
		}
		return connect.NewResponse(&accountv1.BindTotpResponse{RecoveryCodes: codes}), nil
	default:
		return nil, internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, errMfaInvalidStep),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid step"),
		)
	}
}

// GetRecoveryCodes（§3.5 行 924）：存量恢复码一次性展示 {codes, createdAt}；
// 无签发 → code_expired（§8.4 行 1083）。
func (h *Handler) GetRecoveryCodes(ctx context.Context, req *connect.Request[accountv1.GetRecoveryCodesRequest]) (*connect.Response[accountv1.RecoveryCodesResponse], error) {
	if h.mfa == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errMfaNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	res, err := h.mfa.GetRecoveryCodes(ctx, uid)
	if err != nil {
		return nil, mapMfaError("get recovery codes", err)
	}
	return connect.NewResponse(&accountv1.RecoveryCodesResponse{
		Codes:     res.Codes,
		CreatedAt: res.CreatedAt,
	}), nil
}

// RegenerateRecoveryCodes（§3.5 行 925）：重新生成即全量作废，{action:
// "regenerate"}；出参同 GetRecoveryCodes 格式一次性下发新码。
func (h *Handler) RegenerateRecoveryCodes(ctx context.Context, req *connect.Request[accountv1.RegenerateRecoveryCodesRequest]) (*connect.Response[accountv1.RecoveryCodesResponse], error) {
	if h.mfa == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errMfaNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	res, err := h.mfa.RegenerateRecoveryCodes(ctx, uid, req.Msg.GetAction())
	if err != nil {
		return nil, mapMfaError("regenerate recovery codes", err)
	}
	return connect.NewResponse(&accountv1.RecoveryCodesResponse{
		Codes:     res.Codes,
		CreatedAt: res.CreatedAt,
	}), nil
}

// mapMfaError 两步验证族 service 错误 → Connect 形态（§1.5 行 181-195 统一
// 口径）：无有效会话 → unauthenticated；参数 / step / 码格式 / action 类 →
// invalid_argument + ErrorInfo{invalid_request}；码不匹配 → invalid_code；
// 无签发 / 消费尽 / 未启用 → code_expired（§8.4 行 1083 封闭集）；基础设施
// 故障 → internal 固定文案（§1.6 行 273 internal 无 ErrorInfo）；用户不
// 存在 → not_found；其余原样上抛由错误包装拦截器消毒。
func mapMfaError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrMfaUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, accountsvc.ErrMfaInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid request"),
		)
	case errors.Is(err, accountsvc.ErrMfaInvalidCode):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_code", "invalid code"),
		)
	case errors.Is(err, accountsvc.ErrMfaCodeExpired):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "code_expired", "recovery codes not available"),
		)
	case errors.Is(err, accountsvc.ErrMfaInternal):
		return connect.NewError(connect.CodeInternal, errMfaInternal)
	case errors.Is(err, gorm.ErrRecordNotFound):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}

// —— 本人事件日志（接口文档 §3.7 行 1055-1058）——

// eventsListPageSizeMax §1.7 行 277 分页上限（与 admin 域
// providerListPageSize 同值，跨包私有各落一份）。
const eventsListPageSizeMax = 100

// GetEvents（§3.7 行 1057）：本人登录记录（仅成功记录——数据源口径，无
// login_failed 常量与成功标志列，service 头注）；分页沿 §1.7（归一后回显
// page / pageSize）；行 → proto UserEventItem 投影（detail msgpack → JSON
// 对象、created_at → Unix 秒）在 dto.AccountUserEventItem（AdminEventItem
// 同款口径）。sort / order 字段保留但不应用（service 头注：沿
// admin GetUserEvents 先例固定 id DESC，值域核对留待真后端联调）。
func (h *Handler) GetEvents(ctx context.Context, req *connect.Request[accountv1.GetEventsRequest]) (*connect.Response[accountv1.GetEventsResponse], error) {
	if h.events == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errEventsNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	page, size := normalizeListPage(int(req.Msg.GetPage()), int(req.Msg.GetPageSize()))
	rows, total, err := h.events.GetEvents(ctx, uid, req.Msg.GetEvent(), page, size)
	if err != nil {
		return nil, mapEventsError("get events", err)
	}
	items := make([]*accountv1.UserEventItem, len(rows))
	for i := range rows {
		items[i] = dto.AccountUserEventItem(&rows[i])
	}
	return connect.NewResponse(&accountv1.GetEventsResponse{
		Items:    items,
		Total:    total,
		Page:     int64(page),
		PageSize: int64(size),
	}), nil
}

// normalizeListPage §1.7 行 277 分页归一（page 从 1 开始、pageSize 默认 20、
// 上限 100）——响应回显归一后的生效值；admin 域同名函数为包内私有，跨包
// 各落一份（口径相同）。
func normalizeListPage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > eventsListPageSizeMax {
		size = eventsListPageSizeMax
	}
	return page, size
}

// mapEventsError 事件日志 service 错误 → Connect 形态（§1.5 行 181-195 统一
// 口径）：uid 契约违约（拼装层必须注入会话 uid）→ invalid_argument +
// ErrorInfo{invalid_request}；repo 错误原样上抛由错误包装拦截器消毒
//（admin GetUserEvents 同款）。
func mapEventsError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrEventsInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid request"),
		)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}
