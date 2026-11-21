// Package account 实现 AccountService 的 Connect handler。
// 全部方法需 al_session；未装配 service 的方法由 Unimplemented 基类返回 unimplemented。
package account

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"connectrpc.com/connect"
	"database/sql"
	"google.golang.org/protobuf/types/known/structpb"

	accountv1 "authloft/gen/go/api/account/v1"
	"authloft/gen/go/api/account/v1/accountv1connect"
	commonv1 "authloft/gen/go/api/common/v1"
	ssov1 "authloft/gen/go/api/sso/v1"
	"authloft/internal/captcha"
	internalconnect "authloft/internal/connect"
	"authloft/internal/dto"
	"authloft/internal/factor/ipres"
	"authloft/internal/factor/webauthn"
	"authloft/internal/repo"
	"authloft/internal/repo/model"
	accountsvc "authloft/internal/service/account"
	"authloft/internal/service/mfapolicy"
	thirdpartysvc "authloft/internal/service/thirdparty"
	"authloft/internal/service/verification"
	"authloft/internal/session"
	"authloft/internal/settings"
)

// UserReader 用户读取窄接口（生产注入 *repo.UserRepo，测试可传 fake）。
type UserReader interface {
	FindByID(ctx context.Context, id int64) (*model.User, error)
	GetProfile(ctx context.Context, userID int64) (*model.UserProfile, error)
}

// CredentialReader 凭证读取窄接口（hasPassword / mfaPolicy / mfa 绑定态共用）。
type CredentialReader interface {
	FindByUserAndKind(ctx context.Context, userID int64, kind string) (*model.UserCredential, error)
}

// SettingsReader settings 读取窄接口。
type SettingsReader interface {
	GetBool(key string) (bool, bool)
	GetString(key string) (string, bool)
	GetStringSlice(key string) ([]string, bool)
}

// ProviderReader provider 行读取窄接口（avatarUpload 查 storage 行）。
type ProviderReader interface {
	FindByKey(ctx context.Context, providerKey string) (*model.Provider, error)
}

// CaptchaConfiger captcha 当前生效配置出口：注入快照 / GetConfig / 触发响应三处共用，
// 每次现算不缓存；nil Gate 的 Config 走 builtin 降级。
type CaptchaConfiger interface {
	Config(ctx context.Context) captcha.Config
}

// ChannelProber 消息渠道可用性判定窄接口（*provider.CodeBridge 天然满足）：
// GetConfig 两渠道标志的判定出口（§3.2），判定实现归 provider 包公共函数，
// 与发送期 provider_disabled 同源。
type ChannelProber interface {
	Available(ctx context.Context) (bool, error)
}

// Thirdparty 三方绑定族 service 窄接口；nil（未装配）时四个方法返回 unimplemented。
type Thirdparty interface {
	GetThirdpartyBindings(ctx context.Context, uid int64) (*accountsvc.BindingsResult, error)
	UnbindThirdparty(ctx context.Context, uid int64, providerKey, ip string) error
	ThirdpartyOauth(ctx context.Context, in accountsvc.OauthInput) (*accountsvc.BindOutcome, error)
	GetThirdpartyTicket(ctx context.Context, in accountsvc.TicketInput) *ssov1.LoginFlowResponse
}

// Webauthn 通行密钥族 service 窄接口；Delete 为补充实装，nil 时对应方法返回 unimplemented。
type Webauthn interface {
	ListCredentials(ctx context.Context, uid int64) ([]accountsvc.WebauthnItem, error)
	BeginRegister(ctx context.Context, uid int64) (*webauthn.RegistrationChallenge, error)
	FinishRegister(ctx context.Context, uid int64, tok string, credential *structpb.Struct, label string) error
	RenameCredential(ctx context.Context, uid int64, id int64, label string) error
	DeleteCredential(ctx context.Context, uid int64, id int64) error
}

// ProfileUpdater 资料更新 service 窄接口；nil 时 UpdateProfile 返回 unimplemented。
type ProfileUpdater interface {
	UpdateProfile(ctx context.Context, uid int64, in *accountv1.UpdateProfileRequest) error
}

// AvatarDirector 头像上传三桩窄接口（direct 两桩 + proxy bytes 直传）；service
// 直接消费 / 产出 proto 消息，本层不做二次转换。
type AvatarDirector interface {
	PresignAvatar(ctx context.Context, uid int64, in *accountv1.PresignAvatarRequest) (*accountv1.AvatarPresignResponse, error)
	CommitAvatar(ctx context.Context, uid int64, in *accountv1.CommitAvatarRequest) (*accountv1.AvatarResponse, error)
	UploadAvatar(ctx context.Context, uid int64, in *accountv1.UploadAvatarRequest) (*accountv1.AvatarResponse, error)
}

// PasswordChanger 改密 service 窄接口；nil 时 ChangePassword 返回 unimplemented。
type PasswordChanger interface {
	ChangePassword(ctx context.Context, uid int64, currentPassword, newPassword string) error
}

// ContactBinder 换绑 service 窄接口；nil 时对应方法返回 unimplemented。
type ContactBinder interface {
	BindPhone(ctx context.Context, uid int64, in accountsvc.BindPhoneInput) error
	BindEmail(ctx context.Context, uid int64, in accountsvc.BindEmailInput) error
}

// MfaManager 两步验证族 service 窄接口；nil 时对应方法返回 unimplemented。
type MfaManager interface {
	GetMfa(ctx context.Context, uid int64) (*accountsvc.MfaDetail, error)
	SetMfa(ctx context.Context, uid int64, enabled bool) error
	BindTotpChallenge(ctx context.Context, uid int64) (*accountsvc.TotpChallenge, error)
	BindTotpVerify(ctx context.Context, uid int64, secret, code string) ([]string, error)
	RegenerateRecoveryCodes(ctx context.Context, uid int64, action string) (*accountsvc.RecoveryCodesResult, error)
}

// MfaUnbinder 解绑能力窄接口；与 MfaManager 分离，避免既有两步验证族 fake 被迫扩接口。
type MfaUnbinder interface {
	UnbindTotp(ctx context.Context, uid int64, token string) error
}

// Verification step-up 服务窄接口；nil 时两个方法返回 unimplemented。
type Verification interface {
	Start(ctx context.Context, in verification.StartInput) (*verification.StartResult, *captcha.Failure, error)
	Submit(ctx context.Context, in verification.SubmitInput) (*verification.SubmitResult, error)
}

// EventReader 本人事件日志 service 窄接口；nil 时 GetEvents 返回 unimplemented。
type EventReader interface {
	GetEvents(ctx context.Context, uid int64, event string, page, pageSize int) ([]model.EventLog, int64, error)
}

// 线上错误文案：connect.Error 文本直达客户端，一律不携带内部信息。
// 内部故障一律经 internalconnect.InternalError 消毒：响应固定
// "internal error"，根因留在 Unwrap 链供统一错误日志回溯。
var (
	errAuthRequired = errors.New("authentication required")
	errNotFound     = errors.New("not found")
	// errThirdpartyNotConfigured 未装配三方绑定 service（测试桩）。
	errThirdpartyNotConfigured = errors.New("thirdparty service not configured")
	// errWebauthnNotConfigured 未装配通行密钥 service（测试桩）。
	errWebauthnNotConfigured = errors.New("webauthn service not configured")
	// errWebauthnDuplicate 重复注册的固定文案（重复绑定）。
	errWebauthnDuplicate = errors.New("credential already exists")
	// errWebauthnInvalidStep step 取值非法。
	errWebauthnInvalidStep = errors.New("invalid step")
	// errProfileNotConfigured 未装配资料更新 service（测试桩）。
	errProfileNotConfigured = errors.New("profile service not configured")
	// errAvatarNotConfigured 未装配头像直传 service（测试桩）。
	errAvatarNotConfigured = errors.New("avatar service not configured")
	// errPasswordNotConfigured 未装配改密 service（测试桩）。
	errPasswordNotConfigured = errors.New("password service not configured")
	// errBindNotConfigured 未装配换绑 service（测试桩）。
	errBindNotConfigured = errors.New("bind contact service not configured")
	// errMfaNotConfigured 未装配两步验证 service（测试桩）。
	errMfaNotConfigured = errors.New("mfa service not configured")
	// errMfaInvalidStep BindTotp step 取值非法。
	errMfaInvalidStep = errors.New("invalid step")
	// errVerificationNotConfigured 未装配 step-up 服务（测试桩）。
	errVerificationNotConfigured = errors.New("verification service not configured")
	// errEventsNotConfigured 未装配事件日志 service（测试桩）。
	errEventsNotConfigured = errors.New("events service not configured")
)

// Handler AccountService 服务实现；内嵌 Unimplemented 基类，未实现方法返回 CodeUnimplemented。
type Handler struct {
	accountv1connect.UnimplementedAccountServiceHandler
	users     UserReader
	creds     CredentialReader
	settings  SettingsReader
	providers ProviderReader
	// smsChannel / emailChannel 消息渠道可用性探针（GetConfig 两渠道标志，
	// §3.2）；nil 时对应标志按 false 下发（前端隐藏绑定 / 换绑入口）。
	smsChannel   ChannelProber
	emailChannel ChannelProber
	captcha      CaptchaConfiger
	thirdparty   Thirdparty
	webauthn     Webauthn
	profile      ProfileUpdater
	avatar       AvatarDirector
	password     PasswordChanger
	bindcontact  ContactBinder
	mfa          MfaManager
	events       EventReader
	// cookies 会话 Cookie 属性构造器（ChangePassword 成功后清除
	// al_session——service 层 IncEpoch 已令全部旧令牌失效，浏览器侧清
	// Cookie 属 handler 收尾；sso handler 同款注入）。
	cookies *session.Cookie
	// verification step-up 服务；nil（测试 / 未装配）时两个
	// 二次验证方法返回 unimplemented。
	verification Verification
	// listPermissions 当前用户权限点列表查询（GetMyPermissions 用）；窄函数
	// 注入，避免本层依赖具体仓储类型。
	listPermissions func(context.Context, int64) ([]string, error)
}

// NewWithServices 全依赖构造；末尾可变参数 v 注入 step-up 服务，省略时该族方法返回
// unimplemented。各 service 可为 nil（对应方法返回 unimplemented，测试 / 降级装配用）；
// cookies 为 nil 时跳过 Cookie 清除。session.Cookie 属性构造器与拦截器同源。
// smsChannel / emailChannel 注入 otp 发送桥可用性探针（GetConfig 渠道标志）。
func NewWithServices(users UserReader, creds CredentialReader, settings SettingsReader, providers ProviderReader, smsChannel, emailChannel ChannelProber, captcha CaptchaConfiger, thirdparty Thirdparty, webauthn Webauthn, profile ProfileUpdater, avatar AvatarDirector, password PasswordChanger, bindcontact ContactBinder, mfa MfaManager, events EventReader, cookies *session.Cookie, listPermissions func(context.Context, int64) ([]string, error), v ...Verification) *Handler {
	h := &Handler{
		users: users, creds: creds, settings: settings, providers: providers,
		smsChannel: smsChannel, emailChannel: emailChannel,
		captcha: captcha, thirdparty: thirdparty, webauthn: webauthn, profile: profile,
		avatar: avatar, password: password, bindcontact: bindcontact, mfa: mfa,
		events: events, cookies: cookies, listPermissions: listPermissions,
	}
	if len(v) > 0 {
		h.verification = v[0]
	}
	return h
}

// GetProfile 从会话取 uid 读 user + profile，经 dto.AccountProfile 掩码输出。
// session 拦截器放行匿名（既定语义），ctx 无 uid 即 unauthenticated（401）；
// profile 行缺失输出零值消息不视为错误，用户不存在返回 not_found。
func (h *Handler) GetProfile(ctx context.Context, req *connect.Request[accountv1.GetProfileRequest]) (*connect.Response[accountv1.ProfileResponse], error) {
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	user, err := h.users.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, connect.NewError(connect.CodeNotFound, errNotFound)
		}
		return nil, fmt.Errorf("account handler: load user: %w", err)
	}
	profile, err := h.users.GetProfile(ctx, uid)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("account handler: load profile: %w", err)
	}
	return connect.NewResponse(dto.AccountProfile(user, profile)), nil
}

// GetMyPermissions 当前登录用户的全部权限点；主体固定取会话 uid，不接受
// 入参 uid 以免越权查他人权限（§3.9）。无权限点返回空列表（protojson
// 省略空 repeated，调用方按「零值或缺失即空列表」处理）。
func (h *Handler) GetMyPermissions(ctx context.Context, _ *connect.Request[accountv1.GetMyPermissionsRequest]) (*connect.Response[accountv1.GetMyPermissionsResponse], error) {
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	perms, err := h.listPermissions(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("account handler: list permissions: %w", err)
	}
	return connect.NewResponse(&accountv1.GetMyPermissionsResponse{Permissions: perms}), nil
}

// UpdateProfile 当前用户资料部分更新：proto3 optional has 位，未设置 = 不修改、
// 显式设值（含 0 / 空串）= 覆盖；用户名 / 手机号 / 邮箱不可由此修改（proto 不含该三项）。
// 仅本人（会话 uid，不接受入参目标）；全字段未设置 = 合法空操作（零写库直接成功）。
// session 拦截器放行匿名，ctx 无 uid 即 unauthenticated（401）；编排在 ProfileService。
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
	// 成功为空响应：零值消息 protojson 输出 {}。
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// mapProfileError 资料更新错误 → Connect 形态：资料字段非法（birthday
// 格式、nickname / avatarUrl 列宽，§3.2）→ invalid_argument +
// ErrorInfo(account, invalid_request)；用户不存在 → not_found；
// 其余原样上抛由错误包装拦截器消毒。
func mapProfileError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrProfileInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid profile field"),
		)
	case errors.Is(err, sql.ErrNoRows):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}

// GetConfig account entry 配置读取，全量下发（avatarUpload / mfaPolicy /
// captcha / hasPassword / 两渠道可用性标志）。鉴权同 GetProfile：session
// 拦截器放行匿名，ctx 无 uid 即 unauthenticated。
func (h *Handler) GetConfig(ctx context.Context, req *connect.Request[accountv1.GetConfigRequest]) (*connect.Response[accountv1.AccountConfigResponse], error) {
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	user, err := h.users.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
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
	smsAvail, err := channelAvailable(ctx, h.smsChannel)
	if err != nil {
		return nil, err
	}
	emailAvail, err := channelAvailable(ctx, h.emailChannel)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accountv1.AccountConfigResponse{
		AvatarUpload:          avatar,
		MfaPolicy:             mfa,
		Captcha:               h.captchaConfig(ctx),
		HasPassword:           hasPassword,
		SmsChannelAvailable:   smsAvail,
		EmailChannelAvailable: emailAvail,
	}), nil
}

// channelAvailable GetConfig 渠道标志（§3.2）：探针未注入按 false 下发
// （入口隐藏）；判定故障上抛按 internal 映射，不静默降级为可用。
func channelAvailable(ctx context.Context, p ChannelProber) (bool, error) {
	if p == nil {
		return false, nil
	}
	return p.Available(ctx)
}

// avatarUpload 组装 avatarUpload 投影：settings 键 → storage 生效行 → Ext 投影。
// 未配置 / 查无该行 / category 不符 → 零值投影（storage 恒可用，不消费
// is_enabled）；local direct 回退 proxy。基础设施错误（含 ext 解析失败）
// 上抛，按未知异常映射 internal。
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
		if errors.Is(err, sql.ErrNoRows) {
			return dto.AccountAvatarUpload("", nil), nil
		}
		return nil, fmt.Errorf("account handler: load avatar storage provider: %w", err)
	}
	if row.Category != providerCategoryStorage {
		return dto.AccountAvatarUpload("", nil), nil
	}
	ext, err := repo.ParseProviderExt(row.Ext)
	if err != nil {
		return nil, fmt.Errorf("account handler: parse avatar storage provider ext: %w", err)
	}
	return dto.AccountAvatarUpload(row.Type, ext), nil
}

// providerCategoryStorage avatarUpload 只认 storage 行。
const providerCategoryStorage = "storage"

// credential kind 取值（password / totp / webauthn / recovery_code）。
const (
	kindPassword     = "password"
	kindTotp         = "totp"
	kindWebauthn     = "webauthn"
	kindRecoveryCode = "recovery_code"
)

// mfaPolicy 组装 mfaPolicy 摘要（§3.2）：enabled 取 user.mfa_required 原值；
// methods 仅列管理员白名单（settings.mfa_methods）内因子并附绑定态，
// 系统未开放或白名单为空时为 []；trustedDeviceDays 恒 0（预留字段）。
func (h *Handler) mfaPolicy(ctx context.Context, uid int64, user *model.User) (*accountv1.MfaPolicy, error) {
	var allowed []string
	if mfapolicy.SystemEnabled(h.settings) {
		allowed = mfapolicy.AllowedMethods(h.settings)
	}
	bound, err := h.mfaBound(ctx, uid, user)
	if err != nil {
		return nil, err
	}
	return dto.AccountMfaPolicy(user.MfaRequired == 1, allowed, bound), nil
}

// mfaBound 各因子绑定态：totp / webauthn / recovery_code 走凭证行（recovery_code 需
// meta 余量非空；删空写回空数组等价该 kind 不可用）；otp_sms / otp_email
// 走 user.phone / email 非空（OTP 因子无凭证行，目标即绑定）。
func (h *Handler) mfaBound(ctx context.Context, uid int64, user *model.User) (dto.MfaBound, error) {
	var bound dto.MfaBound

	totp, err := h.creds.FindByUserAndKind(ctx, uid, kindTotp)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return bound, fmt.Errorf("account handler: load totp credential: %w", err)
	}
	bound.Totp = err == nil && totp.IsEnabled == 1

	webauthn, err := h.creds.FindByUserAndKind(ctx, uid, kindWebauthn)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return bound, fmt.Errorf("account handler: load webauthn credential: %w", err)
	}
	bound.Webauthn = err == nil && webauthn.IsEnabled == 1

	recovery, err := h.creds.FindByUserAndKind(ctx, uid, kindRecoveryCode)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
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

// hasPassword 当前用户是否持有启用的 password 凭证（供安全中心判断改密入口与三方
// 解绑是否可用）。行不存在 / 已停用均返回 false，不视为错误。
func (h *Handler) hasPassword(ctx context.Context, uid int64) (bool, error) {
	row, err := h.creds.FindByUserAndKind(ctx, uid, kindPassword)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("account handler: load password credential: %w", err)
	}
	return row.IsEnabled == 1, nil
}

// captchaConfig captcha 公开视图（不含凭证）：Gate 现算保降级一致（三处共用出口）；
// 未注入时按 nil 分支降级内置图形码。
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

// —— 三方绑定族四方法 ——
// 请求绑定与信封透传归本层，绑定编排在 service/account.ThirdpartyService。
// 业务失败走哨兵错误 → Connect 错误体 + ErrorInfo；轮询结论走 HTTP 200 信封域。
// 四接口均需 al_session（拦截器放行匿名，ctx 无 uid 即 401）。

// GetThirdpartyBindings 双列表：items 已绑定 + available 可绑定，投影在 handler。
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

// UnbindThirdparty 解绑：成功为空响应（OkResponse）。
func (h *Handler) UnbindThirdparty(ctx context.Context, req *connect.Request[accountv1.UnbindThirdpartyRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.thirdparty == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errThirdpartyNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	// 来源 IP 由 http 挂载层注入 ctx（ipres，与 bindcontact / event_log 审计同款口径），
	// 本层只取现成值传 service（审计落值），不在 handler 解析 Header。
	if err := h.thirdparty.UnbindThirdparty(ctx, uid, req.Msg.GetProviderKey(), ipres.ClientIP(ctx)); err != nil {
		return nil, mapThirdpartyError("unbind thirdparty", err)
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// ThirdpartyOauth redirect 绑定回调落地：从 Cookie 头解 al_login_state 交 service 校验；
// 成功返回 {providerKey, displayName}。不返回登录信封、不签发 login_token、
// 不 Set-Cookie、不重建会话（绑定不改变登录态）。
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
		IP:          ipres.ClientIP(ctx),
	})
	if err != nil {
		return nil, mapThirdpartyError("thirdparty oauth", err)
	}
	return connect.NewResponse(&accountv1.ThirdpartyOauthResponse{
		ProviderKey: out.ProviderKey,
		DisplayName: out.DisplayName,
	}), nil
}

// GetThirdpartyTicket 扫码绑定长轮询：响应复用登录流程信封，轮询结论（pending /
// scanned / expired / success / 失败类）走 HTTP 200 信封域原样透传。
// 不签发 login_token、不 Set-Cookie、不重建会话。
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
		IP:     ipres.ClientIP(ctx),
	})
	return connect.NewResponse(resp), nil
}

// loginStateCookie 从请求 Cookie 头解析 al_login_state；与 handler/sso 同款私有助手
// （跨包复用需导出 sso 层，按既有分工各落一份），未携带返回空串。
func loginStateCookie(req *connect.Request[accountv1.ThirdpartyOauthRequest]) string {
	cookies, err := http.ParseCookie(req.Header().Get("Cookie"))
	if err != nil {
		return ""
	}
	for _, ck := range cookies {
		if ck.Name == thirdpartysvc.LoginStateCookieName {
			return ck.Value
		}
	}
	return ""
}

// mapThirdpartyError 三方绑定族错误 → Connect 形态：参数 / 校验类 → invalid_argument +
// ErrorInfo(account)；target_taken → already_exists(409)；资源不存在 → not_found；
// 上游 / 内部故障 → internal 固定文案（不挂 ErrorInfo）；其余上抛消毒。
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
		return connect.NewError(connect.CodeInternal, internalconnect.InternalError(err))
	case errors.Is(err, sql.ErrNoRows):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}

// —— 通行密钥族 ——
// 请求绑定与投影归本层，挑战 / 断言校验编排在 service/account.WebauthnService。
// 业务失败走哨兵错误 → Connect 错误体 + ErrorInfo。降级窗口 fail-closed：
// ErrWebauthnDegraded → invalid_argument + ErrorInfo{method_disabled, 固定文案}。
// 五接口均需 al_session。

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

// RegisterWebauthn 绑定通行密钥两态：step=challenge → {token, challengeData, expiresIn}
// （token 为独立原子 token，前端不感知结构仅透传）；step=verify → {token, credential,
// label} 注册成功空响应；step 非法 → invalid_request。
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
		// 注册成功为空响应：零值消息 protojson 输出 {}；
		// 该响应消息无字段，protojson 输出 {}。
		return connect.NewResponse(&accountv1.RegisterWebauthnResponse{}), nil
	default:
		return nil, internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, errWebauthnInvalidStep),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid step"),
		)
	}
}

// RenameWebauthnCredential 重命名：{id, label} 仅本人，成功空响应。
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

// DeleteWebauthnCredential 删除：{id} 仅本人，成功空响应。
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

// mapWebauthnError 通行密钥族错误 → Connect 形态：降级窗口 → invalid_argument +
// ErrorInfo{method_disabled, 固定文案}；参数 / 校验类 → invalid_argument + ErrorInfo；
// 重复注册 → already_exists（裸 Connect code）；资源不存在 → not_found；
// 内部故障 → internal 固定文案（不挂 ErrorInfo）；其余上抛消毒。
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
		return connect.NewError(connect.CodeInternal, internalconnect.InternalError(err))
	case errors.Is(err, sql.ErrNoRows):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}

// —— 头像上传三桩 ——
// 请求绑定与错误映射归本层，direct 三步与 proxy 落盘编排在
// service/account.AvatarService。未配置 / 模式不符（direct 调 presign、
// proxy 调上传）被直调按未知异常映射 internal；三接口均需 al_session。

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

// CommitAvatar 仅记录已上传并回显地址，不回读校验（禁止 Get/HEAD）；{key} → {url}。
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

// UploadAvatar（§3.2、§10.8 proxy 模式）：文件内容一次 bytes 直传
// （protojson 下 content 为 base64，§1.1），{filename, contentType, content}
// → {url}；service 直接消费 proto 请求，本层透传。请求体上限由装配层
// WithReadMaxBytes（8 MiB）承担，业务侧 size 校验归 service。
func (h *Handler) UploadAvatar(ctx context.Context, req *connect.Request[accountv1.UploadAvatarRequest]) (*connect.Response[accountv1.AvatarResponse], error) {
	if h.avatar == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errAvatarNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	res, err := h.avatar.UploadAvatar(ctx, uid, req.Msg)
	if err != nil {
		return nil, mapAvatarError("upload avatar", err)
	}
	return connect.NewResponse(res), nil
}

// mapAvatarError 头像上传错误 → Connect 形态：未配置 / 模式不符 → internal 固定文案；
// MIME / size 校验类 → invalid_argument + ErrorInfo{file_type_not_allowed /
// file_too_large}（文案与前端预校验一致）；边界非法入参 → invalid_request；
// 用户不存在 → not_found（profile.go 口径同源）；其余上抛消毒。
func mapAvatarError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrAvatarNotConfigured),
		errors.Is(err, accountsvc.ErrAvatarPresignUnavailable),
		errors.Is(err, accountsvc.ErrAvatarUploadUnavailable):
		return connect.NewError(connect.CodeInternal, internalconnect.InternalError(err))
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
	case errors.Is(err, sql.ErrNoRows):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}

// —— 改密 ——

// ChangePassword 当前用户改密 / 无密码账号设密，编排在 PasswordService。改密成功后
// 旧会话与全部已颁发令牌经 epoch 失效链失效；浏览器侧清除 al_session 收尾
// （与 session 拦截器同一写出出口 AddSessionCookie；未注入时跳过——测试装配用）。
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

// mapPasswordError 改密错误 → Connect 形态：newPassword 不满足策略 → invalid_argument +
// ErrorInfo{password_weak}；旧密码校验失败 → invalid_credentials（password_incorrect
// 系笔误，不另设码）；参数类 → invalid_request；用户不存在 → not_found；其余上抛消毒。
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
	case errors.Is(err, sql.ErrNoRows):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}

// —— 手机 / 邮箱换绑族 ——
// 请求绑定（step / payload 拆解、CaptchaPayload → captcha.Submission）与错误映射归本层，
// 两步编排（captcha 必检、占用判定、发码、GETDEL 核销、列级落库、审计）在 BindContactService。
// IP 维度：来源 IP 由 http 挂载层注入 ctx（ipres，与 event_log 审计同款
// orchestrator.ClientIPFromRequest 口径），本层只取现成值传 service（发码侧
// 单 IP 日限额键 / 审计链路），不在 handler 解析 Header。两接口均需 al_session。

// BindPhone（§3.4 行 887）：手机号绑定 / 换绑两步同端点，由 step 区分
// （challenge 需请求顶层 captcha、payload {phone}；verify payload
// {phone, code}）；成功为空响应。
func (h *Handler) BindPhone(ctx context.Context, req *connect.Request[accountv1.BindPhoneRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.bindcontact == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errBindNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	in := accountsvc.BindPhoneInput{Step: req.Msg.GetStep(), Captcha: captchaSubmission(req.Msg.GetCaptcha()), IP: ipres.ClientIP(ctx)}
	if p := req.Msg.GetPayload(); p != nil {
		in.Target = p.GetPhone()
		in.Code = p.GetCode()
	}
	if err := h.bindcontact.BindPhone(ctx, uid, in); err != nil {
		return nil, mapBindError("bind phone", err)
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// BindEmail 邮箱绑定 / 换绑两步同端点，由 step 区分；成功为空响应。
func (h *Handler) BindEmail(ctx context.Context, req *connect.Request[accountv1.BindEmailRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.bindcontact == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errBindNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	in := accountsvc.BindEmailInput{Step: req.Msg.GetStep(), Captcha: captchaSubmission(req.Msg.GetCaptcha()), IP: ipres.ClientIP(ctx)}
	if p := req.Msg.GetPayload(); p != nil {
		in.Target = p.GetEmail()
		in.Code = p.GetCode()
	}
	if err := h.bindcontact.BindEmail(ctx, uid, in); err != nil {
		return nil, mapBindError("bind email", err)
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// captchaSubmission CaptchaPayload → captcha.Submission：与 dto/sso.go 同名字段直映
// （跨包私有各落一份，本包不为此扩大 dto 导出面）；未提交时返回 nil 交 service 判定缺失。
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

// mapBindError 换绑错误 → Connect 形态：参数 / 校验类 → invalid_argument + ErrorInfo；
// target_taken → already_exists；user_not_found → not_found；限流 / 冷却 → resource_exhausted；
// invalid_code 经 errors.As 挂 ErrorInfo.attemptsLeft；captcha 失败并列 CaptchaConfig detail。
func mapBindError(op string, err error) error {
	switch {
	case errors.Is(err, accountsvc.ErrBindInvalidRequest):
		return internalconnect.WithErrorInfo(
			connect.NewError(connect.CodeInvalidArgument, err),
			internalconnect.NewErrorInfo("account", "invalid_request", "invalid request"),
		)
	case errors.Is(err, accountsvc.ErrBindCaptchaRequired):
		return withBindCaptchaConfig(err, captcha.StatusRequired, "captcha required")
	case errors.Is(err, accountsvc.ErrBindCaptchaInvalid):
		return withBindCaptchaConfig(err, captcha.StatusInvalid, "captcha invalid or used")
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

// withBindCaptchaConfig 构造绑定族 captcha 失败错误体：与 sso 域同一口径；CaptchaConfig
// 三字段取自与 gate 判定同源的失败载荷并与之并列。载荷缺失时不臆造第二配置源，
// 只省去 detail，错误码与 domain 仍完整下发。
func withBindCaptchaConfig(err error, code, message string) error {
	coded := internalconnect.WithErrorInfo(
		connect.NewError(connect.CodeInvalidArgument, errors.New(message)),
		internalconnect.NewErrorInfo("account", code, message),
	)
	var f *accountsvc.BindCaptchaFailure
	if !errors.As(err, &f) {
		return coded
	}
	return internalconnect.WithCaptchaConfig(coded, &commonv1.CaptchaConfig{
		ProviderKey: f.Config.ProviderKey,
		Type:        f.Config.Type,
		SiteKey:     f.Config.SiteKey,
	})
}

// —— 两步验证族四方法 + UnbindTotp ——
// 请求绑定与错误映射归本层，明细聚合 / TOTP 绑定 / 恢复码在 MfaService；均需 al_session。

// GetMfa 五因子绑定明细 + recoveryIssuedAt（摘要走 mfaPolicy，本接口只出明细不重复）。
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

// SetMfa 切换两步验证开关（§3.5），成功为空响应。
func (h *Handler) SetMfa(ctx context.Context, req *connect.Request[accountv1.SetMfaRequest]) (*connect.Response[accountv1.OkResponse], error) {
	if h.mfa == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errMfaNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	if err := h.mfa.SetMfa(ctx, uid, req.Msg.GetEnabled()); err != nil {
		return nil, mapMfaError("set mfa", err)
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// BindTotp 绑定两步：challenge → {secret, otpauthUrl, qrcodeContent}；verify（{secret,
// code}）→ {recoveryCodes} 验证一次后生效并下发 10 个恢复码；step 非法 → invalid_request。
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
			Secret:        ch.Secret,
			OtpauthUrl:    ch.OtpauthUrl,
			QrcodeContent: ch.QrcodeContent,
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

// UnbindTotp 解除当前 TOTP 绑定，成功为空响应。前置须取得 verificationToken
// （biz_purpose=unbind_totp）；缺断言 → verification_required，无效 / 过期 / 重放 →
// verification_invalid，通过后才删除绑定（三重校验在 MfaService）。
func (h *Handler) UnbindTotp(ctx context.Context, req *connect.Request[accountv1.UnbindTotpRequest]) (*connect.Response[accountv1.OkResponse], error) {
	unbinder, ok := h.mfa.(MfaUnbinder)
	if !ok {
		return nil, connect.NewError(connect.CodeUnimplemented, errMfaNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	if err := unbinder.UnbindTotp(ctx, uid, req.Msg.GetVerificationToken()); err != nil {
		return nil, mapMfaError("unbind totp", err)
	}
	return connect.NewResponse(&accountv1.OkResponse{}), nil
}

// StartVerification 主体只由会话 al_session 的 uid 推导，请求不得携带 uid；成功下发挑战令牌与可用因子。
func (h *Handler) StartVerification(ctx context.Context, req *connect.Request[commonv1.StartVerificationRequest]) (*connect.Response[commonv1.StartVerificationResponse], error) {
	if h.verification == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errVerificationNotConfigured)
	}
	uid, ok := session.UIDFromContext(ctx)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	res, failure, err := h.verification.Start(ctx, verification.StartInput{
		Domain:     verification.DomainAccount,
		BizPurpose: verification.BizPurpose(req.Msg.GetBizPurpose()),
		Method:     req.Msg.GetMethod(),
		Operation:  req.Msg.GetOperation(),
		SessionUID: strconv.FormatInt(uid, 10),
		Captcha:    verification.ParseCaptchaSubmission(req.Msg.GetCaptcha()),
	})
	if err != nil {
		return nil, mapVerificationError("account", err)
	}
	if failure != nil {
		return nil, encodeAccountCaptchaFailure(failure)
	}
	return connect.NewResponse(startVerificationResponse(res)), nil
}

// SubmitVerification 提交二次因子，成功返回不透明断言令牌交回发起敏感操作的接口。
// loginToken 仅 SsoService 组可用，本组收到一律按 invalid_request 拒绝。
func (h *Handler) SubmitVerification(ctx context.Context, req *connect.Request[commonv1.SubmitVerificationRequest]) (*connect.Response[commonv1.SubmitVerificationResponse], error) {
	if h.verification == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errVerificationNotConfigured)
	}
	if req.Msg.GetLoginToken() != "" {
		return nil, mapVerificationError("account", &verification.Error{Code: "invalid_request"})
	}
	// 防御性校验：AccountService 组全接口以会话 uid 为主体（§3.8.1），
	// 与 StartVerification 对齐；session 拦截器放行匿名，本 handler 在 ctx 无 uid 时返回 401。
	if _, ok := session.UIDFromContext(ctx); !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errAuthRequired)
	}
	res, err := h.verification.Submit(ctx, verification.SubmitInput{
		Domain:         verification.DomainAccount,
		ChallengeToken: req.Msg.GetChallengeToken(),
		Method:         req.Msg.GetMethod(),
		Payload:        req.Msg.GetPayload(),
	})
	if err != nil {
		return nil, mapVerificationError("account", err)
	}
	return connect.NewResponse(&commonv1.SubmitVerificationResponse{
		VerificationToken: res.VerificationToken,
		ExpiresIn:         res.ExpiresIn,
		Amr:               res.AMR,
	}), nil
}

// mapVerificationError step-up 领域失败 → Connect 错误体 + ErrorInfo：
// verification_required / verification_invalid → failed_precondition；限流 →
// resource_exhausted（带 retry_after）；其余 → invalid_argument；非领域错误上抛消毒。
func mapVerificationError(domain string, err error) error {
	var ve *verification.Error
	if !errors.As(err, &ve) {
		return fmt.Errorf("account handler: verification: %w", err)
	}
	connCode := connect.CodeInvalidArgument
	switch ve.Code {
	case "verification_required", "verification_invalid":
		connCode = connect.CodeFailedPrecondition
	case "too_many_requests":
		connCode = connect.CodeResourceExhausted
	}
	info := internalconnect.NewErrorInfo(domain, ve.Code, ve.Code)
	info.RetryAfter = ve.RetryAfter
	info.AttemptsLeft = ve.AttemptsLeft
	return internalconnect.WithErrorInfo(
		connect.NewError(connCode, errors.New(ve.Code)),
		info,
	)
}

// encodeAccountCaptchaFailure step-up 人机校验失败 → Connect 错误体：错误码与当前生效
// CaptchaConfig 并列 details，与 sso 域同款口径，不静默回落、不丢错误码与配置。
func encodeAccountCaptchaFailure(f *captcha.Failure) error {
	message := "captcha required"
	if f.Code == captcha.StatusInvalid {
		message = "captcha invalid or used"
	}
	coded := internalconnect.WithErrorInfo(
		connect.NewError(connect.CodeInvalidArgument, errors.New(message)),
		internalconnect.NewErrorInfo("account", f.Code, message),
	)
	return internalconnect.WithCaptchaConfig(coded, &commonv1.CaptchaConfig{
		ProviderKey: f.Config.ProviderKey,
		Type:        f.Config.Type,
		SiteKey:     f.Config.SiteKey,
	})
}

// startVerificationResponse 领域结论 → 响应消息投影。
func startVerificationResponse(res *verification.StartResult) *commonv1.StartVerificationResponse {
	out := &commonv1.StartVerificationResponse{
		ChallengeToken: res.ChallengeToken,
		ExpiresIn:      res.ExpiresIn,
	}
	for i := range res.Methods {
		m := &res.Methods[i]
		out.Methods = append(out.Methods, &commonv1.VerificationMethod{
			Method:          m.Method,
			Usage:           m.Usage,
			Steps:           m.Steps,
			ChallengeFields: m.ChallengeFields,
			CodeLength:      m.CodeLength,
			ResendAfter:     m.ResendAfter,
			ExpiresIn:       m.ExpiresIn,
			Capability:      m.Capability,
			Providers:       m.Providers,
		})
	}
	if res.NextStepKind != "" {
		out.NextStep = &commonv1.VerificationNextStep{
			Kind:          res.NextStepKind,
			ChallengeData: res.ChallengeData,
		}
	}
	return out
}

// RegenerateRecoveryCodes 重新生成即全量作废；出参与 BindTotp verify 同格式一次性下发新码。
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

// mapMfaError 两步验证族错误 → Connect 形态：无有效会话 → unauthenticated；
// 参数 / step / 码格式 / action 类 → invalid_argument + ErrorInfo{invalid_request}；
// 码不匹配 → invalid_code；未启用 / 消费尽 → code_expired；基础设施故障 →
// internal 固定文案（不挂 ErrorInfo）；用户不存在 → not_found；其余上抛消毒。
func mapMfaError(op string, err error) error {
	// step-up 断言类失败（缺断言 / 无效 / 重放）走专用错误码，
	// 不并入两步验证族的 invalid_code / code_expired 分支。
	var ve *verification.Error
	if errors.As(err, &ve) {
		return mapVerificationError("account", err)
	}
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
		return connect.NewError(connect.CodeInternal, internalconnect.InternalError(err))
	case errors.Is(err, sql.ErrNoRows):
		return connect.NewError(connect.CodeNotFound, errNotFound)
	default:
		return fmt.Errorf("account handler: %s: %w", op, err)
	}
}

// —— 本人事件日志 ——

// eventsListPageSizeMax 分页上限（与 admin 域同值，跨包私有各落一份）。
const eventsListPageSizeMax = 100

// GetEvents 本人登录记录（仅成功记录——数据源口径，无 login_failed 常量与成功标志列）；
// 分页归一后回显；行 → proto 投影在 dto.AccountUserEventItem。sort / order 字段保留
// 但不应用（沿 admin GetUserEvents 先例固定 id DESC，值域核对留待真后端联调）。
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

// normalizeListPage 分页归一（page 从 1 开始、pageSize 默认 20、上限 100）——响应回显
// 归一后的生效值；admin 域同名函数为包内私有，跨包各落一份（口径相同）。
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

// mapEventsError 事件日志错误 → Connect 形态：uid 契约违约（拼装层必须注入会话 uid）→
// invalid_argument + ErrorInfo{invalid_request}；repo 错误原样上抛消毒。
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
